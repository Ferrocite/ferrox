//! Xray-core's protobuf config, decoded into this tree's JSON AST.
//!
//! The pinned scenario suite builds a binary at run time and spawns it with
//! `-config=stdin: -format=pb` (`testing/scenarios/common_regular.go`), so the
//! conformance seam needs this wire form, not the JSON dialect. Only the
//! messages a scenario names are decoded, and every other field is refused by
//! name: a config that means more than this tree carries fails at start rather
//! than serving something smaller in silence.

use crate::json::Json;

pub(crate) fn to_json(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.core.Config");
    let mut inbounds = Vec::new();
    let mut outbounds = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => inbounds.push(inbound(reader.bytes()?)?),
            (2, 2) => outbounds.push(outbound(reader.bytes()?)?),
            // Apps (dispatcher, proxyman, log) and extensions wire xray's own object graph; nothing below reads them.
            (4 | 6, 2) => {
                reader.bytes()?;
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(object(vec![
        ("inbounds", Json::Arr(inbounds)),
        ("outbounds", Json::Arr(outbounds)),
    ]))
}

fn inbound(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.core.InboundHandlerConfig");
    let mut receiver = None;
    let mut settings = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            // A tag names the handler for xray's router; nothing here routes.
            (1, 2) => {
                reader.bytes()?;
            }
            (2, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name != "xray.app.proxyman.ReceiverConfig" {
                    return Err(format!("inbound receiver `{name}` is not carried"));
                }
                receiver = Some(receiver_config(value)?);
            }
            (3, 2) => settings = Some(typed_message(reader.bytes()?)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let (listen, port) = receiver.ok_or("xray.core.InboundHandlerConfig: no receiver settings")?;
    let (name, value) = settings.ok_or("xray.core.InboundHandlerConfig: no proxy settings")?;
    let protocol = match name.as_str() {
        "xray.proxy.http.ServerConfig" => {
            http_settings(value)?;
            "http"
        }
        _ => return Err(format!("inbound protocol `{name}` is not carried")),
    };
    Ok(object(vec![
        ("protocol", Json::Str(protocol.to_owned())),
        ("port", Json::Num(f64::from(port))),
        ("listen", Json::Str(listen)),
    ]))
}

fn outbound(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.core.OutboundHandlerConfig");
    let mut settings = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            // A tag names the handler and a comment describes it; nothing here reads them.
            (1 | 5, 2) => {
                reader.bytes()?;
            }
            // Sender settings carry the client-side stream and multiplex policy; a scenario that sets them means more than a direct dial.
            (2, 2) => return Err(reader.uncarried("sender settings")),
            (3, 2) => settings = Some(typed_message(reader.bytes()?)?),
            (4, 0) => return Err(reader.uncarried("expire")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let (name, value) = settings.ok_or("xray.core.OutboundHandlerConfig: no proxy settings")?;
    match name.as_str() {
        "xray.proxy.freedom.Config" => {
            freedom_settings(value)?;
            Ok(object(vec![("protocol", Json::Str("freedom".to_owned()))]))
        }
        _ => Err(format!("outbound protocol `{name}` is not carried")),
    }
}

fn receiver_config(bytes: &[u8]) -> Result<(String, u16), String> {
    let mut reader = Reader::new(bytes, "xray.app.proxyman.ReceiverConfig");
    let mut port = None;
    let mut listen = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => port = Some(port_list(reader.bytes()?)?),
            (2, 2) => listen = Some(ip_or_domain(reader.bytes()?)?),
            (3, 2) => return Err(reader.uncarried("stream settings in the protobuf form")),
            (4, 0) => return Err(reader.uncarried("receive_original_destination")),
            (6, 2) => return Err(reader.uncarried("sniffing settings")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let port = port.ok_or("xray.app.proxyman.ReceiverConfig: no port list")?;
    // An absent listen means every interface in xray; this tree binds loopback unless told otherwise, and its JSON dialect reads the same default.
    Ok((listen.unwrap_or_else(|| "127.0.0.1".to_owned()), port))
}

fn port_list(bytes: &[u8]) -> Result<u16, String> {
    let mut reader = Reader::new(bytes, "xray.common.net.PortList");
    let mut port = None;
    let mut ranges = 0;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                ranges += 1;
                let (from, to) = port_range(reader.bytes()?)?;
                if from != to {
                    return Err(format!(
                        "xray.common.net.PortList: the range {from}-{to} is not carried; one port per inbound"
                    ));
                }
                if from == 0 {
                    return Err("xray.common.net.PortList: port 0 is not carried".to_owned());
                }
                port = Some(u16::try_from(from).map_err(|_| {
                    format!("xray.common.net.PortList: port {from} is out of range")
                })?);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    if ranges > 1 {
        return Err(format!(
            "xray.common.net.PortList: {ranges} ranges are not carried; one port per inbound"
        ));
    }
    port.ok_or_else(|| "xray.common.net.PortList: no range".to_owned())
}

fn port_range(bytes: &[u8]) -> Result<(u32, u32), String> {
    let mut reader = Reader::new(bytes, "xray.common.net.PortRange");
    let mut from = 0;
    let mut to = 0;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => {
                let value = reader.varint()?;
                from = u32::try_from(value).map_err(|_| {
                    format!("xray.common.net.PortRange: port {value} is above 65535")
                })?;
            }
            (2, 0) => {
                let value = reader.varint()?;
                to = u32::try_from(value).map_err(|_| {
                    format!("xray.common.net.PortRange: port {value} is above 65535")
                })?;
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((from, to))
}

fn ip_or_domain(bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(bytes, "xray.common.net.IPOrDomain");
    let mut ip = None;
    let mut domain = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => ip = Some(reader.bytes()?),
            (2, 2) => {
                domain = Some(std::str::from_utf8(reader.bytes()?).map_err(|_| {
                    "xray.common.net.IPOrDomain: the domain is not utf-8".to_owned()
                })?);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    match (ip, domain) {
        (Some(ip), None) => match ip.len() {
            4 => Ok(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string()),
            16 => {
                let bytes: [u8; 16] = ip
                    .try_into()
                    .map_err(|_| "xray.common.net.IPOrDomain: a 16-byte address".to_owned())?;
                Ok(std::net::Ipv6Addr::from(bytes).to_string())
            }
            len => Err(format!(
                "xray.common.net.IPOrDomain: an address of {len} bytes is neither IPv4 nor IPv6"
            )),
        },
        (None, Some(domain)) if !domain.is_empty() => Ok(domain.to_owned()),
        (None, Some(_)) => Err("xray.common.net.IPOrDomain: an empty domain".to_owned()),
        (None, None) => Err("xray.common.net.IPOrDomain: no address".to_owned()),
        (Some(_), Some(_)) => Err("xray.common.net.IPOrDomain: both an ip and a domain".to_owned()),
    }
}

fn typed_message(bytes: &[u8]) -> Result<(String, &[u8]), String> {
    let mut reader = Reader::new(bytes, "xray.common.serial.TypedMessage");
    let mut name = None;
    let mut value = &[][..];
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                name = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.common.serial.TypedMessage: the type is not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
            }
            (2, 2) => value = reader.bytes()?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        name.ok_or("xray.common.serial.TypedMessage: no type")?,
        value,
    ))
}

fn http_settings(bytes: &[u8]) -> Result<(), String> {
    let mut reader = Reader::new(bytes, "xray.proxy.http.ServerConfig");
    // Every field of the empty ServerConfig is a capability this tree lacks, so the first one set is the refusal.
    match reader.field()? {
        None => Ok(()),
        Some((2, 2)) => Err(reader.uncarried("an account map")),
        Some((3, 0)) => Err(reader.uncarried("allow_transparent")),
        Some((4, 0)) => Err(reader.uncarried("user_level")),
        Some((field, wire)) => Err(reader.refuse(field, wire)),
    }
}

fn freedom_settings(bytes: &[u8]) -> Result<(), String> {
    let mut reader = Reader::new(bytes, "xray.proxy.freedom.Config");
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => return Err(reader.uncarried("domain_strategy")),
            (3, 2) => return Err(reader.uncarried("destination_override")),
            (4, 0) => return Err(reader.uncarried("user_level")),
            (5, 2) => return Err(reader.uncarried("fragment (README row 120)")),
            (6, 0) => return Err(reader.uncarried("proxy_protocol (README row 117)")),
            (7, 2) => return Err(reader.uncarried("noises")),
            (8, 2) => final_rules(reader.bytes()?)?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(())
}

/// Freedom dials directly unless a final rule says otherwise; an allow rule is
/// that same direct dial, and any other action is a policy this tree has not
/// implemented.
fn final_rules(bytes: &[u8]) -> Result<(), String> {
    let mut reader = Reader::new(bytes, "xray.proxy.freedom.FinalRuleConfig");
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => {
                let action = reader.varint()?;
                if action != 0 {
                    return Err(reader.uncarried(&format!("final rule action {action}")));
                }
            }
            // Networks, ip, port and block delay scope a rule; a scoped rule is one this tree cannot yet honor.
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(())
}

fn object(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

/// One protobuf message reader, walked field by field to the message's end.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    message: &'static str,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8], message: &'static str) -> Self {
        Self {
            buf,
            pos: 0,
            message,
        }
    }

    /// The next field number and wire type, or `None` at the message's end.
    fn field(&mut self) -> Result<Option<(u64, u8)>, String> {
        if self.pos == self.buf.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let (field, wire) = (key >> 3, (key & 7) as u8);
        if field == 0 {
            return Err(format!("{}: field number 0", self.message));
        }
        if !matches!(wire, 0 | 1 | 2 | 5) {
            return Err(format!(
                "{}: field {field} has wire type {wire}",
                self.message
            ));
        }
        Ok(Some((field, wire)))
    }

    fn varint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = *self
                .buf
                .get(self.pos)
                .ok_or_else(|| format!("{}: a varint runs past the message", self.message))?;
            self.pos += 1;
            if shift >= 64 {
                return Err(format!(
                    "{}: a varint is longer than ten bytes",
                    self.message
                ));
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let length = self.varint()?;
        let end = self
            .pos
            .checked_add(
                usize::try_from(length)
                    .map_err(|_| format!("{}: a length overflows", self.message))?,
            )
            .filter(|end| *end <= self.buf.len())
            .ok_or_else(|| {
                format!(
                    "{}: a length-delimited field runs past the message",
                    self.message
                )
            })?;
        let field = &self.buf[self.pos..end];
        self.pos = end;
        Ok(field)
    }

    fn refuse(&self, field: u64, wire: u8) -> String {
        format!(
            "{}: field {field} (wire type {wire}) is not carried",
            self.message
        )
    }

    fn uncarried(&self, what: &str) -> String {
        format!("{}: {what} is not carried", self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while value >= 0x80 {
            out.push(value as u8 | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
        out
    }

    fn varint_field(field: u64, value: u64) -> Vec<u8> {
        let mut out = varint(field << 3);
        out.extend(varint(value));
        out
    }

    fn bytes_field(field: u64, value: &[u8]) -> Vec<u8> {
        let mut out = varint(field << 3 | 2);
        out.extend(varint(value.len() as u64));
        out.extend_from_slice(value);
        out
    }

    fn message(fields: &[Vec<u8>]) -> Vec<u8> {
        fields.concat()
    }

    fn typed(name: &str, value: &[u8]) -> Vec<u8> {
        message(&[bytes_field(1, name.as_bytes()), bytes_field(2, value)])
    }

    fn receiver(port: u64, listen: Option<&[u8]>) -> Vec<u8> {
        let range = message(&[varint_field(1, port), varint_field(2, port)]);
        let list = message(&[bytes_field(1, &range)]);
        let mut fields = vec![bytes_field(1, &list)];
        if let Some(ip) = listen {
            fields.push(bytes_field(2, &bytes_field(1, ip)));
        }
        message(&fields)
    }

    fn http_inbound(receiver: &[u8], settings: &[u8]) -> Vec<u8> {
        message(&[
            bytes_field(2, &typed("xray.app.proxyman.ReceiverConfig", receiver)),
            bytes_field(3, &typed("xray.proxy.http.ServerConfig", settings)),
        ])
    }

    fn freedom_outbound() -> Vec<u8> {
        // `FinalRules: []{{Action: Allow}}` — Allow is the proto3 default, so the entry is empty on the wire.
        let rules = bytes_field(8, &Vec::new());
        message(&[bytes_field(3, &typed("xray.proxy.freedom.Config", &rules))])
    }

    fn config(inbound: &[u8], outbound: &[u8]) -> Vec<u8> {
        message(&[bytes_field(1, inbound), bytes_field(2, outbound)])
    }

    fn http_scenario(port: u64) -> Vec<u8> {
        config(
            &http_inbound(&receiver(port, Some(&[127, 0, 0, 1])), &[]),
            &freedom_outbound(),
        )
    }

    #[test]
    fn the_http_scenario_decodes_to_the_json_this_tree_serves() {
        let json = to_json(&http_scenario(5000)).expect("the pinned shape decodes");
        let inbounds = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds");
        assert_eq!(inbounds.len(), 1);
        assert_eq!(
            inbounds[0].get("protocol").and_then(Json::as_str),
            Some("http")
        );
        assert_eq!(inbounds[0].get("port").and_then(Json::as_port), Some(5000));
        assert_eq!(
            inbounds[0].get("listen").and_then(Json::as_str),
            Some("127.0.0.1")
        );
        let outbounds = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds");
        assert_eq!(
            outbounds[0].get("protocol").and_then(Json::as_str),
            Some("freedom")
        );
    }

    #[test]
    fn an_app_is_not_serving_state() {
        let mut bytes = http_scenario(5000);
        bytes.extend(bytes_field(4, &typed("xray.app.dispatcher.Config", &[])));
        let json = to_json(&bytes).expect("apps are skipped");
        assert_eq!(
            json.get("inbounds")
                .and_then(Json::as_arr)
                .map(<[Json]>::len),
            Some(1)
        );
    }

    #[test]
    fn an_unread_field_is_refused_by_number() {
        let mut receiver = receiver(5000, Some(&[127, 0, 0, 1]));
        receiver.extend(varint_field(7, 1));
        let bytes = config(&http_inbound(&receiver, &[]), &freedom_outbound());
        let error = to_json(&bytes).expect_err("refused");
        assert!(error.contains("field 7"), "{error}");
    }

    #[test]
    fn protobuf_stream_settings_are_refused() {
        let mut receiver = receiver(5000, None);
        receiver.extend(bytes_field(3, &[]));
        let bytes = config(&http_inbound(&receiver, &[]), &freedom_outbound());
        let error = to_json(&bytes).expect_err("refused");
        assert!(error.contains("stream settings"), "{error}");
    }

    #[test]
    fn a_dokodemo_inbound_is_refused_by_name() {
        let inbound = message(&[
            bytes_field(
                2,
                &typed("xray.app.proxyman.ReceiverConfig", &receiver(5000, None)),
            ),
            bytes_field(3, &typed("xray.proxy.dokodemo.Config", &[])),
        ]);
        let error = to_json(&config(&inbound, &freedom_outbound())).expect_err("refused");
        assert!(error.contains("dokodemo"), "{error}");
    }

    #[test]
    fn an_account_map_is_refused() {
        let account = message(&[bytes_field(1, b"user"), bytes_field(2, b"pass")]);
        let settings = message(&[bytes_field(2, &account)]);
        let bytes = config(
            &http_inbound(&receiver(5000, None), &settings),
            &freedom_outbound(),
        );
        let error = to_json(&bytes).expect_err("refused");
        assert!(error.contains("account map"), "{error}");
    }

    #[test]
    fn a_scoped_freedom_rule_is_refused() {
        let rules = bytes_field(8, &varint_field(1, 1));
        let outbound = message(&[bytes_field(3, &typed("xray.proxy.freedom.Config", &rules))]);
        let bytes = config(&http_inbound(&receiver(5000, None), &[]), &outbound);
        let error = to_json(&bytes).expect_err("refused");
        assert!(error.contains("action 1"), "{error}");
    }

    #[test]
    fn a_port_range_is_refused() {
        let range = message(&[varint_field(1, 1000), varint_field(2, 2000)]);
        let list = message(&[bytes_field(1, &range)]);
        let receiver = message(&[bytes_field(1, &list)]);
        let bytes = config(&http_inbound(&receiver, &[]), &freedom_outbound());
        let error = to_json(&bytes).expect_err("refused");
        assert!(error.contains("1000-2000"), "{error}");
    }

    #[test]
    fn a_truncated_field_is_refused() {
        let mut bytes = http_scenario(5000);
        bytes.extend([0x0a, 0x05]);
        let error = to_json(&bytes).expect_err("refused");
        assert!(error.contains("runs past"), "{error}");
    }
}
