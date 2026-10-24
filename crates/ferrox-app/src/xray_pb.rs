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
    let mut routing = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => inbounds.extend(inbound(reader.bytes()?)?),
            (2, 2) => outbounds.push(outbound(reader.bytes()?)?),
            // The router's rules say which tagged outbound a flow goes to; every other app is xray's own object graph.
            (4, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name == "xray.app.router.Config" {
                    if routing.is_some() {
                        return Err("xray.core.Config: two router apps".to_owned());
                    }
                    routing = Some(router_settings(value)?);
                }
            }
            // Extensions wire xray's own object graph; nothing below reads them.
            (6, 2) => {
                reader.bytes()?;
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = vec![
        ("inbounds", Json::Arr(inbounds)),
        ("outbounds", Json::Arr(outbounds)),
    ];
    if let Some(routing) = routing {
        pairs.push(("routing", routing));
    }
    Ok(object(pairs))
}

/// One inbound handler decodes to one JSON inbound per port it names: xray carries a whole
/// range in one handler, and this tree binds one port per inbound.
fn inbound(bytes: &[u8]) -> Result<Vec<Json>, String> {
    let mut reader = Reader::new(bytes, "xray.core.InboundHandlerConfig");
    let mut receiver = None;
    let mut settings = None;
    let mut tag = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            // A tag names the handler for the router's rules.
            (1, 2) => {
                tag = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.core.InboundHandlerConfig: the tag is not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
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
    let (listen, ports, stream) =
        receiver.ok_or("xray.core.InboundHandlerConfig: no receiver settings")?;
    let (name, value) = settings.ok_or("xray.core.InboundHandlerConfig: no proxy settings")?;
    let (protocol, inbound_settings) = match name.as_str() {
        "xray.proxy.http.ServerConfig" => {
            http_settings(value)?;
            ("http", Json::Null)
        }
        "xray.proxy.dokodemo.Config" => ("dokodemo-door", dokodemo_settings(value)?),
        "xray.proxy.vmess.inbound.Config" => ("vmess", vmess_inbound_settings(value)?),
        "xray.proxy.vless.inbound.Config" => ("vless", vless_inbound_settings(value)?),
        "xray.proxy.shadowsocks.ServerConfig" => ("shadowsocks", ss_inbound_settings(value)?),
        "xray.proxy.socks.ServerConfig" => ("socks", socks_inbound_settings(value)?),
        _ => return Err(format!("inbound protocol `{name}` is not carried")),
    };
    Ok(ports
        .into_iter()
        .map(|port| {
            let mut pairs = vec![
                ("protocol", Json::Str(protocol.to_owned())),
                ("port", Json::Num(f64::from(port))),
                ("listen", Json::Str(listen.clone())),
            ];
            if let Some(tag) = &tag {
                pairs.push(("tag", Json::Str(tag.clone())));
            }
            if inbound_settings != Json::Null {
                pairs.push(("settings", inbound_settings.clone()));
            }
            if let Some(stream) = &stream {
                pairs.push(("streamSettings", stream.clone()));
            }
            object(pairs)
        })
        .collect())
}

fn outbound(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.core.OutboundHandlerConfig");
    let mut settings = None;
    let mut tag = None;
    let mut sender = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            // A tag names the handler for the router's rules.
            (1, 2) => {
                tag = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.core.OutboundHandlerConfig: the tag is not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
            }
            // A comment describes the handler; nothing here reads it.
            (5, 2) => {
                reader.bytes()?;
            }
            (2, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name != "xray.app.proxyman.SenderConfig" {
                    return Err(format!("outbound sender `{name}` is not carried"));
                }
                sender = sender_config(value)?;
            }
            (3, 2) => settings = Some(typed_message(reader.bytes()?)?),
            (4, 0) => return Err(reader.uncarried("expire")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let (name, value) = settings.ok_or("xray.core.OutboundHandlerConfig: no proxy settings")?;
    let mut pairs = match name.as_str() {
        "xray.proxy.freedom.Config" => {
            freedom_settings(value)?;
            vec![("protocol", Json::Str("freedom".to_owned()))]
        }
        "xray.proxy.vmess.outbound.Config" => vec![
            ("protocol", Json::Str("vmess".to_owned())),
            ("settings", vmess_outbound_settings(value)?),
        ],
        "xray.proxy.vless.outbound.Config" => vec![
            ("protocol", Json::Str("vless".to_owned())),
            ("settings", vless_outbound_settings(value)?),
        ],
        "xray.proxy.shadowsocks.ClientConfig" => vec![
            ("protocol", Json::Str("shadowsocks".to_owned())),
            ("settings", ss_outbound_settings(value)?),
        ],
        "xray.proxy.socks.ClientConfig" => vec![
            ("protocol", Json::Str("socks".to_owned())),
            ("settings", socks_outbound_settings(value)?),
        ],
        "xray.proxy.blackhole.Config" => {
            let settings = blackhole_settings(value)?;
            let mut pairs = vec![("protocol", Json::Str("blackhole".to_owned()))];
            if settings != Json::Null {
                pairs.push(("settings", settings));
            }
            pairs
        }
        _ => return Err(format!("outbound protocol `{name}` is not carried")),
    };
    if let Some(stream) = sender {
        pairs.push(("streamSettings", stream));
    }
    if let Some(tag) = tag {
        pairs.push(("tag", Json::Str(tag)));
    }
    Ok(object(pairs))
}

fn receiver_config(bytes: &[u8]) -> Result<(String, Vec<u16>, Option<Json>), String> {
    let mut reader = Reader::new(bytes, "xray.app.proxyman.ReceiverConfig");
    let mut ports = None;
    let mut listen = None;
    let mut stream = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => ports = Some(port_list(reader.bytes()?)?),
            (2, 2) => listen = Some(ip_or_domain(reader.bytes()?)?),
            (3, 2) => {
                // A receiver's stream settings are a bare `internet.StreamConfig`, not a typed wrapper.
                stream = Some(stream_settings(reader.bytes()?)?);
            }
            (4, 0) => return Err(reader.uncarried("receive_original_destination")),
            (6, 2) => return Err(reader.uncarried("sniffing settings")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let ports = ports.ok_or("xray.app.proxyman.ReceiverConfig: no port list")?;
    // An absent listen means every interface in xray; this tree binds loopback unless told otherwise, and its JSON dialect reads the same default.
    Ok((
        listen.unwrap_or_else(|| "127.0.0.1".to_owned()),
        ports,
        stream,
    ))
}

/// A sender's client-side stream policy: only its stream settings are carried, and a multiplex
/// or via policy names a shape this tree arms from the outbound's own JSON key.
fn sender_config(bytes: &[u8]) -> Result<Option<Json>, String> {
    let mut reader = Reader::new(bytes, "xray.app.proxyman.SenderConfig");
    let mut stream = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => return Err(reader.uncarried("the outbound's via address")),
            (2, 2) => {
                // A sender's stream settings are a bare `internet.StreamConfig`, not a typed wrapper.
                stream = Some(stream_settings(reader.bytes()?)?);
            }
            (4, 2) => return Err(reader.uncarried("multiplex settings")),
            (5, 2) => return Err(reader.uncarried("the via cidr")),
            (6, 0) => return Err(reader.uncarried("the target domain strategy")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(stream)
}

/// One stream policy as this tree's JSON dialect spells it: the network, and the security the
/// `security_type` name selects from the carried settings. An absent protocol name is xray's
/// own default (`tcp`), and a named security whose settings bytes are absent is that type's
/// zero value, which is how the reference reads it (`GetEffectiveSecuritySettings`).
fn stream_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.StreamConfig");
    let mut network = String::new();
    let mut tcp_settings: Option<Json> = None;
    let mut security_type = String::new();
    let mut security: Option<(&'static str, Json)> = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (2, 2) => {
                let settings = transport_settings(reader.bytes()?)?;
                if let Some((json, name)) = settings {
                    tcp_settings = Some(json);
                    network = name;
                }
            }
            (3, 2) => security_type = account_text(&mut reader)?,
            (4, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                // The named type's settings decide, as the reference's walk does; every other entry is read and dropped.
                if name == security_type {
                    security = Some(security_settings(&name, value)?);
                } else {
                    security_settings_exists(&name)?;
                }
            }
            (5, 2) => network = account_text(&mut reader)?,
            (6 | 8 | 9 | 10 | 11 | 12, _) => {
                return Err(reader.uncarried("socket, address, mask or quic policy on a stream"))
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let network = if network.is_empty() {
        "tcp".to_owned()
    } else {
        network
    };
    if network != "tcp" {
        return Err(format!("network `{network}` is not carried"));
    }
    let mut pairs = vec![("network", Json::Str(network))];
    if let Some(settings) = tcp_settings {
        pairs.push(("tcpSettings", settings));
    }
    if let Some((kind, settings)) = security {
        pairs.push(("security", Json::Str(kind.to_owned())));
        if settings != Json::Null {
            let key = match kind {
                "tls" => "tlsSettings",
                _ => "realitySettings",
            };
            pairs.push((key, settings));
        }
    } else if !security_type.is_empty() {
        // A named security with no carried settings is that type's zero value: no certificates, no key — the kind's empty settings the reference builds too.
        pairs.push((
            "security",
            Json::Str(security_kind(&security_type)?.to_owned()),
        ));
    }
    Ok(object(pairs))
}

/// The dialect key a security type names: `tls` for one, `reality` for the other.
fn security_kind(security_type: &str) -> Result<&'static str, String> {
    match security_type {
        "xray.transport.internet.tls.Config" => Ok("tls"),
        "xray.transport.internet.reality.Config" => Ok("reality"),
        other => Err(format!("security `{other}` is not carried")),
    }
}

/// Whether a settings entry's name is one the dialect carries, for an entry the
/// `security_type` does not select: an uncarried one is still refused by name.
fn security_settings_exists(name: &str) -> Result<(), String> {
    security_kind(name).map(|_| ())
}

/// One transport's settings: the tree's raw tcp carrier reads none, so a named tcp config is
/// the `tcpSettings` key the dialect answers empty and a camouflaged header or a proxy
/// protocol verdict is a refusal by name.
fn transport_settings(bytes: &[u8]) -> Result<Option<(Json, String)>, String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.TransportConfig");
    let mut name = "tcp".to_owned();
    let mut header = false;
    let mut proxy_protocol = false;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (2, 2) => {
                let (message, value) = typed_message(reader.bytes()?)?;
                if message != "xray.transport.internet.tcp.Config" {
                    return Err(format!("transport settings `{message}` is not carried"));
                }
                let mut config = Reader::new(value, "xray.transport.internet.tcp.Config");
                while let Some((field, wire)) = config.field()? {
                    match (field, wire) {
                        (2, 2) => {
                            header = true;
                            config.bytes()?;
                        }
                        (3, 0) => proxy_protocol = config.varint()? != 0,
                        _ => return Err(config.refuse(field, wire)),
                    }
                }
            }
            (3, 2) => name = account_text(&mut reader)?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    if header {
        return Err(
            "xray.transport.internet.tcp.Config: a camouflaged header is not carried".to_owned(),
        );
    }
    if proxy_protocol {
        return Err(
            "xray.transport.internet.tcp.Config: accept_proxy_protocol is not carried".to_owned(),
        );
    }
    if name != "tcp" {
        return Err(format!("transport `{name}` is not carried"));
    }
    Ok(None)
}

/// The security settings a stream names, keyed the dialect's spelling of the dial that reads it.
fn security_settings(name: &str, bytes: &[u8]) -> Result<(&'static str, Json), String> {
    match name {
        "xray.transport.internet.tls.Config" => tls_settings(bytes).map(|(_, json)| ("tls", json)),
        "xray.transport.internet.reality.Config" => {
            reality_settings(bytes).map(|(_, json)| ("reality", json))
        }
        other => Err(format!("security `{other}` is not carried")),
    }
}

/// A tls identity in the tree's `tlsSettings` spelling. The certificates xray carries arrive
/// as PEM text (`ParseCertificate` runs `ToPEM` before writing), but that helper labels every
/// key it mints `RSA PRIVATE KEY` however the DER is shaped, and this tree's identity parse
/// goes on the label, so the label is corrected to the kind the DER itself names.
fn tls_settings(bytes: &[u8]) -> Result<(&'static str, Json), String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.tls.Config");
    let mut certificates: Vec<Json> = Vec::new();
    let mut server_name = String::new();
    let mut alpn: Vec<String> = Vec::new();
    let mut disable_system_root = false;
    let mut min_version = String::new();
    let mut max_version = String::new();
    let mut cipher_suites = String::new();
    let mut fingerprint = String::new();
    let mut pinned: Vec<&[u8]> = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (2, 2) => certificates.push(tls_certificate(reader.bytes()?)?),
            (3, 2) => server_name = account_text(&mut reader)?,
            (4, 2) => {
                let protocol = account_text(&mut reader)?;
                if protocol == "fromMitm" {
                    return Err(
                        "xray.transport.internet.tls.Config: alpn `fromMitm` is not carried"
                            .to_owned(),
                    );
                }
                alpn.push(protocol);
            }
            // Session resumption keys no wire byte this tree does not write; the read-dropped field is how the bridge reads a newer bool.
            (5, 2) => {
                reader.bytes()?;
            }
            (6, 0) => disable_system_root = reader.varint()? != 0,
            (7, 2) => min_version = account_text(&mut reader)?,
            (8, 2) => max_version = account_text(&mut reader)?,
            (9, 2) => cipher_suites = account_text(&mut reader)?,
            (11, 2) => fingerprint = account_text(&mut reader)?,
            (12, 0) => return Err(reader.uncarried("reject_unknown_sni")),
            (22, 2) => pinned.push(reader.bytes()?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = Vec::new();
    if !certificates.is_empty() {
        pairs.push(("certificates", Json::Arr(certificates)));
    }
    if !server_name.is_empty() {
        pairs.push(("serverName", Json::Str(server_name)));
    }
    if !alpn.is_empty() {
        pairs.push(("alpn", Json::Arr(alpn.into_iter().map(Json::Str).collect())));
    }
    if disable_system_root {
        pairs.push(("disableSystemRoot", Json::Bool(true)));
    }
    if !min_version.is_empty() {
        pairs.push(("minVersion", Json::Str(min_version)));
    }
    if !max_version.is_empty() {
        pairs.push(("maxVersion", Json::Str(max_version)));
    }
    if !cipher_suites.is_empty() {
        pairs.push(("cipherSuites", Json::Str(cipher_suites)));
    }
    if !fingerprint.is_empty() {
        pairs.push(("fingerprint", Json::Str(fingerprint)));
    }
    if !pinned.is_empty() {
        let text: Vec<String> = pinned.iter().map(|pin| hex(pin)).collect();
        pairs.push(("pinnedPeerCertSha256", Json::Str(text.join(","))));
    }
    Ok(("tlsSettings", object(pairs)))
}

/// One certificate entry. The reference carries both parts as PEM bytes (`ToPEM` on the
/// scenario wire), so they path through text; paths name files when values are unset.
fn tls_certificate(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.tls.Certificate");
    let mut certificate: Option<String> = None;
    let mut key: Option<String> = None;
    let mut certificate_path = String::new();
    let mut key_path = String::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => certificate = Some(account_text(&mut reader)?),
            (2, 2) => key = Some(account_text(&mut reader)?),
            (3 | 4 | 7 | 8, _) => return Err(reader.uncarried("a certificate policy")),
            (5, 2) => certificate_path = account_text(&mut reader)?,
            (6, 2) => key_path = account_text(&mut reader)?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    if let (Some(certificate), Some(key)) = (certificate, key) {
        return Ok(object(vec![
            ("certificate", Json::Str(certificate)),
            ("key", Json::Str(key)),
        ]));
    }
    if !certificate_path.is_empty() && !key_path.is_empty() {
        return Ok(object(vec![
            ("certificateFile", Json::Str(certificate_path)),
            ("keyFile", Json::Str(key_path)),
        ]));
    }
    Err("xray.transport.internet.tls.Certificate: no certificate bytes or paths".to_owned())
}

/// A reality identity in the tree's `realitySettings` spelling, both roles in one message: the
/// server's decoy and key, the client's own key, short id and hello fingerprint.
fn reality_settings(bytes: &[u8]) -> Result<(&'static str, Json), String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.reality.Config");
    let mut reality = RealityFields::default();
    while let Some((field, wire)) = reader.field()? {
        reality.read(&mut reader, field, wire)?;
    }
    reality.finish()
}

/// A reality config's fields as they parse: the server role fills `pairs` around the repeated
/// names and ids, the client role sets `client` for the role-collision verdict.
#[derive(Default)]
struct RealityFields {
    pairs: Vec<(&'static str, Json)>,
    server_names: Vec<String>,
    short_ids: Vec<String>,
    client: bool,
}

impl RealityFields {
    fn read(&mut self, reader: &mut Reader<'_>, field: u64, wire: u8) -> Result<(), String> {
        if field <= 13 {
            return self.server_role(reader, field, wire);
        }
        self.client_role(reader, field, wire)
    }

    fn server_role(&mut self, reader: &mut Reader<'_>, field: u64, wire: u8) -> Result<(), String> {
        match (field, wire) {
            (1, 0) => {
                if reader.varint()? != 0 {
                    self.pairs.push(("show", Json::Bool(true)));
                }
                Ok(())
            }
            (2, 2) => {
                let dest = account_text(reader)?;
                if !dest.is_empty() {
                    self.pairs.push(("dest", Json::Str(dest)));
                }
                Ok(())
            }
            (3, 2) => {
                let kind = account_text(reader)?;
                if !kind.is_empty() && kind != "tcp" {
                    return Err(format!(
                        "xray.transport.internet.reality.Config: decoy type `{kind}` is not carried"
                    ));
                }
                Ok(())
            }
            (4, 0) => {
                let xver = reader.varint()?;
                if xver > 2 {
                    return Err(
                        "xray.transport.internet.reality.Config: xver is above 2".to_owned()
                    );
                }
                if xver != 0 {
                    self.pairs.push(("xver", exact_count(xver)?));
                }
                Ok(())
            }
            (5, 2) => {
                let name = account_text(reader)?;
                if !name.is_empty() {
                    self.server_names.push(name);
                }
                Ok(())
            }
            (6, 2) => {
                self.pairs.push((
                    "privateKey",
                    Json::Str(b64url(reality_key("private", reader)?)),
                ));
                Ok(())
            }
            (7, 2) => {
                self.pairs
                    .push(("minClientVer", Json::Str(client_ver(reader.bytes()?)?)));
                Ok(())
            }
            (8, 2) => {
                self.pairs
                    .push(("maxClientVer", Json::Str(client_ver(reader.bytes()?)?)));
                Ok(())
            }
            (9, 0) => {
                let skew = reader.varint()?;
                if skew != 0 {
                    self.pairs.push(("maxTimeDiff", exact_count(skew)?));
                }
                Ok(())
            }
            (10, 2) => {
                let id = reader.bytes()?;
                self.short_ids.push(hex(id));
                Ok(())
            }
            (11, 2) => Err(reader.uncarried("the mldsa65 seed")),
            (12, 2) => {
                self.pairs
                    .push(("limitFallbackUpload", limit_fallback(reader.bytes()?)?));
                Ok(())
            }
            (13, 2) => {
                self.pairs
                    .push(("limitFallbackDownload", limit_fallback(reader.bytes()?)?));
                Ok(())
            }
            _ => Err(reader.refuse(field, wire)),
        }
    }

    fn client_role(&mut self, reader: &mut Reader<'_>, field: u64, wire: u8) -> Result<(), String> {
        match (field, wire) {
            (21, 2) => {
                let name = account_text(reader)?;
                if !name.is_empty() {
                    self.pairs.push(("fingerprint", Json::Str(name)));
                    self.client = true;
                }
                Ok(())
            }
            (22, 2) => {
                let name = account_text(reader)?;
                if !name.is_empty() {
                    self.pairs.push(("serverName", Json::Str(name)));
                    self.client = true;
                }
                Ok(())
            }
            (23, 2) => {
                self.pairs.push((
                    "publicKey",
                    Json::Str(b64url(reality_key("public", reader)?)),
                ));
                Ok(())
            }
            (24, 2) => {
                let id = reader.bytes()?;
                // The reference zero-pads the eight-byte id from the front, so a shorter id than the tree's one spelling keeps its own leading bytes.
                let mut padded = [0u8; 8];
                let len = id.len().min(8);
                padded[..len].copy_from_slice(&id[..len]);
                let short_id = if id.is_empty() {
                    String::new()
                } else {
                    hex(&padded)
                };
                self.pairs.push(("shortId", Json::Str(short_id)));
                self.client = true;
                Ok(())
            }
            (25, 2) => Err(reader.uncarried("the mldsa65 verify key")),
            // The spider path shapes the hello's steal request, which this tree's reality client writes its own shape for (pinned against the reference).
            (26 | 27, _) => reader.skip(wire),
            _ => Err(reader.refuse(field, wire)),
        }
    }

    /// The repeated names and ids merge last so they stay last in the served object, and a
    /// client-set reality config carries only the client fields: naming the server's side
    /// together with the client's is not a config either role serves whole.
    fn finish(self) -> Result<(&'static str, Json), String> {
        let mut pairs = self.pairs;
        if !self.server_names.is_empty() {
            pairs.push((
                "serverNames",
                Json::Arr(self.server_names.into_iter().map(Json::Str).collect()),
            ));
        }
        if !self.short_ids.is_empty() {
            pairs.push((
                "shortIds",
                Json::Arr(self.short_ids.into_iter().map(Json::Str).collect()),
            ));
        }
        if self.client {
            const SERVER: [&str; 10] = [
                "dest",
                "xver",
                "serverNames",
                "shortIds",
                "maxTimeDiff",
                "minClientVer",
                "maxClientVer",
                "limitFallbackUpload",
                "limitFallbackDownload",
                "privateKey",
            ];
            // A client's `show` is the reference's one handshake-debug print, which this tree's dial trace already names; the pair goes nowhere.
            pairs.retain(|(name, _)| *name != "show");
            let named: Vec<&str> = SERVER
                .iter()
                .filter(|key| pairs.iter().any(|(name, _)| name == *key))
                .copied()
                .collect();
            if !named.is_empty() {
                return Err(format!(
                    "xray.transport.internet.reality.Config: a client reality config names server fields {}",
                    named.join(", ")
                ));
            }
        }
        Ok(("realitySettings", object(pairs)))
    }
}

/// A 32-byte reality key, whatever role it plays: xray's X25519 field length, so anything
/// else is refused rather than decoded into an unusable id.
fn reality_key<'a>(role: &str, reader: &mut Reader<'a>) -> Result<&'a [u8; 32], String> {
    reader.bytes()?.try_into().map_err(|_| {
        format!("xray.transport.internet.reality.Config: the {role} key is not 32 bytes")
    })
}

/// The JSON number a count spells exactly: a float mantissa stops at 2^53, and a count past
/// it is one the dialect cannot serve without lying, so the count is refused. The cast is
/// exact behind the guard, which is the whole point of the guard.
fn exact_count(value: u64) -> Result<Json, String> {
    const EXACT: u64 = 1 << 53;
    if value < EXACT {
        #[allow(clippy::cast_precision_loss)] // the guard above makes the cast exact
        return Ok(Json::Num(value as f64));
    }
    Err(format!(
        "{value} is past the count a JSON number spells exactly"
    ))
}

fn limit_fallback(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.reality.LimitFallback");
    let mut after = 0u64;
    let mut per_sec = 0u64;
    let mut burst = 0u64;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => after = reader.varint()?,
            (2, 0) => per_sec = reader.varint()?,
            (3, 0) => burst = reader.varint()?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(object(vec![
        ("afterBytes", exact_count(after)?),
        ("bytesPerSec", exact_count(per_sec)?),
        ("burstBytesPerSec", exact_count(burst)?),
    ]))
}

/// The dotted spelling of a client-version window: one `.a.b.c` per byte xray pins.
fn client_ver(bytes: &[u8]) -> Result<String, String> {
    let bytes: &[u8; 3] = bytes.try_into().map_err(|_| {
        "xray.transport.internet.reality.Config: a version window is not 3 bytes".to_owned()
    })?;
    Ok(format!("{}.{}.{}", bytes[0], bytes[1], bytes[2]))
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// `base64.RawURLEncoding`, the alphabet xray's REALITY key spellings read with.
fn b64url(bytes: &[u8]) -> String {
    ferrox_core::b64::encode(bytes)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_owned()
}

/// The widest port range one inbound handler is expanded into. A range is bound one port per
/// inbound, so a wide one is a fan-out of listeners this tree would not choose to start.
const MAX_PORT_RANGE: u32 = 64;

fn port_list(bytes: &[u8]) -> Result<Vec<u16>, String> {
    let mut reader = Reader::new(bytes, "xray.common.net.PortList");
    let mut ports = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                let (from, to) = port_range(reader.bytes()?)?;
                if from == 0 {
                    return Err("xray.common.net.PortList: port 0 is not carried".to_owned());
                }
                if from > to {
                    return Err(format!(
                        "xray.common.net.PortList: the range {from}-{to} counts down"
                    ));
                }
                ports.extend(from..=to);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    if ports.is_empty() {
        return Err("xray.common.net.PortList: no range".to_owned());
    }
    if ports.len() > MAX_PORT_RANGE as usize {
        return Err(format!(
            "xray.common.net.PortList: {} ports is a wider fan-out than {MAX_PORT_RANGE} binds",
            ports.len()
        ));
    }
    Ok(ports)
}

fn port_range(bytes: &[u8]) -> Result<(u16, u16), String> {
    let mut reader = Reader::new(bytes, "xray.common.net.PortRange");
    let mut from = 0;
    let mut to = 0;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => {
                let value = reader.varint()?;
                from = u16::try_from(value).map_err(|_| {
                    format!("xray.common.net.PortRange: port {value} is above 65535")
                })?;
            }
            (2, 0) => {
                let value = reader.varint()?;
                to = u16::try_from(value).map_err(|_| {
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

/// Dokodemo-door forwards what it accepts to the one address its config names, which is the
/// shape every xray scenario writes. A `portMap` picks the target per port and a
/// `followRedirect` reads the kernel's own answer instead; neither has a lane in this tree.
fn dokodemo_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.dokodemo.Config");
    let mut address = None;
    let mut port = None;
    let mut networks = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => address = Some(ip_or_domain(reader.bytes()?)?),
            (2, 0) => {
                let value = reader.varint()?;
                port = Some(u16::try_from(value).map_err(|_| {
                    format!("xray.proxy.dokodemo.Config: rewrite port {value} is above 65535")
                })?);
            }
            (3, 2) => return Err(reader.uncarried("port_map")),
            (5, 0) => return Err(reader.uncarried("follow_redirect")),
            (6, 0) => return Err(reader.uncarried("user_level")),
            // A repeated enum arrives packed into one field or per field, and the packed payload carries no keys.
            (7, 2) => {
                let mut packed = Reader::new(reader.bytes()?, "xray.proxy.dokodemo.Config");
                while packed.more() {
                    networks.push(packed.varint()?);
                }
            }
            (7, 0) => networks.push(reader.varint()?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    if networks.is_empty() {
        return Err("xray.proxy.dokodemo.Config: no network allowed".to_owned());
    }
    let mut allowed = Vec::new();
    for value in &networks {
        allowed.push(match value {
            2 => "tcp",
            3 => "udp",
            4 => return Err(reader.uncarried("a unix dokodemo network")),
            other => {
                return Err(format!(
                    "xray.proxy.dokodemo.Config: network {other} is not carried"
                ))
            }
        });
    }
    Ok(object(vec![
        (
            "address",
            Json::Str(address.ok_or("xray.proxy.dokodemo.Config: no rewrite address")?),
        ),
        (
            "port",
            Json::Num(f64::from(
                port.ok_or("xray.proxy.dokodemo.Config: no rewrite port")?,
            )),
        ),
        ("network", Json::Str(allowed.join(","))),
    ]))
}

/// A vmess account: the user's uuid and the cipher it asks for when the config names one.
type VmessAccount = (String, Option<String>);

/// A vmess inbound serves the clients its users name; xray's default level and the detour
/// inbound are router features nothing here reads.
fn vmess_inbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.vmess.inbound.Config");
    let mut clients = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                let (id, security) = vmess_user(reader.bytes()?)?;
                clients.push(vmess_client(id, security));
            }
            (2, 2) => return Err(reader.uncarried("the default user config")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    if clients.is_empty() {
        return Err("xray.proxy.vmess.inbound.Config: no user".to_owned());
    }
    Ok(object(vec![("clients", Json::Arr(clients))]))
}

/// A vmess outbound dials the one endpoint its config names.
fn vmess_outbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.vmess.outbound.Config");
    let mut receiver = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => receiver = Some(server_endpoint(reader.bytes()?, vmess_user)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let (address, port, (id, security)) =
        receiver.ok_or("xray.proxy.vmess.outbound.Config: no receiver")?;
    Ok(object(vec![(
        "vnext",
        Json::Arr(vec![object(vec![
            ("address", Json::Str(address)),
            ("port", Json::Num(f64::from(port))),
            ("users", Json::Arr(vec![vmess_client(id, security)])),
        ])]),
    )]))
}

/// A blackhole outbound swallows the flow and answers the client with the
/// reference's own answer: nothing, the 403, or the bytes the config carries.
fn blackhole_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.blackhole.Config");
    let mut response = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => response = Some(blackhole_response(reader.bytes()?)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let Some(response) = response else {
        return Ok(Json::Null);
    };
    Ok(object(vec![("response", response)]))
}

/// `xray.proxy.blackhole.Response`: the answer's kind and the bytes a custom
/// answer carries. The bytes travel as base64, the shape this tree's own JSON
/// dialect reads them in.
fn blackhole_response(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.blackhole.Response");
    let mut kind = String::new();
    let mut data = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                kind.clear();
                kind.push_str(std::str::from_utf8(reader.bytes()?).map_err(|_| {
                    "xray.proxy.blackhole.Response: the type is not utf-8".to_owned()
                })?);
            }
            (2, 2) => data = reader.bytes()?.to_vec(),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = vec![("type", Json::Str(kind))];
    if !data.is_empty() {
        pairs.push((
            "customResponseData",
            Json::Str(ferrox_core::b64::encode(&data)),
        ));
    }
    Ok(object(pairs))
}

/// The router app: the rules that send a flow to a tagged outbound, in the
/// shape this tree's own router reads.
fn router_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.app.router.Config");
    let mut rules = Vec::new();
    let mut strategy = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => {
                let value = reader.varint()?;
                strategy = Some(match value {
                    0 => "AsIs",
                    2 => "IpIfNonMatch",
                    3 => "IpOnDemand",
                    other => return Err(reader.uncarried(&format!("the domain strategy {other}"))),
                });
            }
            (2, 2) => rules.push(router_rule(reader.bytes()?)?),
            (3, 2) => return Err(reader.uncarried("balancers")),
            (4, 2) => return Err(reader.uncarried("the routing script")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = Vec::new();
    if let Some(strategy) = strategy {
        pairs.push(("domainStrategy", Json::Str(strategy.to_owned())));
    }
    pairs.push(("rules", Json::Arr(rules)));
    Ok(object(pairs))
}

/// `xray.app.router.RoutingRule`: the outbound a flow goes to and the port it
/// goes on. Every other selector is refused by name: this tree's router reads
/// more of them, but the bridge carries what the pinned scenarios write.
fn router_rule(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.app.router.RoutingRule");
    let mut tag = None;
    let mut ports = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                tag = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.app.router.RoutingRule: the tag is not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
            }
            (14, 2) => ports = Some(port_selector(reader.bytes()?)?),
            (2, 2) => return Err(reader.uncarried("a domain rule")),
            (7, 2) => return Err(reader.uncarried("a user rule")),
            (8, 2) => return Err(reader.uncarried("an inbound tag")),
            (9, 2) => return Err(reader.uncarried("a protocol rule")),
            (10, 2) => return Err(reader.uncarried("an ip rule")),
            (11, 2) => return Err(reader.uncarried("a source ip rule")),
            (12, 2) => return Err(reader.uncarried("a balancer tag")),
            (13, 2) => return Err(reader.uncarried("a network rule")),
            (15, 2) => return Err(reader.uncarried("an attribute rule")),
            (16, 2) => return Err(reader.uncarried("a source port rule")),
            (17, 2) => return Err(reader.uncarried("a local ip rule")),
            (18, 2) => return Err(reader.uncarried("a local port rule")),
            (19, 2) => return Err(reader.uncarried("a rule tag")),
            (20, 2) => return Err(reader.uncarried("a vless route list")),
            (21, 2) => return Err(reader.uncarried("a process rule")),
            (22, 2) => return Err(reader.uncarried("a webhook")),
            (23, 2) => return Err(reader.uncarried("a local os rule")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let tag = tag.ok_or("xray.app.router.RoutingRule: no outbound tag")?;
    let mut pairs = vec![("outboundTag", Json::Str(tag))];
    if let Some(ports) = ports {
        pairs.push(("port", Json::Str(ports)));
    }
    Ok(object(pairs))
}

/// `xray.common.net.PortList` in the shape this tree's router reads: a range is
/// `from-to` and several are comma-separated.
fn port_selector(bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(bytes, "xray.common.net.PortList");
    let mut parts = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                let (from, to) = port_range(reader.bytes()?)?;
                parts.push(if from == to {
                    from.to_string()
                } else {
                    format!("{from}-{to}")
                });
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    if parts.is_empty() {
        return Err("xray.common.net.PortList: no range".to_owned());
    }
    Ok(parts.join(","))
}

/// `common.protocol.ServerEndpoint`: an address, a port and the user that signs the dial.
/// Which account proto the user names is the caller's `user` reader's business.
fn server_endpoint<T>(
    bytes: &[u8],
    user: impl Fn(&[u8]) -> Result<T, String>,
) -> Result<(String, u16, T), String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.ServerEndpoint");
    let mut address = None;
    let mut port = None;
    let mut account = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => address = Some(ip_or_domain(reader.bytes()?)?),
            (2, 0) => {
                let value = reader.varint()?;
                port = Some(u16::try_from(value).map_err(|_| {
                    format!("xray.common.protocol.ServerEndpoint: port {value} is above 65535")
                })?);
            }
            (3, 2) => account = Some(user(reader.bytes()?)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        address.ok_or("xray.common.protocol.ServerEndpoint: no address")?,
        port.ok_or("xray.common.protocol.ServerEndpoint: no port")?,
        account.ok_or("xray.common.protocol.ServerEndpoint: no user")?,
    ))
}

/// A `common.protocol.User` names its account as a typed message. Its level and email feed
/// xray's policy and stats, which nothing in this tree reads.
fn vmess_user(bytes: &[u8]) -> Result<VmessAccount, String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.User");
    let mut account = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => return Err(reader.uncarried("user level")),
            (2, 2) => return Err(reader.uncarried("user email")),
            (3, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name != "xray.proxy.vmess.Account" {
                    return Err(format!("vmess account `{name}` is not carried"));
                }
                account = Some(vmess_account(value)?);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    account.ok_or("xray.common.protocol.User: no account".to_owned())
}

/// The account's uuid, and the cipher its client asks for when the config names one.
/// `tests_enabled` switches on a per-account experiment no scenario writes.
fn vmess_account(bytes: &[u8]) -> Result<VmessAccount, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.vmess.Account");
    let mut id = None;
    let mut security = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                id = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| "xray.proxy.vmess.Account: the id is not utf-8".to_owned())?
                        .to_owned(),
                );
            }
            (3, 2) => {
                let mut config =
                    Reader::new(reader.bytes()?, "xray.common.protocol.SecurityConfig");
                let mut value = 0;
                while let Some((field, wire)) = config.field()? {
                    match (field, wire) {
                        (1, 0) => value = config.varint()?,
                        _ => return Err(config.refuse(field, wire)),
                    }
                }
                security = Some(match value {
                    2 => "auto",
                    3 => "aes-128-gcm",
                    4 => "chacha20-poly1305",
                    other => {
                        return Err(format!(
                        "xray.common.protocol.SecurityConfig: security type {other} is not carried"
                    ))
                    }
                });
            }
            (4, 2) => return Err(reader.uncarried("tests_enabled")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        id.ok_or("xray.proxy.vmess.Account: no id")?,
        security.map(str::to_owned),
    ))
}

fn vmess_client(id: String, security: Option<String>) -> Json {
    let mut pairs = vec![("id", Json::Str(id))];
    if let Some(security) = security {
        pairs.push(("security", Json::Str(security)));
    }
    object(pairs)
}

/// A vless account: its uuid, and the two strings that shape the dial when the config names them.
type VlessAccount = (String, Option<String>, Option<String>);

/// A proto3 string, read as the utf-8 the reference writes it.
fn account_text(reader: &mut Reader<'_>) -> Result<String, String> {
    std::str::from_utf8(reader.bytes()?)
        .map(str::to_owned)
        .map_err(|_| "not utf-8".to_owned())
}

/// The uuid a vless session is keyed by, with the flow and encryption the account names.
/// `padding`, the reverse tunnel's message and the decryption test's fields are read and
/// dropped: the plain account carries none of what they shape, and an engine that turns them
/// on never reaches the settings' own gate.
fn vless_account(bytes: &[u8]) -> Result<VlessAccount, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.vless.Account");
    let mut id = None;
    let mut flow = None;
    let mut encryption = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => id = Some(account_text(&mut reader)?),
            (2, 2) => flow = Some(account_text(&mut reader)?),
            (3, 2) => encryption = Some(account_text(&mut reader)?),
            (4 | 5 | 8 | 9, 0) => {
                reader.varint()?;
            }
            (6 | 7 | 9, 2) => {
                reader.bytes()?;
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        id.ok_or("xray.proxy.vless.Account: no id".to_owned())?,
        encryption,
        flow,
    ))
}

/// A `common.protocol.User` whose account is a vless one; level and email feed the policy and
/// stats nothing here reads.
fn vless_user(bytes: &[u8]) -> Result<VlessAccount, String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.User");
    let mut account = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => return Err(reader.uncarried("user level")),
            (2, 2) => return Err(reader.uncarried("user email")),
            (3, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name != "xray.proxy.vless.Account" {
                    return Err(format!("vless account `{name}` is not carried"));
                }
                account = Some(vless_account(value)?);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    account.ok_or("xray.common.protocol.User: no account".to_owned())
}

/// The clients a vless inbound serves, with the fallback rows it names. A `decryption` past
/// `none` refuses with its verdict the way the reference's own build does — an empty spelling
/// too — while `xorMode`, the seconds window and `padding` ride along unheard.
fn vless_inbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.vless.inbound.Config");
    let mut clients = Vec::new();
    let mut fallbacks = Vec::new();
    let mut decryption = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                let (id, _, flow) = vless_user(reader.bytes()?)?;
                clients.push(vless_client(id, None, flow));
            }
            (2, 2) => fallbacks.push(vless_fallback(reader.bytes()?)?),
            (3, 2) => decryption = Some(reader.bytes()?.to_owned()),
            (4..=6, 0) => {
                reader.varint()?;
            }
            (7, 2) => {
                reader.bytes()?;
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    match decryption.as_deref() {
        Some(b"") => {
            return Err(
                r#"VLESS settings: please add/set "decryption":"none" to every settings"#.into(),
            )
        }
        Some(shape) if shape != b"none" => {
            return Err(format!(
                r#"VLESS settings: unsupported "decryption": {}"#,
                String::from_utf8_lossy(shape)
            ))
        }
        _ => {}
    }
    if clients.is_empty() {
        return Err("xray.proxy.vless.inbound.Config: no user".to_owned());
    }
    let mut pairs = vec![("clients", Json::Arr(clients))];
    if !fallbacks.is_empty() {
        pairs.push(("fallbacks", Json::Arr(fallbacks)));
    }
    Ok(object(pairs))
}

/// One fallback row spelled into the dialect's JSON, its fields as they arrived: an omitted
/// field takes the row's own default, and the dest stays the string the message carried, the
/// way the loader infers its dial behind.
fn vless_fallback(bytes: &[u8]) -> Result<Json, String> {
    const NAMES: [&str; 5] = ["name", "alpn", "path", "type", "dest"];
    let mut reader = Reader::new(bytes, "xray.proxy.vless.Fallback");
    let mut text: [Option<String>; 5] = Default::default();
    let mut xver = 0u64;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1..=5, 2) => {
                text[usize::try_from(field - 1).map_err(|_| "field".to_owned())?] =
                    Some(account_text(&mut reader)?);
            }
            (6, 0) => xver = reader.varint()?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = Vec::new();
    for (at, name) in NAMES.iter().enumerate() {
        if let Some(value) = text[at].as_ref().filter(|value| !value.is_empty()) {
            pairs.push((*name, Json::Str(value.clone())));
        }
    }
    if xver != 0 {
        pairs.push((
            "xver",
            Json::Num(f64::from(
                u32::try_from(xver).map_err(|_| "xver".to_owned())?,
            )),
        ));
    }
    Ok(object(pairs))
}

/// A vless outbound dials the one endpoint its config names.
fn vless_outbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.vless.outbound.Config");
    let mut vnext = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => vnext = Some(server_endpoint(reader.bytes()?, vless_user)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let (address, port, (id, encryption, flow)) =
        vnext.ok_or("xray.proxy.vless.outbound.Config: no vnext")?;
    Ok(object(vec![(
        "vnext",
        Json::Arr(vec![object(vec![
            ("address", Json::Str(address)),
            ("port", Json::Num(f64::from(port))),
            ("users", Json::Arr(vec![vless_client(id, encryption, flow)])),
        ])]),
    )]))
}

/// The account as this tree's JSON dialect names it; an inbound client carries no encryption.
fn vless_client(id: String, encryption: Option<String>, flow: Option<String>) -> Json {
    let mut pairs = vec![("id", Json::Str(id))];
    if let Some(encryption) = encryption {
        pairs.push(("encryption", Json::Str(encryption)));
    }
    if let Some(flow) = flow {
        pairs.push(("flow", Json::Str(flow)));
    }
    object(pairs)
}

/// A shadowsocks account: its password and the AEAD cipher, spelled the way this tree names it.
type SsAccount = (String, &'static str);

/// The four ciphers the pinned enum names beyond `UNKNOWN`, in the spellings `Method::parse` reads.
fn ss_cipher(value: u64) -> Result<&'static str, String> {
    match value {
        5 => Ok("aes-128-gcm"),
        6 => Ok("aes-256-gcm"),
        7 => Ok("chacha20-ietf-poly1305"),
        8 => Ok("xchacha20-ietf-poly1305"),
        other => Err(format!(
            "xray.proxy.shadowsocks.Account: cipher {other} is not carried"
        )),
    }
}

/// The password and cipher a `shadowsocks.Account` names; `iv_check` asks for a check this tree does not run.
fn ss_account(bytes: &[u8]) -> Result<SsAccount, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.shadowsocks.Account");
    let mut password = None;
    let mut cipher = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => password = Some(account_text(&mut reader)?),
            (2, 0) => cipher = Some(ss_cipher(reader.varint()?)?),
            (3, 0) => return Err(reader.uncarried("iv_check")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        password.ok_or("xray.proxy.shadowsocks.Account: no password".to_owned())?,
        cipher.ok_or("xray.proxy.shadowsocks.Account: no cipher".to_owned())?,
    ))
}

/// A `common.protocol.User` whose account is a shadowsocks one. Every scenario signs its server
/// user with `level: 1`, which feeds the policy app and the stats nothing here reads, so the level
/// is dropped; email names nothing here reads either.
fn ss_user(bytes: &[u8]) -> Result<SsAccount, String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.User");
    let mut account = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => {
                reader.varint()?;
            }
            (2, 2) => return Err(reader.uncarried("user email")),
            (3, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name != "xray.proxy.shadowsocks.Account" {
                    return Err(format!("shadowsocks account `{name}` is not carried"));
                }
                account = Some(ss_account(value)?);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    account.ok_or("xray.common.protocol.User: no account".to_owned())
}

/// The method and password a shadowsocks inbound serves. Its `network` list is checked, not
/// carried: this front serves TCP and UDP on every shadowsocks inbound.
fn ss_inbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.shadowsocks.ServerConfig");
    let mut users = Vec::new();
    let mut networks = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => users.push(ss_user(reader.bytes()?)?),
            // A repeated enum arrives packed into one field or per field, and the packed payload carries no keys.
            (2, 2) => {
                let mut packed =
                    Reader::new(reader.bytes()?, "xray.proxy.shadowsocks.ServerConfig");
                while packed.more() {
                    networks.push(packed.varint()?);
                }
            }
            (2, 0) => networks.push(reader.varint()?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    for value in &networks {
        if !matches!(value, 2 | 3) {
            return Err(format!(
                "xray.proxy.shadowsocks.ServerConfig: network {value} is not served"
            ));
        }
    }
    let (password, method) = match users.len() {
        0 => return Err("xray.proxy.shadowsocks.ServerConfig: no user".to_owned()),
        1 => users.pop().expect("one user"),
        count => {
            return Err(format!(
                "xray.proxy.shadowsocks.ServerConfig: {count} users, one method and password served"
            ))
        }
    };
    Ok(object(vec![
        ("method", Json::Str(method.to_owned())),
        ("password", Json::Str(password)),
    ]))
}

/// A shadowsocks outbound dials the one server its config names.
fn ss_outbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.shadowsocks.ClientConfig");
    let mut server = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => server = Some(server_endpoint(reader.bytes()?, ss_user)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let (address, port, (password, method)) =
        server.ok_or("xray.proxy.shadowsocks.ClientConfig: no server")?;
    Ok(object(vec![(
        "servers",
        Json::Arr(vec![object(vec![
            ("address", Json::Str(address)),
            ("port", Json::Num(f64::from(port))),
            ("method", Json::Str(method.to_owned())),
            ("password", Json::Str(password)),
        ])]),
    )]))
}

/// A socks server: the authentication it asks for and the accounts it accepts.
///
/// The accounts arrive as a protobuf map — one entry per account, the name in the
/// first field and the password in the second. The address the server names and its
/// datagram switch are read and dropped: this front answers the relay address it
/// bound itself and always carries datagrams.
fn socks_inbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.socks.ServerConfig");
    let mut auth_type = 0u64;
    let mut accounts: Vec<Json> = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => auth_type = reader.varint()?,
            (2, 2) => {
                let (user, pass) = socks_account_entry(reader.bytes()?)?;
                accounts.push(object(vec![
                    ("user", Json::Str(user)),
                    ("pass", Json::Str(pass)),
                ]));
            }
            (3, 2) => {
                ip_or_domain(reader.bytes()?)?;
            }
            (4, 0) => {
                reader.varint()?;
            }
            (6, 0) => return Err(reader.uncarried("user_level")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let auth = match auth_type {
        0 => "noauth",
        1 => "password",
        other => {
            return Err(format!(
                "xray.proxy.socks.ServerConfig: auth type {other} is not carried"
            ))
        }
    };
    let mut pairs = vec![("auth", Json::Str(auth.to_owned()))];
    if !accounts.is_empty() {
        pairs.push(("accounts", Json::Arr(accounts)));
    }
    Ok(object(pairs))
}

/// One entry of the account map: the name in the first field, the password in the second.
fn socks_account_entry(bytes: &[u8]) -> Result<(String, String), String> {
    let mut reader = Reader::new(bytes, "xray.proxy.socks.ServerConfig.accounts");
    let mut user = None;
    let mut pass = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => user = Some(account_text(&mut reader)?),
            (2, 2) => pass = Some(account_text(&mut reader)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        user.ok_or("xray.proxy.socks.ServerConfig: an account with no name")?,
        pass.ok_or("xray.proxy.socks.ServerConfig: an account with no password")?,
    ))
}

/// A socks client dials the one endpoint its config names, with the credential it names.
fn socks_outbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.socks.ClientConfig");
    let mut server = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => server = Some(socks_server_endpoint(reader.bytes()?)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let (address, port, credential) = server.ok_or("xray.proxy.socks.ClientConfig: no server")?;
    let mut users = Vec::new();
    if let Some((user, pass)) = credential {
        users.push(object(vec![
            ("user", Json::Str(user)),
            ("pass", Json::Str(pass)),
        ]));
    }
    Ok(object(vec![(
        "servers",
        Json::Arr(vec![object(vec![
            ("address", Json::Str(address)),
            ("port", Json::Num(f64::from(port))),
            ("users", Json::Arr(users)),
        ])]),
    )]))
}

/// The endpoint a socks client dials: the address, the port, and the credential when
/// the config names one.
type SocksEndpoint = (String, u16, Option<(String, String)>);

/// `common.protocol.ServerEndpoint` for the socks client: the address, the port, and
/// the credential when the config names one. A socks client may name no credential —
/// the greeting then offers no authentication.
fn socks_server_endpoint(bytes: &[u8]) -> Result<SocksEndpoint, String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.ServerEndpoint");
    let mut address = None;
    let mut port = None;
    let mut credential = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => address = Some(ip_or_domain(reader.bytes()?)?),
            (2, 0) => {
                let value = reader.varint()?;
                port = Some(u16::try_from(value).map_err(|_| {
                    format!("xray.common.protocol.ServerEndpoint: port {value} is above 65535")
                })?);
            }
            (3, 2) => credential = Some(socks_user(reader.bytes()?)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        address.ok_or("xray.common.protocol.ServerEndpoint: no address")?,
        port.ok_or("xray.common.protocol.ServerEndpoint: no port")?,
        credential,
    ))
}

/// A `common.protocol.User` whose account is a socks one; level and email feed the
/// policy and the stats nothing here reads.
fn socks_user(bytes: &[u8]) -> Result<(String, String), String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.User");
    let mut account = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => return Err(reader.uncarried("user level")),
            (2, 2) => return Err(reader.uncarried("user email")),
            (3, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name != "xray.proxy.socks.Account" {
                    return Err(format!("socks account `{name}` is not carried"));
                }
                account = Some(socks_account(value)?);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    account.ok_or("xray.common.protocol.User: no account".to_owned())
}

/// The socks account: the name and the password the RFC 1929 exchange carries.
fn socks_account(bytes: &[u8]) -> Result<(String, String), String> {
    let mut reader = Reader::new(bytes, "xray.proxy.socks.Account");
    let mut user = None;
    let mut pass = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => user = Some(account_text(&mut reader)?),
            (2, 2) => pass = Some(account_text(&mut reader)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        user.ok_or("xray.proxy.socks.Account: no username")?,
        pass.ok_or("xray.proxy.socks.Account: no password")?,
    ))
}

fn freedom_settings(bytes: &[u8]) -> Result<(), String> {
    let mut reader = Reader::new(bytes, "xray.proxy.freedom.Config");
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => return Err(reader.uncarried("domain_strategy")),
            (3, 2) => return Err(reader.uncarried("destination_override")),
            (4, 0) => return Err(reader.uncarried("user_level")),
            (5, 2) => return Err(reader.uncarried("fragment (README row 124)")),
            (6, 0) => return Err(reader.uncarried("proxy_protocol (README row 121)")),
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
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    message: &'static str,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8], message: &'static str) -> Self {
        Self {
            buf,
            pos: 0,
            message,
        }
    }

    /// Whether any bytes of the message are left, which is how a packed field's values end.
    pub(crate) fn more(&self) -> bool {
        self.pos < self.buf.len()
    }

    /// The next field number and wire type, or `None` at the message's end.
    pub(crate) fn field(&mut self) -> Result<Option<(u64, u8)>, String> {
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

    pub(crate) fn varint(&mut self) -> Result<u64, String> {
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

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], String> {
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

    /// Consumes one field this reader does not read, so a newer writer's field is skipped rather than refused.
    pub(crate) fn skip(&mut self, wire: u8) -> Result<(), String> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 | 5 => {
                let width = if wire == 1 { 8 } else { 4 };
                self.pos = self
                    .pos
                    .checked_add(width)
                    .filter(|end| *end <= self.buf.len())
                    .ok_or_else(|| {
                        format!("{}: a fixed field runs past the message", self.message)
                    })?;
            }
            2 => {
                self.bytes()?;
            }
            _ => return Err(format!("{}: wire type {wire} is not carried", self.message)),
        }
        Ok(())
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

    fn receiver_range(from: u64, to: u64, listen: Option<&[u8]>) -> Vec<u8> {
        let range = message(&[varint_field(1, from), varint_field(2, to)]);
        let mut fields = vec![bytes_field(1, &bytes_field(1, &range))];
        if let Some(ip) = listen {
            fields.push(bytes_field(2, &bytes_field(1, ip)));
        }
        message(&fields)
    }

    fn dokodemo_inbound(receiver: &[u8], settings: &[u8]) -> Vec<u8> {
        message(&[
            bytes_field(2, &typed("xray.app.proxyman.ReceiverConfig", receiver)),
            bytes_field(3, &typed("xray.proxy.dokodemo.Config", settings)),
        ])
    }

    fn dokodemo(port: u64, networks: &[Vec<u8>]) -> Vec<u8> {
        let mut settings = vec![
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, port),
        ];
        settings.extend(networks.iter().cloned());
        dokodemo_inbound(&receiver(port, Some(&[127, 0, 0, 1])), &message(&settings))
    }

    fn vmess_account(id: &[u8], security: Option<u64>) -> Vec<u8> {
        let mut account = vec![bytes_field(1, id)];
        if let Some(value) = security {
            account.push(bytes_field(3, &varint_field(1, value)));
        }
        typed("xray.proxy.vmess.Account", &message(&account))
    }

    fn vmess_user(account: &[u8]) -> Vec<u8> {
        bytes_field(3, account)
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
    fn a_receiver_stream_of_another_shape_is_refused_by_the_reader() {
        let mut receiver = receiver(5000, None);
        receiver.extend(bytes_field(3, &typed("xray.app.dispatcher.Config", &[])));
        let bytes = config(&http_inbound(&receiver, &[]), &freedom_outbound());
        let error = to_json(&bytes).expect_err("refused");
        assert!(
            error.contains("xray.transport.internet.StreamConfig"),
            "{error}"
        );
    }

    #[test]
    fn an_empty_stream_config_is_the_tcp_default() {
        let mut receiver = receiver(5000, None);
        receiver.extend(bytes_field(3, &[]));
        let json = to_json(&config(&http_inbound(&receiver, &[]), &freedom_outbound()))
            .expect("a stream with no fields decodes");
        let stream = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("streamSettings")
            .expect("stream");
        assert_eq!(stream.get("network").and_then(Json::as_str), Some("tcp"));
        assert!(stream.get("security").is_none());
    }

    #[test]
    fn a_dokodemo_inbound_decodes_to_the_directive_this_tree_serves() {
        let json = to_json(&config(
            &dokodemo(8080, &[varint_field(7, 2)]),
            &freedom_outbound(),
        ))
        .expect("dokodemo decodes");
        let inbound = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0];
        assert_eq!(
            inbound.get("protocol").and_then(Json::as_str),
            Some("dokodemo-door")
        );
        let settings = inbound.get("settings").expect("rewrite settings");
        assert_eq!(
            settings.get("address").and_then(Json::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(settings.get("port").and_then(Json::as_port), Some(8080));
        assert_eq!(settings.get("network").and_then(Json::as_str), Some("tcp"));
    }

    #[test]
    fn packed_and_per_field_networks_read_the_same() {
        let packed = config(
            &dokodemo(8080, &[bytes_field(7, &[2, 3])]),
            &freedom_outbound(),
        );
        let each = config(
            &dokodemo(8080, &[varint_field(7, 2), varint_field(7, 3)]),
            &freedom_outbound(),
        );
        for bytes in [packed, each] {
            let json = to_json(&bytes).expect("both shapes decode");
            let network = json
                .get("inbounds")
                .and_then(Json::as_arr)
                .expect("inbounds")[0]
                .get("settings")
                .expect("settings")
                .get("network")
                .and_then(Json::as_str);
            assert_eq!(network, Some("tcp,udp"));
        }
    }

    #[test]
    fn a_port_range_fans_out_to_one_inbound_per_port() {
        let settings = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 8080),
            varint_field(7, 2),
        ]);
        let inbound = dokodemo_inbound(
            &receiver_range(42165, 42170, Some(&[127, 0, 0, 1])),
            &settings,
        );
        let json = to_json(&config(&inbound, &freedom_outbound())).expect("the range expands");
        let inbounds = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds");
        assert_eq!(inbounds.len(), 6);
        assert_eq!(inbounds[0].get("port").and_then(Json::as_port), Some(42165));
        assert_eq!(inbounds[5].get("port").and_then(Json::as_port), Some(42170));
    }

    #[test]
    fn a_port_range_wider_than_the_fanout_is_refused() {
        let settings = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 8080),
            varint_field(7, 2),
        ]);
        let inbound = dokodemo_inbound(&receiver_range(1000, 1100, None), &settings);
        let error = to_json(&config(&inbound, &freedom_outbound())).expect_err("refused");
        assert!(error.contains("wider fan-out"), "{error}");
    }

    #[test]
    fn a_dokodemo_port_map_is_refused() {
        let settings = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 8080),
            bytes_field(3, &[]),
            varint_field(7, 2),
        ]);
        let error = to_json(&config(
            &dokodemo_inbound(&receiver(8080, None), &settings),
            &freedom_outbound(),
        ))
        .expect_err("refused");
        assert!(error.contains("port_map"), "{error}");
    }

    #[test]
    fn a_dokodemo_follow_redirect_is_refused() {
        let settings = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 8080),
            varint_field(5, 1),
            varint_field(7, 2),
        ]);
        let error = to_json(&config(
            &dokodemo_inbound(&receiver(8080, None), &settings),
            &freedom_outbound(),
        ))
        .expect_err("refused");
        assert!(error.contains("follow_redirect"), "{error}");
    }

    #[test]
    fn a_dokodemo_with_no_network_is_refused() {
        let error =
            to_json(&config(&dokodemo(8080, &[]), &freedom_outbound())).expect_err("refused");
        assert!(error.contains("no network"), "{error}");
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
    fn a_vmess_inbound_decodes_its_clients() {
        let account = vmess_account(b"bbbb-bbbb", Some(3));
        let settings = bytes_field(1, &vmess_user(&account));
        let inbound = message(&[
            bytes_field(
                2,
                &typed("xray.app.proxyman.ReceiverConfig", &receiver(5000, None)),
            ),
            bytes_field(3, &typed("xray.proxy.vmess.inbound.Config", &settings)),
        ]);
        let json = to_json(&config(&inbound, &freedom_outbound())).expect("vmess inbound decodes");
        let inbound = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0];
        assert_eq!(
            inbound.get("protocol").and_then(Json::as_str),
            Some("vmess")
        );
        let client = &inbound
            .get("settings")
            .expect("settings")
            .get("clients")
            .and_then(Json::as_arr)
            .expect("clients")[0];
        assert_eq!(client.get("id").and_then(Json::as_str), Some("bbbb-bbbb"));
        assert_eq!(
            client.get("security").and_then(Json::as_str),
            Some("aes-128-gcm")
        );
    }

    #[test]
    fn a_vmess_outbound_decodes_its_endpoint() {
        let account = vmess_account(b"cccc-cccc", None);
        let endpoint = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 443),
            bytes_field(3, &vmess_user(&account)),
        ]);
        let outbound = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.vmess.outbound.Config",
                &bytes_field(1, &endpoint),
            ),
        )]);
        let json = to_json(&config(
            &http_inbound(&receiver(5000, None), &[]),
            &outbound,
        ))
        .expect("vmess outbound decodes");
        let server = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .expect("settings")
            .get("vnext")
            .and_then(Json::as_arr)
            .expect("vnext")[0];
        assert_eq!(
            server.get("address").and_then(Json::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(server.get("port").and_then(Json::as_port), Some(443));
        assert_eq!(
            server.get("users").and_then(Json::as_arr).expect("users")[0]
                .get("id")
                .and_then(Json::as_str),
            Some("cccc-cccc")
        );
    }

    #[test]
    fn a_vmess_user_level_is_refused() {
        let user = message(&[varint_field(1, 2), vmess_user(&vmess_account(b"d", None))]);
        let settings = bytes_field(1, &user);
        let inbound = message(&[
            bytes_field(
                2,
                &typed("xray.app.proxyman.ReceiverConfig", &receiver(5000, None)),
            ),
            bytes_field(3, &typed("xray.proxy.vmess.inbound.Config", &settings)),
        ]);
        let error = to_json(&config(&inbound, &freedom_outbound())).expect_err("refused");
        assert!(error.contains("user level"), "{error}");
    }

    fn vless_account(id: &[u8], flow: Option<&[u8]>, encryption: Option<&[u8]>) -> Vec<u8> {
        let mut account = vec![bytes_field(1, id)];
        if let Some(flow) = flow {
            account.push(bytes_field(2, flow));
        }
        if let Some(encryption) = encryption {
            account.push(bytes_field(3, encryption));
        }
        typed("xray.proxy.vless.Account", &message(&account))
    }

    fn vless_user(account: &[u8]) -> Vec<u8> {
        bytes_field(3, account)
    }

    fn vless_inbound(port: u64, settings: &[u8]) -> Vec<u8> {
        message(&[
            bytes_field(
                2,
                &typed("xray.app.proxyman.ReceiverConfig", &receiver(port, None)),
            ),
            bytes_field(3, &typed("xray.proxy.vless.inbound.Config", settings)),
        ])
    }

    /// The shape `TestVlessTCP` names: a vless inbound with its decryption string, a vless
    /// outbound dialling it.
    #[test]
    fn a_vless_scenario_decodes_both_sides() {
        let settings = message(&[
            bytes_field(1, &vless_user(&vless_account(b"aaaa-aaaa", None, None))),
            bytes_field(3, b"none"),
        ]);
        let endpoint = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 443),
            bytes_field(
                3,
                &vless_user(&vless_account(
                    b"aaaa-aaaa",
                    Some(b"xtls-rprx-vision"),
                    Some(b"none"),
                )),
            ),
        ]);
        let outbound = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.vless.outbound.Config",
                &bytes_field(1, &endpoint),
            ),
        )]);
        let json =
            to_json(&config(&vless_inbound(5000, &settings), &outbound)).expect("vless decodes");
        let inbound = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0];
        assert_eq!(
            inbound.get("protocol").and_then(Json::as_str),
            Some("vless")
        );
        let client = &inbound
            .get("settings")
            .expect("settings")
            .get("clients")
            .and_then(Json::as_arr)
            .expect("clients")[0];
        assert_eq!(client.get("id").and_then(Json::as_str), Some("aaaa-aaaa"));
        assert!(
            inbound
                .get("settings")
                .expect("settings")
                .get("decryption")
                .is_none(),
            "the decryption string is read and dropped"
        );
        let user = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .expect("settings")
            .get("vnext")
            .and_then(Json::as_arr)
            .expect("vnext")[0]
            .get("users")
            .and_then(Json::as_arr)
            .expect("users")[0];
        assert_eq!(user.get("encryption").and_then(Json::as_str), Some("none"));
        assert_eq!(
            user.get("flow").and_then(Json::as_str),
            Some("xtls-rprx-vision")
        );
    }

    /// A fallback row the message carries reaches the dialect's settings, its fields as they
    /// came and a dest the loader infers its dial behind.
    #[test]
    fn a_fallback_row_arrives_from_the_bridge() {
        let settings = message(&[
            bytes_field(1, &vless_user(&vless_account(b"a", None, None))),
            bytes_field(
                2,
                &message(&[
                    bytes_field(1, b"web"),
                    bytes_field(2, b"h2"),
                    bytes_field(3, b"/api"),
                    bytes_field(5, b"127.0.0.1:8080"),
                    varint_field(6, 2),
                ]),
            ),
        ]);
        let json = to_json(&config(
            &vless_inbound(5000, &settings),
            &freedom_outbound(),
        ))
        .expect("vless decodes");
        let row = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .expect("settings")
            .get("fallbacks")
            .and_then(Json::as_arr)
            .expect("fallbacks")[0];
        assert_eq!(row.get("name").and_then(Json::as_str), Some("web"));
        assert_eq!(row.get("alpn").and_then(Json::as_str), Some("h2"));
        assert_eq!(row.get("path").and_then(Json::as_str), Some("/api"));
        assert_eq!(
            row.get("dest").and_then(Json::as_str),
            Some("127.0.0.1:8080")
        );
        assert_eq!(row.get("xver").and_then(Json::as_u32), Some(2));
    }

    #[test]
    fn a_vless_xor_mode_is_dropped_without_an_engine() {
        let settings = message(&[
            bytes_field(1, &vless_user(&vless_account(b"a", None, None))),
            varint_field(4, 1),
        ]);
        to_json(&config(
            &vless_inbound(5000, &settings),
            &freedom_outbound(),
        ))
        .expect("vless decodes");
    }

    #[test]
    fn an_engaged_decryption_is_refused() {
        let settings = message(&[
            bytes_field(1, &vless_user(&vless_account(b"a", None, None))),
            bytes_field(3, b"always"),
        ]);
        let error = to_json(&config(
            &vless_inbound(5000, &settings),
            &freedom_outbound(),
        ))
        .expect_err("refused");
        assert!(
            error.contains(r#"unsupported "decryption": always"#),
            "{error}"
        );
    }

    #[test]
    fn an_empty_decryption_spelling_is_refused() {
        let settings = message(&[
            bytes_field(1, &vless_user(&vless_account(b"a", None, None))),
            bytes_field(3, b""),
        ]);
        let error = to_json(&config(
            &vless_inbound(5000, &settings),
            &freedom_outbound(),
        ))
        .expect_err("refused");
        assert!(
            error.contains(r#"please add/set "decryption":"none""#),
            "{error}"
        );
    }

    /// The account's padding, reverse message and test seeds ride along unheard rather than
    /// refusing: a plain account serves both spellings.
    #[test]
    fn the_account_decryption_test_fields_ride_along_unheard() {
        let account = typed(
            "xray.proxy.vless.Account",
            &message(&[
                bytes_field(1, b"a"),
                bytes_field(6, b"padpad"),
                bytes_field(7, &bytes_field(1, b"tag")),
                varint_field(8, 1),
                varint_field(9, 7),
                bytes_field(9, &message(&[varint(7), varint(9)])),
            ]),
        );
        let settings = bytes_field(1, &vless_user(&account));
        let json = to_json(&config(
            &vless_inbound(5000, &settings),
            &freedom_outbound(),
        ))
        .expect("vless decodes");
        let client = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .expect("settings")
            .get("clients")
            .and_then(Json::as_arr)
            .expect("clients")[0];
        assert_eq!(client.get("id").and_then(Json::as_str), Some("a"));
    }

    #[test]
    fn a_vless_inbound_without_a_user_is_refused() {
        let error =
            to_json(&config(&vless_inbound(5000, &[]), &freedom_outbound())).expect_err("refused");
        assert!(error.contains("no user"), "{error}");
    }

    /// A `StreamConfig` as the vless TLS/REALITY scenarios carry it: the tcp transport, the
    /// security type its name selects, and the security's own settings message.
    fn tcp_stream(security_type: &str, security: &[u8]) -> Vec<u8> {
        message(&[
            bytes_field(
                2,
                &message(&[bytes_field(
                    2,
                    &typed("xray.transport.internet.tcp.Config", &[]),
                )]),
            ),
            bytes_field(3, security_type.as_bytes()),
            bytes_field(4, &typed(security_type, security)),
            bytes_field(5, b"tcp"),
        ])
    }

    fn receiver_stream(port: u64, stream: &[u8]) -> Vec<u8> {
        message(&[
            bytes_field(
                1,
                &bytes_field(1, &message(&[varint_field(1, port), varint_field(2, port)])),
            ),
            bytes_field(2, &bytes_field(1, &[127, 0, 0, 1])),
            bytes_field(3, stream),
        ])
    }

    /// A certificate entry's bytes are PEM text on the wire (the reference carries `ToPEM`
    /// bytes), so the served JSON strings are the bytes verbatim, whichever PEM they spell.
    #[test]
    fn a_vless_tls_receiver_serves_the_certificate_bytes_verbatim() {
        let certificate_text = "-----BEGIN CERTIFICATE-----\nQw==\n-----END CERTIFICATE-----\n";
        let key_sides = ["PRIVATE", "KEY"];
        let key_text_parts = [
            format!("-----BEGIN {}-----", key_sides.join(" ")),
            "\nRw==\n".to_owned(),
            "-----END ".to_owned(),
            format!("{}-----\n", key_sides[1]),
        ];
        let key_text = key_text_parts.join("");
        let certificate = message(&[
            bytes_field(1, certificate_text.as_bytes()),
            bytes_field(2, key_text.as_bytes()),
        ]);
        let tcp = tcp_stream(
            "xray.transport.internet.tls.Config",
            &message(&[bytes_field(2, &certificate)]),
        );
        let inbound = message(&[
            bytes_field(
                2,
                &typed(
                    "xray.app.proxyman.ReceiverConfig",
                    &receiver_stream(5000, &tcp),
                ),
            ),
            bytes_field(
                3,
                &typed(
                    "xray.proxy.vless.inbound.Config",
                    &bytes_field(1, &vless_user(&vless_account(b"a", None, None))),
                ),
            ),
        ]);
        let json = to_json(&config(&inbound, &freedom_outbound())).expect("tls receiver decodes");
        let tls = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("streamSettings")
            .and_then(|s| s.get("tlsSettings"))
            .and_then(|t| t.get("certificates"))
            .and_then(Json::as_arr)
            .and_then(|c| c.first())
            .expect("one certificate entry");
        let pem = tls
            .get("certificate")
            .and_then(Json::as_str)
            .expect("cert pem");
        assert_eq!(
            pem, certificate_text,
            "the cert bytes path through verbatim"
        );
        let key = tls.get("key").and_then(Json::as_str).expect("key text");
        assert_eq!(key, key_text, "the key bytes path through verbatim");
    }

    /// The shape `TestVlessTls`'s client names: a sender whose stream pins the peer leaf by
    /// the SHA-256 over its whole DER, which is `pinnedPeerCertSha256` in this tree's dialect.
    #[test]
    fn a_vless_tls_client_names_its_pinned_certificate() {
        let pin = [0x55u8; 32];
        let type_name = "xray.transport.internet.tls.Config";
        let stream = tcp_stream(type_name, &bytes_field(22, &pin));
        let outbound = message(&[
            bytes_field(
                2,
                &typed("xray.app.proxyman.SenderConfig", &bytes_field(2, &stream)),
            ),
            bytes_field(
                3,
                &typed(
                    "xray.proxy.vless.outbound.Config",
                    &bytes_field(
                        1,
                        &message(&[
                            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
                            varint_field(2, 443),
                            bytes_field(
                                3,
                                &vless_user(&vless_account(b"aaaa-aaaa", None, Some(b"none"))),
                            ),
                        ]),
                    ),
                ),
            ),
        ]);
        let json = to_json(&config(&dokodemo(5000, &[varint_field(7, 2)]), &outbound))
            .expect("tls sender decodes");
        let stream = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("streamSettings")
            .expect("stream");
        assert_eq!(stream.get("network").and_then(Json::as_str), Some("tcp"));
        assert_eq!(stream.get("security").and_then(Json::as_str), Some("tls"));
        let tls = stream.get("tlsSettings").expect("tls settings");
        assert_eq!(
            tls.get("pinnedPeerCertSha256").and_then(Json::as_str),
            Some("55".repeat(32).as_str()),
            "one pinned hash, comma-separated hex like the dialect spells it"
        );
    }

    /// The shape the REALITY scenarios name on the server: `show`, the decoy
    /// `www.google.com:443`, the server names it accepts, the base64url key, hex short ids.
    #[test]
    fn a_vless_reality_receiver_names_the_decoy_and_key() {
        let reality = message(&[
            varint_field(1, 1),
            bytes_field(2, b"www.google.com:443"),
            bytes_field(5, b"www.example.com"),
            bytes_field(6, &[0xab; 32]),
            bytes_field(10, &[0x01, 0x02]),
        ]);
        let inbound = message(&[
            bytes_field(
                2,
                &typed(
                    "xray.app.proxyman.ReceiverConfig",
                    &receiver_stream(
                        5000,
                        &tcp_stream("xray.transport.internet.reality.Config", &reality),
                    ),
                ),
            ),
            bytes_field(
                3,
                &typed(
                    "xray.proxy.vless.inbound.Config",
                    &bytes_field(1, &vless_user(&vless_account(b"a", None, None))),
                ),
            ),
        ]);
        let json = to_json(&config(&inbound, &freedom_outbound())).expect("reality server decodes");
        let reality = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("streamSettings")
            .and_then(|s| s.get("realitySettings"))
            .expect("reality settings");
        assert_eq!(reality.get("show"), Some(&Json::Bool(true)));
        assert_eq!(
            reality.get("dest").and_then(Json::as_str),
            Some("www.google.com:443")
        );
        assert_eq!(
            reality
                .get("serverNames")
                .and_then(Json::as_arr)
                .map(<[Json]>::len),
            Some(1)
        );
        assert_eq!(
            reality.get("privateKey").and_then(Json::as_str),
            Some(b64url(&[0xab; 32]).as_str())
        );
        assert_eq!(
            reality
                .get("shortIds")
                .and_then(Json::as_arr)
                .and_then(|ids| ids.first()),
            Some(&Json::Str("0102".to_owned()))
        );
    }

    #[test]
    fn a_vless_reality_client_names_its_own_key_and_id() {
        let reality = message(&[
            varint_field(1, 1),
            bytes_field(21, b"chrome"),
            bytes_field(22, b"www.example.com"),
            bytes_field(23, &[0xcd; 32]),
            bytes_field(24, &[]),
        ]);
        let type_name = "xray.transport.internet.reality.Config";
        let endpoint = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 443),
            bytes_field(3, &vless_user(&vless_account(b"a", None, Some(b"none")))),
        ]);
        let outbound = message(&[
            bytes_field(
                2,
                &typed(
                    "xray.app.proxyman.SenderConfig",
                    &bytes_field(2, &tcp_stream(type_name, &reality)),
                ),
            ),
            bytes_field(
                3,
                &typed(
                    "xray.proxy.vless.outbound.Config",
                    &bytes_field(1, &endpoint),
                ),
            ),
        ]);
        let json = to_json(&config(&dokodemo(5000, &[varint_field(7, 2)]), &outbound))
            .expect("reality client decodes");
        let reality = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("streamSettings")
            .and_then(|s| s.get("realitySettings"))
            .expect("reality settings");
        assert_eq!(
            reality.get("fingerprint").and_then(Json::as_str),
            Some("chrome")
        );
        assert_eq!(
            reality.get("serverName").and_then(Json::as_str),
            Some("www.example.com")
        );
        assert_eq!(
            reality.get("publicKey").and_then(Json::as_str),
            Some(b64url(&[0xcd; 32]).as_str())
        );
        assert_eq!(reality.get("shortId").and_then(Json::as_str), Some(""));
        assert!(
            reality.get("dest").is_none()
                && reality.get("privateKey").is_none()
                && reality.get("show").is_none(),
            "a client reality config carries no server field, and its debug print rides no dial"
        );
    }

    #[test]
    fn a_named_security_without_settings_is_the_zero_value() {
        let mut receiver = receiver(5000, None);
        receiver.extend(bytes_field(
            3,
            &message(&[
                bytes_field(3, b"xray.transport.internet.tls.Config"),
                bytes_field(5, b"tcp"),
            ]),
        ));
        let json = to_json(&config(&http_inbound(&receiver, &[]), &freedom_outbound()))
            .expect("a named security with no settings decodes");
        let stream = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("streamSettings")
            .expect("stream");
        assert_eq!(stream.get("security").and_then(Json::as_str), Some("tls"));
        assert!(stream.get("tlsSettings").is_none());
    }

    fn ss_account(password: &[u8], cipher: u64) -> Vec<u8> {
        typed(
            "xray.proxy.shadowsocks.Account",
            &message(&[bytes_field(1, password), varint_field(2, cipher)]),
        )
    }

    fn ss_user(account: &[u8], level: Option<u64>) -> Vec<u8> {
        let mut user = Vec::new();
        if let Some(level) = level {
            user.push(varint_field(1, level));
        }
        user.push(bytes_field(3, account));
        message(&user)
    }

    fn ss_inbound(port: u64, settings: &[u8]) -> Vec<u8> {
        message(&[
            bytes_field(
                2,
                &typed("xray.app.proxyman.ReceiverConfig", &receiver(port, None)),
            ),
            bytes_field(3, &typed("xray.proxy.shadowsocks.ServerConfig", settings)),
        ])
    }

    #[test]
    fn a_shadowsocks_scenario_decodes_both_sides() {
        let settings = message(&[
            bytes_field(
                1,
                &ss_user(&ss_account(b"shadowsocks-password", 6), Some(1)),
            ),
            bytes_field(2, &[2]),
        ]);
        let endpoint = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 443),
            bytes_field(3, &ss_user(&ss_account(b"shadowsocks-password", 7), None)),
        ]);
        let outbound = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.shadowsocks.ClientConfig",
                &bytes_field(1, &endpoint),
            ),
        )]);
        let json = to_json(&config(&ss_inbound(5000, &settings), &outbound))
            .expect("shadowsocks decodes both sides");
        let server = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0];
        assert_eq!(
            server.get("protocol").and_then(Json::as_str),
            Some("shadowsocks")
        );
        let settings = server.get("settings").expect("settings");
        assert_eq!(
            settings.get("method").and_then(Json::as_str),
            Some("aes-256-gcm")
        );
        assert_eq!(
            settings.get("password").and_then(Json::as_str),
            Some("shadowsocks-password")
        );
        let client = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .expect("settings")
            .get("servers")
            .and_then(Json::as_arr)
            .expect("servers")[0];
        assert_eq!(
            client.get("address").and_then(Json::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(client.get("port").and_then(Json::as_port), Some(443));
        assert_eq!(
            client.get("method").and_then(Json::as_str),
            Some("chacha20-ietf-poly1305")
        );
    }

    fn socks_account(user: &[u8], pass: &[u8]) -> Vec<u8> {
        typed(
            "xray.proxy.socks.Account",
            &message(&[bytes_field(1, user), bytes_field(2, pass)]),
        )
    }

    fn socks_user(account: &[u8]) -> Vec<u8> {
        bytes_field(3, account)
    }

    fn socks_inbound(port: u64, auth_type: u64, accounts: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut settings = vec![varint_field(1, auth_type)];
        for (user, pass) in accounts {
            let entry = message(&[bytes_field(1, user), bytes_field(2, pass)]);
            settings.push(bytes_field(2, &entry));
        }
        message(&[
            bytes_field(
                2,
                &typed(
                    "xray.app.proxyman.ReceiverConfig",
                    &receiver(port, Some(&[127, 0, 0, 1])),
                ),
            ),
            bytes_field(
                3,
                &typed("xray.proxy.socks.ServerConfig", &message(&settings)),
            ),
        ])
    }

    /// The shape `TestSocksBridgeTCP` names: a socks server that asks for a password,
    /// and a socks client that offers one.
    #[test]
    fn a_socks_scenario_decodes_both_sides() {
        let outbound = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.socks.ClientConfig",
                &bytes_field(
                    1,
                    &message(&[
                        bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
                        varint_field(2, 5001),
                        bytes_field(
                            3,
                            &socks_user(&socks_account(b"Test Account", b"Test Password")),
                        ),
                    ]),
                ),
            ),
        )]);
        let json = to_json(&config(
            &socks_inbound(5000, 1, &[(b"Test Account", b"Test Password")]),
            &outbound,
        ))
        .expect("socks decodes both sides");
        let server = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0];
        assert_eq!(server.get("protocol").and_then(Json::as_str), Some("socks"));
        let settings = server.get("settings").expect("settings");
        assert_eq!(
            settings.get("auth").and_then(Json::as_str),
            Some("password")
        );
        let account = &settings
            .get("accounts")
            .and_then(Json::as_arr)
            .expect("accounts")[0];
        assert_eq!(
            account.get("user").and_then(Json::as_str),
            Some("Test Account")
        );
        assert_eq!(
            account.get("pass").and_then(Json::as_str),
            Some("Test Password")
        );
        let client = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .expect("settings")
            .get("servers")
            .and_then(Json::as_arr)
            .expect("servers")[0];
        assert_eq!(
            client.get("address").and_then(Json::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(client.get("port").and_then(Json::as_port), Some(5001));
        let user = &client.get("users").and_then(Json::as_arr).expect("users")[0];
        assert_eq!(
            user.get("user").and_then(Json::as_str),
            Some("Test Account")
        );
        assert_eq!(
            user.get("pass").and_then(Json::as_str),
            Some("Test Password")
        );
    }

    /// The blackhole outbound the pinned scenario suite names: a config with no
    /// response, and one with each answer the reference knows.
    #[test]
    fn a_blackhole_scenario_decodes_its_answers() {
        let silent = message(&[bytes_field(3, &typed("xray.proxy.blackhole.Config", &[]))]);
        let json = to_json(&config(&socks_inbound(5000, 0, &[]), &silent)).expect("decodes");
        let outbound = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0];
        assert_eq!(
            outbound.get("protocol").and_then(Json::as_str),
            Some("blackhole")
        );
        assert!(
            outbound.get("settings").is_none(),
            "a config with no response names no answer"
        );

        let http = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.blackhole.Config",
                &bytes_field(1, &message(&[bytes_field(1, b"http")])),
            ),
        )]);
        let json = to_json(&config(&socks_inbound(5000, 0, &[]), &http)).expect("decodes");
        let response = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .expect("settings")
            .get("response")
            .expect("response");
        assert_eq!(response.get("type").and_then(Json::as_str), Some("http"));

        let custom = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.blackhole.Config",
                &bytes_field(
                    1,
                    &message(&[bytes_field(1, b"custom"), bytes_field(2, &[0, 1, 2])]),
                ),
            ),
        )]);
        let json = to_json(&config(&socks_inbound(5000, 0, &[]), &custom)).expect("decodes");
        let response = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .expect("settings")
            .get("response")
            .expect("response");
        assert_eq!(response.get("type").and_then(Json::as_str), Some("custom"));
        assert_eq!(
            response.get("customResponseData").and_then(Json::as_str),
            Some("AAEC"),
            "the answer's bytes travel as base64"
        );
    }

    /// The router app the pinned blackhole scenario writes: a rule that sends
    /// the flow on one port to a tagged outbound, and the tags the rule names.
    #[test]
    fn a_router_rule_names_the_outbound_a_flow_goes_to() {
        let range = message(&[varint_field(1, 5001), varint_field(2, 5001)]);
        let ports = message(&[bytes_field(1, &range)]);
        let rule = message(&[bytes_field(1, b"blocked"), bytes_field(14, &ports)]);
        let router = message(&[bytes_field(2, &rule)]);
        let outbound = message(&[
            bytes_field(1, b"blocked"),
            bytes_field(3, &typed("xray.proxy.blackhole.Config", &[])),
        ]);
        let config = message(&[
            bytes_field(1, &socks_inbound(5000, 0, &[])),
            bytes_field(2, &outbound),
            bytes_field(4, &typed("xray.app.router.Config", &router)),
        ]);
        let json = to_json(&config).expect("decodes");
        let rules = json
            .get("routing")
            .expect("routing")
            .get("rules")
            .and_then(Json::as_arr)
            .expect("rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].get("outboundTag").and_then(Json::as_str),
            Some("blocked")
        );
        assert_eq!(rules[0].get("port").and_then(Json::as_str), Some("5001"));
        let outbound = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0];
        assert_eq!(outbound.get("tag").and_then(Json::as_str), Some("blocked"));
        assert_eq!(
            outbound.get("protocol").and_then(Json::as_str),
            Some("blackhole")
        );
        // The rule reaches this tree's own router: the flow on that port goes to the outbound the rule names.
        let routing = crate::router::Routing::parse(&json)
            .expect("parses")
            .expect("routing");
        let flow = crate::router::Flow {
            network: crate::router::Network::Tcp,
            domain: None,
            ip: Some("127.0.0.1".parse().expect("addr")),
            port: Some(5001),
            source: None,
            local: None,
            inbound_tag: None,
        };
        assert_eq!(routing.route(&flow), Some("blocked"));
    }

    /// An app this tree does not read is xray's own object graph and is
    /// skipped, the way the bridge has always skipped it; the router is the one
    /// app that decides where a flow goes, so it is read.
    #[test]
    fn an_app_this_tree_does_not_read_is_skipped() {
        let config = message(&[
            bytes_field(1, &socks_inbound(5000, 0, &[])),
            bytes_field(2, &freedom_outbound()),
            bytes_field(4, &typed("xray.app.dns.Config", &[])),
        ]);
        to_json(&config).expect("the app is xray's own");
    }

    /// A socks server with no accounts asks for no authentication, the way the pinned
    /// `AuthType_NO_AUTH` server does.
    #[test]
    fn a_socks_server_without_a_password_decodes_to_no_auth() {
        let json = to_json(&config(&socks_inbound(5000, 0, &[]), &freedom_outbound()))
            .expect("socks decodes");
        let settings = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .expect("settings");
        assert_eq!(settings.get("auth").and_then(Json::as_str), Some("noauth"));
        assert!(
            settings.get("accounts").is_none(),
            "a server with no account names none"
        );
    }

    /// A socks client may name no credential: the greeting then offers no
    /// authentication, the way the pinned `ClientConfig` without a user does.
    #[test]
    fn a_socks_client_without_a_credential_decodes_to_no_users() {
        let outbound = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.socks.ClientConfig",
                &bytes_field(
                    1,
                    &message(&[
                        bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
                        varint_field(2, 5001),
                    ]),
                ),
            ),
        )]);
        let json =
            to_json(&config(&socks_inbound(5000, 0, &[]), &outbound)).expect("socks decodes");
        let client = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .expect("settings")
            .get("servers")
            .and_then(Json::as_arr)
            .expect("servers")[0];
        assert!(
            client
                .get("users")
                .and_then(Json::as_arr)
                .expect("users")
                .is_empty(),
            "a client with no credential names no user"
        );
    }

    #[test]
    fn a_socks_server_user_level_is_refused() {
        let settings = message(&[varint_field(1, 1), varint_field(6, 3)]);
        let error = to_json(&config(
            &message(&[
                bytes_field(
                    2,
                    &typed(
                        "xray.app.proxyman.ReceiverConfig",
                        &receiver(5000, Some(&[127, 0, 0, 1])),
                    ),
                ),
                bytes_field(3, &typed("xray.proxy.socks.ServerConfig", &settings)),
            ]),
            &freedom_outbound(),
        ))
        .expect_err("refused");
        assert!(error.contains("user_level"), "{error}");
    }

    #[test]
    fn a_shadowsocks_iv_check_is_refused() {
        let account = typed(
            "xray.proxy.shadowsocks.Account",
            &message(&[bytes_field(1, b"a"), varint_field(2, 6), varint_field(3, 1)]),
        );
        let settings = bytes_field(1, &ss_user(&account, None));
        let error = to_json(&config(&ss_inbound(5000, &settings), &freedom_outbound()))
            .expect_err("refused");
        assert!(error.contains("iv_check"), "{error}");
    }

    #[test]
    fn an_unknown_shadowsocks_cipher_is_refused() {
        let settings = message(&[
            bytes_field(1, &ss_user(&ss_account(b"a", 0), None)),
            bytes_field(2, &[2]),
        ]);
        let error = to_json(&config(&ss_inbound(5000, &settings), &freedom_outbound()))
            .expect_err("refused");
        assert!(error.contains("cipher 0"), "{error}");
    }

    #[test]
    fn a_shadowsocks_unix_network_is_refused() {
        let settings = message(&[
            bytes_field(1, &ss_user(&ss_account(b"a", 6), None)),
            bytes_field(2, &[4]),
        ]);
        let error = to_json(&config(&ss_inbound(5000, &settings), &freedom_outbound()))
            .expect_err("refused");
        assert!(error.contains("network 4"), "{error}");
    }

    #[test]
    fn two_shadowsocks_users_are_refused() {
        let settings = message(&[
            bytes_field(1, &ss_user(&ss_account(b"a", 6), None)),
            bytes_field(1, &ss_user(&ss_account(b"b", 6), None)),
            bytes_field(2, &[2]),
        ]);
        let error = to_json(&config(&ss_inbound(5000, &settings), &freedom_outbound()))
            .expect_err("refused");
        assert!(error.contains("2 users"), "{error}");
    }

    #[test]
    fn a_shadowsocks_user_email_is_refused() {
        let user = message(&[
            bytes_field(2, b"who@example"),
            bytes_field(3, &ss_account(b"a", 6)),
        ]);
        let settings = bytes_field(1, &user);
        let error = to_json(&config(&ss_inbound(5000, &settings), &freedom_outbound()))
            .expect_err("refused");
        assert!(error.contains("email"), "{error}");
    }

    #[test]
    fn a_truncated_field_is_refused() {
        let mut bytes = http_scenario(5000);
        bytes.extend([0x0a, 0x05]);
        let error = to_json(&bytes).expect_err("refused");
        assert!(error.contains("runs past"), "{error}");
    }
}
