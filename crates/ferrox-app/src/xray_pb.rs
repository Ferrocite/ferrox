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
            (1, 2) => inbounds.extend(inbound(reader.bytes()?)?),
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

/// One inbound handler decodes to one JSON inbound per port it names: xray carries a whole
/// range in one handler, and this tree binds one port per inbound.
fn inbound(bytes: &[u8]) -> Result<Vec<Json>, String> {
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
    let (listen, ports) = receiver.ok_or("xray.core.InboundHandlerConfig: no receiver settings")?;
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
            if inbound_settings != Json::Null {
                pairs.push(("settings", inbound_settings.clone()));
            }
            object(pairs)
        })
        .collect())
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
        "xray.proxy.vmess.outbound.Config" => Ok(object(vec![
            ("protocol", Json::Str("vmess".to_owned())),
            ("settings", vmess_outbound_settings(value)?),
        ])),
        "xray.proxy.vless.outbound.Config" => Ok(object(vec![
            ("protocol", Json::Str("vless".to_owned())),
            ("settings", vless_outbound_settings(value)?),
        ])),
        "xray.proxy.shadowsocks.ClientConfig" => Ok(object(vec![
            ("protocol", Json::Str("shadowsocks".to_owned())),
            ("settings", ss_outbound_settings(value)?),
        ])),
        _ => Err(format!("outbound protocol `{name}` is not carried")),
    }
}

fn receiver_config(bytes: &[u8]) -> Result<(String, Vec<u16>), String> {
    let mut reader = Reader::new(bytes, "xray.app.proxyman.ReceiverConfig");
    let mut ports = None;
    let mut listen = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => ports = Some(port_list(reader.bytes()?)?),
            (2, 2) => listen = Some(ip_or_domain(reader.bytes()?)?),
            (3, 2) => return Err(reader.uncarried("stream settings in the protobuf form")),
            (4, 0) => return Err(reader.uncarried("receive_original_destination")),
            (6, 2) => return Err(reader.uncarried("sniffing settings")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let ports = ports.ok_or("xray.app.proxyman.ReceiverConfig: no port list")?;
    // An absent listen means every interface in xray; this tree binds loopback unless told otherwise, and its JSON dialect reads the same default.
    Ok((listen.unwrap_or_else(|| "127.0.0.1".to_owned()), ports))
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
/// `padding` and `reverse` change the bytes on the wire or name a tunnel this tree does not carry.
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
            (6, 2) => return Err(reader.uncarried("the account's padding")),
            (7, 2) => return Err(reader.uncarried("the account's reverse tunnel")),
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

/// The clients a vless inbound serves. `decryption` is read and dropped: the uuid is what
/// authenticates here and nothing in this tree gates on that string. `fallbacks`, `xorMode`,
/// the `seconds_*` window and a `padding` name bytes this tree does not write.
fn vless_inbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.vless.inbound.Config");
    let mut clients = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                let (id, _, flow) = vless_user(reader.bytes()?)?;
                clients.push(vless_client(id, None, flow));
            }
            (2, 2) => return Err(reader.uncarried("a fallback destination")),
            (3, 2) => {
                account_text(&mut reader)?;
            }
            (4, 0) => return Err(reader.uncarried("xorMode")),
            (5 | 6, 0) => return Err(reader.uncarried("the padding seconds window")),
            (7, 2) => return Err(reader.uncarried("the inbound's padding")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    if clients.is_empty() {
        return Err("xray.proxy.vless.inbound.Config: no user".to_owned());
    }
    Ok(object(vec![("clients", Json::Arr(clients))]))
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

    /// Whether any bytes of the message are left, which is how a packed field's values end.
    fn more(&self) -> bool {
        self.pos < self.buf.len()
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
    fn protobuf_stream_settings_are_refused() {
        let mut receiver = receiver(5000, None);
        receiver.extend(bytes_field(3, &[]));
        let bytes = config(&http_inbound(&receiver, &[]), &freedom_outbound());
        let error = to_json(&bytes).expect_err("refused");
        assert!(error.contains("stream settings"), "{error}");
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
            bytes_field(3, b"always"),
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

    #[test]
    fn a_vless_fallback_is_refused() {
        let settings = message(&[
            bytes_field(1, &vless_user(&vless_account(b"a", None, None))),
            bytes_field(2, &message(&[bytes_field(5, b"127.0.0.1:80")])),
            bytes_field(3, b"always"),
        ]);
        let error = to_json(&config(
            &vless_inbound(5000, &settings),
            &freedom_outbound(),
        ))
        .expect_err("refused");
        assert!(error.contains("fallback"), "{error}");
    }

    #[test]
    fn a_vless_xor_mode_is_refused() {
        let settings = message(&[
            bytes_field(1, &vless_user(&vless_account(b"a", None, None))),
            bytes_field(3, b"always"),
            varint_field(4, 1),
        ]);
        let error = to_json(&config(
            &vless_inbound(5000, &settings),
            &freedom_outbound(),
        ))
        .expect_err("refused");
        assert!(error.contains("xorMode"), "{error}");
    }

    #[test]
    fn a_vless_account_padding_is_refused() {
        let account = typed(
            "xray.proxy.vless.Account",
            &message(&[
                bytes_field(1, b"a"),
                bytes_field(6, b"1234567890abcdef1234567890abcdef"),
            ]),
        );
        let settings = bytes_field(1, &vless_user(&account));
        let error = to_json(&config(
            &vless_inbound(5000, &settings),
            &freedom_outbound(),
        ))
        .expect_err("refused");
        assert!(error.contains("padding"), "{error}");
    }

    #[test]
    fn a_vless_inbound_without_a_user_is_refused() {
        let error = to_json(&config(
            &vless_inbound(5000, &bytes_field(3, b"always")),
            &freedom_outbound(),
        ))
        .expect_err("refused");
        assert!(error.contains("no user"), "{error}");
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
