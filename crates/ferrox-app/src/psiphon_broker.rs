//! The in-proxy broker client: a Noise XK session carried in plaintext
//! `/inproxy-broker` round trips, with CBOR records and an AES-GCM
//! obfuscation layer.

use crate::json::Json;
use crate::psiphon_meek::{self, Meek};
use crate::psiphon_ssh::{random, Identity, Proxy};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use curve25519_dalek::edwards::CompressedEdwardsY;
use hkdf::Hkdf;
use sha2::Sha256;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const RECORD_VERSION: u8 = 1;
const SESSION_PACKET: u8 = 1;
const SESSION_ROUND_TRIP: u8 = 2;
const CLIENT_OFFER_REQUEST: u8 = 7;
const CLIENT_OFFER_RESPONSE: u8 = 8;
const BROKER_PATH: &str = "/inproxy-broker";
const PROLOGUE_VERSION: u64 = 1;
const LATEST_PROTOCOL_VERSION: u64 = 2;
// The upstream context misspells "initiator"; the derived key depends on it.
const CLIENT_SEND_CONTEXT: &[u8] = b"in-proxy-session-packet-intiator-to-responder";
const CLIENT_RECEIVE_CONTEXT: &[u8] = b"in-proxy-session-packet-responder-to-initiator";
const NOISE_PARAMS: &str = "Noise_XK_25519_ChaChaPoly_BLAKE2b";
const MAX_MESSAGE: usize = 64 * 1024;
const MAX_PADDING: usize = 256;

/// A CBOR value. Maps preserve their entries so callers can encode
/// deterministic integer-key maps.
#[derive(Debug, Clone, PartialEq)]
enum Value {
    UInt(u64),
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
    Float(f64),
}

impl Value {
    fn get(&self, key: u64) -> Option<&Value> {
        let Self::Map(entries) = self else {
            return None;
        };
        entries
            .iter()
            .find_map(|(entry_key, value)| match entry_key {
                Value::UInt(number) if *number == key => Some(value),
                _ => None,
            })
    }

    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    fn text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            _ => None,
        }
    }

    fn uint(&self) -> Option<u64> {
        match self {
            Self::UInt(number) => Some(*number),
            Self::Int(number) => u64::try_from(*number).ok(),
            _ => None,
        }
    }

    fn bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }
}

/// A decoded record with its type stripped.
#[derive(Debug, Clone, PartialEq)]
struct Record {
    kind: u8,
    value: Value,
}

/// One broker destination: a signed server entry and the in-proxy address.
#[derive(Debug, Clone)]
pub(crate) struct Destination {
    pub(crate) address: String,
    pub(crate) network_protocol: u64,
    pub(crate) packed_server_entry: Vec<u8>,
}

/// The in-proxy destination a signed server entry names.
pub(crate) fn destination(entry: &Json, host: &str) -> Option<Destination> {
    let capabilities = entry.get("capabilities").and_then(Json::as_arr)?;
    let has = |name: &str| {
        capabilities
            .iter()
            .filter_map(Json::as_str)
            .any(|capability| capability == name)
    };
    let (port, network_protocol) = if has("INPROXY-WEBRTC-OSSH") {
        (
            entry.get("inproxyOSSHPort").and_then(Json::as_port),
            NetworkProtocol::Tcp,
        )
    } else if has("INPROXY-WEBRTC-SSH") {
        (
            entry.get("inproxySSHPort").and_then(Json::as_port),
            NetworkProtocol::Tcp,
        )
    } else if has("INPROXY-WEBRTC-QUIC-OSSH") {
        (
            entry.get("inproxyQUICPort").and_then(Json::as_port),
            NetworkProtocol::Udp,
        )
    } else {
        return None;
    };
    let port = port.filter(|port| *port > 0)?;
    let address = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Some(Destination {
        address,
        network_protocol: network_protocol as u64,
        packed_server_entry: pack_server_entry(entry)?,
    })
}

#[derive(Clone, Copy)]
enum NetworkProtocol {
    Tcp = 0,
    Udp = 1,
}

fn pack_server_entry(entry: &Json) -> Option<Vec<u8>> {
    let Json::Obj(pairs) = entry else {
        return None;
    };
    if !pairs.iter().any(|(name, _)| name == "signature") {
        return None;
    }
    let local_tag = pairs
        .iter()
        .find(|(name, _)| name == "isLocalDerivedTag")
        .and_then(|(_, value)| value.as_bool())
        .unwrap_or(false);
    let fields = pairs
        .iter()
        .filter(|(name, _)| match name.as_str() {
            "localSource" | "localTimestamp" | "isLocalDerivedTag" => false,
            "tag" => !local_tag,
            _ => true,
        })
        .map(|(name, value)| (Value::Text(name.clone()), json_value(value)))
        .collect();
    Some(encode(&Value::Map(vec![(
        Value::UInt(2),
        Value::Map(fields),
    )])))
}

fn json_value(value: &Json) -> Value {
    match value {
        Json::Null => Value::Null,
        Json::Bool(value) => Value::Bool(*value),
        Json::Num(number) if number.fract() == 0.0 && *number >= 0.0 => Value::UInt(*number as u64),
        Json::Num(number) if number.fract() == 0.0 => Value::Int(*number as i64),
        Json::Num(number) => Value::Float(*number),
        Json::Str(text) => Value::Text(text.clone()),
        Json::Arr(items) => Value::Array(items.iter().map(json_value).collect()),
        Json::Obj(pairs) => Value::Map(
            pairs
                .iter()
                .map(|(name, value)| (Value::Text(name.clone()), json_value(value)))
                .collect(),
        ),
    }
}

/// One broker fronting endpoint.
#[derive(Debug, Clone)]
pub(crate) struct Front {
    pub(crate) host: String,
    pub(crate) dial: String,
    pub(crate) port: u16,
    pub(crate) disable_sni: bool,
}

/// A broker's front and session keys, from a tactics payload.
#[derive(Debug, Clone)]
pub(crate) struct Broker {
    pub(crate) public_key: String,
    pub(crate) root_secret: String,
}

/// The answer half of a client offer.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Offer {
    pub(crate) limited: bool,
    pub(crate) no_match: bool,
    pub(crate) must_upgrade: bool,
    pub(crate) connection_id: Vec<u8>,
    pub(crate) protocol_version: u64,
    pub(crate) answer_sdp: String,
    pub(crate) relay_packet_to_server: Vec<u8>,
}

/// Anything that carries one opaque broker round trip.
pub(crate) trait Transport {
    fn round_trip(&mut self, body: &[u8]) -> Result<Vec<u8>, String>;
}

/// A fronted plaintext broker transport that reuses one HTTP stream.
struct MeekTransport {
    http: psiphon_meek::MeekHttp,
}

impl Transport for MeekTransport {
    fn round_trip(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        self.http.round_trip(body)
    }
}

/// The Noise transport keys of one established session.
struct Session {
    id: [u8; 32],
    send: Aes256Gcm,
    receive: Aes256Gcm,
    noise: snow::TransportState,
}

/// A broker client with at most one live session.
pub(crate) struct Client {
    broker: Broker,
    static_secret: [u8; 32],
    root: [u8; 32],
    offer_secret: [u8; 32],
    transport: Box<dyn Transport>,
    session: Option<Session>,
}

impl Client {
    /// Build a client from a broker spec and a transport.
    pub(crate) fn new(
        broker: Broker,
        transport: Box<dyn Transport>,
        static_secret: [u8; 32],
    ) -> Result<Self, String> {
        let root = ferrox_core::b64::decode(broker.root_secret.as_bytes())
            .ok_or_else(|| "psiphon broker: root secret is not base64".to_owned())?;
        let root: [u8; 32] = root
            .try_into()
            .map_err(|_| "psiphon broker: root secret is not 32 bytes".to_owned())?;
        Ok(Self {
            broker,
            static_secret,
            root,
            offer_secret: random::<32>(),
            transport,
            session: None,
        })
    }

    /// Build a client from a broker spec and one paired front.
    pub(crate) fn connect(
        broker: Broker,
        front: &Front,
        timeout: Duration,
        proxy: Option<&Proxy>,
    ) -> Result<Self, String> {
        let sni = if front.disable_sni || front.dial.parse::<std::net::IpAddr>().is_ok() {
            String::new()
        } else {
            front.dial.clone()
        };
        let meek = Meek {
            dial: front.dial.clone(),
            port: front.port,
            host: front.host.clone(),
            sni,
            public_key: String::new(),
            obfuscated_key: String::new(),
            disable_sni: front.disable_sni,
            alpn: Vec::new(),
            fronts: vec![(front.dial.clone(), front.port)],
            hosts: vec![front.host.clone()],
            https: true,
            fronted: true,
            protocol: "INPROXY-BROKER",
        };
        let http = psiphon_meek::MeekHttp::new_plain(meek, proxy.cloned(), timeout, BROKER_PATH);
        let transport = Box::new(MeekTransport { http });
        Self::new(broker, transport, random::<32>())
    }

    /// Send one client offer and return the broker's answer.
    pub(crate) fn client_offer(
        &mut self,
        destination: &Destination,
        common_compartments: &[[u8; 32]],
        personal_compartments: &[[u8; 32]],
        sdp: &str,
        metrics: &Metrics,
    ) -> Result<Offer, String> {
        if common_compartments.is_empty() && personal_compartments.is_empty() {
            return Err("psiphon broker: no compartments".to_owned());
        }
        let request = client_offer_request(
            destination,
            common_compartments,
            personal_compartments,
            sdp,
            metrics,
            self.offer_secret,
        );
        let reply = self.session_request(&record(CLIENT_OFFER_REQUEST, &request)?)?;
        let response = decode_record(&reply)?;
        if response.kind != CLIENT_OFFER_RESPONSE {
            return Err(format!(
                "psiphon broker: offer response is record {}",
                response.kind
            ));
        }
        Ok(parse_offer(&response.value))
    }

    /// Wrap a record in a session round trip, establishing the session with
    /// the first request as the XK handshake's payload.
    fn session_request(&mut self, request: &[u8]) -> Result<Vec<u8>, String> {
        let round_trip_id = random::<32>();
        let round_trip = record(
            SESSION_ROUND_TRIP,
            &Value::Map(vec![
                (Value::UInt(1), Value::Bytes(round_trip_id.to_vec())),
                (Value::UInt(2), Value::Bytes(request.to_vec())),
            ]),
        )?;
        let plain = if self.session.is_none() {
            self.handshake(&round_trip)?
        } else {
            let payload = self.send_packet(&round_trip)?;
            let reply = self.transport.round_trip(&payload)?;
            self.receive_packet(&reply)?
        };
        let response = decode_record(&plain)?;
        if response.kind != SESSION_ROUND_TRIP {
            return Err(format!(
                "psiphon broker: expected a session round trip, got {}",
                response.kind
            ));
        }
        let id = response
            .value
            .get(1)
            .and_then(Value::bytes)
            .ok_or_else(|| "psiphon broker: round trip has no ID".to_owned())?;
        if id != round_trip_id {
            return Err("psiphon broker: round trip ID mismatch".to_owned());
        }
        response
            .value
            .get(2)
            .and_then(Value::bytes)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| "psiphon broker: round trip has no payload".to_owned())
    }

    fn handshake(&mut self, first_request: &[u8]) -> Result<Vec<u8>, String> {
        let broker_public = broker_curve25519(&self.broker.public_key)?;
        let session_id = random::<32>();
        let prologue = encode_prologue(&session_id);
        let params: snow::params::NoiseParams = NOISE_PARAMS
            .parse()
            .map_err(|error| format!("psiphon broker: noise parameters: {error}"))?;
        let mut noise = snow::Builder::new(params)
            .local_private_key(&self.static_secret)
            .map_err(|error| format!("psiphon broker: noise key: {error}"))?
            .remote_public_key(&broker_public)
            .map_err(|error| format!("psiphon broker: noise peer: {error}"))?
            .prologue(&prologue)
            .map_err(|error| format!("psiphon broker: noise prologue: {error}"))?
            .build_initiator()
            .map_err(|error| format!("psiphon broker: noise initiator: {error}"))?;
        let send_secret = derive(&self.root, CLIENT_SEND_CONTEXT)?;
        let receive_secret = derive(&self.root, CLIENT_RECEIVE_CONTEXT)?;
        let send = Aes256Gcm::new_from_slice(&send_secret)
            .map_err(|_| "psiphon broker: send key".to_owned())?;
        let receive = Aes256Gcm::new_from_slice(&receive_secret)
            .map_err(|_| "psiphon broker: receive key".to_owned())?;
        let mut buffer = vec![0u8; MAX_MESSAGE];
        let length = noise
            .write_message(&[], &mut buffer)
            .map_err(|error| format!("psiphon broker: noise e: {error}"))?;
        let first = wrap_session_packet(session_id, 0, &buffer[..length], &send)?;
        let reply = self.transport.round_trip(&first)?;
        let packet = unwrap_session_packet(&reply, &receive, false)?;
        if packet.session_id != session_id || packet.nonce != 0 {
            return Err("psiphon broker: handshake session or nonce mismatch".to_owned());
        }
        let length = noise
            .read_message(&packet.payload, &mut buffer)
            .map_err(|error| format!("psiphon broker: noise ee: {error}"))?;
        if length != 0 {
            return Err("psiphon broker: unexpected handshake payload".to_owned());
        }
        let length = noise
            .write_message(first_request, &mut buffer)
            .map_err(|error| format!("psiphon broker: noise s: {error}"))?;
        let third = wrap_session_packet(session_id, 0, &buffer[..length], &send)?;
        let reply = self.transport.round_trip(&third)?;
        let transport = noise
            .into_transport_mode()
            .map_err(|error| format!("psiphon broker: noise transport: {error}"))?;
        self.session = Some(Session {
            id: session_id,
            send,
            receive,
            noise: transport,
        });
        self.receive_packet(&reply)
    }

    fn send_packet(&mut self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| "psiphon broker: no session".to_owned())?;
        let mut buffer = vec![0u8; payload.len() + 1024];
        let nonce = session.noise.sending_nonce();
        let length = session
            .noise
            .write_message(payload, &mut buffer)
            .map_err(|error| format!("psiphon broker: noise write: {error}"))?;
        wrap_session_packet(session.id, nonce, &buffer[..length], &session.send)
    }

    fn receive_packet(&mut self, reply: &[u8]) -> Result<Vec<u8>, String> {
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| "psiphon broker: no session".to_owned())?;
        let packet = unwrap_session_packet(reply, &session.receive, false)?;
        if packet.session_id != session.id {
            return Err("psiphon broker: session mismatch".to_owned());
        }
        let mut plain = vec![0u8; packet.payload.len() + 1024];
        let length = session
            .noise
            .read_message(&packet.payload, &mut plain)
            .map_err(|error| format!("psiphon broker: noise read: {error}"))?;
        plain.truncate(length);
        Ok(plain)
    }
}

/// Client metrics sent with every offer.
#[derive(Debug, Clone)]
pub(crate) struct Metrics {
    base_parameters: Value,
    protocol_version: u64,
    nat_type: u64,
    port_mapping_types: Vec<u64>,
}

impl Metrics {
    /// Build the metrics record for the current client.
    fn new(base_parameters: Value) -> Self {
        Self {
            base_parameters,
            protocol_version: LATEST_PROTOCOL_VERSION,
            nat_type: 0,
            port_mapping_types: Vec::new(),
        }
    }

    /// Build the metrics record from the identity the other Psiphon lanes use.
    pub(crate) fn from_identity(identity: &Identity<'_>) -> Self {
        Self::new(api_parameters(identity))
    }
}

fn api_parameters(identity: &Identity<'_>) -> Value {
    let session_id = hex_bytes(identity.session_id).unwrap_or_default();
    let mut fields = vec![
        (Value::UInt(5), Value::Bytes(session_id.clone())),
        (Value::UInt(14), Value::Bytes(session_id)),
        (
            Value::UInt(6),
            Value::Bytes(hex_bytes(identity.propagation).unwrap_or_default()),
        ),
        (
            Value::UInt(7),
            Value::Bytes(hex_bytes(identity.sponsor).unwrap_or_default()),
        ),
        (
            Value::UInt(8),
            Value::UInt(identity.version.parse().unwrap_or(0)),
        ),
        (Value::UInt(9), Value::Text(identity.platform.to_owned())),
        (Value::UInt(54), Value::Text("unknown".to_owned())),
    ];
    if !identity.client_features.is_empty() {
        fields.push((
            Value::UInt(10),
            Value::Array(
                identity
                    .client_features
                    .iter()
                    .map(|feature| Value::Text(feature.clone()))
                    .collect(),
            ),
        ));
    }
    if let Some(region) = identity.device_region {
        fields.push((Value::UInt(12), Value::Text(region.to_owned())));
    }
    if let Some(location) = identity.device_location {
        fields.push((Value::UInt(13), Value::Text(location.to_owned())));
    }
    if let Some(region) = identity.egress_region {
        fields.push((Value::UInt(43), Value::Text(region.to_owned())));
    }
    Value::Map(fields)
}

fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().as_chunks::<2>().0 {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        out.push((high << 4) | low);
    }
    Some(out)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn client_offer_request(
    destination: &Destination,
    common_compartments: &[[u8; 32]],
    personal_compartments: &[[u8; 32]],
    sdp: &str,
    metrics: &Metrics,
    offer_secret: [u8; 32],
) -> Value {
    let mut metrics_fields = vec![
        (Value::UInt(1), metrics.base_parameters.clone()),
        (Value::UInt(2), Value::UInt(metrics.protocol_version)),
    ];
    if metrics.nat_type != 0 {
        metrics_fields.push((Value::UInt(3), Value::UInt(metrics.nat_type)));
    }
    if !metrics.port_mapping_types.is_empty() {
        metrics_fields.push((
            Value::UInt(4),
            Value::Array(
                metrics
                    .port_mapping_types
                    .iter()
                    .map(|kind| Value::UInt(*kind))
                    .collect(),
            ),
        ));
    }
    let metrics = Value::Map(metrics_fields);
    let common = Value::Array(
        common_compartments
            .iter()
            .map(|id| Value::Bytes(id.to_vec()))
            .collect(),
    );
    let mut fields = vec![(Value::UInt(1), metrics)];
    if !common_compartments.is_empty() {
        fields.push((Value::UInt(2), common));
    }
    if !personal_compartments.is_empty() {
        fields.push((
            Value::UInt(3),
            Value::Array(
                personal_compartments
                    .iter()
                    .map(|id| Value::Bytes(id.to_vec()))
                    .collect(),
            ),
        ));
    }
    if destination.network_protocol != 0 {
        fields.push((Value::UInt(10), Value::UInt(destination.network_protocol)));
    }
    fields.extend([
        (
            Value::UInt(4),
            Value::Map(vec![
                (Value::UInt(1), Value::UInt(1)),
                (Value::UInt(2), Value::Text(sdp.to_owned())),
            ]),
        ),
        (
            Value::UInt(5),
            Value::Array(vec![Value::UInt(1), Value::UInt(3), Value::UInt(4)]),
        ),
        (Value::UInt(6), Value::Bytes(offer_secret.to_vec())),
        (Value::UInt(7), Value::Bool(true)),
        (
            Value::UInt(9),
            Value::Bytes(destination.packed_server_entry.clone()),
        ),
        (Value::UInt(11), Value::Text(destination.address.clone())),
    ]);
    Value::Map(fields)
}

fn parse_offer(value: &Value) -> Offer {
    Offer {
        limited: value.get(1).and_then(Value::bool).unwrap_or(false),
        no_match: value.get(2).and_then(Value::bool).unwrap_or(false),
        connection_id: value
            .get(3)
            .and_then(Value::bytes)
            .map(<[u8]>::to_vec)
            .unwrap_or_default(),
        protocol_version: value.get(4).and_then(Value::uint).unwrap_or(0),
        answer_sdp: value
            .get(5)
            .and_then(|sdp| sdp.get(2))
            .and_then(Value::text)
            .unwrap_or("")
            .to_owned(),
        relay_packet_to_server: value
            .get(6)
            .and_then(Value::bytes)
            .map(<[u8]>::to_vec)
            .unwrap_or_default(),
        must_upgrade: value.get(7).and_then(Value::bool).unwrap_or(false),
    }
}

fn encode_prologue(session_id: &[u8; 32]) -> Vec<u8> {
    encode(&Value::Map(vec![
        (
            Value::UInt(1),
            Value::Text("psiphon-inproxy-session".to_owned()),
        ),
        (Value::UInt(2), Value::UInt(PROLOGUE_VERSION)),
        (Value::UInt(3), Value::Bytes(session_id.to_vec())),
    ]))
}

fn derive(root: &[u8; 32], context: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, root)
        .expand(context, &mut key)
        .map_err(|_| "psiphon broker: HKDF".to_owned())?;
    Ok(key)
}

fn broker_curve25519(public_key: &str) -> Result<[u8; 32], String> {
    let bytes = ferrox_core::b64::decode(public_key.as_bytes())
        .ok_or_else(|| "psiphon broker: public key is not base64".to_owned())?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "psiphon broker: public key is not 32 bytes".to_owned())?;
    CompressedEdwardsY(bytes)
        .decompress()
        .map(|point| point.to_montgomery().to_bytes())
        .ok_or_else(|| "psiphon broker: public key is not Ed25519".to_owned())
}

struct SessionPacket {
    session_id: [u8; 32],
    nonce: u64,
    payload: Vec<u8>,
}

fn wrap_session_packet(
    session_id: [u8; 32],
    nonce: u64,
    payload: &[u8],
    key: &Aes256Gcm,
) -> Result<Vec<u8>, String> {
    let mut fields = vec![(Value::UInt(1), Value::Bytes(session_id.to_vec()))];
    if nonce != 0 {
        fields.push((Value::UInt(2), Value::UInt(nonce)));
    }
    fields.push((Value::UInt(3), Value::Bytes(payload.to_vec())));
    let record = record(SESSION_PACKET, &Value::Map(fields))?;
    obfuscate(&record, key, true)
}

fn unwrap_session_packet(
    reply: &[u8],
    key: &Aes256Gcm,
    timestamped: bool,
) -> Result<SessionPacket, String> {
    let record = deobfuscate(reply, key, timestamped)?;
    let record = decode_record(&record)?;
    if record.kind != SESSION_PACKET {
        return Err("psiphon broker: expected a session packet".to_owned());
    }
    let session_id = record
        .value
        .get(1)
        .and_then(Value::bytes)
        .ok_or_else(|| "psiphon broker: session packet has no ID".to_owned())?;
    let session_id: [u8; 32] = session_id
        .try_into()
        .map_err(|_| "psiphon broker: session ID is not 32 bytes".to_owned())?;
    let payload = record
        .value
        .get(3)
        .and_then(Value::bytes)
        .ok_or_else(|| "psiphon broker: session packet has no payload".to_owned())?;
    Ok(SessionPacket {
        session_id,
        nonce: record.value.get(2).and_then(Value::uint).unwrap_or(0),
        payload: payload.to_vec(),
    })
}

fn obfuscate(record: &[u8], key: &Aes256Gcm, timestamped: bool) -> Result<Vec<u8>, String> {
    let nonce = random::<12>();
    let mut plain = Vec::with_capacity(record.len() + MAX_PADDING + 16);
    if timestamped {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "psiphon broker: clock".to_owned())?
            .as_secs()
            .cast_signed();
        put_varint(&mut plain, timestamp);
    }
    let padding = usize::from(u16::from_be_bytes(random::<2>())) % (MAX_PADDING + 1);
    put_uvarint(&mut plain, padding as u64);
    plain.resize(plain.len() + padding, 0);
    plain.extend_from_slice(record);
    let sealed = key
        .encrypt(
            &Nonce::try_from(&nonce[..]).map_err(|_| "psiphon broker: nonce".to_owned())?,
            plain.as_slice(),
        )
        .map_err(|_| "psiphon broker: encrypt".to_owned())?;
    let mut out = Vec::with_capacity(nonce.len() + sealed.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn deobfuscate(reply: &[u8], key: &Aes256Gcm, timestamped: bool) -> Result<Vec<u8>, String> {
    if reply.len() < 12 {
        return Err("psiphon broker: obfuscated packet is too short".to_owned());
    }
    let (nonce, sealed) = reply.split_at(12);
    let mut plain = key
        .decrypt(
            &Nonce::try_from(nonce).map_err(|_| "psiphon broker: nonce".to_owned())?,
            sealed,
        )
        .map_err(|_| "psiphon broker: decrypt".to_owned())?;
    let after_timestamp = if timestamped {
        get_varint(&plain)
            .map(|(_, rest)| rest)
            .ok_or_else(|| "psiphon broker: timestamp".to_owned())?
    } else {
        plain.as_slice()
    };
    let (padding, after_padding) =
        get_uvarint(after_timestamp).ok_or_else(|| "psiphon broker: padding".to_owned())?;
    let padding = usize::try_from(padding).map_err(|_| "psiphon broker: padding".to_owned())?;
    if padding > after_padding.len() {
        return Err("psiphon broker: padding".to_owned());
    }
    let start = plain.len() - after_padding.len() + padding;
    plain.drain(..start);
    Ok(plain)
}

fn record(kind: u8, payload: &Value) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(512);
    out.push(RECORD_VERSION);
    out.push(kind);
    let length_at = out.len();
    out.resize(length_at + 10, 0);
    encode_into(payload, &mut out);
    let length = out.len() - length_at - 10;
    if length > 0xffff {
        return Err("psiphon broker: record is too long".to_owned());
    }
    let mut length_bytes = [0u8; 10];
    let mut length_buffer = Vec::new();
    put_uvarint(&mut length_buffer, length as u64);
    length_bytes[..length_buffer.len()].copy_from_slice(&length_buffer);
    out[length_at..length_at + length_buffer.len()]
        .copy_from_slice(&length_bytes[..length_buffer.len()]);
    out.drain(length_at + length_buffer.len()..length_at + 10);
    Ok(out)
}

fn decode_record(payload: &[u8]) -> Result<Record, String> {
    if payload.len() < 3 || payload[0] != RECORD_VERSION {
        return Err("psiphon broker: bad record preamble".to_owned());
    }
    let (length, rest) =
        get_uvarint(&payload[2..]).ok_or_else(|| "psiphon broker: bad record length".to_owned())?;
    let length =
        usize::try_from(length).map_err(|_| "psiphon broker: bad record length".to_owned())?;
    if rest.len() != length {
        return Err("psiphon broker: record length mismatch".to_owned());
    }
    let (value, consumed) = decode(rest).ok_or_else(|| "psiphon broker: bad CBOR".to_owned())?;
    if consumed != rest.len() {
        return Err("psiphon broker: trailing CBOR".to_owned());
    }
    Ok(Record {
        kind: payload[1],
        value,
    })
}

fn put_uvarint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn get_uvarint(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0u64;
    let mut shift = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, &bytes[index + 1..]));
        }
        shift += 7;
    }
    None
}

fn put_varint(out: &mut Vec<u8>, value: i64) {
    let zigzag = ((value << 1) ^ (value >> 63)) as u64;
    put_uvarint(out, zigzag);
}

fn get_varint(bytes: &[u8]) -> Option<(i64, &[u8])> {
    let (zigzag, rest) = get_uvarint(bytes)?;
    let value = (zigzag >> 1).cast_signed() ^ -(zigzag & 1).cast_signed();
    Some((value, rest))
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::UInt(number) => encode_head(0, *number, out),
        Value::Int(number) if *number >= 0 => encode_head(0, *number as u64, out),
        Value::Int(number) => encode_head(1, (-1 - *number).cast_unsigned(), out),
        Value::Bytes(bytes) => {
            encode_head(2, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        Value::Text(text) => {
            encode_head(3, text.len() as u64, out);
            out.extend_from_slice(text.as_bytes());
        }
        Value::Array(items) => {
            encode_head(4, items.len() as u64, out);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(entries) => {
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                .iter()
                .map(|(key, value)| {
                    let mut key_bytes = Vec::new();
                    encode_into(key, &mut key_bytes);
                    let mut value_bytes = Vec::new();
                    encode_into(value, &mut value_bytes);
                    (key_bytes, value_bytes)
                })
                .collect();
            encoded.sort_by(|left, right| {
                left.0
                    .len()
                    .cmp(&right.0.len())
                    .then_with(|| left.0.cmp(&right.0))
            });
            encode_head(5, encoded.len() as u64, out);
            for (key, value) in encoded {
                out.extend_from_slice(&key);
                out.extend_from_slice(&value);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
        Value::Float(number) => {
            out.push(0xfb);
            out.extend_from_slice(&number.to_bits().to_be_bytes());
        }
    }
}

fn encode_head(major: u8, value: u64, out: &mut Vec<u8>) {
    if value < 24 {
        out.push((major << 5) | value as u8);
    } else if value <= 0xff {
        out.push((major << 5) | 0x18);
        out.push(value as u8);
    } else if value <= 0xffff {
        out.push((major << 5) | 0x19);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= 0xffff_ffff {
        out.push((major << 5) | 0x1a);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push((major << 5) | 0x1b);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn decode(bytes: &[u8]) -> Option<(Value, usize)> {
    decode_depth(bytes, 0)
}

fn decode_depth(bytes: &[u8], depth: usize) -> Option<(Value, usize)> {
    if depth > 32 {
        return None;
    }
    let (&head, rest) = bytes.split_first()?;
    let major = head >> 5;
    let additional = head & 0x1f;
    let (argument, mut used) = match additional {
        0..=23 => (u64::from(additional), 0),
        24 => (u64::from(*rest.first()?), 1),
        25 => {
            let value = u16::from_be_bytes(rest.get(..2)?.try_into().ok()?);
            (u64::from(value), 2)
        }
        26 => {
            let value = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?);
            (u64::from(value), 4)
        }
        27 => (u64::from_be_bytes(rest.get(..8)?.try_into().ok()?), 8),
        _ => return None,
    };
    used += 1;
    match major {
        0 => Some((Value::UInt(argument), used)),
        1 => Some((Value::Int(-1 - argument.cast_signed()), used)),
        2 | 3 => {
            let length = usize::try_from(argument).ok()?;
            let start = used;
            let end = start.checked_add(length)?;
            let data = bytes.get(start..end)?;
            used = end;
            if major == 2 {
                Some((Value::Bytes(data.to_vec()), used))
            } else {
                Some((Value::Text(String::from_utf8(data.to_vec()).ok()?), used))
            }
        }
        4 => {
            let length = usize::try_from(argument).ok()?;
            let remaining = bytes.len().saturating_sub(used);
            if length > remaining {
                return None;
            }
            let mut items = Vec::with_capacity(length);
            for _ in 0..length {
                let (item, consumed) = decode_depth(bytes.get(used..)?, depth + 1)?;
                items.push(item);
                used += consumed;
            }
            Some((Value::Array(items), used))
        }
        5 => {
            let length = usize::try_from(argument).ok()?;
            let remaining = bytes.len().saturating_sub(used);
            if length > remaining / 2 {
                return None;
            }
            let mut entries = Vec::with_capacity(length);
            for _ in 0..length {
                let (key, key_len) = decode_depth(bytes.get(used..)?, depth + 1)?;
                used += key_len;
                let (value, value_len) = decode_depth(bytes.get(used..)?, depth + 1)?;
                used += value_len;
                entries.push((key, value));
            }
            Some((Value::Map(entries), used))
        }
        7 => match additional {
            20 => Some((Value::Bool(false), used)),
            21 => Some((Value::Bool(true), used)),
            22 => Some((Value::Null, used)),
            27 => {
                let bits = argument;
                Some((Value::Float(f64::from_bits(bits)), used))
            }
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_destination() -> Destination {
        Destination {
            address: "192.0.2.1:443".to_owned(),
            network_protocol: 0,
            packed_server_entry: vec![0xa0],
        }
    }

    #[test]
    fn canonical_maps_order_keys_by_encoded_length() {
        let value = Value::Map(vec![
            (Value::UInt(24), Value::UInt(1)),
            (Value::UInt(1), Value::UInt(2)),
            (Value::Text("aa".to_owned()), Value::UInt(3)),
        ]);
        assert_eq!(
            encode(&value),
            vec![0xa3, 0x01, 0x02, 0x18, 0x18, 0x01, 0x62, 0x61, 0x61, 0x03,]
        );
    }

    #[test]
    fn records_round_trip_the_type_and_body() {
        let body = Value::Map(vec![
            (Value::UInt(1), Value::Bytes(vec![1; 32])),
            (Value::UInt(2), Value::Text("value".to_owned())),
        ]);
        let bytes = record(CLIENT_OFFER_REQUEST, &body).unwrap();
        let decoded = decode_record(&bytes).unwrap();
        assert_eq!(decoded.kind, CLIENT_OFFER_REQUEST);
        assert_eq!(decoded.value, body);
    }

    #[test]
    fn a_record_whose_length_disagrees_with_its_preamble_is_rejected() {
        let bytes = record(SESSION_PACKET, &Value::Null).unwrap();
        assert!(decode_record(&bytes[..bytes.len() - 1]).is_err());
        let mut wrong = bytes.clone();
        wrong[1] = 0xff;
        assert_eq!(decode_record(&wrong).unwrap().kind, 0xff);
    }

    #[test]
    fn varints_match_go_zigzag_and_uvarint() {
        assert_eq!(
            encode(&Value::UInt(0xffff_ffff)),
            vec![0x1a, 0xff, 0xff, 0xff, 0xff]
        );
        let mut out = Vec::new();
        put_varint(&mut out, 1_700_000_000);
        assert_eq!(get_varint(&out).unwrap().0, 1_700_000_000);
        put_varint(&mut out, 0);
        assert_eq!(get_varint(&[0]).unwrap().0, 0);
        let mut out = Vec::new();
        put_uvarint(&mut out, 300);
        assert_eq!(out, vec![0xac, 0x02]);
        assert_eq!(get_uvarint(&out).unwrap().0, 300);
    }

    #[test]
    fn obfuscation_hides_the_record_and_recovers_it() {
        let root = [7u8; 32];
        let key = Aes256Gcm::new_from_slice(&derive(&root, CLIENT_SEND_CONTEXT).unwrap()).unwrap();
        let receive =
            Aes256Gcm::new_from_slice(&derive(&root, CLIENT_RECEIVE_CONTEXT).unwrap()).unwrap();
        let record = record(SESSION_PACKET, &Value::Text("payload".to_owned())).unwrap();
        let sealed = obfuscate(&record, &key, true).unwrap();
        assert_ne!(sealed, record);
        assert_eq!(deobfuscate(&sealed, &key, true).unwrap(), record);
        assert!(deobfuscate(&sealed, &receive, true).is_err());
        let mut corrupted = sealed.clone();
        if let Some(byte) = corrupted.last_mut() {
            *byte ^= 1;
        }
        assert!(deobfuscate(&corrupted, &key, true).is_err());
    }

    #[test]
    fn an_ed25519_key_converts_to_its_montgomery_form() {
        let secret = [3u8; 32];
        let edwards = curve25519_dalek::edwards::EdwardsPoint::mul_base(
            &curve25519_dalek::scalar::Scalar::from_bytes_mod_order(secret),
        );
        let montgomery = edwards.to_montgomery().to_bytes();
        assert_eq!(
            broker_curve25519(&ferrox_core::b64::encode(&edwards.compress().to_bytes())).unwrap(),
            montgomery
        );
    }

    #[test]
    fn offer_request_names_the_destination_and_compartments() {
        let metrics = Metrics::new(Value::Map(vec![(
            Value::UInt(6),
            Value::Text("PROP".to_owned()),
        )]));
        let request = client_offer_request(
            &sample_destination(),
            &[[9u8; 32]],
            &[[8u8; 32]],
            "v=0\r\n",
            &metrics,
            [4u8; 32],
        );
        assert_eq!(request.get(1).unwrap().get(2).unwrap().uint(), Some(2));
        assert_eq!(
            request.get(4).unwrap().get(2).unwrap().text(),
            Some("v=0\r\n")
        );
        assert_eq!(request.get(9).unwrap().bytes(), Some(&[0xa0][..]));
        assert_eq!(request.get(11).unwrap().text(), Some("192.0.2.1:443"));
        let Value::Array(common) = request.get(2).unwrap() else {
            panic!("common compartments");
        };
        assert_eq!(common[0].bytes(), Some(&[9u8; 32][..]));
        let Value::Array(personal) = request.get(3).unwrap() else {
            panic!("personal compartments");
        };
        assert_eq!(personal[0].bytes(), Some(&[8u8; 32][..]));
    }

    struct MockBroker {
        secret: [u8; 32],
        receive: Aes256Gcm,
        send: Aes256Gcm,
        session_id: Option<[u8; 32]>,
        noise: Option<snow::HandshakeState>,
        transport: Option<snow::TransportState>,
    }

    impl MockBroker {
        fn new(root: [u8; 32], secret: [u8; 32]) -> Self {
            Self {
                secret,
                receive: Aes256Gcm::new_from_slice(&derive(&root, CLIENT_SEND_CONTEXT).unwrap())
                    .unwrap(),
                send: Aes256Gcm::new_from_slice(&derive(&root, CLIENT_RECEIVE_CONTEXT).unwrap())
                    .unwrap(),
                session_id: None,
                noise: None,
                transport: None,
            }
        }

        fn reply(&self, session_id: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, String> {
            let packet = Value::Map(vec![
                (Value::UInt(1), Value::Bytes(session_id.to_vec())),
                (Value::UInt(3), Value::Bytes(payload.to_vec())),
            ]);
            let record = record(SESSION_PACKET, &packet)?;
            obfuscate(&record, &self.send, false)
        }
    }

    impl Transport for MockBroker {
        fn round_trip(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
            let packet = unwrap_session_packet(body, &self.receive, true)?;
            let mut buffer = vec![0u8; MAX_MESSAGE];
            if self.session_id.is_none() {
                let prologue = encode_prologue(&packet.session_id);
                let params: snow::params::NoiseParams = NOISE_PARAMS.parse().unwrap();
                let mut noise = snow::Builder::new(params)
                    .local_private_key(&self.secret)
                    .unwrap()
                    .prologue(&prologue)
                    .unwrap()
                    .build_responder()
                    .unwrap();
                let length = noise.read_message(&packet.payload, &mut buffer).unwrap();
                if length != 0 {
                    return Err("unexpected first payload".to_owned());
                }
                let length = noise.write_message(&[], &mut buffer).unwrap();
                self.session_id = Some(packet.session_id);
                self.noise = Some(noise);
                return self.reply(&packet.session_id, &buffer[..length]);
            }
            let mut noise = self.noise.take().unwrap();
            let length = noise.read_message(&packet.payload, &mut buffer).unwrap();
            let request = decode_record(&buffer[..length])?;
            let round_trip_id = request
                .value
                .get(1)
                .and_then(Value::bytes)
                .ok_or_else(|| "missing round trip ID".to_owned())?;
            self.transport = Some(noise.into_transport_mode().unwrap());
            let response = record(
                CLIENT_OFFER_RESPONSE,
                &Value::Map(vec![
                    (Value::UInt(3), Value::Bytes(vec![4; 32])),
                    (Value::UInt(4), Value::UInt(2)),
                    (
                        Value::UInt(5),
                        Value::Map(vec![(Value::UInt(2), Value::Text("answer".to_owned()))]),
                    ),
                ]),
            )?;
            let round_trip = record(
                SESSION_ROUND_TRIP,
                &Value::Map(vec![
                    (Value::UInt(1), Value::Bytes(round_trip_id.to_vec())),
                    (Value::UInt(2), Value::Bytes(response)),
                ]),
            )?;
            let length = self
                .transport
                .as_mut()
                .unwrap()
                .write_message(&round_trip, &mut buffer)
                .unwrap();
            self.reply(&packet.session_id, &buffer[..length])
        }
    }

    #[test]
    fn a_mock_broker_answers_a_client_offer() {
        let root = [7u8; 32];
        let mut secret = [9u8; 32];
        secret[0] &= 0xf8;
        secret[31] &= 127;
        secret[31] |= 64;
        let edwards = curve25519_dalek::edwards::EdwardsPoint::mul_base(
            &curve25519_dalek::scalar::Scalar::from_bytes_mod_order(secret),
        );
        let broker = Broker {
            public_key: ferrox_core::b64::encode(&edwards.compress().to_bytes()),
            root_secret: ferrox_core::b64::encode(&root),
        };
        let mock = MockBroker::new(root, secret);
        let mut client = Client::new(broker, Box::new(mock), [5u8; 32]).unwrap();
        let offer = client
            .client_offer(
                &sample_destination(),
                &[[9u8; 32]],
                &[],
                "v=0\r\n",
                &Metrics::new(Value::Map(vec![])),
            )
            .unwrap();
        assert_eq!(offer.answer_sdp, "answer");
        assert_eq!(offer.connection_id, vec![4; 32]);
        assert_eq!(offer.protocol_version, 2);
    }

    #[test]
    fn offer_response_reads_every_answer_flag() {
        let value = Value::Map(vec![
            (Value::UInt(1), Value::Bool(true)),
            (Value::UInt(2), Value::Bool(true)),
            (Value::UInt(3), Value::Bytes(vec![4; 32])),
            (Value::UInt(4), Value::UInt(2)),
            (
                Value::UInt(5),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(1)),
                    (Value::UInt(2), Value::Text("answer".to_owned())),
                ]),
            ),
            (Value::UInt(6), Value::Bytes(vec![8; 8])),
            (Value::UInt(7), Value::Bool(true)),
        ]);
        let offer = parse_offer(&value);
        assert!(offer.limited && offer.no_match && offer.must_upgrade);
        assert_eq!(offer.connection_id, vec![4; 32]);
        assert_eq!(offer.answer_sdp, "answer");
        assert_eq!(offer.relay_packet_to_server, vec![8; 8]);
        assert_eq!(offer.protocol_version, 2);
    }
}
