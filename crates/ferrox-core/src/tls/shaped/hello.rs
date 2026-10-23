// The shaped ClientHello: the pinned parrot's cipher list, extension order and bodies,
// with the GREASE, key shares, ECH cover and padding a real browser draws per connection.
use super::keys::{self, Share};
use super::{Body, Profile, GREASE};
use crate::tls::TlsError;

const TLS12: u16 = 0x0303;
const PAD: u16 = 0x0015;
const ALPN: u16 = 0x0010;

/// A built hello and everything a retry has to keep: the same random, session id,
/// GREASE, ECH cover and ALPN, with only the key share the server asked for.
pub(crate) struct Hello {
    pub msg: Vec<u8>,
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    pub shares: Vec<Share>,
    profile: &'static Profile,
    grease: [u16; 5],
    alpn: Option<Vec<Vec<u8>>>,
    sni: Option<String>,
    ech: Option<Vec<u8>>,
    /// A fixture build: fixed entropy, table order, and a fixed ECH payload length.
    canonical: bool,
}

impl Hello {
    pub(crate) fn build(
        profile: &'static Profile,
        server_name: &str,
        alpn: &[Vec<u8>],
        websocket: bool,
    ) -> Result<Self, TlsError> {
        let mut random = [0u8; 32];
        let mut session_id = [0u8; 32];
        let mut grease_bytes = [0u8; 10];
        getrandom::fill(&mut random).map_err(entropy)?;
        getrandom::fill(&mut session_id).map_err(entropy)?;
        getrandom::fill(&mut grease_bytes).map_err(entropy)?;
        let mut grease = [0u16; 5];
        for (slot, pair) in grease.iter_mut().zip(grease_bytes.chunks_exact(2)) {
            *slot = u16::from_le_bytes([pair[0], pair[1]]);
        }
        // uTLS moves the second extension off the first when the two draws collide.
        if grease_value(&grease, 2) == grease_value(&grease, 3) {
            grease[3] ^= 0x1010;
        }
        let (groups, reuse) = share_spec(profile);
        let shares = keys::generate(groups, reuse).map_err(TlsError::Other)?;
        let mut hello = Self {
            msg: Vec::new(),
            random,
            session_id,
            shares,
            profile,
            grease,
            alpn: alpn_override(alpn, websocket),
            sni: sni_name(server_name).map(str::to_owned),
            ech: ech_body(profile, false),
            canonical: false,
        };
        hello.msg = hello.encode(None);
        Ok(hello)
    }

    /// The second hello a `HelloRetryRequest` asks for: one fresh share for the group
    /// the server named, and its cookie echoed when one came.
    pub(crate) fn retry(&self, group: u16, cookie: Option<&[u8]>) -> Result<Self, TlsError> {
        let shares = keys::generate(&[group], false).map_err(TlsError::Other)?;
        let msg = self.encode_with(&shares, cookie);
        Ok(Self {
            msg,
            random: self.random,
            session_id: self.session_id,
            shares,
            profile: self.profile,
            grease: self.grease,
            alpn: self.alpn.clone(),
            sni: self.sni.clone(),
            ech: self.ech.clone(),
            canonical: self.canonical,
        })
    }

    /// The X25519 secret a REALITY auth key is built from, in the order the server reads.
    pub(crate) fn auth_secret(&self) -> Option<[u8; 32]> {
        let plain = self
            .shares
            .iter()
            .find(|share| share.group == keys::X25519)
            .and_then(Share::auth_secret);
        plain.or_else(|| {
            self.shares
                .iter()
                .find(|share| {
                    matches!(
                        share.group,
                        keys::X25519_MLKEM768 | keys::X25519_MLKEM768_DRAFT
                    )
                })
                .and_then(Share::auth_secret)
        })
    }

    /// The public share this hello carries for a group, before `agree` consumes it.
    pub(crate) fn share_public(&self, group: u16) -> Option<&[u8]> {
        self.shares
            .iter()
            .find(|share| share.group == group)
            .map(|share| share.data.as_slice())
    }

    /// The secret agreement for the group the server selected, consuming that share.
    pub(crate) fn agree(&mut self, group: u16, peer: &[u8]) -> Result<Vec<u8>, TlsError> {
        let at = self
            .shares
            .iter()
            .position(|share| share.group == group)
            .ok_or_else(|| {
                TlsError::Other(format!("server selected an unoffered group {group:#06x}"))
            })?;
        self.shares
            .remove(at)
            .agree(peer)
            .map_err(TlsError::Other)
    }

    /// The ALPN protocols this hello offers, so a server's pick can be checked against them.
    pub(crate) fn alpn_offered(&self) -> Vec<Vec<u8>> {
        if let Some(list) = &self.alpn {
            return list.clone();
        }
        for ext in self.profile.exts {
            if let Body::Alpn(body) = &ext.body {
                return parse_alpn(body);
            }
        }
        Vec::new()
    }

    /// The 16-byte sealed session id replaces the random one in place, at the
    /// handshake message's fixed session-id offset (4 header + 2 version + 32 random + 1).
    pub(crate) fn seal_session(&mut self, sealed: [u8; 32]) {
        self.session_id = sealed;
        self.msg[39..71].copy_from_slice(&sealed);
    }

    /// Clears the session id so the REALITY seal covers an all-zero id, as xray zeroes it.
    pub(crate) fn zero_session(&mut self) {
        self.session_id = [0u8; 32];
        self.msg[39..71].fill(0);
    }

    fn encode(&self, cookie: Option<&[u8]>) -> Vec<u8> {
        self.encode_with(&self.shares, cookie)
    }

    fn encode_with(&self, shares: &[Share], cookie: Option<&[u8]>) -> Vec<u8> {
        let mut entries: Vec<Entry> = Vec::with_capacity(self.profile.exts.len() + 1);
        let mut grease_exts = 0usize;
        for ext in self.profile.exts {
            let entry = match &ext.body {
                Body::Grease => {
                    let slot = grease_exts.min(1);
                    grease_exts += 1;
                    Entry {
                        kind: grease_value(&self.grease, 2 + slot),
                        body: if slot == 0 { Vec::new() } else { vec![0] },
                        invariant: true,
                    }
                }
                Body::Sni => match &self.sni {
                    Some(name) => Entry {
                        kind: 0x0000,
                        body: sni_body(name),
                        invariant: false,
                    },
                    None => continue,
                },
                Body::Pad => Entry {
                    kind: PAD,
                    body: Vec::new(),
                    invariant: true,
                },
                Body::Groups(groups) => {
                    let values: Vec<u16> = groups
                        .iter()
                        .map(|&g| grease_or(g, &self.grease, 1))
                        .collect();
                    Entry {
                        kind: 0x000a,
                        body: uint16_list(&values),
                        invariant: false,
                    }
                }
                Body::Sigalgs(values) => Entry {
                    kind: 0x000d,
                    body: uint16_list(values),
                    invariant: false,
                },
                Body::Alpn(_) => {
                    let body = match &self.alpn {
                        Some(list) => alpn_body(list),
                        None => alpn_table_body(ext),
                    };
                    Entry {
                        kind: ALPN,
                        body,
                        invariant: false,
                    }
                }
                Body::Versions(values) => {
                    let values: Vec<u16> = values
                        .iter()
                        .map(|&v| grease_or(v, &self.grease, 4))
                        .collect();
                    Entry {
                        kind: 0x002b,
                        body: uint8_list(&values),
                        invariant: false,
                    }
                }
                Body::KeyShare { .. } => {
                    if shares.is_empty() {
                        continue;
                    }
                    Entry {
                        kind: 0x0033,
                        body: key_share_body(shares),
                        invariant: false,
                    }
                }
                Body::Ech { .. } => match &self.ech {
                    Some(body) => Entry {
                        kind: 0xfe0d,
                        body: body.clone(),
                        invariant: false,
                    },
                    None => continue,
                },
                Body::Raw(body) => Entry {
                    kind: ext.kind,
                    body: body.to_vec(),
                    invariant: false,
                },
            };
            entries.push(entry);
        }
        if let Some(cookie) = cookie {
            let mut body = Vec::with_capacity(cookie.len() + 2);
            body.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
            body.extend_from_slice(cookie);
            let at = entries.len().saturating_sub(1);
            entries.insert(
                at,
                Entry {
                    kind: 0x002c,
                    body,
                    invariant: false,
                },
            );
        }

        let mut cipher_values: Vec<u16> = self
            .profile
            .ciphers
            .iter()
            .map(|&c| grease_or(c, &self.grease, 0))
            .collect();

        if self.profile.shuffle && !self.canonical {
            shuffle(&mut entries);
        }

        // xray appends the forced ALPN after the preset's extensions, and patches it in place when the preset carries one.
        if let Some(list) = &self.alpn {
            if !entries.iter().any(|entry| entry.kind == ALPN) {
                entries.push(Entry {
                    kind: ALPN,
                    body: alpn_body(list),
                    invariant: true,
                });
            }
        }

        let header = 2 + 32 + 1 + self.session_id.len() + 2 + 2 * cipher_values.len() + 1 + 1;
        let unpadded = header
            + 4
            + entries
                .iter()
                .filter(|entry| entry.kind != PAD)
                .map(|entry| 4 + entry.body.len())
                .sum::<usize>()
            + 2;
        let pad = boring_padding(unpadded);
        entries.retain(|entry| entry.kind != PAD || pad.is_some());
        if let (Some(len), Some(entry)) = (pad, entries.iter_mut().find(|entry| entry.kind == PAD)) {
            entry.body = vec![0; len];
        }

        let ext_len: usize = entries.iter().map(|entry| 4 + entry.body.len()).sum();
        let mut body = Vec::with_capacity(unpadded + ext_len);
        body.extend_from_slice(&TLS12.to_be_bytes());
        body.extend_from_slice(&self.random);
        body.push(self.session_id.len() as u8);
        body.extend_from_slice(&self.session_id);
        body.extend_from_slice(&(2 * cipher_values.len() as u16).to_be_bytes());
        for cipher in cipher_values.drain(..) {
            body.extend_from_slice(&cipher.to_be_bytes());
        }
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(ext_len as u16).to_be_bytes());
        for entry in &entries {
            body.extend_from_slice(&entry.kind.to_be_bytes());
            body.extend_from_slice(&(entry.body.len() as u16).to_be_bytes());
            body.extend_from_slice(&entry.body);
        }
        let mut msg = Vec::with_capacity(body.len() + 4);
        msg.push(1);
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        msg
    }

    /// The table order as a canonical hello: zero random, session id, GREASE
    /// draws and share material, so a fixture can name every wire byte.
    #[cfg(test)]
    pub(crate) fn canonical(profile: &'static Profile, server_name: &str) -> Self {
        let (groups, _) = share_spec(profile);
        let mut hello = Self {
            msg: Vec::new(),
            random: [0u8; 32],
            session_id: [0u8; 32],
            shares: keys::canonical(groups),
            profile,
            grease: [0; 5],
            alpn: None,
            sni: sni_name(server_name).map(str::to_owned),
            ech: ech_body(profile, true),
            canonical: true,
        };
        hello.msg = hello.encode(None);
        hello
    }
}

struct Entry {
    kind: u16,
    body: Vec<u8>,
    invariant: bool,
}

fn share_spec(profile: &Profile) -> (&'static [u16], bool) {
    for ext in profile.exts {
        if let Body::KeyShare { groups, reuse } = &ext.body {
            return (groups, *reuse);
        }
    }
    (&[], false)
}

fn grease_or(value: u16, grease: &[u16; 5], slot: usize) -> u16 {
    if value == GREASE {
        grease_value(grease, slot)
    } else {
        value
    }
}

fn grease_value(grease: &[u16; 5], slot: usize) -> u16 {
    let mut byte = (grease[slot] & 0x00f0) as u8 | 0x0a;
    if byte == 0 {
        byte = 0x0a;
    }
    let value = u16::from(byte);
    value | (value << 8)
}

fn uint16_list(values: &[u16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + values.len() * 2);
    body.extend_from_slice(&((values.len() * 2) as u16).to_be_bytes());
    for value in values {
        body.extend_from_slice(&value.to_be_bytes());
    }
    body
}

fn uint8_list(values: &[u16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + values.len() * 2);
    body.push((values.len() * 2) as u8);
    for value in values {
        body.extend_from_slice(&value.to_be_bytes());
    }
    body
}

fn key_share_body(shares: &[Share]) -> Vec<u8> {
    let total: usize = shares.iter().map(|share| 4 + share.data.len()).sum();
    let mut body = Vec::with_capacity(2 + total);
    body.extend_from_slice(&(total as u16).to_be_bytes());
    for share in shares {
        body.extend_from_slice(&share.group.to_be_bytes());
        body.extend_from_slice(&(share.data.len() as u16).to_be_bytes());
        body.extend_from_slice(&share.data);
    }
    body
}

fn sni_body(name: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(5 + name.len());
    body.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(name.len() as u16).to_be_bytes());
    body.extend_from_slice(name.as_bytes());
    body
}

fn sni_name(name: &str) -> Option<&str> {
    let mut host = name;
    if host.len() > 1 && host.starts_with('[') && host.ends_with(']') {
        host = &host[1..host.len() - 1];
    }
    if let Some(at) = host.rfind('%') {
        if at > 0 {
            host = &host[..at];
        }
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let name = name.trim_end_matches('.');
    (!name.is_empty()).then_some(name)
}

fn alpn_table_body(ext: &super::Ext) -> Vec<u8> {
    match &ext.body {
        Body::Alpn(body) => body.to_vec(),
        _ => Vec::new(),
    }
}

fn alpn_body(list: &[Vec<u8>]) -> Vec<u8> {
    let protocols: usize = list.iter().map(|proto| proto.len() + 1).sum();
    let mut body = Vec::with_capacity(2 + protocols);
    body.extend_from_slice(&(protocols as u16).to_be_bytes());
    for proto in list {
        body.push(proto.len() as u8);
        body.extend_from_slice(proto);
    }
    body
}

fn parse_alpn(body: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if body.len() < 2 {
        return out;
    }
    let end = 2 + usize::from(u16::from_be_bytes([body[0], body[1]]));
    let mut at = 2;
    while at < end && at < body.len() {
        let len = usize::from(body[at]);
        at += 1;
        if at + len > body.len() {
            break;
        }
        out.push(body[at..at + len].to_vec());
        at += len;
    }
    out
}

/// xray's rule for a WebSocket- or HTTPUpgrade-carried hello: force the outer
/// ALPN to `http/1.1` unless the config named exactly `h2` then `http/1.1`.
/// Every other carrier keeps the parrot's own ALPN list, as uTLS does.
fn alpn_override(alpn: &[Vec<u8>], websocket: bool) -> Option<Vec<Vec<u8>>> {
    if !websocket {
        return None;
    }
    let both = [b"h2".to_vec(), b"http/1.1".to_vec()];
    if alpn == both {
        Some(both.to_vec())
    } else {
        Some(vec![b"http/1.1".to_vec()])
    }
}

/// uTLS's GREASE ECH cover: the picked suite, a random config id, 32 bytes of
/// X25519 encapsulation and a payload one tag longer than a candidate length.
fn ech_body(profile: &Profile, canonical: bool) -> Option<Vec<u8>> {
    let mut spec = None;
    for ext in profile.exts {
        if let Body::Ech { suites, payloads } = &ext.body {
            spec = Some((suites, payloads));
            break;
        }
    }
    let (suites, payloads) = spec?;
    let mut body = Vec::new();
    body.push(0);
    let (suite, config_id, enc, payload_len) = if canonical {
        (suites[0], 0u8, [0u8; 32], 128 + 16)
    } else {
        let mut pick = [0u8; 5];
        getrandom::fill(&mut pick).ok()?;
        let suite = suites[usize::from(u16::from_le_bytes([pick[0], pick[1]])) % suites.len()];
        let config_id = pick[2];
        let len = usize::from(payloads[usize::from(u16::from_le_bytes([pick[3], pick[4]])) % payloads.len()])
            + 16;
        (suite, config_id, enc_random(), len)
    };
    let suite = suite.to_be_bytes();
    body.extend_from_slice(&suite[..2]);
    body.extend_from_slice(&suite[2..]);
    body.push(config_id);
    body.extend_from_slice(&(enc.len() as u16).to_be_bytes());
    body.extend_from_slice(&enc);
    body.extend_from_slice(&(payload_len as u16).to_be_bytes());
    if payload_len > 0 {
        let mut payload = vec![0u8; payload_len];
        if !canonical {
            getrandom::fill(&mut payload).ok()?;
        }
        body.extend_from_slice(&payload);
    }
    Some(body)
}

fn enc_random() -> [u8; 32] {
    let mut enc = [0u8; 32];
    if getrandom::fill(&mut enc).is_err() {
        enc.fill(0);
    }
    enc
}

/// Chrome's positional shuffle: only the extensions between the fixed GREASE and
/// padding ends move, so the invariant ends stay where the browser puts them.
fn shuffle(entries: &mut [Entry]) {
    let n = entries.len();
    if n < 2 {
        return;
    }
    let mut draws = vec![0u8; 4 * n];
    if getrandom::fill(&mut draws).is_err() {
        return;
    }
    for i in (1..n).rev() {
        let at = 4 * i;
        let pick = usize::from(u16::from_le_bytes([draws[at], draws[at + 1]]));
        let j = pick % (i + 1);
        if entries[i].invariant || entries[j].invariant {
            continue;
        }
        entries.swap(i, j);
    }
}

/// BoringSSL's padding: only a hello that lands just past one byte and just short
/// of 512 bytes is padded, to exactly 512.
fn boring_padding(unpadded: usize) -> Option<usize> {
    if unpadded > 0xff && unpadded < 0x200 {
        let len = 0x200 - unpadded;
        Some(if len >= 5 { len - 4 } else { 1 })
    } else {
        None
    }
}

fn entropy(error: getrandom::Error) -> TlsError {
    TlsError::Other(format!("no entropy: {error}"))
}
