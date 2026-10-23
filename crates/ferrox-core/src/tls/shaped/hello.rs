// The shaped ClientHello: a pinned parrot's ciphers, extension order and bodies, with the GREASE, key shares, ECH cover and padding a browser draws.
use super::keys::{self, Share};
use super::{Body, Ext, Profile, GREASE};
use crate::tls::TlsError;

/// The version this hello's legacy field names, which a static-RSA premaster repeats.
pub(super) const TLS12: u16 = 0x0303;
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
        for (slot, pair) in grease.iter_mut().zip(grease_bytes.as_chunks::<2>().0) {
            *slot = u16::from_le_bytes(*pair);
        }
        let grease = distinct_grease(grease);
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

    /// The ECDHE point and secret for a TLS 1.2 `ClientKeyExchange` on a curve the hello committed
    /// no `key_share` to, drawn only when that curve is in the hello's advertised groups.
    pub(crate) fn ephemeral(
        &self,
        group: u16,
        peer: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        let advertised = self
            .profile
            .exts
            .iter()
            .any(|ext| matches!(&ext.body, Body::Groups(groups) if groups.contains(&group)));
        if !advertised {
            return Err(TlsError::NoSharedCipher);
        }
        let mut pool = keys::generate(&[group], false).map_err(TlsError::Other)?;
        let mut share = pool.pop().expect("one group");
        let point = std::mem::take(&mut share.data);
        let shared = share.agree(peer).map_err(TlsError::Other)?;
        Ok((point, shared))
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
        self.shares.remove(at).agree(peer).map_err(TlsError::Other)
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

    /// The hello's own length ahead of its extensions: version, random, session id, cipher list
    /// and the one compression method. The padding extension is sized from it, and the message
    /// is reserved to it, so neither pass guesses at the width.
    fn fixed_len(&self) -> usize {
        2 + 32 + 1 + self.session_id.len() + 2 + 2 * self.profile.ciphers.len() + 1 + 1
    }

    /// Two walks of one body rule and two buffers: the first runs every walk into a width, so the
    /// message's total is known before its first byte, and the second runs the same walks into that
    /// message. No extension body carries a buffer of its own and no body rule is written twice.
    fn encode_with(&self, shares: &[Share], cookie: Option<&[u8]>) -> Vec<u8> {
        let mut entries = self.extension_entries(shares, cookie);
        self.pad_entries(&mut entries);
        let ext_len: usize = entries.iter().map(|entry| 4 + entry.len).sum();
        let body = self.fixed_len() + 2 + ext_len;
        let mut msg = Vec::with_capacity(body + 4);
        msg.push(1);
        msg.extend_from_slice(&(body as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&TLS12.to_be_bytes());
        msg.extend_from_slice(&self.random);
        msg.push(self.session_id.len() as u8);
        msg.extend_from_slice(&self.session_id);
        msg.extend_from_slice(&(2 * self.profile.ciphers.len() as u16).to_be_bytes());
        for &cipher in self.profile.ciphers {
            msg.extend_from_slice(&grease_or(cipher, &self.grease, 0).to_be_bytes());
        }
        msg.extend_from_slice(&[1, 0]);
        msg.extend_from_slice(&(ext_len as u16).to_be_bytes());
        for entry in &entries {
            msg.extend_from_slice(&entry.kind.to_be_bytes());
            msg.extend_from_slice(&(entry.len as u16).to_be_bytes());
            self.write_body(&entry.source, shares, &mut msg);
        }
        msg
    }

    fn extension_entries<'a>(
        &'a self,
        shares: &[Share],
        cookie: Option<&'a [u8]>,
    ) -> Vec<Entry<'a>> {
        let mut entries: Vec<Entry<'a>> = Vec::with_capacity(self.profile.exts.len() + 1);
        let mut grease_exts = 0usize;
        for ext in self.profile.exts {
            if let Some(entry) = self.entry(ext, shares, &mut grease_exts) {
                entries.push(entry);
            }
        }
        if let Some(cookie) = cookie {
            let at = entries.len().saturating_sub(1);
            let source = Source::Cookie(cookie);
            let len = self.width_of(&source, shares);
            entries.insert(at, Entry::new(0x002c, len, false, source));
        }

        if self.profile.shuffle && !self.canonical {
            shuffle(&mut entries);
        }

        // xray appends the forced ALPN after the preset's extensions, and patches it in place when the preset carries one.
        if let Some(list) = &self.alpn {
            if !entries.iter().any(|entry| entry.kind == ALPN) {
                let source = Source::Alpn(list);
                let len = self.width_of(&source, shares);
                entries.push(Entry::new(ALPN, len, true, source));
            }
        }
        entries
    }

    fn entry(&self, ext: &Ext, shares: &[Share], grease_exts: &mut usize) -> Option<Entry<'_>> {
        let (kind, invariant, source) = match &ext.body {
            Body::Grease => {
                let slot = (*grease_exts).min(1);
                *grease_exts += 1;
                (
                    grease_value(&self.grease, 2 + slot),
                    true,
                    Source::Zeros(slot),
                )
            }
            Body::Sni => (0x0000, false, Source::Name(self.sni.as_deref()?)),
            Body::Pad => (PAD, true, Source::Zeros(0)),
            Body::Groups(groups) => (0x000a, false, Source::Groups(groups)),
            Body::Sigalgs(values) => (0x000d, false, Source::Sigalgs(values)),
            Body::Alpn(table) => (
                ALPN,
                false,
                match &self.alpn {
                    Some(list) => Source::Alpn(list),
                    None => Source::Fixed(table),
                },
            ),
            Body::Versions(values) => (0x002b, false, Source::Versions(values)),
            Body::KeyShare { .. } if shares.is_empty() => return None,
            Body::KeyShare { .. } => (0x0033, false, Source::Shares),
            Body::Ech { .. } => (0xfe0d, false, Source::Fixed(self.ech.as_deref()?)),
            Body::Raw(body) => (ext.kind, false, Source::Fixed(body)),
        };
        let len = self.width_of(&source, shares);
        Some(Entry::new(kind, len, invariant, source))
    }

    /// The width one body walk writes, so the message is reserved to its exact total before the
    /// first byte and the bytes themselves land in the walk that follows.
    fn width_of(&self, source: &Source<'_>, shares: &[Share]) -> usize {
        let mut width = Width(0);
        self.write_body(source, shares, &mut width);
        width.0
    }

    /// The one rule for a body's bytes, run twice. A zeros body names its own count, so the GREASE
    /// draw and the padding length carry through Chrome's shuffle without a second walk's state.
    fn write_body<W: Sink>(&self, source: &Source<'_>, shares: &[Share], out: &mut W) {
        match *source {
            Source::Zeros(count) => out.zeros(count),
            Source::Name(name) => sni_body(out, name),
            Source::Groups(groups) => {
                uint16_list(out, groups, |g| grease_or(g, &self.grease, 1));
            }
            Source::Sigalgs(values) => uint16_list(out, values, |v| v),
            Source::Versions(values) => {
                uint8_list(out, values, |v| grease_or(v, &self.grease, 4));
            }
            Source::Alpn(list) => alpn_body(out, list),
            Source::Fixed(body) => out.put(body),
            Source::Shares => key_share_body(out, shares),
            Source::Cookie(value) => {
                out.put(&(value.len() as u16).to_be_bytes());
                out.put(value);
            }
        }
    }

    fn pad_entries(&self, entries: &mut Vec<Entry<'_>>) {
        let unpadded = self.fixed_len()
            + 4
            + entries
                .iter()
                .filter(|entry| entry.kind != PAD)
                .map(|entry| 4 + entry.len)
                .sum::<usize>()
            + 2;
        let pad = boring_padding(unpadded);
        entries.retain(|entry| entry.kind != PAD || pad.is_some());
        if let Some(len) = pad {
            if let Some(entry) = entries.iter_mut().find(|entry| entry.kind == PAD) {
                entry.source = Source::Zeros(len);
                entry.len = len;
            }
        }
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
            grease: distinct_grease([0; 5]),
            alpn: None,
            sni: sni_name(server_name).map(str::to_owned),
            ech: ech_body(profile, true),
            canonical: true,
        };
        hello.msg = hello.encode(None);
        hello
    }
}

/// One extension's place in the hello: its kind on the wire, the width its body measured, whether
/// Chrome's shuffle may move it, and which bytes the second walk writes into the message.
struct Entry<'a> {
    kind: u16,
    len: usize,
    invariant: bool,
    source: Source<'a>,
}

impl<'a> Entry<'a> {
    fn new(kind: u16, len: usize, invariant: bool, source: Source<'a>) -> Self {
        Self {
            kind,
            len,
            invariant,
            source,
        }
    }
}

/// The bytes behind an entry, resolved from the table: a count of zeros the walk names itself, a
/// value the hello holds, or one of the preset's lists.
enum Source<'a> {
    Zeros(usize),
    Name(&'a str),
    Groups(&'a [u16]),
    Sigalgs(&'a [u16]),
    Versions(&'a [u16]),
    Alpn(&'a [Vec<u8>]),
    Fixed(&'a [u8]),
    Shares,
    Cookie(&'a [u8]),
}

/// Where a body walk puts its bytes: the message, or a width that only adds up what the same walk
/// writes, so no extension needs a buffer before the message has one.
trait Sink {
    fn put(&mut self, bytes: &[u8]);
    fn zeros(&mut self, count: usize);
}

impl Sink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }

    fn zeros(&mut self, count: usize) {
        self.resize(self.len() + count, 0);
    }
}

/// The count a walk writes. Every body is measured by this sink and then written by the message
/// sink, which is why the message can be reserved to its exact total before its first byte.
struct Width(usize);

impl Sink for Width {
    fn put(&mut self, bytes: &[u8]) {
        self.0 += bytes.len();
    }

    fn zeros(&mut self, count: usize) {
        self.0 += count;
    }
}

fn share_spec(profile: &Profile) -> (&'static [u16], bool) {
    for ext in profile.exts {
        if let Body::KeyShare { groups, reuse } = &ext.body {
            return (groups, *reuse);
        }
    }
    (&[], false)
}

/// uTLS moves the second extension off the first when the two draws collide.
fn distinct_grease(mut grease: [u16; 5]) -> [u16; 5] {
    if grease_value(&grease, 2) == grease_value(&grease, 3) {
        grease[3] ^= 0x1010;
    }
    grease
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

fn uint16_list<W: Sink>(out: &mut W, values: &[u16], each: impl Fn(u16) -> u16) {
    out.put(&((values.len() * 2) as u16).to_be_bytes());
    for value in values {
        out.put(&each(*value).to_be_bytes());
    }
}

fn uint8_list<W: Sink>(out: &mut W, values: &[u16], each: impl Fn(u16) -> u16) {
    out.put(&((values.len() * 2) as u8).to_be_bytes());
    for value in values {
        out.put(&each(*value).to_be_bytes());
    }
}

fn key_share_body<W: Sink>(out: &mut W, shares: &[Share]) {
    let total: usize = shares.iter().map(|share| 4 + share.data.len()).sum();
    out.put(&(total as u16).to_be_bytes());
    for share in shares {
        out.put(&share.group.to_be_bytes());
        out.put(&(share.data.len() as u16).to_be_bytes());
        out.put(&share.data);
    }
}

fn sni_body<W: Sink>(out: &mut W, name: &str) {
    out.put(&((name.len() + 3) as u16).to_be_bytes());
    out.zeros(1);
    out.put(&(name.len() as u16).to_be_bytes());
    out.put(name.as_bytes());
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

/// A protocol list as an ALPN body: the list's width, then each name behind its own length byte.
fn alpn_body<W: Sink>(out: &mut W, list: &[Vec<u8>]) {
    let protocols: usize = list.iter().map(|proto| proto.len() + 1).sum();
    out.put(&(protocols as u16).to_be_bytes());
    for proto in list {
        out.put(&[proto.len() as u8]);
        out.put(proto);
    }
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
/// The header and the payload are one buffer reserved to their sum, and the payload
/// is randomised where it lies rather than staged in a zero-filled buffer beside it.
fn ech_body(profile: &Profile, canonical: bool) -> Option<Vec<u8>> {
    let mut spec = None;
    for ext in profile.exts {
        if let Body::Ech { suites, payloads } = &ext.body {
            spec = Some((suites, payloads));
            break;
        }
    }
    let (suites, payloads) = spec?;
    let (suite, config_id, enc, payload_len) = if canonical {
        (suites[0], 0u8, [0u8; 32], usize::from(payloads[0]) + 16)
    } else {
        let mut pick = [0u8; 5];
        getrandom::fill(&mut pick).ok()?;
        let suite = suites[usize::from(u16::from_le_bytes([pick[0], pick[1]])) % suites.len()];
        let config_id = pick[2];
        let len = usize::from(
            payloads[usize::from(u16::from_le_bytes([pick[3], pick[4]])) % payloads.len()],
        ) + 16;
        (suite, config_id, enc_random(), len)
    };
    // 42 = content type, suite and KEM, config id, encapsulation length and bytes, payload length.
    let mut body = Vec::with_capacity(42 + payload_len);
    body.push(0);
    body.extend_from_slice(&suite.to_be_bytes());
    body.push(config_id);
    body.extend_from_slice(&(enc.len() as u16).to_be_bytes());
    body.extend_from_slice(&enc);
    body.extend_from_slice(&(payload_len as u16).to_be_bytes());
    let at = body.len();
    body.resize(at + payload_len, 0);
    if !canonical {
        getrandom::fill(&mut body[at..]).ok()?;
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
fn shuffle(entries: &mut [Entry<'_>]) {
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

/// `BoringSSL`'s padding: only a hello that lands just past one byte and just short
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::shaped::Fingerprint;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(text, "{byte:02x}");
        }
        text
    }

    /// The extension TLVs of a `ClientHello` body, in wire order.
    fn extensions(body: &[u8]) -> Vec<&[u8]> {
        let at = 2 + 32;
        let mut at = at + 1 + usize::from(body[at]);
        let ciphers = usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
        at += 2 + ciphers;
        at += 1 + usize::from(body[at]);
        let total = usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
        at += 2;
        let end = at + total;
        let mut out = Vec::new();
        while at < end {
            let len = usize::from(u16::from_be_bytes([body[at + 2], body[at + 3]]));
            out.push(&body[at..at + 4 + len]);
            at += 4 + len;
        }
        assert_eq!(at, end, "extension vector length");
        out
    }

    fn kind(ext: &[u8]) -> u16 {
        u16::from_be_bytes([ext[0], ext[1]])
    }

    fn invariant(kind: u16) -> bool {
        kind & 0x0f0f == 0x0a0a || kind == 0x0015 || kind == 0x0029
    }

    /// Replay the uTLS oracle: every xray name that shapes a hello must emit the reference's bytes, or its extension multiset plus invariant slots where Chrome shuffles.
    #[test]
    fn oracle_replay_matches_utls() {
        let script = include_str!("../../../../../scripts/utls-oracle/script.txt");
        let expected = include_str!("../../../../../scripts/utls-oracle/expected.txt");
        let cases: Vec<(&str, &str)> = script
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                (fields[0], fields[1])
            })
            .collect();
        let golden: Vec<&str> = expected
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(cases.len(), golden.len(), "script and golden differ");
        let mut seen: Vec<usize> = Vec::new();
        for ((name, id), want) in cases.iter().zip(&golden) {
            let fields: Vec<&str> = want.split_whitespace().collect();
            assert_eq!(fields[1], *name, "golden order");
            let profile = Fingerprint::resolve(name)
                .expect("a preset name resolves")
                .profile()
                .expect("a shaped profile");
            let pointer = std::ptr::from_ref(profile) as usize;
            if !seen.contains(&pointer) {
                seen.push(pointer);
            }
            assert_eq!(profile.shuffle, fields[0] == "SH", "{name} shuffle flag");
            let hello = Hello::canonical(profile, "example.com");
            let body = &hello.msg[4..];
            let exts = extensions(body);
            if fields[0] == "CH" {
                assert_eq!(hex(body), fields[2], "{name} ({id})");
            } else {
                let fixed: Vec<usize> = exts
                    .iter()
                    .enumerate()
                    .filter(|(_, ext)| invariant(kind(ext)))
                    .map(|(at, _)| at)
                    .collect();
                let want_fixed: Vec<usize> = fields[3]
                    .split(',')
                    .map(|at| at.parse().expect("an index"))
                    .collect();
                assert_eq!(fixed, want_fixed, "{name} invariant positions");
                let mut sorted = exts.clone();
                sorted.sort();
                let joined: Vec<u8> = sorted.iter().flat_map(|ext| ext.iter().copied()).collect();
                assert_eq!(hex(&joined), fields[2], "{name} ({id}) extension multiset");
            }
        }
        assert_eq!(cases.len(), 46, "every xray name is covered");
        assert_eq!(seen.len(), 28, "the names resolve to 28 distinct presets");
    }

    /// The hello's own bytes cost one heap buffer, reserved to their exact length before the first
    /// write, beside the one list that orders the extensions: 2 allocations for a Chrome hello,
    /// where a body buffer each cost 18. Every width comes from the same walk that writes the body.
    #[test]
    fn a_shaped_hello_writes_into_one_buffer() {
        let profile = Fingerprint::resolve("chrome")
            .expect("a preset name resolves")
            .profile()
            .expect("a shaped profile");
        let hello = Hello::canonical(profile, "example.com");
        let (msg, counts) = crate::alloc_count::measure(|| hello.encode(None));
        assert_eq!(hex(&msg), hex(&hello.msg), "the replayed bytes");
        assert_eq!(
            msg.len(),
            msg.capacity(),
            "no slack after the exact reserve"
        );
        assert_eq!(
            counts.allocs, 2,
            "one list and one message for the hello: {counts:?}"
        );
    }

    /// A dial's own hello — random draws, Chrome's shuffle, a carrier's forced ALPN and a retry's
    /// cookie — is the walk no golden byte names, and it still closes exactly on the vector it
    /// measured: every width below is the one the same walk wrote its bytes into.
    #[test]
    fn a_shuffled_hello_with_a_cookie_and_a_forced_alpn_stays_exactly_sized() {
        let profile = Fingerprint::resolve("chrome")
            .expect("a preset name resolves")
            .profile()
            .expect("a shaped profile");
        let hello = Hello::build(profile, "example.com", &[b"http/1.1".to_vec()], true)
            .expect("a shaped dial hello");
        let retry = hello
            .retry(keys::X25519, Some(&[7, 6, 5]))
            .expect("a retry hello");
        let exts = extensions(&retry.msg[4..]);
        let cookie = exts
            .iter()
            .find(|ext| kind(ext) == 0x002c)
            .expect("the cookie echoes back");
        assert_eq!(
            cookie[2..],
            [0, 5, 0, 3, 7, 6, 5],
            "the cookie's width beside its bytes"
        );
        let alpn = exts
            .iter()
            .find(|ext| kind(ext) == ALPN)
            .expect("the carrier names its protocol");
        assert_eq!(
            alpn[2..],
            [0, 11, 0, 9, 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'],
            "the forced ALPN's width beside its bytes"
        );
    }

    /// The GREASE ECH cover a dial ships is one buffer reserved to its own length,
    /// where a grown header beside a staged payload cost five.
    #[test]
    fn an_ech_cover_is_written_into_one_buffer() {
        let profile = Fingerprint::resolve("chrome")
            .expect("a preset name resolves")
            .profile()
            .expect("a shaped profile");
        let (cover, counts) = crate::alloc_count::measure(|| ech_body(profile, false));
        let cover = cover.expect("a profile that offers ECH builds a cover");
        assert_eq!(counts.allocs, 1, "one buffer for the cover: {counts:?}");
        assert_eq!(
            counts.zeroed, 0,
            "the payload is filled in place, not staged: {counts:?}"
        );
        assert_eq!(
            cover.len(),
            cover.capacity(),
            "no slack after the exact reserve"
        );
    }
}
