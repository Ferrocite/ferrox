//! Foxy: an account-authenticated CONNECT lane in front of a CDN edge — arithmetic over the lane's inputs only (pass renewal, edge ordering, pinning, refusal backoff); nothing here opens a socket, reads a clock, or prints.

pub mod account;
pub mod catalog;
pub mod connectip;
pub mod flow;
pub mod frames;
pub mod hpack;
pub mod link;
pub mod masque;
pub mod pin;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Rejected(u16),
    /// A refusal that named the target in its own head: the edge is healthy and the pair is valid, and no other edge or fresh token will carry this host.
    BlockedHost(u16),
    Stream,
    Frame,
    Io,
    /// The edge presented a chain this device does not trust. It is a fact about the certificate, not about the moment: no retry changes it, and every carrier on that edge answers it the same way.
    Untrusted,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(status) => write!(f, "edge answered {status}"),
            Self::BlockedHost(status) => write!(f, "edge will not carry this target ({status})"),
            Self::Stream => f.write_str("the edge closed the stream"),
            Self::Frame => f.write_str("the edge sent a frame the carrier cannot read"),
            Self::Io => f.write_str("the carrier io failed"),
            Self::Untrusted => f.write_str("this device does not trust the edge's certificate"),
        }
    }
}

impl std::error::Error for Failure {}

impl From<std::io::Error> for Failure {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

impl From<crate::tls::TlsError> for Failure {
    fn from(error: crate::tls::TlsError) -> Self {
        match error {
            crate::tls::TlsError::BadCertificate(_) => Self::Untrusted,
            _ => Self::Io,
        }
    }
}

#[must_use]
pub fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The peer an edge name already is: a literal address and its port, read straight out of the text — no name built, no buffer taken, no resolver asked. A host that is not a literal answers `None`, so the names that need resolving still reach it.
#[must_use]
pub fn edge_peer(host: &str, port: u16) -> Option<std::net::SocketAddr> {
    Some(std::net::SocketAddr::new(host.parse().ok()?, port))
}

/// The authority an edge's own head carries, which is not what its socket is keyed by: the name, bracketed when it already spells an address, and the port only when it is not the one the scheme implies. A plain name at the default port is the caller's text, borrowed, so a lane open there spells its authority without taking a buffer.
#[must_use]
pub fn edge_authority(host: &str, port: u16) -> std::borrow::Cow<'_, str> {
    let address = host.contains(':');
    if port == 443 {
        return if address {
            std::borrow::Cow::Owned(format!("[{host}]"))
        } else {
            std::borrow::Cow::Borrowed(host)
        };
    }
    std::borrow::Cow::Owned(if address {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

/// The `Proxy-Authorization` line a pass is presented with: the scheme rides the literal because the record lane's gather stack holds seven runs, and a scheme coded into the value would need an eighth.
pub const BEARER_HEAD: &[u8] = b"\r\nProxy-Authorization: Bearer ";

/// HTTP/1.1 CONNECT, the one carrier an account's edge is certain to speak: the pieces in wire order, so the writer gathers them into one record instead of building a buffer to hold the request first.
#[must_use]
pub fn connect_request<'a>(
    target: &'a str,
    authorization_head: &'static [u8],
    credential: &'a str,
) -> [&'a [u8]; 7] {
    [
        b"CONNECT ",
        target.as_bytes(),
        b" HTTP/1.1\r\nHost: ",
        target.as_bytes(),
        authorization_head,
        credential.as_bytes(),
        b"\r\n\r\n",
    ]
}

/// Where the head ends: the offset of the empty line that closes an HTTP/1.1 answer, or `None` while it has not arrived. The lane walks a window at a time and asks this before it reads again, so the delimiter rule lives in one place.
///
/// One word at a time: a SWAR pass marks the `\n` lanes of each eight-byte block and only the byte after a marked `\n` is checked against the whole terminator. Bit-identical to `head.windows(4).position(|w| w == b"\r\n\r\n")` — which compares four bytes at every offset — but this reads eight bytes per load and skips the ~255/256 of offsets that hold no `\n`, doing the four-byte verify only at a real candidate. Portable integer code: no target feature, no unsafe. It is the tree's one terminator scan, and every reader that ends a head at `\r\n\r\n` — this lane's window walk, the `httpUpgrade` and xHTTP head readers — reaches it rather than reopening the byte loop.
#[must_use]
pub fn head_end(head: &[u8]) -> Option<usize> {
    const CR: u8 = b'\r';
    const LF: u8 = b'\n';
    const SPREAD: u64 = 0x0101_0101_0101_0101;
    const HIGH: u64 = 0x8080_8080_8080_8080;
    let n = head.len();
    // A terminator needs four bytes, so the latest start that can still hold one.
    if n < 4 {
        return None;
    }
    let last = n - 4;
    let want_lf = (LF as u64).wrapping_mul(SPREAD);
    let mut word = 0usize;
    while word + 8 <= n {
        let block = u64::from_le_bytes(
            head[word..word + 8]
                .try_into()
                .expect("one eight-byte block"),
        );
        let x = block ^ want_lf;
        // A zero byte of `x` is a `\n` lane; isolate those lanes and walk them low to high.
        let mut lf = x.wrapping_sub(SPREAD) & !x & HIGH;
        while lf != 0 {
            let a = word + lf.trailing_zeros() as usize / 8;
            // The terminator's first `\n` sits one byte past its start (`a >= 1`), which must still hold four bytes (`a - 1 <= last`).
            if a >= 1 && a - 1 <= last {
                let s = a - 1;
                if head[s] == CR && head[s + 2] == CR && head[s + 3] == LF {
                    return Some(s);
                }
            }
            lf &= lf - 1;
        }
        word += 8;
    }
    // Starts past the last whole block, and the one whose first `\n` fell on the block boundary, are too few for SWAR to pay: check them as four-byte windows.
    let mut s = if word == 0 { 0 } else { word - 1 };
    while s <= last {
        if head[s..s + 4] == [CR, LF, CR, LF] {
            return Some(s);
        }
        s += 1;
    }
    None
}

pub fn connect_status(head: &[u8]) -> Result<u16, Failure> {
    let line_end = head_end(head).ok_or(Failure::Frame)?;
    let line = &head[..line_end];
    let mut parts = line.split(|byte| *byte == b' ');
    let version = parts.next().ok_or(Failure::Frame)?;
    if !version.starts_with(b"HTTP/1.") {
        return Err(Failure::Frame);
    }
    let status = parts.next().ok_or(Failure::Frame)?;
    let status = std::str::from_utf8(status).map_err(|_| Failure::Frame)?;
    status.parse::<u16>().map_err(|_| Failure::Frame)
}

/// One field of an answer's head, read where the octets landed: a name matches case-insensitively as `connect_status` reads the code above it, and the value comes back borrowed with the one space after the colon gone. A field the answer does not carry is `None`, and a line with no colon is not a field. Cold-path only — an answer that opened the tunnel never has its head walked twice.
#[must_use]
pub fn head_field<'a>(head: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let end = head_end(head)?;
    let mut lines = head[..end].split(|byte| *byte == b'\n');
    lines.next()?;
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        // A slice has no `split_once` on this toolchain, and the separator is one byte to find.
        let Some(at) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        if line[..at].eq_ignore_ascii_case(name) {
            let value = &line[at + 1..];
            return Some(value.strip_prefix(b" ").unwrap_or(value));
        }
    }
    None
}

/// Half the remaining life, brought forward by a safety margin so a pass is replaced before the edge refuses it, and clamped so a long pass comes back on a clock.
#[must_use]
pub fn renewal_delay(expires_at: Option<u64>, now: u64) -> std::time::Duration {
    const SAFETY: u64 = 30;
    const FLOOR: u64 = 15;
    const CEILING: u64 = 1_800;
    const UNKNOWN: u64 = 240;
    let Some(remaining) = expires_at.map(|at| at.saturating_sub(now)) else {
        return std::time::Duration::from_secs(UNKNOWN);
    };
    let delay = (remaining / 2).min(remaining.saturating_sub(SAFETY));
    std::time::Duration::from_secs(delay.clamp(FLOOR, CEILING))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pass {
    /// The bearer the plane minted, shared rather than copied: a flow's dial clones the pass into every
    /// carrier it tries, and the token is the same bytes each time.
    pub token: std::sync::Arc<str>,
    pub expires_at: Option<u64>,
    pub quota_remaining: Option<u64>,
    pub quota_reset: Option<u64>,
    /// The allowance the plane grants, when it names one: the ceiling the remaining bytes are counted
    /// against, and the only way to tell a metered account from an unmetered one. `None` is not zero —
    /// a plane that names no ceiling has named no ceiling, not an empty one.
    pub quota_limit: Option<u64>,
}

impl Pass {
    #[must_use]
    pub fn renews_in(&self, now: u64) -> std::time::Duration {
        renewal_delay(self.expires_at, now)
    }

    /// The traffic allowance the plane named, in the one shape a caller prints: the bytes left in the
    /// largest unit that keeps a digit, what it is left of when the plane named a ceiling, and when the
    /// bytes come back. `None` when the plane said nothing, which is not zero — an account whose headers
    /// name no allowance is not an account with nothing left.
    #[must_use]
    pub fn allowance_line(&self) -> Option<String> {
        let left = self.quota_remaining?;
        let mut line = allowance_bytes(left);
        if let Some(limit) = self.quota_limit {
            line.push_str(" of ");
            line.push_str(&allowance_bytes(limit));
        }
        if let Some(reset) = self.quota_reset {
            line.push_str(", resets in ");
            line.push_str(&allowance_clock(reset));
        }
        Some(line)
    }
}

/// Bytes in the largest unit that keeps a digit: integer arithmetic throughout, because a quota is a
/// count of bytes and a float here is a rounding bug waiting for an account at 1023 MiB.
fn allowance_bytes(bytes: u64) -> String {
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    const KIB: u64 = 1 << 10;
    if bytes < KIB {
        return format!("{bytes} B");
    }
    if bytes < MIB {
        return format!("{} KiB", bytes / KIB);
    }
    if bytes < GIB {
        return format!("{} MiB", bytes / MIB);
    }
    let tenths = bytes / (GIB / 10);
    format!("{}.{} GiB", tenths / 10, tenths % 10)
}

/// A wait in the two units a person reads it in, and never a decimal: an hour and a minute is what a
/// reset clock means, and the seconds under it are noise a caller cannot act on.
fn allowance_clock(seconds: u64) -> String {
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{seconds}s")
    }
}

/// The pass itself is the problem, so a different edge answers the same way.
#[must_use]
pub fn pass_is_rejected(status: u16) -> bool {
    matches!(status, 401 | 403 | 407)
}

/// This target is refused at the edge, so a second attempt costs a round trip to learn the same thing.
#[must_use]
pub fn target_is_unreachable(status: u16) -> bool {
    matches!(status, 502..=504)
}

#[must_use]
pub fn refusal_backoff(strikes: u32) -> std::time::Duration {
    const BASE: u64 = 30;
    const CAP: u64 = 600;
    std::time::Duration::from_secs((BASE << strikes.saturating_sub(1).min(16)).min(CAP))
}

/// Remembers the targets an edge has declined, so the next flow to one is answered locally instead of paying a round trip for the same status.
#[derive(Debug)]
pub struct Refusals {
    entries: std::collections::HashMap<String, u64>,
    cap: usize,
}

impl Refusals {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            cap: cap.max(1),
        }
    }

    pub fn remember(&mut self, key: &str, until: u64) {
        if self.entries.len() >= self.cap && !self.entries.contains_key(key) {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, until)| **until)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(key.to_owned(), until);
    }

    #[must_use]
    pub fn blocked(&self, key: &str, now: u64) -> bool {
        self.entries.get(key).is_some_and(|until| *until > now)
    }

    pub fn clear(&mut self, key: &str) {
        self.entries.remove(key);
    }
}

/// A tunnel that stayed up this long proves its edge good, so its end clears the streak counted against it; only tunnels that end sooner, one after another, rest the edge.
pub const TUNNEL_STAYED_UP: std::time::Duration = std::time::Duration::from_secs(300);

/// How many quick tunnel ends in a row take an edge out of the dial order.
pub const EDGE_REST_STRIKES: u32 = 2;

/// How long a rested edge stays out of the order, on the assumption it was the edge and not the moment.
pub const EDGE_REST: std::time::Duration = std::time::Duration::from_secs(300);

/// The quick-end streak after one more tunnel end that `lasted`: a tunnel that stayed up resets it to none, a shorter one extends it by one.
#[must_use]
pub fn count_tunnel_end(in_a_row: u32, lasted: std::time::Duration) -> u32 {
    if lasted >= TUNNEL_STAYED_UP {
        0
    } else {
        in_a_row.saturating_add(1)
    }
}

/// The edges whose tunnels kept ending soon: each one's quick-end streak and, once the streak reached [`EDGE_REST_STRIKES`], until when the edge is out of the dial order. A check that only proves an edge answers keeps dialing one whose tunnel dies on arrival, as on an exit the edge refuses; this rests it so the next flow asks a different one.
#[derive(Debug)]
pub struct EdgeStrikes {
    entries: std::collections::HashMap<String, (u32, u64)>,
    cap: usize,
}

impl EdgeStrikes {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            cap: cap.max(1),
        }
    }

    /// Whether the edge is rested at `now`.
    #[must_use]
    pub fn resting(&self, key: &str, now: u64) -> bool {
        self.entries.get(key).is_some_and(|&(_, until)| until > now)
    }

    /// Records a tunnel through `key` that ended after lasting `lasted`, at `now`. A tunnel that stayed up clears the streak and frees the entry; a short one that completes the strikes rests the edge, otherwise it only bumps the streak.
    pub fn note_end(&mut self, key: &str, lasted: std::time::Duration, now: u64) {
        let next = count_tunnel_end(self.entries.get(key).map_or(0, |&(count, _)| count), lasted);
        if next == 0 {
            self.entries.remove(key);
            return;
        }
        let entry = next >= EDGE_REST_STRIKES;
        if entry && !self.entries.contains_key(key) && self.entries.len() >= self.cap {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, &(_, until))| until)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        let until = if entry {
            now.saturating_add(EDGE_REST.as_secs())
        } else {
            0
        };
        self.entries.insert(key.to_owned(), (next, until));
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Candidate {
    pub host: String,
    pub port: u16,
    pub country: String,
    pub city: String,
}

impl Candidate {
    #[must_use]
    pub fn authority(&self) -> String {
        authority(&self.host, self.port)
    }
}

#[must_use]
pub fn candidates_for_country(candidates: &[Candidate], country: &str) -> Vec<Candidate> {
    candidates
        .iter()
        .filter(|candidate| candidate.country.eq_ignore_ascii_case(country))
        .cloned()
        .collect()
}

/// Stored edge first when it is in the pinned country, then that country's listed edges in order, one alternate more than the last.
#[must_use]
pub fn dial_order(
    candidates: &[Candidate],
    country: &str,
    stored: Option<&Candidate>,
    max_alternates: usize,
) -> Vec<Candidate> {
    let mut order: Vec<Candidate> = Vec::new();
    if let Some(stored) = stored.filter(|edge| edge.country.eq_ignore_ascii_case(country)) {
        order.push(stored.clone());
    }
    for edge in candidates {
        if order.len() > max_alternates {
            break;
        }
        if edge.country.eq_ignore_ascii_case(country) && !order.contains(edge) {
            order.push(edge.clone());
        }
    }
    order
}

/// One verdict per failure, not a score: the pass, the tunnel, or the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Target,
    Unauthenticated,
    Session,
}

#[derive(Debug, Default)]
pub struct Health {
    timeouts: std::collections::HashSet<String>,
}

impl Health {
    /// Ten distinct targets that went silent with no success between them is the tunnel; one target that keeps failing is the target.
    pub fn timed_out(&mut self, target: &str) -> Verdict {
        self.timeouts.insert(target.to_owned());
        if self.timeouts.len() >= 10 {
            Verdict::Session
        } else {
            Verdict::Target
        }
    }

    pub fn status(&mut self, status: u16) -> Verdict {
        if pass_is_rejected(status) {
            self.timeouts.clear();
            Verdict::Unauthenticated
        } else {
            Verdict::Target
        }
    }

    pub fn succeeded(&mut self) {
        self.timeouts.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refused chain is the one TLS failure a caller can act on, so the mapping keeps its name; every other TLS failure stays a moment about the connection.
    #[test]
    fn a_refused_chain_is_untrusted_and_every_other_tls_failure_is_a_moment() {
        for (error, want) in [
            (
                crate::tls::TlsError::BadCertificate("UnknownIssuer".to_owned()),
                Failure::Untrusted,
            ),
            (crate::tls::TlsError::Timeout, Failure::Io),
            (crate::tls::TlsError::Closed, Failure::Io),
            (crate::tls::TlsError::NoSharedCipher, Failure::Io),
            (
                crate::tls::TlsError::Other("peer misbehaved".to_owned()),
                Failure::Io,
            ),
        ] {
            assert_eq!(Failure::from(error), want, "{want}");
        }
        assert_eq!(
            Failure::Untrusted.to_string(),
            "this device does not trust the edge's certificate"
        );
    }

    /// The allowance a person reads: the bytes in the largest unit that keeps a digit, and the reset
    /// clock in two units. Integer arithmetic, so a quota that lands on a boundary is not rounded into
    /// the wrong unit, and no headers is no line rather than a zero.
    #[test]
    fn the_allowance_is_the_bytes_left_and_when_they_return() {
        let pass = |left: Option<u64>, reset: Option<u64>| Pass {
            token: std::sync::Arc::from(""),
            expires_at: None,
            quota_remaining: left,
            quota_reset: reset,
            quota_limit: None,
        };
        assert_eq!(
            pass(Some(4_294_967_296), Some(3_600)).allowance_line(),
            Some("4.0 GiB, resets in 1h 0m".to_owned())
        );
        assert_eq!(
            pass(Some(1_610_612_736), None).allowance_line(),
            Some("1.5 GiB".to_owned()),
            "a half gibibyte is a tenth, not a truncation"
        );
        assert_eq!(
            pass(Some((1 << 30) - 1), Some(90)).allowance_line(),
            Some("1023 MiB, resets in 1m".to_owned()),
            "one byte under a gibibyte is still mebibytes"
        );
        assert_eq!(
            pass(Some(1_048_575), Some(45)).allowance_line(),
            Some("1023 KiB, resets in 45s".to_owned())
        );
        assert_eq!(
            pass(Some(512), Some(0)).allowance_line(),
            Some("512 B, resets in 0s".to_owned())
        );
        assert_eq!(
            pass(None, Some(3_600)).allowance_line(),
            None,
            "an account the plane said nothing about is not an empty one"
        );
    }

    /// The ceiling the plane named rides with the remainder: what is left, and what it is left of. A
    /// remainder on its own cannot be told from a spent one, and the plane that names a ceiling is
    /// the only one that can say what the remainder is counted against.
    #[test]
    fn the_allowance_names_the_ceiling_it_is_left_of() {
        let pass = |left: Option<u64>, limit: Option<u64>| Pass {
            token: std::sync::Arc::from(""),
            expires_at: None,
            quota_remaining: left,
            quota_reset: None,
            quota_limit: limit,
        };
        assert_eq!(
            pass(Some(4_294_967_296), Some(5_368_709_120)).allowance_line(),
            Some("4.0 GiB of 5.0 GiB".to_owned())
        );
        assert_eq!(
            pass(Some(0), Some(5_368_709_120)).allowance_line(),
            Some("0 B of 5.0 GiB".to_owned()),
            "a spent account says so next to the ceiling it spent"
        );
        assert_eq!(
            pass(Some(4_294_967_296), None).allowance_line(),
            Some("4.0 GiB".to_owned()),
            "a plane that named no ceiling gets no ceiling claimed for it"
        );
    }

    #[test]
    fn an_authority_brackets_ipv6_and_leaves_names_alone() {
        assert_eq!(authority("example.com", 443), "example.com:443");
        assert_eq!(authority("::1", 443), "[::1]:443");
        assert_eq!(authority("2001:db8::1", 8080), "[2001:db8::1]:8080");
    }

    /// A literal edge address is read out of the text it is written in — no name built and no buffer taken, which the window below counts rather than infers — and a host that is not a literal is left for the resolver with a `None`, not a half-read address.
    #[test]
    fn a_literal_edge_address_is_read_without_a_buffer_of_its_own() {
        assert_eq!(
            edge_peer("192.0.2.12", 8443),
            Some("192.0.2.12:8443".parse().expect("address")),
            "the listed address and its port, as one peer"
        );
        assert_eq!(
            edge_peer("2001:db8::1", 443),
            Some("[2001:db8::1]:443".parse().expect("address")),
            "a bare v6 literal is an address, not the ambiguous host:port the old name spelled"
        );
        assert_eq!(
            edge_peer("edge.example", 443),
            None,
            "a name is the resolver's"
        );
        assert_eq!(
            edge_peer("fe80::1%eth0", 443),
            None,
            "a scoped address keeps the answer the resolver gives"
        );
        assert_eq!(edge_peer("", 443), None, "no host is not an address");
        // Both branches, through an input the optimizer cannot fold out of the loop.
        let hosts = ["192.0.2.12", "edge.example"];
        let ((), counts) = crate::alloc_count::measure(|| {
            for at in 0..4096 {
                std::hint::black_box(edge_peer(
                    std::hint::black_box(hosts[at % hosts.len()]),
                    std::hint::black_box(443),
                ));
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "4096 reads of an edge address take no heap at all"
        );
    }

    /// The authority as the edge's head wants it: bracketed when the name is an address, ported only off the default, and the caller's own text when neither applies. The borrow is witnessed by pointer identity, not by bytes — a test that only compares text passes with the copy and without it.
    #[test]
    fn an_edge_authority_brackets_an_address_and_borrows_a_plain_default_port_name() {
        let host = String::from("edge.example");
        let plain = edge_authority(&host, 443);
        assert_eq!(
            plain.as_ptr() as usize - host.as_ptr() as usize,
            0,
            "the authority IS the caller's own bytes, not a copy of them"
        );
        assert_eq!(plain, "edge.example");
        assert_eq!(edge_authority("edge.example", 8443), "edge.example:8443");
        assert_eq!(
            edge_authority("2001:db8::1", 443),
            "[2001:db8::1]",
            "an address is bracketed even with no port to write"
        );
        assert_eq!(edge_authority("2001:db8::1", 8443), "[2001:db8::1]:8443");
        assert_eq!(
            edge_authority("::1", 443),
            "[::1]",
            "the shortest address is still not a bare name"
        );
        // The shape a lane opens on: plain names at the default port, alternating so the call cannot be folded out of the loop. An address at the default port is a buffer this window does not measure, and the page says so.
        let hosts = ["edge.example", "edge2.example"];
        let ((), counts) = crate::alloc_count::measure(|| {
            for at in 0..4096 {
                std::hint::black_box(edge_authority(
                    std::hint::black_box(hosts[at % hosts.len()]),
                    std::hint::black_box(443),
                ));
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "4096 authorities at the default port take no heap at all"
        );
    }

    #[test]
    fn a_connect_request_carries_one_authorization_and_nothing_else() {
        let block = connect_request("example.com:443", BEARER_HEAD, "pass.jwt.value").concat();
        assert_eq!(
            String::from_utf8(block).expect("ascii"),
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Bearer pass.jwt.value\r\n\r\n"
        );
    }

    #[test]
    fn only_a_two_hundred_opens_a_tunnel() {
        assert_eq!(
            connect_status(b"HTTP/1.1 200 Connection established\r\n\r\n"),
            Ok(200)
        );
        assert_eq!(connect_status(b"HTTP/1.1 403 Forbidden\r\n\r\n"), Ok(403));
        assert_eq!(connect_status(b"nonsense"), Err(Failure::Frame));
        assert_eq!(connect_status(b"HTTP/2 200\r\n\r\n"), Err(Failure::Frame));
        assert_eq!(connect_status(b"HTTP/1.1 abc\r\n\r\n"), Err(Failure::Frame));
    }

    /// The lookup a refusal is read with: a name matched whichever way the edge spelled it, the value as it arrived with or without its space, and a marker that only appears inside another field's value is not the field.
    #[test]
    fn head_field_reads_the_names_the_edge_sent() {
        let head =
            b"HTTP/1.1 403 Forbidden\r\nX-Hola-Error: Forbidden Host\r\nConnection: close\r\n\r\n";
        let names: [&[u8]; 4] = [
            b"X-Hola-Error",
            b"x-hola-error",
            b"X-HOLA-ERROR",
            b"x-hoLa-ErRoR",
        ];
        for name in names {
            assert_eq!(
                head_field(head, name),
                Some(&b"Forbidden Host"[..]),
                "the name matches whichever way the edge spelled it: {name:?}"
            );
        }
        assert_eq!(head_field(head, b"Connection"), Some(&b"close"[..]));
        assert_eq!(head_field(head, b"Proxy-Connection"), None);
        assert_eq!(
            head_field(
                b"HTTP/1.1 403 F\r\nX-Hola-Error:Forbidden Host\r\n\r\n",
                b"X-Hola-Error"
            ),
            Some(&b"Forbidden Host"[..]),
            "the space after the colon is the convention, not part of the value"
        );
        assert_eq!(
            head_field(
                b"HTTP/1.1 403 F\r\nNote: X-Hola-Error: Forbidden Host\r\n\r\n",
                b"X-Hola-Error"
            ),
            None,
            "the marker inside another field's value is not this field"
        );
        assert_eq!(
            head_field(
                b"HTTP/1.1 403 F\r\nnot a field\r\nX\r\n\r\n",
                b"X-Hola-Error"
            ),
            None,
            "a line with no colon is skipped, not a stop"
        );
        assert_eq!(
            head_field(
                b"HTTP/1.1 403 F\r\nX-Hola-Error: Forbidden Host\r\n",
                b"X-Hola-Error"
            ),
            None,
            "a head that never reached its blank line has no fields to read"
        );
        // Bytes alone cannot witness the borrow: the offset of the answer inside the caller's own head is what says nothing was staged.
        let found = head_field(head, b"X-Hola-Error").expect("the edge named the host");
        let offset = found.as_ptr() as usize - head.as_ptr() as usize;
        let width = found.len();
        assert!(
            offset + width <= head.len(),
            "the value lies inside the head it was read from: offset {offset}, {width} bytes"
        );
        let ((), counts) = crate::alloc_count::measure(|| {
            for at in 0..4096 {
                std::hint::black_box(head_field(
                    std::hint::black_box(head.as_slice()),
                    std::hint::black_box(names[at % names.len()]),
                ));
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "4096 field reads of an answer's head take no heap at all"
        );
    }

    #[test]
    fn a_pass_comes_back_at_half_its_life_and_never_later_than_the_ceiling() {
        for (expires, now, want) in [
            (Some(1_000_u64), 0_u64, 500_u64),
            (Some(1_000), 400, 300),
            (Some(100), 90, 15),
            (None, 0, 240),
            (Some(1_000_000), 0, 1_800),
            (Some(10), 10, 15),
            (Some(20), 0, 15),
        ] {
            assert_eq!(renewal_delay(expires, now).as_secs(), want, "at {now}");
        }
    }

    #[test]
    fn a_rejected_pass_and_an_unreachable_target_are_different_verdicts() {
        for status in [401, 403, 407] {
            assert!(pass_is_rejected(status), "{status}");
            assert!(!target_is_unreachable(status), "{status}");
        }
        for status in [502, 503, 504] {
            assert!(target_is_unreachable(status), "{status}");
            assert!(!pass_is_rejected(status), "{status}");
        }
    }

    #[test]
    fn a_refusal_backs_off_by_a_power_of_two_and_stops_at_ten_minutes() {
        let backs: Vec<u64> = (0..=9).map(|n| refusal_backoff(n).as_secs()).collect();
        assert_eq!(backs, [30, 30, 60, 120, 240, 480, 600, 600, 600, 600]);
    }

    /// The carrier-probe cache: remember, block inside the window, free at its edge, clear without a trace — so a QUIC-deaf edge is asked once per window and found again at the next.
    #[test]
    fn a_carrier_this_edge_did_not_answer_waits_out_its_window() {
        let mut probe = Refusals::new(8);
        probe.remember("H3 edge.example:2499", 1_000);
        assert!(probe.blocked("H3 edge.example:2499", 10));
        assert!(
            !probe.blocked("H2 edge.example:2499", 10),
            "the other carrier is not what was asked"
        );
        assert!(
            !probe.blocked("H3 edge.example:2499", 1_000),
            "the window ends, and the edge is asked again"
        );
        probe.remember("H3 edge.example:2499", 2_000);
        probe.clear("H3 edge.example:2499");
        assert!(
            !probe.blocked("H3 edge.example:2499", 10),
            "a cleared carrier is asked"
        );
        assert!(probe.entries.is_empty(), "and the map is left empty");
    }

    #[test]
    fn a_refusal_expires_and_the_cache_stays_capped() {
        let mut refusals = Refusals::new(2);
        refusals.remember("a:80", 30);
        refusals.remember("b:80", 40);
        assert!(refusals.blocked("a:80", 10) && refusals.blocked("b:80", 10));
        assert!(!refusals.blocked("a:80", 40));
        refusals.remember("c:80", 90);
        assert_eq!(refusals.entries.len(), 2);
        refusals.clear("c:80");
        assert!(!refusals.blocked("c:80", 10));
    }

    /// One tunnel that stayed up clears the streak a short one built; only ends sooner than the mark, one after another, extend it.
    #[test]
    fn a_tunnel_that_stayed_up_clears_the_quick_end_streak() {
        use std::time::Duration;
        let short = TUNNEL_STAYED_UP.saturating_sub(Duration::from_secs(1));
        assert_eq!(count_tunnel_end(0, short), 1);
        assert_eq!(count_tunnel_end(1, short), 2);
        assert_eq!(count_tunnel_end(5, Duration::from_secs(300)), 0);
        assert_eq!(count_tunnel_end(5, Duration::from_secs(3600)), 0);
    }

    /// Two quick ends rest the edge for the window; a third carrier that carried traffic for its length frees the entry instead of adding a strike.
    #[test]
    fn two_quick_ends_rest_an_edge_and_a_long_tunnel_frees_it() {
        use std::time::Duration;
        let short = TUNNEL_STAYED_UP.saturating_sub(Duration::from_secs(1));
        let mut strikes = EdgeStrikes::new(8);
        strikes.note_end("edge:443", short, 100);
        assert!(
            !strikes.resting("edge:443", 100),
            "one quick end is not yet a reason to rest"
        );
        strikes.note_end("edge:443", short, 100);
        assert!(
            strikes.resting("edge:443", 100),
            "the second quick end in a row rests it"
        );
        assert!(
            !strikes.resting("edge:443", 400),
            "another edge is untouched"
        );
        assert!(
            !strikes.resting("edge:443", 100 + EDGE_REST.as_secs()),
            "the rest expires and the edge is dialed again"
        );
        // A fresh streak that runs long is proof of a good edge, not a third strike.
        strikes.note_end("edge:443", short, 500);
        strikes.note_end("edge:443", Duration::from_secs(300), 500);
        strikes.note_end("edge:443", short, 500);
        assert!(
            !strikes.resting("edge:443", 500),
            "the long tunnel cleared the streak, so one short end is not a rest"
        );
    }

    fn edge(host: &str, country: &str, city: &str) -> Candidate {
        Candidate {
            host: host.to_owned(),
            port: 443,
            country: country.to_owned(),
            city: city.to_owned(),
        }
    }

    #[test]
    fn a_dial_order_stays_in_the_pinned_country_with_the_stored_edge_first() {
        let edges = vec![
            edge("de1", "DE", "berlin"),
            edge("us1", "US", "nyc"),
            edge("de2", "de", "frankfurt"),
            edge("us2", "US", "sf"),
        ];
        let authorities =
            |order: &[Candidate]| order.iter().map(Candidate::authority).collect::<Vec<_>>();
        assert_eq!(
            authorities(&dial_order(&edges, "de", Some(&edges[2]), 2)),
            ["de2:443", "de1:443"]
        );
        assert_eq!(
            authorities(&dial_order(&edges, "DE", Some(&edges[1]), 2)),
            ["de1:443", "de2:443"]
        );
        assert_eq!(authorities(&dial_order(&edges, "us", None, 0)), ["us1:443"]);
        assert_eq!(dial_order(&edges, "fr", None, 3), Vec::new());
    }

    #[test]
    fn ten_distinct_timeouts_without_a_success_condemn_the_tunnel() {
        let mut health = Health::default();
        for index in 0..9 {
            assert_eq!(
                health.timed_out(&format!("t{index}")),
                Verdict::Target,
                "{index}"
            );
        }
        assert_eq!(health.timed_out("t9"), Verdict::Session);
        let mut health = Health::default();
        for _ in 0..99 {
            assert_eq!(health.timed_out("one"), Verdict::Target);
        }
        health.succeeded();
        assert!(health.timeouts.is_empty());
        assert_eq!(health.status(401), Verdict::Unauthenticated);
        assert_eq!(health.status(502), Verdict::Target);
        health.timed_out("two");
        health.status(403);
        assert!(health.timeouts.is_empty());
    }

    #[test]
    fn a_pin_matches_the_certificate_it_was_taken_from() {
        let leaf = certificate(11);
        let pin = pin::spki_pin(&leaf).expect("a pin");
        assert!(pin.starts_with("sha256/") && pin.len() == 7 + 44);
        assert!(pin::Pins::parse([pin.clone()]).holds(&leaf));
        assert!(pin::Pins::default().holds(&leaf));
        let other = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert!(!pin::Pins::parse([other.to_owned()]).holds(&leaf));
        assert!(pin::Pins::parse(["nonsense".to_owned(), pin]).holds(&leaf));
        assert!(pin::Pins::parse(["sha256/".to_owned()]).is_empty());
        assert_eq!(pin::Pins::parse([other.to_owned()]).len(), 1);
    }

    #[test]
    fn a_certificate_that_is_not_a_certificate_yields_no_pin() {
        for der in [
            &[][..],
            &[0x30, 0x00][..],
            &[0x30, 0x03, 0x02, 0x01, 0x01][..],
            &[0x30, 0x7f, 0x30, 0x7d][..],
            &[0x31, 0x00][..],
        ] {
            assert!(pin::spki_pin(der).is_none(), "{der:?}");
        }
    }

    fn certificate(issuer_width: usize) -> Vec<u8> {
        pin::build::certificate(issuer_width).0
    }

    #[test]
    fn a_pass_reports_when_it_wants_to_come_back() {
        let pass = Pass {
            token: std::sync::Arc::from("t"),
            expires_at: Some(1_000),
            quota_remaining: Some(12),
            quota_reset: Some(9),
            quota_limit: None,
        };
        assert_eq!(pass.renews_in(0).as_secs(), 500);
        assert_eq!(pass.quota_remaining, Some(12));
    }

    /// A flow's dial clones the pass into every carrier it tries, and the token is the same bytes each time: the clone shares the token rather than copying it. A byte-level test passes with the copy and without it, so only the pointer can witness that the token was not copied.
    #[test]
    fn a_cloned_pass_shares_its_token_rather_than_copying_it() {
        let pass = Pass {
            token: std::sync::Arc::from("a-token-long-enough-to-stand-alone"),
            expires_at: None,
            quota_remaining: None,
            quota_reset: None,
            quota_limit: None,
        };
        let copied = pass.clone();
        assert_eq!(
            copied.token.as_ptr(),
            pass.token.as_ptr(),
            "the clone shares the token's bytes"
        );
        assert_eq!(copied.token.as_ref(), pass.token.as_ref());
    }

    /// `head_end` is the tree's one terminator scan and the shared head readers reach it in place of `windows(4).position`; this sweep is its oracle. A forged `\r\n\r`, a length that is not a multiple of eight, a terminator whose first `\n` lands exactly on a block boundary, and an all-`\n` body that keeps the verify busy must all return the very same offset — or the same `None` — as the byte-by-byte form it replaced.
    #[test]
    fn the_swar_terminator_scan_is_the_windows_four_scan() {
        // Nested so the sweep takes any start iterator without collecting one first.
        fn sweep(len: usize, starts: impl Iterator<Item = usize>) {
            const CR: u8 = b'\r';
            const LF: u8 = b'\n';
            const NEEDLE: [u8; 4] = [CR, LF, CR, LF];
            let oracle = |buf: &[u8]| buf.windows(4).position(|w| w == b"\r\n\r\n");
            for start in starts {
                // A `\n`-and-`Z` body with no `\r`, so the only terminator is the one planted at `start`.
                if start + 4 <= len {
                    let mut v: Vec<u8> = (0..len)
                        .map(|i| if i % 5 == 0 { LF } else { b'Z' })
                        .collect();
                    v[start..start + 4].copy_from_slice(&NEEDLE);
                    assert_eq!(head_end(&v), oracle(&v), "len {len} at {start}");
                }
            }
            let no_lf: Vec<u8> = vec![CR; len];
            assert_eq!(head_end(&no_lf), oracle(&no_lf), "len {len} no LF");
            let all_lf: Vec<u8> = vec![LF; len];
            assert_eq!(head_end(&all_lf), oracle(&all_lf), "len {len} all LF");
        }

        // Exhaustive over {\r, \n, Z} up to eight bytes: every alignment and near-miss.
        const ALPHABET: [u8; 3] = *b"\r\nZ";
        let mut small = [0u8; 8];
        let oracle = |buf: &[u8]| buf.windows(4).position(|w| w == b"\r\n\r\n");
        for len in 0..=8usize {
            for code in 0..ALPHABET.len().pow(len as u32) {
                let mut rest = code;
                for slot in &mut small[..len] {
                    *slot = ALPHABET[rest % ALPHABET.len()];
                    rest /= ALPHABET.len();
                }
                let view = &small[..len];
                assert_eq!(head_end(view), oracle(view), "exhaustive {view:?}");
            }
        }

        // Every start over the lengths that straddle a block boundary at both ends.
        for len in 0..=130usize {
            sweep(len, 0..len);
        }
        // At scale, the first two words, mid-buffer, and the final partial word.
        for len in [511usize, 512, 513, 4096, 16 * 1024] {
            sweep(
                len,
                (0..17)
                    .chain([len / 2, len / 2 + 1])
                    .chain(len.saturating_sub(9)..len),
            );
        }
    }

    /// The scan, and nothing else: 64 walks of one 87-byte `200` answer, each found offset folded into a running `u32` whose expected value is pinned, the head handed over opaquely so no round can be answered from the literal. The mirror below walks the same head a byte-window at a time under the identical fold, so one ops job reports both frames and only their difference is a claim about the scan.
    #[test]
    fn the_head_walk_costs_the_scan_and_nothing_else() {
        const HEAD: &[u8] = b"HTTP/1.1 200 Connection established\r\nProxy-Agent: ferrox\r\nX-Trace: 0123456789abcdef\r\n\r\n";
        let mut fold: u32 = 0;
        for _ in 0..64 {
            let end =
                head_end(std::hint::black_box(HEAD)).expect("the delimiter of a shipped head");
            fold = fold.wrapping_mul(31).wrapping_add(end as u32 + 1);
        }
        assert_eq!(fold, 0x734b_5000, "64 walks of one head, folded after each");
    }

    /// The walk the scan replaced, kept as this run's other frame: the same 64 walks of the same head through `windows(4).position`, the same pinned fold, so the pair prices the scan without a second CI run being trusted to agree with the first.
    #[test]
    fn the_serial_terminator_walk_costs_the_same_answer() {
        const HEAD: &[u8] = b"HTTP/1.1 200 Connection established\r\nProxy-Agent: ferrox\r\nX-Trace: 0123456789abcdef\r\n\r\n";
        let mut fold: u32 = 0;
        for _ in 0..64 {
            let end = std::hint::black_box(HEAD)
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("the delimiter of a shipped head");
            fold = fold.wrapping_mul(31).wrapping_add(end as u32 + 1);
        }
        assert_eq!(
            fold, 0x734b_5000,
            "the same 64 walks, byte-window at a time"
        );
    }
}
