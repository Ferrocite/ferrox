//! `VeePN`: the plane of a free browser extension — an anonymous launch, a rotating API domain, a region's server list, and HTTPS `CONNECT` upstreams that answer `Basic`. Arithmetic only: nothing here opens a socket, reads a clock, or prints.

use crate::b64;

/// The `Proxy-Authorization` head for the pair that server's own list entry handed out, not a `Bearer` pass. It rides the literal rather than the value so the request stays seven runs — the width of the record lane's gather stack.
pub const BASIC_HEAD: &[u8] = b"\r\nProxy-Authorization: Basic ";

/// The answer that names the target rather than the pair: the plane's edge sends this field and value when the host itself is one it will not carry, so the pair is valid, the edge is healthy, and no other edge or fresh token changes the answer.
pub const FORBIDDEN_TARGET: (&[u8], &[u8]) = (b"X-Hola-Error", b"Forbidden Host");

/// What the launch body publishes. The API keys its free pool on these, so they are sent verbatim.
pub const APP_VERSION: &str = "5.0.2";
pub const DEVICE_NAME: &str = "Chrome 130";
pub const PLATFORM: &str = "chrome";

/// The origin list the extension ships; a reserve list a public bucket publishes is appended to it, never replaces it.
pub const DEFAULT_DOMAINS: [&str; 7] = [
    "https://antpeak.com",
    "https://hibchr.com",
    "https://hisball.com",
    "https://bitphox.com",
    "https://freloop.com",
    "https://tronlit.com",
    "https://tronyza.com",
];

/// The paths of the plane, in the order a lane needs them.
pub const LAUNCH: &str = "/v3/launch/";
pub const LOCATIONS: &str = "/v3/location/extension/";
pub const OPTIMAL: &str = "/v3/location/optimal/";
pub const SERVER_LIST: &str = "/v3/server/list/";

/// How long a launch token is worth asking with again, a region's server list is kept, and a reserve domain list outlives its fetch.
pub const TOKEN_TTL: u64 = 7 * 24 * 3600;
pub const SERVERS_TTL: u64 = 12 * 3600;
pub const RESERVE_TTL: u64 = 24 * 3600;

/// How soon a plane that could not be reached at all is asked again while the answer it already gave keeps the lane running: an outage costs the flows in this window nothing, and a recovered plane is back inside it.
pub const PLANE_RETRY: u64 = 30;

/// The pause the walk earns before a retry of a plane that asked for patience, and the wall the whole request runs out against: a dead network has to surface as an error, not as a lane that hangs.
pub const BACKOFF: [u64; 5] = [1, 2, 4, 8, 10];
pub const REQUEST_BUDGET: u64 = 120;
pub const MAX_ATTEMPTS: usize = 14;

/// The seconds owed before the walk's next attempt. A `429` or a `5xx` is the plane asking for patience, so it gets the table; a domain that gave no answer back asked for nothing and the rotation away from it is the retry, so a seized API or a dead network costs the flow its transports and no pause at all. The attempt that closes the walk earns nothing either, because there is no next attempt to pace.
#[must_use]
pub const fn pause(attempt: usize, attempts: usize, answered: bool) -> u64 {
    if !answered || attempt + 1 >= attempts {
        return 0;
    }
    if attempt < BACKOFF.len() {
        BACKOFF[attempt]
    } else {
        BACKOFF[BACKOFF.len() - 1]
    }
}

/// How long an upstream that declined a flow is left alone. One refused handshake says the edge is gone for now, and the flow after it has nothing to learn from paying the same discovery again.
pub const EDGE_SILENCE: u64 = 60;
pub const MAX_RESERVE_DOMAINS: usize = 10;

/// The `user:pass` of one list entry, coded straight into the caller's window: the pair it encodes is never a buffer, because the coder reads the two runs and the colon between them as one stream.
///
/// # Errors
/// [`std::io::ErrorKind::InvalidInput`] when `out` is shorter than [`credential_len`].
pub fn credential_into<'a>(
    username: &str,
    password: &str,
    out: &'a mut [u8],
) -> std::io::Result<&'a [u8]> {
    let want = credential_len(username, password);
    let window = out
        .get_mut(..want)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let coded = b64::encode_parts_into(&[username.as_bytes(), b":", password.as_bytes()], window)?;
    Ok(&window[..coded])
}

/// The bytes [`credential_into`] needs for one pair: the coded `user:pass`, the scheme not included.
#[must_use]
pub const fn credential_len(username: &str, password: &str) -> usize {
    b64::encoded_len(username.len() + password.len() + 1)
}

/// What the launch publishes as `platformVersion`, and the one user-agent the plane answers with: this tree's browser-UA shape — `Chrome/130.0`, the way `foxy_challenge` spells its `Chrome/126.0` — because the build-number tail a real Chrome sends is matched by no reader at either end.
pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";

/// The launch body in literals and the two names it carries: `udid` and the zone are the only fields that differ between installations, so every other octet is already written out, in the order the extension's serializer puts them.
///
/// # Errors
/// [`std::io::ErrorKind::InvalidInput`] when `out` is shorter than [`launch_len`] or a name holds a byte the string form would have to escape.
pub fn launch_into<'a>(
    udid: &str,
    time_zone: &str,
    out: &'a mut [u8],
) -> std::io::Result<&'a [u8]> {
    escaped(udid)?;
    escaped(time_zone)?;
    copy_parts(out, &launch_parts(udid, time_zone))
}

/// The bytes [`launch_into`] writes for these two names.
#[must_use]
pub fn launch_len(udid: &str, time_zone: &str) -> usize {
    parts_len(&launch_parts(udid, time_zone))
}

#[must_use]
fn launch_parts<'a>(udid: &'a str, time_zone: &'a str) -> [&'a [u8]; 13] {
    [
        b"{\"udid\": \"",
        udid.as_bytes(),
        b"\", \"appVersion\": \"",
        APP_VERSION.as_bytes(),
        b"\", \"platform\": \"",
        PLATFORM.as_bytes(),
        b"\", \"platformVersion\": \"",
        USER_AGENT.as_bytes(),
        b"\", \"timeZone\": \"",
        time_zone.as_bytes(),
        b"\", \"deviceName\": \"",
        DEVICE_NAME.as_bytes(),
        b"\"}",
    ]
}

/// The server list ask for one region. `protocol` is `https` because that is the only value the API answers with a list of upstreams this lane dials.
///
/// # Errors
/// [`std::io::ErrorKind::InvalidInput`] when `out` is shorter than [`server_list_len`] or the region holds a byte the string form would have to escape.
pub fn server_list_into<'a>(region: &str, out: &'a mut [u8]) -> std::io::Result<&'a [u8]> {
    escaped(region)?;
    copy_parts(out, &server_list_parts(region))
}

/// The bytes [`server_list_into`] writes for this region.
#[must_use]
pub fn server_list_len(region: &str) -> usize {
    parts_len(&server_list_parts(region))
}

#[must_use]
fn server_list_parts(region: &str) -> [&[u8]; 3] {
    [
        b"{\"protocol\": \"https\", \"region\": \"",
        region.as_bytes(),
        b"\", \"type\": 0}",
    ]
}

/// The runs put end to end, written into the caller's window: a request body of literals and names costs one length check and one copy per run.
///
/// # Errors
/// [`std::io::ErrorKind::InvalidInput`] when `out` is shorter than the runs together.
fn copy_parts<'a>(out: &'a mut [u8], parts: &[&[u8]]) -> std::io::Result<&'a [u8]> {
    let mut text = out
        .get_mut(..parts_len(parts))
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let written = text.len();
    for part in parts {
        let (head, rest) = text.split_at_mut(part.len());
        head.copy_from_slice(part);
        text = rest;
    }
    Ok(&out[..written])
}

#[must_use]
const fn parts_len(parts: &[&[u8]]) -> usize {
    let mut total = 0;
    let mut at = 0;
    while at < parts.len() {
        total += parts[at].len();
        at += 1;
    }
    total
}

/// A name the string form would have to escape is a refusal, not a surprise: the plane's own values never carry one, and a pasted region or zone might.
fn escaped(text: &str) -> std::io::Result<()> {
    if text
        .bytes()
        .any(|byte| byte < 0x20 || matches!(byte, b'"' | b'\\'))
    {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    Ok(())
}

/// An HTTPS origin with a sane host and, when it names one, a real TCP port: a host is `label.` once or more and a final label, each bounded and filled by alphanumerics and inner hyphens. `Some` is the host it named and the port — 443 when it named none; `None` is the refusal.
///
/// A walk, not a backtracking match: the reference this replaces pays a regex engine per candidate domain, and a hostname either parses or it does not.
#[must_use]
pub fn api_domain(url: &str) -> Option<(&str, u16)> {
    let url = url.trim().trim_end_matches('/');
    let host = url.strip_prefix("https://")?;
    let (host, port) = match host.rsplit_once(':') {
        Some((host, digits)) => (host, parse_port(digits)?),
        None => (host, 443),
    };
    labels(host).then_some((host, port))
}

#[must_use]
fn parse_port(digits: &str) -> Option<u16> {
    let digits = digits.as_bytes();
    if digits.is_empty() || digits.len() > 5 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut value = 0u32;
    for digit in digits {
        value = value * 10 + u32::from(digit - b'0');
    }
    (1..65_536).contains(&value).then_some(value as u16)
}

/// `label.` once or more, then a final label: every label non-empty, alphanumeric-bounded, and filled by alphanumerics and hyphens. The dot and the byte it follows are one walk, not a split and a second scan per label.
#[must_use]
fn labels(host: &str) -> bool {
    let mut labels = 0usize;
    let mut at_start = true;
    let mut last = 0u8;
    for &byte in host.as_bytes() {
        if byte == b'.' {
            if at_start || !last.is_ascii_alphanumeric() {
                return false;
            }
            labels += 1;
            at_start = true;
            last = 0;
            continue;
        }
        if !byte.is_ascii_alphanumeric() && byte != b'-' {
            return false;
        }
        if at_start && !byte.is_ascii_alphanumeric() {
            return false;
        }
        at_start = false;
        last = byte;
    }
    if at_start || !last.is_ascii_alphanumeric() {
        return false;
    }
    labels += 1;
    labels >= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_basic_request_is_the_pair_the_upstream_reads_back() {
        let mut window = [0u8; 256];
        let credential = credential_into("1000-abc", "s3cr3t", &mut window).expect("window");
        let block = crate::foxy::connect_request(
            "192.0.2.12:443",
            BASIC_HEAD,
            std::str::from_utf8(credential).unwrap(),
        )
        .concat();
        assert_eq!(
            String::from_utf8(block).expect("ascii"),
            "CONNECT 192.0.2.12:443 HTTP/1.1\r\nHost: 192.0.2.12:443\r\nProxy-Authorization: Basic MTAwMC1hYmM6czNjcjN0\r\n\r\n"
        );
    }

    /// The pair is coded where the caller will read it: the returned slice starts at the window's own base, so it was never staged anywhere else.
    #[test]
    fn the_credential_lands_in_the_callers_window_and_not_in_one_of_its_own() {
        let mut window = [0u8; 512];
        let base = window.as_ptr();
        {
            let first = credential_into("u", "p", &mut window).expect("window");
            assert_eq!(
                first.as_ptr() as usize - base as usize,
                0,
                "the pair begins at the caller's own base, not in a buffer of its own"
            );
            assert_eq!(first.len(), credential_len("u", "p"), "exactly the pair");
        }
        assert_eq!(
            &window[credential_len("u", "p")..],
            &[0u8; 508][..],
            "and nothing past it was touched"
        );
        assert_eq!(
            b64::decode(&window[..credential_len("u", "p")]).as_deref(),
            Some(&b"u:p"[..]),
            "the coded window is the pair the caller owns"
        );
        // Every pair shape, so both paddings and the colon that straddles a group are covered.
        for user in 0..=12usize {
            for pass in 0..=12usize {
                let name = "u".repeat(user);
                let secret = "p".repeat(pass);
                let mut other = [0u8; 128];
                let want = credential_len(&name, &secret);
                let coded = credential_into(&name, &secret, &mut other)
                    .expect("window")
                    .to_vec();
                assert_eq!(coded.len(), want, "{user}+{pass}");
                let mut plain = name;
                plain.push(':');
                plain.push_str(&secret);
                assert_eq!(
                    coded,
                    b64::encode(plain.as_bytes()).as_bytes(),
                    "{user}+{pass}"
                );
            }
        }
    }

    #[test]
    fn a_domain_under_https_with_a_host_and_a_real_port_is_a_origin() {
        for (url, host, port) in [
            ("https://antpeak.com", "antpeak.com", 443_u16),
            ("https://hibchr.com/", "hibchr.com", 443),
            ("https://api.example.com:8443", "api.example.com", 8443),
            ("https://a.b.c.example.org", "a.b.c.example.org", 443),
            (" https://tronyza.com ", "tronyza.com", 443),
        ] {
            assert_eq!(api_domain(url), Some((host, port)), "{url}");
        }
        for refused in [
            "http://antpeak.com",
            "antpeak.com",
            "https://",
            "https://localhost",
            "https://-bad.com",
            "https://bad-.com",
            "https://a..b.com",
            "https://a.com/path",
            "https://a.com:0",
            "https://a.com:70000",
            "https://a.com:abc",
            "https://a.com:123456",
            "https://a b.com",
            "https://[::1]:443",
            "https://a.com.",
        ] {
            assert_eq!(api_domain(refused), None, "{refused}");
        }
    }

    /// The launch body is the reference's `json.dumps` byte for byte: the same keys, the same order, the same separators — and it lands in the caller's window, so the ask serializes nothing.
    #[test]
    fn a_launch_body_is_the_document_the_api_reads() {
        let mut window = [0u8; 512];
        let base = window.as_ptr();
        {
            let body = launch_into(
                "3f2b1c00-0000-4000-8000-000000000000",
                "Europe/Berlin",
                &mut window,
            )
            .expect("window");
            assert_eq!(
                std::str::from_utf8(body).expect("ascii"),
                format!("{{\"udid\": \"3f2b1c00-0000-4000-8000-000000000000\", \"appVersion\": \"5.0.2\", \"platform\": \"chrome\", \"platformVersion\": \"{USER_AGENT}\", \"timeZone\": \"Europe/Berlin\", \"deviceName\": \"Chrome 130\"}}")
            );
            assert_eq!(
                body.as_ptr() as usize - base as usize,
                0,
                "the body begins at the caller's own base, not in a buffer of its own"
            );
            assert_eq!(
                body.len(),
                launch_len("3f2b1c00-0000-4000-8000-000000000000", "Europe/Berlin"),
                "the bound is the length written"
            );
        }
        assert_eq!(
            std::str::from_utf8(server_list_into("EU Germany", &mut window).expect("window")),
            Ok("{\"protocol\": \"https\", \"region\": \"EU Germany\", \"type\": 0}")
        );
        assert_eq!(
            server_list_len("DE"),
            "{\"protocol\": \"https\", \"region\": \"DE\", \"type\": 0}".len()
        );
    }

    /// A name the string form would have to escape is refused before a byte is written, so the document the API reads is never a broken one.
    #[test]
    fn a_name_that_would_need_escaping_is_refused_and_leaves_the_window_untouched() {
        let mut window = [0u8; 128];
        for (udid, zone) in [
            ("a\"b", "UTC"),
            ("a\\b", "UTC"),
            ("a\u{7}b", "UTC"),
            ("a", "UTC\u{1}"),
        ] {
            assert_eq!(
                launch_into(udid, zone, &mut window)
                    .err()
                    .map(|error| error.kind()),
                Some(std::io::ErrorKind::InvalidInput),
                "{udid:?} {zone:?}"
            );
        }
        assert_eq!(window, [0u8; 128], "and nothing was written");
        let mut short = [0u8; 8];
        assert_eq!(
            launch_into("0123456789", "UTC", &mut short)
                .err()
                .map(|error| error.kind()),
            Some(std::io::ErrorKind::InvalidInput),
            "a window under the body is refused rather than partially filled"
        );
    }

    /// The walk's pause belongs to the answer, not to the attempt counter: a domain that gave nothing back is rotated away from rather than waited on, and the attempt that closes the walk earns no pause because there is no next attempt to pace. The two sums are what the page's rows read.
    #[test]
    fn a_plane_that_answered_nothing_is_rotated_away_from_not_waited_on() {
        for attempt in 0..MAX_ATTEMPTS * 2 {
            assert_eq!(
                pause(attempt, DEFAULT_DOMAINS.len(), false),
                0,
                "no answer asks for nothing at attempt {attempt}"
            );
        }
        for (attempt, want) in BACKOFF.iter().enumerate() {
            assert_eq!(
                pause(attempt, DEFAULT_DOMAINS.len(), true),
                *want,
                "a plane that said slow down is paced by the table at attempt {attempt}"
            );
        }
        assert_eq!(
            pause(6, DEFAULT_DOMAINS.len(), true),
            0,
            "the walk's closing attempt earns no pause"
        );
        assert_eq!(
            pause(0, 1, true),
            0,
            "a one-origin rotation has no next attempt to wait for"
        );
        let waited: u64 = (0..DEFAULT_DOMAINS.len())
            .map(|attempt| pause(attempt, DEFAULT_DOMAINS.len(), true))
            .sum();
        assert_eq!(
            waited, 35,
            "the shipped rotation, a plane that answered `429` throughout"
        );
        let rotated: u64 = (0..DEFAULT_DOMAINS.len())
            .map(|attempt| pause(attempt, DEFAULT_DOMAINS.len(), false))
            .sum();
        assert_eq!(
            rotated, 0,
            "the same rotation, a plane that answered nothing"
        );
    }

    /// The split-and-scan walk exactly as it stood, kept as the oracle the one-pass form must answer with the same verdict on every host.
    fn labels_staged(host: &str) -> bool {
        let host = host.as_bytes();
        let mut parts = host.split(|byte| *byte == b'.').peekable();
        let mut dotted = false;
        while let Some(label) = parts.next() {
            if label.is_empty()
                || !label[0].is_ascii_alphanumeric()
                || !label[label.len() - 1].is_ascii_alphanumeric()
                || label
                    .iter()
                    .any(|byte| !byte.is_ascii_alphanumeric() && *byte != b'-')
            {
                return false;
            }
            if parts.peek().is_some() {
                dotted = true;
            } else if !dotted {
                return false;
            }
        }
        true
    }

    /// Every curated shape, then 20 000 seeded byte strings: the one-pass walk and the split oracle must agree on the verdict, not just on the shipped origins.
    #[test]
    fn the_one_pass_label_walk_is_the_split_walk_at_every_host() {
        for host in [
            "", ".", "a", "a.", ".a", "a.b", "a..b", "a.b.", "a-b.c", "-a.b", "a-.b", "a_b.c",
            "a/b.c", "a b.c", "a:b.c", "a.b:443", "A.B", "a.1", "1.2", "é.b", "a.b-c", "a-.b",
            "a.-b", "a.b.", "a..", "..a", "a.-", "a.b..c",
        ] {
            assert_eq!(labels(host), labels_staged(host), "{host:?}");
        }
        let alphabet = b"abzAZ09-._:/ \t\n\r\x7f\x80";
        let mut word = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..20_000 {
            let len = (word as usize >> 7) % 33;
            let mut host = String::with_capacity(len);
            for _ in 0..len {
                word ^= word << 13;
                word ^= word >> 7;
                word ^= word << 17;
                host.push(alphabet[(word as usize >> 11) % alphabet.len()] as char);
            }
            assert_eq!(labels(&host), labels_staged(&host), "{host:?}");
        }
    }

    /// The origin walk, and nothing else: the seven domains this crate ships, walked 64 times over with the answer folded after each, so the frame is the walk and no socket, buffer or fixture rides in it. Read as the difference between two runs of this row, never as the cost of the method alone.
    #[test]
    fn the_domain_walk_costs_the_labels_and_nothing_else() {
        assert_eq!(api_domain(DEFAULT_DOMAINS[0]), Some(("antpeak.com", 443)));
        let mut fold: u32 = 0;
        for _ in 0..64 {
            for url in DEFAULT_DOMAINS {
                let (host, port) = api_domain(url).expect("a shipped origin");
                for &byte in host.as_bytes() {
                    fold = fold.wrapping_mul(31).wrapping_add(u32::from(byte));
                }
                fold = fold.wrapping_add(u32::from(port));
            }
        }
        assert_eq!(
            fold, 0xe2ea_d240,
            "64 walks of the seven shipped origins, folded after each"
        );
    }

    /// The pair coder, and nothing else: one list entry's `user:pass` coded 512 times into one stack window and folded after each pass, so the frame is the coder — fifteen plain bytes to twenty coded ones, no padding.
    #[test]
    fn the_pair_coder_costs_the_coder_and_nothing_else() {
        let mut window = [0u8; 32];
        let mut fold: u32 = 0;
        for _ in 0..512 {
            for &byte in credential_into("1000-abc", "s3cr3t", &mut window).expect("window") {
                fold = fold.wrapping_mul(31).wrapping_add(u32::from(byte));
            }
        }
        assert_eq!(
            fold, 0xe88e_0600,
            "512 codings of one pair, folded after each"
        );
    }
}
