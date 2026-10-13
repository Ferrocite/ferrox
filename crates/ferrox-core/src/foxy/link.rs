//! A Foxy account as a pasteable link, in the two spellings people type — `foxy://username=…` and `foxy://host:port?username=…` — with the account read as `email` then `username` so a link from either client works.

use std::collections::BTreeMap;
use std::fmt;

pub const SCHEME: &str = "foxy://";
/// The Guardian origin a link gets when it names no other.
pub const DEFAULT_GUARDIAN: &str = "https://vpn.mozilla.org";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FoxyLink {
    /// The authority, empty when the parameters follow the scheme directly.
    pub authority: String,
    pub params: BTreeMap<String, String>,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoxyLinkError {
    Scheme,
}

impl fmt::Display for FoxyLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scheme => f.write_str("link must start with foxy://"),
        }
    }
}

impl std::error::Error for FoxyLinkError {}

impl FoxyLink {
    pub fn parse(link: &str) -> Result<Self, FoxyLinkError> {
        let rest = link.strip_prefix(SCHEME).ok_or(FoxyLinkError::Scheme)?;
        let (rest, name_enc) = match rest.split_once('#') {
            Some((head, tail)) => (head, tail),
            None => (rest, ""),
        };
        let (authority, query) = match rest.split_once('?') {
            Some((head, tail)) => (head, tail),
            None => ("", rest),
        };
        let mut params = BTreeMap::new();
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (key, value) = match pair.split_once('=') {
                Some((key, value)) => (key, value),
                None => (pair, ""),
            };
            params.insert(percent_decode(key), percent_decode(value));
        }
        Ok(Self {
            authority: percent_decode(authority),
            params,
            name: percent_decode(name_enc),
        })
    }

    #[must_use]
    pub fn param(&self, key: &str) -> &str {
        self.params.get(key).map_or("", String::as_str)
    }

    /// The first of `keys` that carries something, which gives one field two spellings without two parsers.
    #[must_use]
    pub fn first(&self, keys: &[&str]) -> &str {
        keys.iter()
            .map(|key| self.param(key))
            .find(|value| !value.is_empty())
            .unwrap_or("")
    }

    /// The account, under either spelling.
    #[must_use]
    pub fn email(&self) -> &str {
        self.first(&["email", "username", "user"])
    }

    #[must_use]
    pub fn password(&self) -> &str {
        self.first(&["password", "passwd"])
    }

    /// The Guardian origin, the link's own authority when it names one.
    #[must_use]
    pub fn guardian(&self) -> &str {
        if self.authority.is_empty() {
            DEFAULT_GUARDIAN
        } else {
            &self.authority
        }
    }

    #[must_use]
    pub fn carrier(&self) -> &str {
        self.first(&["carrier", "type"])
    }

    /// The country to pin the dial at, under either spelling; `REC` is a value like any other, not a mode the lane must know.
    #[must_use]
    pub fn country(&self) -> &str {
        self.first(&["country", "cc", "loc"])
    }

    /// The city inside the country: a failover tier, never a filter, so naming a city does not refuse the country.
    #[must_use]
    pub fn city(&self) -> &str {
        self.first(&["city", "cityCode", "city_code"])
    }

    /// An upstream proxy the edge dial chains through, so a proxy-egress-only network can still start the lane; empty means direct.
    #[must_use]
    pub fn upstream_proxy(&self) -> &str {
        self.first(&["upstreamProxy", "upstream_proxy", "via"])
    }

    /// An edge the link names outright, for a link without a catalogue to read; empty lets the catalogue decide.
    #[must_use]
    pub fn host(&self) -> &str {
        self.first(&["host", "edge", "server", "hostname"])
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.param("port").parse().unwrap_or(443)
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' && at + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex(bytes[at + 1]), hex(bytes[at + 2])) {
                out.push(hi << 4 | lo);
                at += 3;
                continue;
            }
        }
        if bytes[at] == b'+' {
            out.push(b' ');
            at += 1;
            continue;
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_go_in_after_the_scheme_or_after_an_authority() {
        for link in [
            "foxy://username=a@b.c&password=pw",
            "foxy://?username=a@b.c&password=pw",
            "foxy://vpn.mozilla.org?username=a@b.c&password=pw",
        ] {
            let parsed = FoxyLink::parse(link).expect(link);
            assert_eq!(parsed.email(), "a@b.c", "{link}");
            assert_eq!(parsed.password(), "pw", "{link}");
        }
        assert_eq!(
            FoxyLink::parse("foxy://username=a@b.c")
                .expect("parses")
                .guardian(),
            DEFAULT_GUARDIAN
        );
        assert_eq!(
            FoxyLink::parse("foxy://vpn.example.org?username=a@b.c")
                .expect("parses")
                .guardian(),
            "vpn.example.org"
        );
    }

    #[test]
    fn an_account_is_called_email_or_username_and_not_both() {
        assert_eq!(
            FoxyLink::parse("foxy://email=e@f.gh&username=u@f.gh")
                .expect("parses")
                .email(),
            "e@f.gh"
        );
        assert_eq!(
            FoxyLink::parse("foxy://username=u%40f.gh&password=p%26w")
                .expect("parses")
                .email(),
            "u@f.gh"
        );
        assert_eq!(
            FoxyLink::parse("foxy://username=u@f.gh&password=p%26w")
                .expect("parses")
                .password(),
            "p&w"
        );
    }

    #[test]
    fn the_carrier_the_lane_carries_and_the_name_it_is_given_are_not_the_pass() {
        let parsed = FoxyLink::parse("foxy://username=a@b.c&password=pw&carrier=h3&pass=t#home")
            .expect("parses");
        assert_eq!(parsed.carrier(), "h3");
        assert_eq!(parsed.param("pass"), "t");
        assert_eq!(parsed.password(), "pw", "the pass is not the password");
        assert_eq!(parsed.name, "home");
    }

    #[test]
    fn a_link_carries_the_whole_lane_not_just_the_credentials() {
        let link = FoxyLink::parse(
            "foxy://vpn.example.org?email=a%40b.c&password=pw&code=424242&country=us&city=SFO&carrier=auto&spkiPins=sha256%2FAAA%2C-sha256%2FBBB&exitProbe=cloudflare.com%2Fcdn-cgi%2Ftrace&directPorts=22%2C53&directDomains=lan.example&edge=edge.example&port=8443#home",
        )
        .expect("parses");
        assert_eq!(link.email(), "a@b.c");
        assert_eq!(link.password(), "pw");
        assert_eq!(link.param("code"), "424242");
        assert_eq!(
            link.country(),
            "us",
            "the lane upper-cases it, not the parser"
        );
        assert_eq!(link.city(), "SFO");
        assert_eq!(link.carrier(), "auto");
        assert_eq!(link.param("spkiPins"), "sha256/AAA,-sha256/BBB");
        assert_eq!(link.param("exitProbe"), "cloudflare.com/cdn-cgi/trace");
        assert_eq!(link.param("directPorts"), "22,53");
        assert_eq!(link.param("directDomains"), "lan.example");
        assert_eq!(link.host(), "edge.example");
        assert_eq!(link.port(), 8443);
        assert_eq!(link.name, "home");
    }

    #[test]
    fn an_upstream_proxy_rides_the_link_under_three_names_or_not_at_all() {
        assert_eq!(
            FoxyLink::parse("foxy://username=a@b.c&upstreamProxy=http%3A%2F%2Fp%3A8080")
                .expect("parses")
                .upstream_proxy(),
            "http://p:8080"
        );
        assert_eq!(
            FoxyLink::parse("foxy://username=a@b.c&via=socks5%3A%2F%2Fp%3A1080")
                .expect("parses")
                .upstream_proxy(),
            "socks5://p:1080"
        );
        assert_eq!(
            FoxyLink::parse("foxy://username=a@b.c")
                .expect("parses")
                .upstream_proxy(),
            ""
        );
    }

    #[test]
    fn an_edge_the_link_does_not_name_is_not_invented() {
        let link = FoxyLink::parse("foxy://email=a@b.c&password=pw").expect("parses");
        assert_eq!(link.host(), "");
        assert_eq!(link.port(), 443);
        assert_eq!(link.country(), "");
        assert_eq!(link.city(), "");
    }

    #[test]
    fn a_link_that_is_not_a_foxy_link_is_refused_rather_than_guessed() {
        assert_eq!(FoxyLink::default().guardian(), DEFAULT_GUARDIAN);
        assert_eq!(FoxyLink::parse("vless://x"), Err(FoxyLinkError::Scheme));
        assert_eq!(
            FoxyLink::parse("https://vpn.mozilla.org"),
            Err(FoxyLinkError::Scheme)
        );
        assert_eq!(FoxyLink::parse("foxy://").expect("parses").email(), "");
    }

    #[test]
    fn a_bare_key_and_a_lost_escape_are_both_read_as_they_are() {
        assert_eq!(
            FoxyLink::parse("foxy://username&password")
                .expect("parses")
                .password(),
            ""
        );
        assert_eq!(
            FoxyLink::parse("foxy://username=a@b.c&password=p%")
                .expect("parses")
                .password(),
            "p%"
        );
        assert_eq!(
            FoxyLink::parse("foxy://username=a%2Bb&password=x")
                .expect("parses")
                .email(),
            "a+b"
        );
    }
}
