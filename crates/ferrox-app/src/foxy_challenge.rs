//! A `406` from a Fastly host is a challenge ending in a cookie: without it the plane answers `406` forever.

use std::collections::BTreeMap;
use std::sync::Mutex;

use sha2::Digest as _;

use crate::foxy_account::{Denied, Endpoint, Reply};
use crate::json::{self, Json};

/// Who a request says it is: the challenge's origin refuses the account plane's own agent, so both are named once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Agent {
    /// The account plane: what the reference's Mozilla VPN client sends.
    Api,
    /// The challenge page and its script.
    Page,
    /// The private-access token call, which wants plain text back.
    Text,
}

impl Agent {
    #[must_use]
    pub(crate) fn user_agent(self) -> &'static str {
        match self {
            Self::Api => crate::foxy_account::USER_AGENT,
            Self::Page | Self::Text => BROWSER_AGENT,
        }
    }

    #[must_use]
    pub(crate) fn accept(self) -> &'static str {
        match self {
            Self::Api => crate::foxy_account::JSON_ACCEPT,
            Self::Page => HTML_ACCEPT,
            Self::Text => "text/plain",
        }
    }
}

const BROWSER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";
const HTML_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

/// Rounds of post-back before the edge is taken at its word.
const MAX_ROUNDS: usize = 3;
/// How many times one account-plane call may be challenged and retried.
pub(crate) const MAX_ATTEMPTS: usize = 5;
/// The two characters a proof of work is asked to find, over this alphabet.
const ALPHABET: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
/// The hosts to try when the one that answered will not serve the page itself.
const FALLBACKS: [&str; 2] = ["api.accounts.firefox.com", "accounts.firefox.com"];

/// Cookies kept by domain, so a challenge solved on one host does not travel to another.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Jar {
    by_name: BTreeMap<String, (String, String)>,
}

impl Jar {
    #[must_use]
    pub(crate) fn header(&self, host: &str) -> Option<String> {
        let mut out = String::new();
        for (name, (domain, value)) in &self.by_name {
            if host != domain && !host.ends_with(&format!(".{domain}")) {
                continue;
            }
            if !out.is_empty() {
                out.push_str("; ");
            }
            out.push_str(name);
            out.push('=');
            out.push_str(value);
        }
        (!out.is_empty()).then_some(out)
    }

    /// Every `Set-Cookie` in a reply, as `name=value` pairs with their domains.
    pub(crate) fn absorb(&mut self, host: &str, reply: &Reply) {
        for value in reply
            .headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, value)| value.as_str())
        {
            let mut pair = value.split(';');
            let Some((name, value)) = pair.next().unwrap_or_default().split_once('=') else {
                continue;
            };
            let domain = pair
                .find_map(|attribute| {
                    attribute
                        .trim()
                        .strip_prefix("Domain=")
                        .map(|domain| domain.trim_start_matches('.').to_ascii_lowercase())
                })
                .unwrap_or_else(|| host.to_ascii_lowercase());
            let value = value.split('"').next().unwrap_or_default();
            self.by_name
                .insert(name.trim().to_owned(), (domain, value.to_owned()));
        }
    }
}

/// The `406` answered with a challenge instead of a refusal; naming it beats a retry loop in the dark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Challenge {
    /// The edge keeps asking after every round this is willing to spend.
    Unsolved,
    /// A challenge type a client cannot answer — a captcha.
    Unsupported(&'static str),
    /// The page the solver needed was not served at all.
    Absent,
}

/// One account-plane call: sent, and on a `406` solved and resent, up to the attempts the reference allows.
pub(crate) fn send_with_challenge(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Result<Reply, Denied> {
    for attempt in 1..=MAX_ATTEMPTS {
        let reply =
            crate::foxy_account::send(endpoint, jar, Agent::Api, method, path, extra, body)?;
        if reply.status != 406 {
            return Ok(reply);
        }
        if attempt == MAX_ATTEMPTS {
            break;
        }
        solve(endpoint, jar).map_err(|_| Denied::Challenged(406))?;
    }
    Err(Denied::Challenged(406))
}

/// Solves the challenge on whichever host serves it and installs the cookies the plane needs.
pub(crate) fn solve(endpoint: &Endpoint, jar: &Mutex<Jar>) -> Result<(), Challenge> {
    let mut asked = Vec::new();
    asked.push(endpoint.clone());
    for host in FALLBACKS {
        if host != endpoint.host {
            asked.push(
                Endpoint::parse(&format!("https://{host}"), endpoint.roots.clone())
                    .ok_or(Challenge::Absent)?,
            );
        }
    }
    let mut last = Challenge::Absent;
    for host in &asked {
        match solve_on(host, jar) {
            Ok(()) => return Ok(()),
            Err(Challenge::Absent) => last = Challenge::Absent,
            Err(other) => last = other,
        }
    }
    Err(last)
}

fn solve_on(endpoint: &Endpoint, jar: &Mutex<Jar>) -> Result<(), Challenge> {
    let page = get(endpoint, jar, "/", HTML_ACCEPT)?;
    if !page.contains("/_fs-ch-") || !page.contains("Client Challenge") {
        return Err(Challenge::Absent);
    }
    let prefix = prefix_of(&page).ok_or(Challenge::Absent)?;
    let script = get(
        endpoint,
        jar,
        &format!("{prefix}/script.js?reload=true"),
        HTML_ACCEPT,
    )?;
    let (mut challenges, mut token) = parse_init(&script).ok_or(Challenge::Absent)?;
    for _ in 0..MAX_ROUNDS {
        let mut answers = Vec::new();
        for challenge in challenges.as_arr().unwrap_or(&[]) {
            answers.push(answer(endpoint, jar, prefix, &token, challenge)?);
        }
        let mut post = String::from("{\"token\":\"");
        ferrox_core::foxy::account::escape_json_into(&token, &mut post);
        post.push_str("\",\"data\":[");
        for (at, answer) in answers.iter().enumerate() {
            if at > 0 {
                post.push(',');
            }
            json::write(answer, &mut post);
        }
        post.push_str("]}");
        let mut body = Vec::new();
        body.extend_from_slice(post.as_bytes());
        let reply = crate::foxy_account::send(
            endpoint,
            jar,
            Agent::Page,
            "POST",
            &format!("{prefix}/fst-post-back"),
            &[
                ("Content-Type", "application/json"),
                ("Origin", &endpoint.origin()),
            ],
            &body,
        )
        .map_err(|_| Challenge::Absent)?;
        if reply.status / 100 != 2 {
            return Err(Challenge::Absent);
        }
        let answer =
            json::parse(&String::from_utf8_lossy(&reply.body)).map_err(|_| Challenge::Absent)?;
        if answer.get("status").and_then(Json::as_str) == Some("success") {
            return confirm(endpoint, jar);
        }
        let Some(next) = answer.get("ch").and_then(Json::as_arr) else {
            return Err(Challenge::Absent);
        };
        let Some(next_token) = answer.get("tok").and_then(Json::as_str) else {
            return Err(Challenge::Absent);
        };
        if next.is_empty() || next_token.is_empty() {
            return Err(Challenge::Absent);
        }
        challenges = Json::Arr(next.to_vec());
        next_token.clone_into(&mut token);
    }
    Err(Challenge::Unsolved)
}

/// The page must no longer be a challenge for the cookie to be worth keeping.
fn confirm(endpoint: &Endpoint, jar: &Mutex<Jar>) -> Result<(), Challenge> {
    let page = get(endpoint, jar, "/", HTML_ACCEPT)?;
    (!page.contains("/_fs-ch-"))
        .then_some(())
        .ok_or(Challenge::Unsolved)
}

fn get(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    path: &str,
    accept: &str,
) -> Result<String, Challenge> {
    let agent = if accept == HTML_ACCEPT {
        Agent::Page
    } else {
        Agent::Text
    };
    let reply = crate::foxy_account::send(endpoint, jar, agent, "GET", path, &[], b"")
        .map_err(|_| Challenge::Absent)?;
    if reply.status / 100 != 2 {
        return Err(Challenge::Absent);
    }
    Ok(String::from_utf8_lossy(&reply.body).into_owned())
}

/// The asset prefix the page points at (`/_fs-ch-<id>`), which every later call goes to.
fn prefix_of(page: &str) -> Option<&str> {
    let at = page.find("/_fs-ch-")?;
    let rest = &page[at + "/_fs-ch-".len()..];
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .unwrap_or(rest.len());
    (end > 0).then(|| &page[at..at + "/_fs-ch-".len() + end])
}

/// The `init` call: challenge list and token. Only the script's last call is live; earlier ones are scaffolding.
fn parse_init(script: &str) -> Option<(Json, String)> {
    let mut found = None;
    for (at, _) in script.match_indices("init(") {
        let rest = &script[at + "init(".len()..];
        if let Some((list, tail)) = split_list(rest) {
            let token = quoted(tail)?;
            found = Some((json::parse(&list).ok()?, token.to_owned()));
        }
    }
    found
}

fn split_list(rest: &str) -> Option<(String, &str)> {
    let rest = rest.trim_start();
    if !rest.starts_with('[') {
        return None;
    }
    let mut depth = 0usize;
    let mut quoted = false;
    for (at, byte) in rest.bytes().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            b'[' if !quoted => depth += 1,
            b']' if !quoted => {
                depth -= 1;
                if depth == 0 {
                    return Some((rest[..=at].to_owned(), &rest[at + 1..]));
                }
            }
            _ => {}
        }
    }
    None
}

fn quoted(tail: &str) -> Option<&str> {
    let tail = tail.trim_start().strip_prefix(',')?.trim_start();
    let rest = tail.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn answer(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    prefix: &str,
    token: &str,
    challenge: &Json,
) -> Result<Json, Challenge> {
    let kind = challenge.get("ty").and_then(Json::as_str).unwrap_or("");
    let data = challenge.get("data");
    let text = |key: &str| {
        data.and_then(|data| data.get(key))
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned()
    };
    match kind {
        "pow" => {
            let base = text("base");
            let hash = text("hash");
            let found = solve_pow(&base, &hash).ok_or(Challenge::Absent)?;
            Ok(Json::Obj(vec![
                ("ty".to_owned(), Json::Str("pow".to_owned())),
                ("base".to_owned(), Json::Str(base)),
                (
                    "answer".to_owned(),
                    Json::Str(String::from_utf8_lossy(&found).into_owned()),
                ),
                ("hmac".to_owned(), Json::Str(text("hmac"))),
                ("expires".to_owned(), Json::Str(text("expires"))),
            ]))
        }
        "pat" => Ok(Json::Obj(vec![
            ("ty".to_owned(), Json::Str("pat".to_owned())),
            (
                "auth".to_owned(),
                Json::Str(fetch_pat(endpoint, jar, prefix, token)?),
            ),
        ])),
        "clientmetrics" => Ok(Json::Obj(vec![
            ("ty".to_owned(), Json::Str("clientmetrics".to_owned())),
            ("webdriver".to_owned(), Json::Bool(false)),
            (
                "bot_detection_result".to_owned(),
                Json::Obj(vec![
                    ("bot_detected".to_owned(), Json::Bool(false)),
                    ("bot_kind".to_owned(), Json::Null),
                ]),
            ),
            (
                "browser_metrics".to_owned(),
                Json::Obj(vec![
                    ("client_data".to_owned(), Json::Str("{}".to_owned())),
                    ("error_trace".to_owned(), Json::Null),
                ]),
            ),
            ("detector_results".to_owned(), Json::Obj(Vec::new())),
            ("v".to_owned(), Json::Num(2.0)),
        ])),
        "captcha" => Err(Challenge::Unsupported("captcha")),
        _ => Err(Challenge::Unsupported("")),
    }
}

/// The edge's private-access token; with no browser to ask it is empty, which the edge reads as no answer.
fn fetch_pat(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    prefix: &str,
    token: &str,
) -> Result<String, Challenge> {
    let reply = crate::foxy_account::send(
        endpoint,
        jar,
        Agent::Text,
        "POST",
        &format!("{prefix}/pat?token={}", encode(token)),
        &[
            ("Content-Type", crate::foxy_account::JSON_ACCEPT),
            ("Origin", &endpoint.origin()),
        ],
        b"",
    )
    .map_err(|_| Challenge::Absent)?;
    if matches!(reply.status, 400 | 401) {
        return Ok(String::new());
    }
    if reply.status / 100 != 2 {
        return Err(Challenge::Absent);
    }
    let body = json::parse(&String::from_utf8_lossy(&reply.body)).map_err(|_| Challenge::Absent)?;
    body.get("auth")
        .and_then(Json::as_str)
        .filter(|auth| !auth.is_empty())
        .map(str::to_owned)
        .ok_or(Challenge::Absent)
}

/// The two characters making `SHA-256(base + pair)` hit the target: one hash and no allocation per pair.
fn solve_pow(base: &str, target: &str) -> Option<[u8; 2]> {
    let want = ferrox_core::foxy::account::hex_to_bytes(target);
    let want: [u8; 32] = want.as_slice().try_into().ok()?;
    let mut input = Vec::with_capacity(base.len() + 2);
    input.extend_from_slice(base.as_bytes());
    input.extend_from_slice(&[0, 0]);
    for high in ALPHABET {
        for low in ALPHABET {
            let at = base.len();
            input[at] = *high;
            input[at + 1] = *low;
            if sha2::Sha256::digest(&input)[..] == want {
                return Some([*high, *low]);
            }
        }
    }
    None
}

fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push_str("%20"),
            _ => {
                out.push('%');
                out.push(
                    char::from_digit(u32::from(byte >> 4), 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit(u32::from(byte & 0x0f), 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(headers: &[(&str, &str)], body: &str) -> Reply {
        Reply {
            status: 200,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn a_cookie_answers_the_host_that_set_it_and_no_other() {
        let mut jar = Jar::default();
        jar.absorb(
            "api.accounts.firefox.com",
            &reply(
                &[("Set-Cookie", "_fs_chl=abc; Path=/; Domain=.firefox.com")],
                "",
            ),
        );
        jar.absorb(
            "vpn.mozilla.org",
            &reply(&[("Set-Cookie", "edge=x1; Path=/")], ""),
        );
        assert_eq!(
            jar.header("api.accounts.firefox.com").as_deref(),
            Some("_fs_chl=abc")
        );
        assert_eq!(
            jar.header("accounts.firefox.com").as_deref(),
            Some("_fs_chl=abc"),
            "a subdomain of the domain still matches"
        );
        assert_eq!(jar.header("vpn.mozilla.org").as_deref(), Some("edge=x1"));
        assert_eq!(jar.header("example.org"), None);
    }

    #[test]
    fn a_set_cookie_that_is_not_a_pair_changes_nothing() {
        let mut jar = Jar::default();
        jar.absorb("h", &reply(&[("Set-Cookie", "novalue")], ""));
        assert_eq!(jar.header("h"), None);
    }

    #[test]
    fn one_jar_serves_both_hosts_that_share_a_domain() {
        let mut jar = Jar::default();
        jar.absorb(
            "api.accounts.firefox.com",
            &reply(&[("set-cookie", "a=1; Domain=firefox.com")], ""),
        );
        assert_eq!(
            jar.header("api.accounts.firefox.com").as_deref(),
            Some("a=1")
        );
        assert_eq!(jar.header("vpn.mozilla.org"), None, "a different domain");
    }

    #[test]
    fn an_agent_names_itself_and_its_accept() {
        assert_eq!(Agent::Api.user_agent(), crate::foxy_account::USER_AGENT);
        assert_eq!(Agent::Page.accept(), HTML_ACCEPT);
        assert_eq!(Agent::Text.accept(), "text/plain");
        assert_eq!(Agent::Page.user_agent(), Agent::Text.user_agent());
        assert_ne!(Agent::Api.user_agent(), Agent::Page.user_agent());
    }

    #[test]
    fn a_proof_of_work_finds_the_two_characters_the_hash_names() {
        let base = "abc";
        let target = ferrox_core::foxy::account::hex_encode(&sha2::Sha256::digest(b"abc5Z"));
        let found = solve_pow(base, &target).expect("a solution exists");
        assert_eq!(&found, b"5Z");
        assert_eq!(solve_pow(base, &"00".repeat(32)), None, "no such pair");
        assert_eq!(solve_pow(base, "abcd"), None, "not 32 bytes");
    }

    #[test]
    fn a_proof_of_work_is_over_the_base_and_the_pair_and_nothing_else() {
        let base = "base";
        let want =
            |bytes: &[u8]| ferrox_core::foxy::account::hex_encode(&sha2::Sha256::digest(bytes));
        assert_eq!(&solve_pow(base, &want(b"basea0")).expect("solved"), b"a0");
        assert!(solve_pow(base, &want(b"othera0")).is_none());
    }

    #[test]
    fn a_page_names_the_prefix_the_later_calls_go_to() {
        assert_eq!(
            prefix_of("<html>go to /_fs-ch-3f9a2b/x.js now</html>"),
            Some("/_fs-ch-3f9a2b")
        );
        assert_eq!(prefix_of("<html>nothing</html>"), None);
        assert_eq!(prefix_of("/_fs-ch-"), None, "no id after the marker");
    }

    #[test]
    fn the_last_init_call_wins_because_the_others_are_scaffolding() {
        let script = "function init(){}\ninit([{\"ty\":\"pow\"}],\"scaffold\",\"x\");\
             init([{\"ty\":\"pow\"},{\"ty\":\"clientmetrics\"}],\"live\",\"y\");";
        let (challenges, token) = parse_init(script).expect("parses");
        let challenges = challenges.as_arr().expect("a list").to_vec();
        assert_eq!(challenges.len(), 2);
        assert_eq!(token, "live");
        assert_eq!(
            challenges[1].get("ty").and_then(Json::as_str),
            Some("clientmetrics")
        );
        assert!(parse_init("no init here").is_none());
        assert!(parse_init("init(\"not a list\",\"t\",\"x\")").is_none());
    }

    #[test]
    fn an_init_call_with_a_bracket_inside_a_string_is_not_cut_short() {
        let script = "init([{\"ty\":\"pow\",\"data\":{\"base\":\"a]b\"}}],\"tok\",\"x\")";
        let (challenges, token) = parse_init(script).expect("parses");
        assert_eq!(token, "tok");
        assert_eq!(challenges.as_arr().expect("a list").len(), 1);
    }

    #[test]
    fn a_token_is_encoded_the_way_a_query_carries_one() {
        assert_eq!(encode("a+b/c=d"), "a%2Bb%2Fc%3Dd");
        assert_eq!(encode("abcXYZ019-_.~"), "abcXYZ019-_.~");
        assert_eq!(encode("a b"), "a%20b");
    }
}
