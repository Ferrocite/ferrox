//! A sign-in the real browser finishes: Guardian's PKCE flow, no password sent by this binary.

use std::io::{IsTerminal as _, Write as _};
use std::process::Command;

use crate::foxy_account::{Auth, Denied, Endpoint, TokenFile};
use crate::foxy_challenge::Jar;
use crate::json::{self, Json};
use sha2::Digest as _;

const LOGIN_PATH: &str = "/api/v2/vpn/login/android";
const VERIFY_PATH: &str = "/api/v2/vpn/login/verify";
const VERIFIER_LEN: usize = 128;
const VERIFIER_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
const LANGUAGE: &str = "en-US,en;q=0.5";

fn verifier() -> String {
    let mut raw = [0u8; VERIFIER_LEN];
    getrandom::fill(&mut raw).unwrap_or_default();
    raw.iter()
        .map(|byte| char::from(VERIFIER_ALPHABET[usize::from(*byte) % VERIFIER_ALPHABET.len()]))
        .collect()
}

fn challenge(verifier: &str) -> String {
    let digest = sha2::Sha256::digest(verifier.as_bytes());
    ferrox_core::b64::encode(&digest)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

fn login_path(challenge: &str) -> String {
    format!(
        "{LOGIN_PATH}?code_challenge={challenge}&code_challenge_method=S256&user_agent={}\
         &utm_medium=vpn-client&utm_source=cli&iap=true",
        crate::foxy_challenge::encode(crate::foxy_account::USER_AGENT)
    )
}

fn verify_body(code: &str, verifier: &str) -> String {
    let body = Json::Obj(vec![
        ("code".to_owned(), Json::Str(code.to_owned())),
        ("code_verifier".to_owned(), Json::Str(verifier.to_owned())),
    ]);
    let mut out = String::new();
    json::write(&body, &mut out);
    out
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' && at + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[at + 1..at + 3]).ok();
            if let Some(byte) = hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                out.push(byte);
                at += 3;
                continue;
            }
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_code(input: &str) -> Option<String> {
    let text = input.trim();
    let found = text.split_once("code=");
    if found.is_none() && text.contains("://") {
        return None;
    }
    let coded = found
        .map_or(text, |(_, tail)| {
            tail.split(['&', '#', ' ', '\n', '\r', '\t'])
                .next()
                .unwrap_or("")
        })
        .trim_matches(['"', '\'']);
    let clean: String = percent_decode(coded)
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~'))
        .collect();
    (clean.len() >= 8).then_some(clean)
}

fn open(url: &str) {
    let mut command = if cfg!(target_os = "macos") {
        let mut command = Command::new("open");
        command.arg(url);
        command
    } else if cfg!(target_os = "windows") {
        let mut command = Command::new("cmd");
        command.args(["/C", "start", "", url]);
        command
    } else {
        let mut command = Command::new("xdg-open");
        command.arg(url);
        command
    };
    if command.spawn().is_err() {
        println!("open this in a browser: {url}");
    }
}

fn ask(prompt: &str) -> Option<String> {
    if !std::io::stdin().is_terminal() {
        return None;
    }
    print!("{prompt}");
    std::io::stdout().flush().ok()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok()?;
    Some(line)
}

/// Signs in through Guardian's PKCE flow and writes the grant the lane resumes, without sending a password from here.
pub(crate) fn login(email: &str, token_file: &str, code: Option<&str>, no_open: bool) -> ! {
    let Some(endpoint) = Endpoint::parse(
        ferrox_core::foxy::account::GUARDIAN_SERVER,
        crate::quic::system_roots(),
    ) else {
        exit("the Guardian endpoint did not parse");
    };
    let jar = std::sync::Mutex::new(Jar::default());
    let verifier = verifier();
    let location = start_url(&endpoint, &verifier);
    if no_open {
        println!("open this in a browser: {location}");
    } else {
        println!("opening the Firefox sign-in in your browser");
        open(&location);
    }
    let code =
        match code.filter(|code| !code.is_empty()) {
            Some(code) => code.to_owned(),
            None => ask("after signing in, paste the code from the address bar: ").unwrap_or_else(
                || exit("no terminal to ask for the code: pass --code or run from a terminal"),
            ),
        };
    let Some(code) = parse_code(&code) else {
        exit("the sign-in did not hand over a usable authorization code");
    };
    let body = verify_body(&code, &verifier);
    let reply = crate::foxy_challenge::send_with_challenge(
        &endpoint,
        &jar,
        "POST",
        VERIFY_PATH,
        &[
            ("Content-Type", crate::foxy_account::JSON_ACCEPT),
            ("Accept-Language", LANGUAGE),
        ],
        body.as_bytes(),
    )
    .unwrap_or_else(|denied: Denied| exit(&format!("the sign-in could not be verified: {denied}")));
    if reply.status != 200 {
        let text = String::from_utf8_lossy(&reply.body);
        exit(&format!(
            "the sign-in was not verified: HTTP {} {}",
            reply.status,
            text.chars().take(200).collect::<String>()
        ));
    }
    let Some(token) = reply.field("token").filter(|token| !token.is_empty()) else {
        exit("the sign-in returned no access token");
    };
    let expires_at = ferrox_core::foxy::account::jwt_expiry(&token)
        .unwrap_or_else(|| crate::foxy_account::epoch() + 86_400);
    let auth = Auth {
        access_token: token,
        refresh_token: String::new(),
        expires_at,
    };
    let Some(tokens) = TokenFile::new(token_file, email) else {
        exit("the browser sign-in needs an account email and a token file path");
    };
    tokens.save(Some(&auth), None);
    println!("signed in; the grant is stored in {token_file}, expires_at={expires_at}");
    std::process::exit(0);
}

/// The Guardian start page the browser itself must load, so the session that registers the code is the browser's own.
fn start_url(endpoint: &Endpoint, verifier: &str) -> String {
    format!(
        "https://{}{}",
        endpoint.host,
        login_path(&challenge(verifier))
    )
}

fn exit(message: &str) -> ! {
    eprintln!("browser-login: {message}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_is_the_rfc_vector() {
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(verifier().len(), VERIFIER_LEN);
    }

    #[test]
    fn a_pasted_code_is_read_from_a_url_or_a_bare_value() {
        assert_eq!(
            parse_code("https://vpn.mozilla.org/oauth/success?code=abcDEF123&state=pkce-x")
                .as_deref(),
            Some("abcDEF123")
        );
        assert_eq!(parse_code("abcDEF123").as_deref(), Some("abcDEF123"));
        assert_eq!(parse_code("abc%2DDEF123").as_deref(), Some("abc-DEF123"));
        assert_eq!(parse_code("  "), None);
    }

    #[test]
    fn the_start_url_names_the_method_and_the_agent() {
        let path = login_path("ch");
        assert!(path.contains("code_challenge=ch"), "{path}");
        assert!(path.contains("code_challenge_method=S256"), "{path}");
        assert!(path.contains("MozillaVPN%2F2.35.0"), "{path}");
    }

    #[test]
    fn a_verify_body_carries_the_code_and_its_verifier() {
        let body = verify_body("c", "v");
        assert!(body.contains(r#""code":"c""#), "{body}");
        assert!(body.contains(r#""code_verifier":"v""#), "{body}");
    }
}
