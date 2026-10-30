//! Foxy's account authorisation — Firefox Accounts in, a Guardian proxy pass out — as arithmetic over bytes (stretched password, Hawk MAC, request bodies, expiry) provable against the RFCs without a socket, and nothing here formats or prints a credential.

use crate::b64;
use ring::{digest, hmac, pbkdf2};

/// The OAuth origin serves the same account routes without the Fastly pat wall the API origin now answers with a bare 406.
pub const FXA_SERVER: &str = "https://oauth.accounts.firefox.com/v1";
pub const GUARDIAN_SERVER: &str = "https://vpn.mozilla.org";
pub const FXA_CLIENT_ID: &str = "5882386c6d801776";
pub const OAUTH_SCOPE: &str = "profile https://identity.mozilla.com/apps/vpn";
pub const PROTOCOL: &str = "identity.mozilla.com/picl/v1/";

/// Mozilla raised the `FxA` stretch after 2023, so a client sending 1000 may stop working and the round count is named once here rather than at each call.
pub const STRETCH_ROUNDS: u32 = 1_000;
pub const STRETCH_LEN: usize = 32;
pub const HAWK_KEY_LEN: usize = 32;

/// The stretched password the login carries: PBKDF2 over the password salted with the account and protocol, then HKDF to a fixed width.
#[must_use]
pub fn auth_pw(email: &str, password: &str) -> String {
    let mut quick = [0u8; STRETCH_LEN];
    let mut salt = Vec::with_capacity(PROTOCOL.len() + 14 + email.len());
    salt.extend_from_slice(PROTOCOL.as_bytes());
    salt.extend_from_slice(b"quickStretch:");
    salt.extend_from_slice(email.as_bytes());
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        core::num::NonZeroU32::new(STRETCH_ROUNDS).unwrap_or(core::num::NonZeroU32::MIN),
        &salt,
        password.as_bytes(),
        &mut quick,
    );
    let prk = hkdf_extract(&quick, &NO_SALT);
    hex_encode(&hkdf_expand(&prk, AUTH_PW, 32))
}

const NO_SALT: [u8; 32] = [0u8; 32];
const AUTH_PW: &[u8] = b"identity.mozilla.com/picl/v1/authPW";
const SESSION_TOKEN: &[u8] = b"identity.mozilla.com/picl/v1/sessionToken";

/// HKDF-SHA256 extract: one HMAC, because that is all it is.
#[must_use]
pub fn hkdf_extract(ikm: &[u8], salt: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let tag = hmac::sign(&key, ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Hawk credentials from a session token: the id is the expansion's first half in hex, the MAC key its second half.
#[must_use]
pub fn hawk_credentials(session_token: &str) -> Option<(String, [u8; HAWK_KEY_LEN])> {
    let raw = hex_to_bytes(session_token);
    if raw.len() < 32 {
        return None;
    }
    let prk = hkdf_extract(&raw, &NO_SALT);
    let expanded = hkdf_expand(&prk, SESSION_TOKEN, 64);
    Some((
        hex_encode(&expanded[..32]),
        <[u8; 32]>::try_from(&expanded[32..64]).ok()?,
    ))
}

#[must_use]
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .filter(|pair| pair.len() == 2)
        .filter_map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            Some(((hi << 4) | lo) as u8)
        })
        .collect()
}

#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// HKDF-SHA256 expand: one HMAC per output block, chained.
#[must_use]
pub fn hkdf_expand(prk: &[u8], info: &[u8], want: usize) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, prk);
    let mut out = Vec::with_capacity(want);
    // `T(0)` is empty, not a block of zeros: only the blocks after the first carry the one before them.
    let mut previous: [u8; 32] = [0; 32];
    let mut chained = false;
    let mut block = Vec::with_capacity(32 + info.len() + 1);
    while out.len() < want {
        block.clear();
        if chained {
            block.extend_from_slice(&previous);
        }
        block.extend_from_slice(info);
        block.push(u8::try_from(out.len() / 32 + 1).unwrap_or(255));
        let tag = hmac::sign(&key, &block);
        previous.copy_from_slice(tag.as_ref());
        chained = true;
        out.extend_from_slice(&previous);
    }
    out.truncate(want);
    out
}

/// The Hawk header: `body` hashes under a fixed prefix into it only when there is a body — a hash field versus none, the difference the two grants rely on.
#[must_use]
pub fn hawk_payload_hash(body: &[u8]) -> String {
    if body.is_empty() {
        return String::new();
    }
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(b"hawk.1.payload\napplication/json\n");
    ctx.update(body);
    ctx.update(b"\n");
    b64::encode(ctx.finish().as_ref())
}

/// The normalised string the MAC signs: ten lines, the last of them empty, and the payload hash empty or not.
#[must_use]
pub fn hawk_normalised(
    method: &str,
    path: &str,
    host: &str,
    port: u16,
    body: &[u8],
    timestamp: u64,
    nonce: &str,
) -> String {
    let hash = hawk_payload_hash(body);
    let mut out = String::with_capacity(
        13 + 20 + nonce.len() + method.len() + path.len() + host.len() + hash.len() + 8,
    );
    out.push_str("hawk.1.header\n");
    push_u64(&mut out, timestamp);
    out.push('\n');
    out.push_str(nonce);
    out.push('\n');
    out.push_str(&method.to_ascii_uppercase());
    out.push('\n');
    out.push_str(path);
    out.push('\n');
    out.push_str(host);
    out.push('\n');
    push_u64(&mut out, u64::from(port));
    out.push('\n');
    out.push_str(&hash);
    out.push_str("\n\n");
    out
}

fn push_u64(out: &mut String, value: u64) {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    let mut left = value;
    loop {
        at -= 1;
        digits[at] = b'0' + u8::try_from(left % 10).unwrap_or(0);
        left /= 10;
        if left == 0 {
            break;
        }
    }
    for byte in &digits[at..] {
        out.push(char::from(*byte));
    }
}

/// One request's worth of what Hawk signs: where it went and what it carried.
#[derive(Debug, Clone)]
pub struct Signed<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub body: &'a [u8],
    pub timestamp: u64,
    pub nonce: &'a str,
}

impl Signed<'_> {
    #[must_use]
    pub fn normalised(&self) -> String {
        hawk_normalised(
            self.method,
            self.path,
            self.host,
            self.port,
            self.body,
            self.timestamp,
            self.nonce,
        )
    }

    #[must_use]
    pub fn header(&self, token_id: &str, mac_key: &[u8; HAWK_KEY_LEN]) -> String {
        let hash = hawk_payload_hash(self.body);
        let key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
        let mac = b64::encode(hmac::sign(&key, self.normalised().as_bytes()).as_ref());
        let mut header = format!(
            "Hawk id=\"{token_id}\", ts=\"{}\", nonce=\"{}\", mac=\"{mac}\"",
            self.timestamp, self.nonce
        );
        if !hash.is_empty() {
            header.push_str(", hash=\"");
            header.push_str(&hash);
            header.push('"');
        }
        header
    }
}

/// The login body; `verification_method` asks for the two-factor code, which the account may not have enrolled, so the caller retries without it.
#[must_use]
pub fn login_body(email: &str, auth_pw: &str, verification_method: Option<&str>) -> Vec<u8> {
    body(&[
        ("email", email),
        ("authPW", auth_pw),
        ("verificationMethod", verification_method.unwrap_or("")),
    ])
}

/// The two-factor body, the one call a username and a password cannot make on their own.
#[must_use]
pub fn code_body(code: &str) -> Vec<u8> {
    body(&[("code", code)])
}

/// The token-exchange body, whose grant distinguishes a first login from a refresh: one is signed with Hawk, the other is not.
#[must_use]
pub fn token_body(grant: &str, refresh_token: Option<&str>) -> Vec<u8> {
    let mut fields = vec![
        ("client_id", FXA_CLIENT_ID),
        ("grant_type", grant),
        ("scope", OAUTH_SCOPE),
    ];
    if let Some(refresh) = refresh_token {
        fields.push(("refresh_token", refresh));
    }
    if grant == "fxa-credentials" {
        fields.push(("access_type", "offline"));
    }
    body(&fields)
}

/// A JSON object with the fields in the order the reference writes them, so a request's Hawk payload hash is reproducible from the same field list.
#[must_use]
pub fn body(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut out = String::from("{");
    let mut first = true;
    for (key, value) in fields {
        if value.is_empty() {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        out.push('"');
        out.push_str(key);
        out.push_str("\":\"");
        escape_into(value, &mut out);
        out.push('"');
    }
    out.push('}');
    out.into_bytes()
}

/// Escapes one value into a JSON string body, without the quotes, under the same rules the app's writer uses.
#[must_use]
pub fn escape_json(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    escape_into(value, &mut out);
    out
}

/// The escaped value written into an output that is already building JSON.
pub fn escape_json_into(value: &str, out: &mut String) {
    escape_into(value, out);
}

fn escape_into(value: &str, out: &mut String) {
    for byte in value.bytes() {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x00..=0x1f => {
                out.push('\\');
                out.push('u');
                out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
                out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
            }
            _ => out.push(byte as char),
        }
    }
}

/// The pass's own expiry, read from the JWT when the response omits it; a token that does not parse has no expiry rather than a wrong one.
#[must_use]
pub fn jwt_expiry(token: &str) -> Option<u64> {
    let payload = token.split('.').nth(1)?;
    let raw = b64::decode(payload.as_bytes())?;
    let json = String::from_utf8(raw).ok()?;
    let key = "\"exp\":";
    let at = json.find(key)? + key.len();
    let digits: String = json[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 test case 1, the pair this is two functions of.
    #[test]
    fn hkdf_matches_rfc5869_case_one() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();
        let prk = hkdf_extract(&ikm, &salt);
        assert_eq!(
            hex_encode(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        assert_eq!(
            hex_encode(&hkdf_expand(&prk, &info, 42)),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn an_expansion_is_the_same_prefix_however_much_is_asked_for() {
        let prk = hkdf_extract(b"ikm", b"salt");
        let one = hkdf_expand(&prk, b"info", 32);
        let two = hkdf_expand(&prk, b"info", 64);
        assert_eq!(&two[..32], &one[..]);
        assert_ne!(&two[..32], &two[32..]);
        assert_eq!(two.len(), 64);
        assert_eq!(hkdf_expand(&prk, b"other", 32).len(), 32);
    }

    #[test]
    fn hawk_credentials_are_two_halves_of_one_expansion() {
        let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let (id, mac) = hawk_credentials(token).expect("expands");
        assert_eq!(id.len(), 64, "32 bytes as hex");
        let prk = hkdf_extract(&hex_to_bytes(token), &[0u8; 32]);
        let expanded = hkdf_expand(&prk, b"identity.mozilla.com/picl/v1/sessionToken", 64);
        assert_eq!(id, hex_encode(&expanded[..32]));
        assert_eq!(mac.to_vec(), expanded[32..]);
        assert!(hawk_credentials("zzzz").is_none());
        assert!(hawk_credentials("00").is_none(), "too short to be a token");
    }

    #[test]
    fn the_normalised_string_is_ten_lines_and_the_mac_is_over_it() {
        let mac = [7u8; 32];
        assert_eq!(
            hawk_normalised(
                "get",
                "/v1/oauth/token",
                "api.accounts.firefox.com",
                443,
                b"",
                9,
                "abc"
            ),
            "hawk.1.header\n9\nabc\nGET\n/v1/oauth/token\napi.accounts.firefox.com\n443\n\n\n"
        );
        let signed = Signed {
            method: "POST",
            path: "/v1/account/login",
            host: "api.accounts.firefox.com",
            port: 443,
            body: b"{}",
            timestamp: 1,
            nonce: "n1",
        };
        let with_body = signed.header("id", &mac);
        assert!(with_body.starts_with("Hawk id=\"id\", ts=\"1\", nonce=\"n1\", mac=\""));
        assert!(with_body.contains(", hash=\""), "{with_body}");
        let empty = Signed {
            body: b"",
            ..signed
        };
        let without = empty.header("id", &mac);
        assert!(!without.contains("hash="), "{without}");
        let key = hmac::Key::new(hmac::HMAC_SHA256, &mac);
        let want = b64::encode(hmac::sign(&key, empty.normalised().as_bytes()).as_ref());
        assert!(without.contains(&want), "{without} should carry {want}");
    }

    #[test]
    fn a_hawk_header_changes_with_every_input_it_signs() {
        let mac = [7u8; 32];
        let one = Signed {
            method: "POST",
            path: "/p",
            host: "h",
            port: 443,
            body: b"b",
            timestamp: 1,
            nonce: "n",
        };
        assert!(one.header("i", &mac).contains("mac=\""));
        for other in [
            Signed {
                method: "GET",
                ..one
            }
            .normalised(),
            Signed { path: "/q", ..one }.normalised(),
            Signed { port: 444, ..one }.normalised(),
            Signed { body: b"c", ..one }.normalised(),
            Signed {
                timestamp: 2,
                ..one
            }
            .normalised(),
            Signed { nonce: "m", ..one }.normalised(),
        ] {
            assert_ne!(one.normalised(), other);
        }
    }

    #[test]
    fn a_login_body_asks_for_two_factor_only_when_it_is_asked_for() {
        let plain = String::from_utf8(login_body("a@b.c", "pw", None)).expect("ascii");
        assert_eq!(plain, r#"{"email":"a@b.c","authPW":"pw"}"#);
        let two = String::from_utf8(login_body("a@b.c", "pw", Some("email-2fa"))).expect("ascii");
        assert_eq!(
            two,
            r#"{"email":"a@b.c","authPW":"pw","verificationMethod":"email-2fa"}"#
        );
    }

    #[test]
    fn a_two_factor_body_carries_the_code_and_nothing_else() {
        assert_eq!(
            String::from_utf8(code_body("123456")).expect("ascii"),
            r#"{"code":"123456"}"#
        );
    }

    #[test]
    fn the_two_grants_are_different_bodies_and_only_one_is_hawked() {
        let first = String::from_utf8(token_body("fxa-credentials", None)).expect("ascii");
        assert_eq!(
            first,
            format!(
                r#"{{"client_id":"{FXA_CLIENT_ID}","grant_type":"fxa-credentials","scope":"{OAUTH_SCOPE}","access_type":"offline"}}"#
            )
        );
        assert!(!first.contains("refresh_token"));
        let refresh = String::from_utf8(token_body("refresh_token", Some("rt"))).expect("ascii");
        assert!(refresh.contains(r#""grant_type":"refresh_token""#));
        assert!(!refresh.contains("access_type"));
    }

    #[test]
    fn a_body_escapes_what_json_would_not_carry_raw() {
        assert_eq!(
            String::from_utf8(body(&[("k", "a\"b\\c\nd"), ("e", "")])).expect("ascii"),
            r#"{"k":"a\"b\\c\nd"}"#
        );
    }

    #[test]
    fn the_stretched_password_is_thirty_two_bytes_and_is_not_the_password() {
        let short = auth_pw("a@b.c", "pw");
        assert_eq!(short.len(), 64, "32 bytes as hex");
        assert_ne!(short, "pw");
        assert_ne!(short, auth_pw("a@b.c", "pw2"));
        assert_ne!(short, auth_pw("d@e.f", "pw"), "the account is in the salt");
    }

    #[test]
    fn a_jwt_expiry_is_read_from_the_payload_and_nowhere_else() {
        let claims = br#"{"sub":"x","exp":1735689600}"#;
        let token = format!(
            "aaa.{}.bbb",
            b64::encode(claims).replace('+', "-").replace('/', "_")
        );
        assert_eq!(jwt_expiry(&token), Some(1_735_689_600));
        assert_eq!(jwt_expiry("aaa.bbb"), None);
        assert_eq!(jwt_expiry(""), None);
        assert_eq!(
            jwt_expiry(&format!("aaa.{}.bbb", b64::encode(b"{\"exp\":}"))),
            None
        );
    }
}
