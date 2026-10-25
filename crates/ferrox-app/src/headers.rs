/// The browser a masked request claims to be when the config names none.
const CHROME_UA: &str = concat!(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144",
    ".0.0.0 Safari/537.36"
);
const CHROME_UACH: &str =
    "\"Not:A-Brand\";v=\"99\", \"Chromium\";v=\"144\", \"Google Chrome\";v=\"144\"";

/// The headers xray's WebSocket and `HTTPUpgrade` dials add under a custom set.
pub(crate) const WS: &[(&str, &str)] = &[
    ("User-Agent", CHROME_UA),
    ("Accept", "*/*"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("Cache-Control", "no-cache"),
    ("DNT", "1"),
    ("Pragma", "no-cache"),
    ("Sec-CH-UA", CHROME_UACH),
    ("Sec-CH-UA-Mobile", "?0"),
    ("Sec-CH-UA-Platform", "\"Windows\""),
    ("Sec-Fetch-Dest", "empty"),
    ("Sec-Fetch-Mode", "websocket"),
    ("Sec-Fetch-Site", "same-origin"),
];

/// The same set for xHTTP's fetch-shaped requests.
pub(crate) const FETCH: &[(&str, &str)] = &[
    ("User-Agent", CHROME_UA),
    ("Accept", "*/*"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("Cache-Control", "no-cache"),
    ("DNT", "1"),
    ("Pragma", "no-cache"),
    ("Priority", "u=1, i"),
    ("Sec-CH-UA", CHROME_UACH),
    ("Sec-CH-UA-Mobile", "?0"),
    ("Sec-CH-UA-Platform", "\"Windows\""),
    ("Sec-Fetch-Dest", "empty"),
    ("Sec-Fetch-Mode", "cors"),
    ("Sec-Fetch-Site", "same-origin"),
];

/// The handshake names a configured header may not restate: the request builder writes each one itself.
fn fixed(name: &str) -> bool {
    [
        "host",
        "connection",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-version",
        "content-length",
        "transfer-encoding",
    ]
    .iter()
    .any(|fixed| name.eq_ignore_ascii_case(fixed))
}

/// xray reads a `User-Agent` naming a browser as a selector for its own masked set rather than a value to send.
fn selector(value: &str) -> bool {
    ["chrome", "firefox", "safari", "edge", "curl", "golang"]
        .iter()
        .any(|browser| value.eq_ignore_ascii_case(browser))
}

fn suppressed(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(key, value)| {
        key.eq_ignore_ascii_case(name)
            && !(name.eq_ignore_ascii_case("user-agent") && selector(value))
    })
}

fn line(name: &str, value: &str) -> usize {
    name.len() + 2 + value.len() + 2
}

/// The bytes `masked` would write, without staging them first.
pub(crate) fn masked_len(headers: &[(String, String)], defaults: &[(&str, &str)]) -> usize {
    defaults
        .iter()
        .filter(|(name, _)| !suppressed(headers, name))
        .map(|(name, value)| line(name, value))
        .sum::<usize>()
        + headers
            .iter()
            .filter(|(name, value)| {
                !(fixed(name) || (name.eq_ignore_ascii_case("user-agent") && selector(value)))
            })
            .map(|(name, value)| line(name, value))
            .sum::<usize>()
}

/// Append the header lines a dial writes before its blank line: the browser defaults the config did not override, then the config's own headers.
pub(crate) fn write_masked(
    out: &mut Vec<u8>,
    headers: &[(String, String)],
    defaults: &[(&str, &str)],
) {
    for &(name, value) in defaults {
        if !suppressed(headers, name) {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    for (name, value) in headers {
        if fixed(name) || (name.eq_ignore_ascii_case("user-agent") && selector(value)) {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
}

/// The same lines as one `String` for the dials that build their head with `format!`.
pub(crate) fn masked(headers: &[(String, String)], defaults: &[(&str, &str)]) -> String {
    let mut out = Vec::with_capacity(masked_len(headers, defaults));
    write_masked(&mut out, headers, defaults);
    String::from_utf8(out).expect("header names and values are UTF-8")
}

/// The `Host` a configured header names, if any.
pub(crate) fn host(headers: &[(String, String)]) -> Option<&str> {
    headers
        .iter()
        .find(|(name, value)| name.eq_ignore_ascii_case("host") && !value.is_empty())
        .map(|(_, value)| value.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_configured_header_is_written_after_the_defaults_it_does_not_override() {
        let headers = vec![("X-Custom".to_owned(), "1".to_owned())];
        let text = masked(&headers, WS);
        assert!(text.contains("User-Agent: Mozilla/5.0"));
        assert!(text.contains("Sec-Fetch-Mode: websocket"));
        assert!(text.contains("X-Custom: 1\r\n"));
    }

    #[test]
    fn a_configured_name_replaces_its_default_and_a_browser_selector_masks_the_user_agent() {
        let headers = vec![
            ("Accept".to_owned(), "text/plain".to_owned()),
            ("User-Agent".to_owned(), "chrome".to_owned()),
        ];
        let text = masked(&headers, WS);
        assert!(!text.contains("Accept: */*"));
        assert!(text.contains("Accept: text/plain\r\n"));
        assert!(!text.contains("User-Agent: chrome"));
        assert!(text.contains("User-Agent: Mozilla/5.0"));
    }

    #[test]
    fn the_request_builder_owns_the_handshake_names() {
        let headers = vec![
            ("Host".to_owned(), "front.example".to_owned()),
            ("Connection".to_owned(), "close".to_owned()),
            ("X-Custom".to_owned(), "1".to_owned()),
        ];
        let text = masked(&headers, &[]);
        assert!(!text.contains("Host:"));
        assert!(!text.contains("Connection:"));
        assert!(text.contains("X-Custom: 1\r\n"));
        assert_eq!(host(&headers), Some("front.example"));
    }
}
