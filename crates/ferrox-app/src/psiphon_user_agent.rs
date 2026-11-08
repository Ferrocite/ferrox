//! The reference's `values.GetUserAgent`: a plausible browser User-Agent drawn
//! from the same five families, so an HTTP dial does not repeat one string.

use crate::psiphon_ssh::dial_random;

/// A random value in `0..bound`.
fn below(bound: usize) -> usize {
    if bound <= 1 {
        return 0;
    }
    usize::try_from(
        u64::from_be_bytes(dial_random::<8>()) % u64::try_from(bound).unwrap_or(u64::MAX),
    )
    .unwrap_or(0)
}

/// A random value in the inclusive range.
fn range(low: usize, high: usize) -> usize {
    low + below(high - low + 1)
}

/// One element of a non-empty list.
fn pick<'a>(values: &'a [&'a str]) -> &'a str {
    values[below(values.len())]
}

fn chrome_version() -> String {
    format!(
        "{}.0.{}.{}",
        range(101, 104),
        range(4951, 5162),
        range(80, 212)
    )
}

fn safari_version() -> String {
    format!("{}.{}.{}", range(537, 611), range(1, 36), range(1, 15))
}

fn webkit_version() -> String {
    if below(2) == 0 {
        safari_version()
    } else {
        format!(
            "600.{}.{}",
            range(1, 8),
            if below(2) == 0 {
                range(10, 17)
            } else {
                range(20, 27)
            }
        )
    }
}

fn version() -> String {
    let patch = if below(2) == 0 {
        String::new()
    } else {
        format!(".{}", range(1, 9) * 10 + range(0, 7))
    };
    format!("{}.{}{patch}", range(10, 14), range(0, 7))
}

fn mac_minor(high: usize) -> String {
    let minor = if below(2) == 0 {
        format!("1{}", range(0, high))
    } else {
        range(0, high).to_string()
    };
    format!("{}_{minor}", range(10, 11))
}

fn android_token() -> String {
    let length = range(5, 10);
    (0..length)
        .map(|_| {
            let index = below(63);
            match index {
                0..=9 => char::from(b'0' + u8::try_from(index).unwrap_or(0)),
                10..=35 => char::from(b'a' + u8::try_from(index - 10).unwrap_or(0)),
                36..=61 => char::from(b'A' + u8::try_from(index - 36).unwrap_or(0)),
                _ => '_',
            }
        })
        .collect()
}

fn mobile_token() -> String {
    (0..6)
        .map(|_| {
            let index = below(36);
            if index < 10 {
                char::from(b'0' + u8::try_from(index).unwrap_or(0))
            } else {
                char::from(b'A' + u8::try_from(index - 10).unwrap_or(0))
            }
        })
        .collect()
}

/// The reference's browser families: Chrome on macOS, Windows and Android, and
/// Safari on iPhone and macOS.
pub(crate) fn generate() -> String {
    match below(5) {
        0 => format!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X {}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{} Safari/537.36",
            mac_minor(5),
            chrome_version()
        ),
        1 => format!(
            "Mozilla/5.0 (Windows NT {}.0; {}{}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{} Safari/537.36",
            pick(&["10", "11"]),
            pick(&["WOW64", "Win64"]),
            if below(2) == 0 { "; x64" } else { "" },
            chrome_version()
        ),
        2 => format!(
            "Mozilla/5.0 (Linux; Android {}; {}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{} Mobile Safari/537.36",
            pick(&["9", "10", "11", "12"]),
            android_token(),
            chrome_version()
        ),
        3 => format!(
            "Mozilla/5.0 (iPhone; CPU iPhone OS {}_{} like Mac OS X) AppleWebKit/{} (KHTML, like Gecko) Version/{} Mobile/{} Safari/{}",
            range(13, 15),
            range(1, 5),
            webkit_version(),
            version(),
            mobile_token(),
            safari_version()
        ),
        _ => format!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X {}{}) AppleWebKit/{} (KHTML, like Gecko) Version/{} Safari/{}",
            mac_minor(7),
            if below(2) == 0 {
                format!("_{}", range(1, 7))
            } else {
                String::new()
            },
            webkit_version(),
            version(),
            safari_version()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_user_agent_is_a_browser_string() {
        for _ in 0..64 {
            let agent = generate();
            assert!(agent.starts_with("Mozilla/5.0 ("));
            assert!(agent.contains("AppleWebKit/"));
            assert!(!agent.contains("__VER__"));
        }
    }

    #[test]
    fn every_family_is_reachable() {
        let mut chrome = false;
        let mut safari = false;
        let mut android = false;
        let mut iphone = false;
        for _ in 0..512 {
            let agent = generate();
            chrome |= agent.contains("Chrome/");
            safari |= agent.contains("Safari/") && agent.contains("Version/");
            android |= agent.contains("Android");
            iphone |= agent.contains("iPhone");
        }
        assert!(chrome);
        assert!(safari);
        assert!(android);
        assert!(iphone);
    }
}
