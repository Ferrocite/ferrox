use crate::json::Json;
use std::sync::Arc;
use std::time::Duration;

pub(crate) fn inbound_reality_config(
    inbound: &Json,
) -> Option<ferrox_core::tls::RealityServerConfig> {
    let settings = inbound.get("streamSettings")?;
    if settings.get("security").and_then(Json::as_str) != Some("reality") {
        return None;
    }
    let reality = settings.get("realitySettings")?;
    let short_ids: Vec<[u8; 8]> = reality
        .get("shortIds")?
        .as_arr()?
        .iter()
        .filter_map(|item| item.as_str().and_then(short_id))
        .collect();
    if short_ids.is_empty() {
        return None;
    }
    let server_names: Vec<String> = reality
        .get("serverNames")?
        .as_arr()?
        .iter()
        .filter_map(|item| item.as_str())
        .map(str::to_owned)
        .collect();
    if server_names.is_empty() {
        return None;
    }
    Some(ferrox_core::tls::RealityServerConfig {
        private_key: reality.get("privateKey")?.as_str().and_then(key32)?,
        short_ids,
        server_names,
        max_time_skew: reality
            .get("maxTimeDiff")
            .and_then(as_millis)
            .map(Duration::from_millis),
        min_client_ver: reality
            .get("minClientVer")
            .and_then(Json::as_str)
            .and_then(client_ver),
        max_client_ver: reality
            .get("maxClientVer")
            .and_then(Json::as_str)
            .and_then(client_ver),
        limit_fallback_upload: reality.get("limitFallbackUpload").and_then(rate_limit),
        limit_fallback_download: reality.get("limitFallbackDownload").and_then(rate_limit),
        dest: reality
            .get("dest")
            .and_then(Json::as_str)
            .filter(|d| !d.is_empty())
            .map(str::to_owned),
        xver: reality
            .get("xver")
            .and_then(as_uint)
            .and_then(|n| u8::try_from(n).ok())
            .unwrap_or(0),
        show: reality.get("show").and_then(Json::as_bool).unwrap_or(false),
    })
}

fn client_ver(text: &str) -> Option<[u8; 3]> {
    let mut out = [0u8; 3];
    let mut at = 0;
    for part in text.split('.') {
        let value = part.parse::<u8>().ok()?;
        *out.get_mut(at)? = value;
        at += 1;
    }
    (at > 0).then_some(out)
}

fn rate_limit(node: &Json) -> Option<ferrox_core::tls::RateLimit> {
    Some(ferrox_core::tls::RateLimit {
        after_bytes: node.get("afterBytes").and_then(as_uint)?,
        bytes_per_sec: node.get("bytesPerSec").and_then(as_uint)?,
        burst_bytes_per_sec: node.get("burstBytesPerSec").and_then(as_uint)?,
    })
}

fn as_uint(node: &Json) -> Option<u64> {
    if let Json::Num(n) = node {
        if *n >= 0.0 && n.fract() == 0.0 {
            return u64::try_from(*n as i64).ok();
        }
    }
    None
}

/// Xray fills the eight bytes from the front and zero-pads the tail, so `a8` is `a8 00 ...`, never `00 ... a8`.
pub(crate) fn short_id(hex: &str) -> Option<[u8; 8]> {
    let mut out = [0u8; 8];
    if hex.is_empty() || hex.len() > 16 || !hex.len().is_multiple_of(2) {
        return None;
    }
    for (i, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

pub(crate) fn key32(text: &str) -> Option<[u8; 32]> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut word = 0u32;
    let mut bits = 0;
    let mut out = Vec::with_capacity(32);
    for byte in text.bytes() {
        let value = ALPHABET.iter().position(|c| *c == byte)? as u32;
        word = (word << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((word >> bits) as u8);
        }
    }
    <[u8; 32]>::try_from(out).ok()
}

fn as_millis(node: &Json) -> Option<u64> {
    match node {
        Json::Num(n) if *n >= 0.0 && n.fract() == 0.0 => Some(*n as u64),
        _ => None,
    }
}

pub(crate) fn inbound_tls_identity(
    inbound: &Json,
) -> Option<Arc<ferrox_core::tls::TlsServerConfig>> {
    let settings = inbound.get("streamSettings")?;
    if settings.get("security").and_then(Json::as_str) != Some("tls") {
        return None;
    }
    let (cert_pem, key_pem) = tls_cert_pem(settings)?;
    ferrox_core::tls::parse_pem_identity(&cert_pem, &key_pem)
        .ok()
        .map(Arc::new)
}

/// PEM for the first certificate entry, in either spelling xray accepts: `certificateFile`/`keyFile` paths, or an inline `certificate`/`key` given as a string or as an array of PEM lines. A peer that hands over a bare TLS listener (a REALITY decoy, say) uses the inline form, so refusing it here leaves the inbound serving nothing.
fn tls_cert_pem(settings: &Json) -> Option<(Vec<u8>, Vec<u8>)> {
    let first = settings
        .get("tlsSettings")?
        .get("certificates")?
        .as_arr()?
        .first()?;
    if let (Some(cert_path), Some(key_path)) = (
        first.get("certificateFile").and_then(Json::as_str),
        first.get("keyFile").and_then(Json::as_str),
    ) {
        return Some((
            std::fs::read(cert_path).ok()?,
            std::fs::read(key_path).ok()?,
        ));
    }
    let inline = |field: &str| -> Option<Vec<u8>> {
        let value = first.get(field)?;
        if let Some(text) = value.as_str() {
            return Some(text.as_bytes().to_vec());
        }
        let lines = value.as_arr()?;
        Some(
            lines
                .iter()
                .filter_map(Json::as_str)
                .collect::<Vec<_>>()
                .join("\n")
                .into_bytes(),
        )
    };
    Some((inline("certificate")?, inline("key")?))
}

pub(crate) fn tls_cert_paths(settings: &Json) -> Option<(&str, &str)> {
    let first = settings
        .get("tlsSettings")?
        .get("certificates")?
        .as_arr()?
        .first()?;
    Some((
        first.get("certificateFile")?.as_str()?,
        first.get("keyFile")?.as_str()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_id_hex_fills_from_the_front() {
        assert_eq!(short_id("a8"), Some([0xa8, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(short_id("01020304"), Some([1, 2, 3, 4, 0, 0, 0, 0]));
        assert_eq!(short_id(""), None);
        assert_eq!(short_id("abc"), None);
    }

    #[test]
    fn tls_cert_paths_read_the_first_certificate() {
        let tls = crate::json::parse(
            r#"{"streamSettings": {"security": "tls", "tlsSettings": {"certificates": [{"certificateFile": "/tmp/a.crt", "keyFile": "/tmp/a.key"}]}}}"#,
        )
        .expect("parses");
        let settings = tls.get("streamSettings").expect("settings");
        assert_eq!(tls_cert_paths(settings), Some(("/tmp/a.crt", "/tmp/a.key")));
        assert!(inbound_tls_identity(&tls).is_none());
        let plain =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp"}}"#).expect("parses");
        let settings = plain.get("streamSettings").expect("settings");
        assert_eq!(tls_cert_paths(settings), None);
    }

    #[test]
    fn inbound_tls_identity_reads_an_inline_certificate() {
        let minted =
            rcgen::generate_simple_self_signed(vec!["tls.test".to_owned()]).expect("mints");
        let lines_json = |pem: &str| -> String {
            pem.trim_end()
                .lines()
                .map(|line| format!("\"{line}\""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let string_json = |pem: &str| -> String {
            format!(
                "\"{}\"",
                pem.trim_end().replace('\r', "").replace('\n', "\\n")
            )
        };
        // The array-of-lines spelling a REALITY decoy hands over.
        let array_form = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"certificates": [{{"certificate": [{}], "key": [{}]}}]}}}}}}"#,
            lines_json(&minted.cert.pem()),
            lines_json(&minted.key_pair.serialize_pem())
        ))
        .expect("parses");
        assert!(
            inbound_tls_identity(&array_form).is_some(),
            "an inline certificate/key array loads, so the inbound binds"
        );
        // The single-string spelling resolves to the same identity.
        let string_form = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"certificates": [{{"certificate": {}, "key": {}}}]}}}}}}"#,
            string_json(&minted.cert.pem()),
            string_json(&minted.key_pair.serialize_pem())
        ))
        .expect("parses");
        assert!(
            inbound_tls_identity(&string_form).is_some(),
            "an inline certificate/key string loads too"
        );
    }
}
