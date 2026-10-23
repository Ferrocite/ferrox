use crate::b64;
#[cfg(test)]
use x25519_dalek::{PublicKey, StaticSecret};

pub(crate) const VERSION: u16 = 0xfe0d;
pub(crate) const KEM_X25519: u16 = 0x0020;
pub(crate) const KDF_SHA256: u16 = 0x0001;
pub(crate) const AEAD_AES_128_GCM: u16 = 0x0001;
pub(crate) const AEAD_CHACHA20_POLY1305: u16 = 0x0003;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Config {
    pub(crate) id: u8,
    pub(crate) kem_id: u16,
    pub(crate) public_key: Vec<u8>,
    pub(crate) cipher_suites: Vec<(u16, u16)>,
    pub(crate) maximum_name_length: u8,
    pub(crate) public_name: Vec<u8>,
    pub(crate) extensions: Vec<u8>,
}

impl Config {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let suites = self.cipher_suites.len() * 4;
        let contents = 1
            + 2
            + 2
            + self.public_key.len()
            + 2
            + suites
            + 1
            + 1
            + self.public_name.len()
            + 2
            + self.extensions.len();
        // The length is known before the first byte, so the config lands in one buffer and no contents copy.
        let mut out = Vec::with_capacity(4 + contents);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&(contents as u16).to_be_bytes());
        out.push(self.id);
        out.extend_from_slice(&self.kem_id.to_be_bytes());
        out.extend_from_slice(&(self.public_key.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&(suites as u16).to_be_bytes());
        for (kdf, aead) in &self.cipher_suites {
            out.extend_from_slice(&kdf.to_be_bytes());
            out.extend_from_slice(&aead.to_be_bytes());
        }
        out.push(self.maximum_name_length);
        out.push(self.public_name.len() as u8);
        out.extend_from_slice(&self.public_name);
        out.extend_from_slice(&(self.extensions.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.extensions);
        out
    }

    fn decode_at(bytes: &[u8], at: &mut usize, end: usize) -> Result<Self, String> {
        let version = take_u16(bytes, at, end)?;
        if version != VERSION {
            return Err(format!("ech: unsupported version {version:#06x}"));
        }
        let length = usize::from(take_u16(bytes, at, end)?);
        let config_end = at
            .checked_add(length)
            .filter(|config_end| *config_end <= end)
            .ok_or("ech: config length past the end")?;
        let id = take_u8(bytes, at, config_end)?;
        let kem_id = take_u16(bytes, at, config_end)?;
        let public_key = take_vec16(bytes, at, config_end)?;
        let suites_len = usize::from(take_u16(bytes, at, config_end)?);
        if suites_len % 4 != 0 {
            return Err("ech: cipher suite list is not four-byte entries".to_owned());
        }
        let suites_end = at
            .checked_add(suites_len)
            .filter(|suites_end| *suites_end <= config_end)
            .ok_or("ech: cipher suite list past the end")?;
        let mut cipher_suites = Vec::with_capacity(suites_len / 4);
        while *at < suites_end {
            let kdf = take_u16(bytes, at, suites_end)?;
            let aead = take_u16(bytes, at, suites_end)?;
            cipher_suites.push((kdf, aead));
        }
        let maximum_name_length = take_u8(bytes, at, config_end)?;
        let name_len = usize::from(take_u8(bytes, at, config_end)?);
        let public_name = take(bytes, at, name_len, config_end)?.to_vec();
        let extensions = take_vec16(bytes, at, config_end)?;
        if *at != config_end {
            return Err("ech: trailing bytes in config".to_owned());
        }
        Ok(Self {
            id,
            kem_id,
            public_key,
            cipher_suites,
            maximum_name_length,
            public_name,
            extensions,
        })
    }

    pub(crate) fn has_unknown_mandatory_extension(&self) -> bool {
        let mut at = 0;
        while at < self.extensions.len() {
            if self.extensions.len() - at < 4 {
                return true;
            }
            let kind = u16::from_be_bytes([self.extensions[at], self.extensions[at + 1]]);
            let len = usize::from(u16::from_be_bytes([
                self.extensions[at + 2],
                self.extensions[at + 3],
            ]));
            let next = at + 4 + len;
            if next > self.extensions.len() || kind & 0x8000 != 0 {
                return true;
            }
            at = next;
        }
        false
    }

    fn single(bytes: &[u8]) -> Result<Self, String> {
        let mut at = 0;
        let config = Self::decode_at(bytes, &mut at, bytes.len())?;
        if at != bytes.len() {
            return Err("ech: trailing bytes after config".to_owned());
        }
        Ok(config)
    }
}

pub(crate) fn parse_config_list(bytes: &[u8]) -> Result<Vec<Config>, String> {
    let mut at = 0;
    let length = usize::from(take_u16(bytes, &mut at, bytes.len())?);
    let end = at
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or("ech: config list length past the end")?;
    if end != bytes.len() {
        return Err("ech: trailing bytes after the config list".to_owned());
    }
    let mut configs = Vec::new();
    while at < end {
        if end - at < 4 {
            return Err("ech: short config header".to_owned());
        }
        let version = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
        let length = usize::from(u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]));
        let config_end = at
            .checked_add(4 + length)
            .filter(|config_end| *config_end <= end)
            .ok_or("ech: config length past the end")?;
        if version == VERSION {
            configs.push(Config::decode_at(bytes, &mut at, end)?);
        } else {
            at = config_end;
        }
    }
    if at != end {
        return Err("ech: trailing bytes in config list".to_owned());
    }
    if configs.is_empty() {
        return Err("ech: no supported config in the list".to_owned());
    }
    Ok(configs)
}

#[cfg(test)]
pub(crate) fn encode_config_list(configs: &[Config]) -> Vec<u8> {
    let encoded: Vec<Vec<u8>> = configs.iter().map(Config::encode).collect();
    let mut out = Vec::with_capacity(2 + encoded.iter().map(Vec::len).sum::<usize>());
    out.extend_from_slice(&(encoded.iter().map(Vec::len).sum::<usize>() as u16).to_be_bytes());
    for config in encoded {
        out.extend_from_slice(&config);
    }
    out
}

pub(crate) fn normalize_config_list(bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    if parse_config_list(&bytes).is_ok() {
        return Ok(bytes);
    }
    if Config::single(&bytes).is_ok() {
        let length = u16::try_from(bytes.len()).map_err(|_| "ech: config too long")?;
        let mut out = Vec::with_capacity(2 + bytes.len());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&bytes);
        return Ok(out);
    }
    Err("ech: neither a config list nor a config".to_owned())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerKey {
    pub(crate) private_key: Vec<u8>,
    pub(crate) config: Vec<u8>,
}

pub(crate) fn parse_server_keys(bytes: &[u8]) -> Result<Vec<ServerKey>, String> {
    let mut keys = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let private_key = take_vec16(bytes, &mut at, bytes.len())?;
        let config = take_vec16(bytes, &mut at, bytes.len())?;
        if private_key.len() != 32 {
            return Err("ech: server key is not a 32-byte X25519 secret".to_owned());
        }
        Config::single(&config)?;
        keys.push(ServerKey {
            private_key,
            config,
        });
    }
    if keys.is_empty() {
        return Err("ech: no server keys".to_owned());
    }
    Ok(keys)
}

#[cfg(test)]
pub(crate) fn encode_server_keys(keys: &[ServerKey]) -> Vec<u8> {
    let mut out = Vec::new();
    for key in keys {
        out.extend_from_slice(&(key.private_key.len() as u16).to_be_bytes());
        out.extend_from_slice(&key.private_key);
        out.extend_from_slice(&(key.config.len() as u16).to_be_bytes());
        out.extend_from_slice(&key.config);
    }
    out
}

#[cfg(test)]
pub(crate) fn generate(public_name: &str, config_id: u8) -> Result<(Vec<u8>, Vec<u8>), String> {
    if public_name.is_empty() || public_name.len() > 255 {
        return Err("ech: public name must be 1..=255 bytes".to_owned());
    }
    let mut private = [0u8; 32];
    getrandom::fill(&mut private).map_err(|_| "ech: no randomness")?;
    let public = PublicKey::from(&StaticSecret::from(private)).to_bytes();
    let config = Config {
        id: config_id,
        kem_id: KEM_X25519,
        public_key: public.to_vec(),
        cipher_suites: vec![
            (KDF_SHA256, AEAD_AES_128_GCM),
            (KDF_SHA256, AEAD_CHACHA20_POLY1305),
        ],
        maximum_name_length: 0,
        public_name: public_name.as_bytes().to_vec(),
        extensions: Vec::new(),
    };
    let config_bytes = config.encode();
    let list = encode_config_list(&[config]);
    let keys = encode_server_keys(&[ServerKey {
        private_key: private.to_vec(),
        config: config_bytes,
    }]);
    Ok((list, keys))
}

pub(crate) fn decode_source(text: &str, label: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    let body = if text.starts_with("-----BEGIN") {
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let after = text
            .split_once(begin.as_str())
            .ok_or_else(|| format!("ech: no {label} PEM block"))?
            .1;
        after
            .split_once(end.as_str())
            .ok_or_else(|| format!("ech: unterminated {label} PEM block"))?
            .0
    } else {
        text
    };
    let clean: Vec<u8> = body
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    b64::decode(&clean).ok_or_else(|| format!("ech: {label} is not base64"))
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, len: usize, end: usize) -> Result<&'a [u8], String> {
    let next = at
        .checked_add(len)
        .filter(|next| *next <= end)
        .ok_or("ech: field past the end")?;
    let out = &bytes[*at..next];
    *at = next;
    Ok(out)
}

fn take_u8(bytes: &[u8], at: &mut usize, end: usize) -> Result<u8, String> {
    let field = take(bytes, at, 1, end)?;
    Ok(field[0])
}

fn take_u16(bytes: &[u8], at: &mut usize, end: usize) -> Result<u16, String> {
    let field = take(bytes, at, 2, end)?;
    Ok(u16::from_be_bytes([field[0], field[1]]))
}

fn take_vec16(bytes: &[u8], at: &mut usize, end: usize) -> Result<Vec<u8>, String> {
    let len = usize::from(take_u16(bytes, at, end)?);
    Ok(take(bytes, at, len, end)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(miri, ignore = "uses the OS random source")]
    #[test]
    fn a_generated_pair_round_trips() {
        let (list, keys) = generate("cloudflare-ech.com", 7).unwrap();
        let configs = parse_config_list(&list).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].id, 7);
        assert_eq!(configs[0].kem_id, KEM_X25519);
        assert_eq!(configs[0].public_key.len(), 32);
        assert_eq!(configs[0].public_name, b"cloudflare-ech.com");
        assert_eq!(encode_config_list(&configs), list);

        let parsed = parse_server_keys(&keys).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].private_key.len(), 32);
        assert_eq!(parsed[0].config, configs[0].encode());
        assert_eq!(encode_server_keys(&parsed), keys);
    }

    /// The configs are framed before the first byte is written: one buffer, no contents copy or regrowth.
    #[cfg_attr(miri, ignore = "uses the OS random source")]
    #[test]
    fn an_encoded_config_is_one_buffer() {
        let (list, _) = generate("example.com", 0).unwrap();
        let config = parse_config_list(&list).unwrap().remove(0);
        let (bytes, counts) = crate::alloc_count::measure(|| config.encode());
        assert_eq!(counts.allocs, 1, "one reservation holds the whole config");
        assert_eq!(bytes, config.encode(), "the bytes are unchanged");
    }

    #[cfg_attr(miri, ignore = "uses the OS random source")]
    #[test]
    fn a_bare_config_is_wrapped() {
        let (list, _) = generate("example.com", 0).unwrap();
        let config = parse_config_list(&list).unwrap()[0].encode();
        assert_eq!(normalize_config_list(config.clone()).unwrap(), list);
        assert_eq!(normalize_config_list(list.clone()).unwrap(), list);
    }

    #[cfg_attr(miri, ignore = "uses the OS random source")]
    #[test]
    fn pem_and_base64_sources_decode() {
        let (list, keys) = generate("example.com", 0).unwrap();
        let list_pem = format!(
            "-----BEGIN ECH CONFIGS-----\n{}\n-----END ECH CONFIGS-----\n",
            b64::encode(&list)
        );
        let keys_pem = format!(
            "-----BEGIN ECH KEYS-----\n{}\n-----END ECH KEYS-----\n",
            b64::encode(&keys)
        );
        assert_eq!(decode_source(&list_pem, "ECH CONFIGS").unwrap(), list);
        assert_eq!(decode_source(&keys_pem, "ECH KEYS").unwrap(), keys);
        assert_eq!(
            decode_source(&b64::encode(&list), "ECH CONFIGS").unwrap(),
            list
        );
    }

    #[cfg_attr(miri, ignore = "uses the OS random source")]
    #[test]
    fn an_unsupported_version_is_skipped() {
        let (list, _) = generate("example.com", 7).unwrap();
        let mut body = vec![0xfe, 0x0e, 0x00, 0x04, 0, 0, 0, 0];
        body.extend_from_slice(&list[2..]);
        let mut bytes = (body.len() as u16).to_be_bytes().to_vec();
        bytes.extend_from_slice(&body);
        let configs = parse_config_list(&bytes).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].public_name, b"example.com");
    }

    #[test]
    fn malformed_inputs_are_refused() {
        assert!(parse_config_list(&[]).is_err());
        assert!(parse_config_list(&[0, 3, 0xfe, 0x0d]).is_err());
        assert!(parse_server_keys(&[]).is_err());
        assert!(parse_server_keys(&[0, 32]).is_err());
        assert!(decode_source("not base64!", "ECH CONFIGS").is_err());
    }
}
