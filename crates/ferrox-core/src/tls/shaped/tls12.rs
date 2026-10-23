// TLS 1.2's master secret, key block and Finished, through the version's PRF.
use super::kdf;
use super::record::Suite;

pub(super) struct KeyBlock {
    pub client_key: Vec<u8>,
    pub server_key: Vec<u8>,
    pub client_iv: Vec<u8>,
    pub server_iv: Vec<u8>,
}

/// The master secret and both directions' keys: an extended-master-secret
/// transcript when the server accepted the extension, the legacy seed otherwise.
pub(super) fn keys(
    suite: Suite,
    pre_master: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    session_hash: Option<&[u8]>,
) -> (Vec<u8>, KeyBlock) {
    let hash = suite.hash();
    let mut master = vec![0u8; 48];
    if let Some(transcript) = session_hash {
        kdf::prf(
            hash,
            pre_master,
            b"extended master secret",
            transcript,
            &mut master,
        );
    } else {
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(client_random);
        seed.extend_from_slice(server_random);
        kdf::prf(hash, pre_master, b"master secret", &seed, &mut master);
    }
    let key_len = suite.key_len();
    let iv_len = suite.fixed_iv_len();
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let mut block = vec![0u8; 2 * (key_len + iv_len)];
    kdf::prf(hash, &master, b"key expansion", &seed, &mut block);
    let block = KeyBlock {
        client_key: block[..key_len].to_vec(),
        server_key: block[key_len..2 * key_len].to_vec(),
        client_iv: block[2 * key_len..2 * key_len + iv_len].to_vec(),
        server_iv: block[2 * key_len + iv_len..].to_vec(),
    };
    (master, block)
}

pub(super) fn finished(suite: Suite, master: &[u8], label: &[u8], transcript: &[u8]) -> Vec<u8> {
    let hash = suite.hash();
    let hashed = hash.hash(transcript);
    let mut out = vec![0u8; 12];
    kdf::prf(hash, master, label, &hashed, &mut out);
    out
}
