// TLS 1.2's master secret, key block and Finished, through the version's PRF.
use super::kdf::{self, Mac};
use super::record::{Direction, Suite};

/// A session's two record directions, each keyed from the expansion.
pub(crate) struct Directions {
    pub client: Direction,
    pub server: Direction,
}

/// The master secret and both directions' keys: an extended-master-secret transcript when the
/// server accepted the extension, the legacy seed otherwise.
pub(crate) fn keys(
    suite: Suite,
    pre_master: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    session_hash: Option<&[u8]>,
) -> (Vec<u8>, Directions) {
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
    let directions = directions(suite, &master, client_random, server_random);
    (master, directions)
}

/// `key expansion` over the server-then-client random, cut as RFC 5246 §6.3 lays it out: the two
/// MAC keys, then the two cipher keys, then the two IVs, client first in each pair. An AEAD
/// suite's MAC length is zero, and a CBC suite reserves a whole block of IV that its records never
/// use, because each carries its own in the clear.
pub(crate) fn directions(
    suite: Suite,
    master: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Directions {
    let mac_len = suite.mac().map_or(0, Mac::len);
    let key_len = suite.key_len();
    let iv_len = suite.iv_len();
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let mut block = vec![0u8; 2 * (mac_len + key_len + iv_len)];
    kdf::prf(suite.hash(), master, b"key expansion", &seed, &mut block);
    let pair = |offset: usize, len: usize| {
        (
            &block[offset..offset + len],
            &block[offset + len..offset + 2 * len],
        )
    };
    let (client_mac, server_mac) = pair(0, mac_len);
    let (client_key, server_key) = pair(2 * mac_len, key_len);
    let (client_iv, server_iv) = pair(2 * mac_len + 2 * key_len, iv_len);
    Directions {
        client: Direction::tls12(suite, client_key, client_mac, client_iv),
        server: Direction::tls12(suite, server_key, server_mac, server_iv),
    }
}

pub(crate) fn finished(suite: Suite, master: &[u8], label: &[u8], transcript: &[u8]) -> Vec<u8> {
    let hash = suite.hash();
    let hashed = hash.hash(transcript);
    let mut out = vec![0u8; 12];
    kdf::prf(hash, master, label, &hashed, &mut out);
    out
}
