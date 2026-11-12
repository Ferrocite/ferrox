// Psiphon's obfuscated session ticket: a client-made session state, encrypted to a shared key, carried as a ticket or a TLS 1.3 PSK.
use super::kdf::{self, Hash};
use crate::tls::TlsError;
use aes::Aes128;
use ctr::cipher::{KeyIvInit as _, StreamCipher as _};
use ring::hmac;
use std::time::{SystemTime, UNIX_EPOCH};

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

const PADDED: [usize; 8] = [160, 176, 192, 208, 218, 224, 240, 255];
const INITIAL: usize = 120;
pub(super) const TLS12_SUITE: u16 = 0xc02f;
pub(super) const TLS13_SUITE: u16 = 0x1301;
const X25519: u16 = 0x001d;

/// One client-made session: the encoded ticket, the master secret or PSK it resumes, and the age
/// the PSK extension reports.
pub(crate) struct Ticket {
    pub(crate) bytes: Vec<u8>,
    pub(crate) secret: [u8; 48],
    pub(crate) tls13: bool,
    age_add: u32,
    created: u64,
}

impl Ticket {
    /// Builds and encrypts the state `NewObfuscatedClientSessionState` makes for one dial.
    pub(crate) fn new(shared: &[u8; 32], tls13: bool, ems: bool) -> Result<Self, TlsError> {
        let mut secret = [0u8; 48];
        random(&mut secret)?;
        let mut age = [0u8; 4];
        random(&mut age)?;
        let age_add = u32::from_le_bytes(age);
        let created = now_secs();
        let (version, suite) = if tls13 {
            (0x0304u16, TLS13_SUITE)
        } else {
            (0x0303, TLS12_SUITE)
        };
        let mut state = Vec::with_capacity(128);
        state.extend_from_slice(&version.to_be_bytes());
        state.push(1);
        state.extend_from_slice(&suite.to_be_bytes());
        state.extend_from_slice(&created.to_be_bytes());
        state.push(48);
        state.extend_from_slice(&secret);
        state.extend_from_slice(&[0, 0, 0]);
        state.push(u8::from(ems));
        state.push(0);
        state.extend_from_slice(&[0, 0, 0]);
        state.extend_from_slice(&[0, 0, 0]);
        if !tls13 {
            state.extend_from_slice(&X25519.to_be_bytes());
        }
        let mut pick = [0u8; 1];
        random(&mut pick)?;
        state.resize(
            state.len() + PADDED[usize::from(pick[0]) % PADDED.len()] - INITIAL,
            0,
        );
        let bytes = encrypt(shared, &state)?;
        Ok(Self {
            bytes,
            secret,
            tls13,
            age_add,
            created,
        })
    }

    /// The `obfuscated_ticket_age` a PSK identity carries: whole seconds since creation, plus the
    /// observable random offset the server subtracts.
    pub(crate) fn age(&self) -> u32 {
        let elapsed = now_secs().saturating_sub(self.created);
        u32::try_from(elapsed)
            .unwrap_or(u32::MAX)
            .wrapping_mul(1000)
            .wrapping_add(self.age_add)
    }
}

/// Fills an existing encrypted ticket's sole binder from the ticket secret.
pub(crate) fn complete_binder(msg: &mut [u8], prefix: &[u8], secret: &[u8; 48]) {
    let Some((truncated, range)) = binder_span(msg) else {
        return;
    };
    let early = kdf::extract(Hash::Sha256, &[], secret);
    let binder_key = kdf::derive(Hash::Sha256, &early, b"res binder", &[]);
    let finished = kdf::finished_key(Hash::Sha256, &binder_key);
    let binder = kdf::verify_data_parts(Hash::Sha256, &finished, &[prefix, &msg[..truncated]]);
    if range.len() == binder.len() {
        msg[range].copy_from_slice(&binder);
    }
}

fn encrypt(shared: &[u8; 32], state: &[u8]) -> Result<Vec<u8>, TlsError> {
    let hashed = ring::digest::digest(&ring::digest::SHA512, shared);
    let hashed = hashed.as_ref();
    let mut iv = [0u8; 16];
    random(&mut iv)?;
    let mut out = Vec::with_capacity(16 + state.len() + 32);
    out.extend_from_slice(&iv);
    out.extend_from_slice(state);
    Aes128Ctr::new_from_slices(&hashed[16..32], &iv)
        .map_err(|e| TlsError::Other(format!("ticket cipher: {e}")))?
        .apply_keystream(&mut out[16..]);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &hashed[32..48]);
    let tag = hmac::sign(&key, &out);
    out.extend_from_slice(tag.as_ref());
    Ok(out)
}

fn binder_span(msg: &[u8]) -> Option<(usize, std::ops::Range<usize>)> {
    let mut at = 4 + 2 + 32;
    at += 1 + usize::from(*msg.get(at)?);
    let ciphers = usize::from(u16::from_be_bytes([*msg.get(at)?, *msg.get(at + 1)?]));
    at += 2 + ciphers;
    at += 1 + usize::from(*msg.get(at)?);
    let extensions = usize::from(u16::from_be_bytes([*msg.get(at)?, *msg.get(at + 1)?]));
    at += 2;
    let end = at.checked_add(extensions)?.min(msg.len());
    while at + 4 <= end {
        let kind = u16::from_be_bytes([msg[at], msg[at + 1]]);
        let len = usize::from(u16::from_be_bytes([msg[at + 2], msg[at + 3]]));
        let body = at + 4;
        let body_end = body.checked_add(len)?;
        if body_end > msg.len() {
            return None;
        }
        if kind == 0x0029 {
            let identities =
                usize::from(u16::from_be_bytes([*msg.get(body)?, *msg.get(body + 1)?]));
            let binders = body.checked_add(2 + identities)?;
            let length = usize::from(*msg.get(binders.checked_add(2)?)?);
            let start = binders.checked_add(3)?;
            let end = start.checked_add(length)?;
            return (end <= msg.len()).then_some((binders, start..end));
        }
        at = body_end;
    }
    None
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn random<const N: usize>(out: &mut [u8; N]) -> Result<(), TlsError> {
    getrandom::fill(out).map_err(|e| TlsError::Other(format!("ticket entropy: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(shared: &[u8; 32], ticket: &[u8]) -> Vec<u8> {
        let hashed = ring::digest::digest(&ring::digest::SHA512, shared);
        let hashed = hashed.as_ref();
        let (iv, rest) = ticket.split_at(16);
        let (ciphertext, tag) = rest.split_at(rest.len() - 32);
        let key = hmac::Key::new(hmac::HMAC_SHA256, &hashed[32..48]);
        hmac::verify(&key, &ticket[..ticket.len() - 32], tag).expect("the ticket tag verifies");
        let mut plain = ciphertext.to_vec();
        Aes128Ctr::new_from_slices(&hashed[16..32], iv)
            .expect("a sixteen-byte key and iv")
            .apply_keystream(&mut plain);
        plain
    }

    #[test]
    fn a_tls13_state_is_the_go_layout_and_padding() {
        let shared = [0x11; 32];
        let ticket = Ticket::new(&shared, true, true).expect("entropy");
        let state = open(&shared, &ticket.bytes);
        assert_eq!(&state[0..2], &[0x03, 0x04]);
        assert_eq!(state[2], 1, "a server state");
        assert_eq!(&state[3..5], &[0x13, 0x01]);
        assert_eq!(&state[5..13], &ticket.created.to_be_bytes());
        assert_eq!(state[13], 48);
        assert_eq!(&state[14..62], &ticket.secret);
        assert_eq!(&state[62..65], &[0, 0, 0], "no extra state");
        assert_eq!(state[65], 1, "extended master secret");
        assert_eq!(state[66], 0, "no early data");
        assert_eq!(&state[67..70], &[0, 0, 0], "no peer certificates");
        assert_eq!(&state[70..73], &[0, 0, 0], "no verified chains");
        let padding = state.len() - 73;
        assert!(
            PADDED.iter().any(|size| *size - INITIAL == padding),
            "padding {padding} is one of the reference's sizes"
        );
        assert!(state[73..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn a_tls12_state_carries_the_x25519_curve() {
        let shared = [0x22; 32];
        let ticket = Ticket::new(&shared, false, false).expect("entropy");
        let state = open(&shared, &ticket.bytes);
        assert_eq!(&state[0..2], &[0x03, 0x03]);
        assert_eq!(&state[3..5], &[0xc0, 0x2f]);
        assert_eq!(state[65], 0, "no extended master secret");
        assert_eq!(&state[73..75], &[0x00, 0x1d], "the curve the state carries");
        let padding = state.len() - 75;
        assert!(PADDED.iter().any(|size| *size - INITIAL == padding));
    }
}
