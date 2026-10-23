// The ephemeral keys a shaped hello carries: one per key-share group, agreeing with whatever the server picks.
use ml_kem::kem::{Decapsulate as _, KeyExport as _};
use ml_kem::{Ciphertext, Kem as _, MlKem768};
use x25519_dalek::{PublicKey, StaticSecret};

pub(crate) const GREASE: u16 = 0x0a0a;
pub(crate) const X25519: u16 = 0x001d;
pub(crate) const P256: u16 = 0x0017;
pub(crate) const P384: u16 = 0x0018;
pub(crate) const X25519_MLKEM768: u16 = 0x11ec;
pub(crate) const X25519_MLKEM768_DRAFT: u16 = 0x6399;

const MLKEM_EK: usize = 1184;
const MLKEM_CT: usize = 1088;

enum Secret {
    X25519(StaticSecret),
    Ecdh {
        algorithm: &'static ring::agreement::Algorithm,
        key: ring::agreement::EphemeralPrivateKey,
    },
    Hybrid {
        kyber: Box<ml_kem::DecapsulationKey<MlKem768>>,
        x25519: StaticSecret,
        draft: bool,
    },
}

/// One `key_share` entry and the private half that agrees with it.
pub(crate) struct Share {
    pub group: u16,
    pub data: Vec<u8>,
    secret: Option<Secret>,
}

impl Share {
    /// The X25519 secret REALITY's auth key is built from: the plain share if the
    /// hello carries one, else the hybrid's ECDHE half, which is the order the
    /// server reads.
    pub(crate) fn auth_secret(&self) -> Option<[u8; 32]> {
        match &self.secret {
            Some(Secret::X25519(secret)) => Some(secret.to_bytes()),
            Some(Secret::Hybrid { x25519, .. }) => Some(x25519.to_bytes()),
            _ => None,
        }
    }

    /// The secret agreement for the group the server selected: the hybrid's own
    /// ECDHE half is what the client used to build it, never the reused share.
    pub(crate) fn agree(self, peer: &[u8]) -> Result<Vec<u8>, String> {
        let Some(secret) = self.secret else {
            return Err("canonical share cannot agree".to_owned());
        };
        match secret {
            Secret::X25519(secret) => agree_x25519(&secret, peer),
            Secret::Ecdh { algorithm, key } => {
                let peer = ring::agreement::UnparsedPublicKey::new(algorithm, peer);
                ring::agreement::agree_ephemeral(key, &peer, |shared| shared.to_vec())
                    .map_err(|_| "server EC share is not a point".to_owned())
            }
            Secret::Hybrid {
                kyber,
                x25519,
                draft,
            } => {
                let (x_peer, ct) = if draft {
                    let split = peer.len().checked_sub(MLKEM_CT).ok_or("short share")?;
                    (&peer[..split], &peer[split..])
                } else {
                    let split = peer.len().checked_sub(32).ok_or("short share")?;
                    (&peer[split..], &peer[..split])
                };
                let x = agree_x25519(&x25519, x_peer)?;
                let ct = Ciphertext::<MlKem768>::try_from(ct)
                    .map_err(|_| "server key share is not a ciphertext".to_owned())?;
                let kyber = kyber.decapsulate(&ct);
                let mut out = Vec::with_capacity(64);
                if draft {
                    out.extend_from_slice(&x);
                    out.extend_from_slice(&draft_shared(kyber.as_ref(), peer));
                } else {
                    out.extend_from_slice(kyber.as_ref());
                    out.extend_from_slice(&x);
                }
                Ok(out)
            }
        }
    }
}

fn agree_x25519(secret: &StaticSecret, peer: &[u8]) -> Result<Vec<u8>, String> {
    let peer: [u8; 32] = peer
        .try_into()
        .map_err(|_| "server X25519 share is not 32 bytes".to_owned())?;
    let shared = secret.diffie_hellman(&PublicKey::from(peer));
    if shared.as_bytes() == &[0u8; 32] {
        return Err("X25519 shared secret was all zero".to_owned());
    }
    Ok(shared.as_bytes().to_vec())
}

/// Kyber's remove-the-final-hash trick, as uTLS applies it to an ML-KEM shared key.
fn draft_shared(k: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    use sha3::Digest as _;
    use shake::{ExtendableOutput as _, Update as _, XofReader as _};
    let mut hash = sha3::Sha3_256::new();
    sha3::Digest::update(&mut hash, ciphertext);
    let mut shake = shake::Shake256::default();
    shake.update(k);
    shake.update(&hash.finalize());
    let mut out = [0u8; 32];
    shake.finalize_xof().read(&mut out);
    out
}

/// The shares a profile names, in wire order. A reuse profile draws the plain
/// X25519 share from the hybrid's ECDHE key, which is the shape Firefox sends.
pub(crate) fn generate(groups: &[u16], reuse: bool) -> Result<Vec<Share>, String> {
    let mut shares = Vec::with_capacity(groups.len());
    let mut reusable: Option<StaticSecret> = None;
    for &group in groups {
        let share = match group {
            GREASE => Share {
                group,
                data: vec![0],
                secret: None,
            },
            X25519 => {
                let secret = match reusable.clone() {
                    Some(secret) => secret,
                    None => x25519_secret(&mut share_entropy(32)?)?,
                };
                let public = PublicKey::from(&secret);
                Share {
                    group,
                    data: public.as_bytes().to_vec(),
                    secret: Some(Secret::X25519(secret)),
                }
            }
            P256 | P384 => {
                let algorithm: &'static ring::agreement::Algorithm = if group == P256 {
                    &ring::agreement::ECDH_P256
                } else {
                    &ring::agreement::ECDH_P384
                };
                let key = ring::agreement::EphemeralPrivateKey::generate(
                    algorithm,
                    &ring::rand::SystemRandom::new(),
                )
                .map_err(|e| format!("EC key: {e}"))?;
                let public = key
                    .compute_public_key()
                    .map_err(|e| format!("EC share: {e}"))?
                    .as_ref()
                    .to_vec();
                Share {
                    group,
                    data: public,
                    secret: Some(Secret::Ecdh { algorithm, key }),
                }
            }
            X25519_MLKEM768 | X25519_MLKEM768_DRAFT => {
                let (kyber, ek) = MlKem768::generate_keypair();
                let ecdhe = x25519_secret(&mut share_entropy(32)?)?;
                let mut data = Vec::with_capacity(MLKEM_EK + 32);
                if group == X25519_MLKEM768_DRAFT {
                    data.extend_from_slice(PublicKey::from(&ecdhe).as_bytes());
                    data.extend_from_slice(&ek.to_bytes());
                } else {
                    data.extend_from_slice(&ek.to_bytes());
                    data.extend_from_slice(PublicKey::from(&ecdhe).as_bytes());
                }
                if reuse {
                    reusable = Some(ecdhe.clone());
                }
                Share {
                    group,
                    data,
                    secret: Some(Secret::Hybrid {
                        kyber: Box::new(kyber),
                        x25519: ecdhe,
                        draft: group == X25519_MLKEM768_DRAFT,
                    }),
                }
            }
            other => return Err(format!("unsupported key share group {other:#06x}")),
        };
        shares.push(share);
    }
    Ok(shares)
}

/// A share's length with its bytes zeroed, so the canonical hello keeps every offset a real one has.
#[cfg(test)]
pub(crate) fn canonical(groups: &[u16]) -> Vec<Share> {
    groups
        .iter()
        .map(|&group| {
            let len = match group {
                GREASE => 1,
                X25519 => 32,
                P256 => 65,
                P384 => 97,
                X25519_MLKEM768 | X25519_MLKEM768_DRAFT => MLKEM_EK + 32,
                _ => 0,
            };
            Share {
                group,
                data: vec![0; len],
                secret: None,
            }
        })
        .collect()
}

fn share_entropy(n: usize) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; n];
    getrandom::fill(&mut out).map_err(|e| format!("no entropy: {e}"))?;
    Ok(out)
}

fn x25519_secret(seed: &mut [u8]) -> Result<StaticSecret, String> {
    if seed.len() != 32 {
        return Err("X25519 seed is 32 bytes".to_owned());
    }
    let bytes: [u8; 32] = seed
        .try_into()
        .map_err(|_| "X25519 seed is 32 bytes".to_owned())?;
    seed.fill(0);
    Ok(StaticSecret::from(bytes))
}
