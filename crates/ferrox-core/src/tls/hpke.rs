use aes_gcm::aead::{Aead as _, Payload};
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const SECRET_LEN: usize = 32;

#[derive(Clone, Copy, Debug)]
enum Aead {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Aead {
    fn id(self) -> u16 {
        match self {
            Self::Aes128Gcm => 0x0001,
            Self::Aes256Gcm => 0x0002,
            Self::ChaCha20Poly1305 => 0x0003,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    fn key_id(self) -> HpkeAead {
        match self {
            Self::Aes128Gcm => HpkeAead::AES_128_GCM,
            Self::Aes256Gcm => HpkeAead::AES_256_GCM,
            Self::ChaCha20Poly1305 => HpkeAead::CHACHA20_POLY_1305,
        }
    }

    fn seal(
        self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, rustls::Error> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match self {
            Self::Aes128Gcm => {
                use aes_gcm::{Aes128Gcm, KeyInit as _};
                let cipher = Aes128Gcm::new_from_slice(key)
                    .map_err(|_| general("hpke: aes-128-gcm key length"))?;
                cipher
                    .encrypt(aes_gcm::Nonce::from_slice(nonce), payload)
                    .map_err(|_| general("hpke: aes-128-gcm seal"))
            }
            Self::Aes256Gcm => {
                use aes_gcm::{Aes256Gcm, KeyInit as _};
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|_| general("hpke: aes-256-gcm key length"))?;
                cipher
                    .encrypt(aes_gcm::Nonce::from_slice(nonce), payload)
                    .map_err(|_| general("hpke: aes-256-gcm seal"))
            }
            Self::ChaCha20Poly1305 => {
                use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _};
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| general("hpke: chacha20poly1305 key length"))?;
                cipher
                    .encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
                    .map_err(|_| general("hpke: chacha20poly1305 seal"))
            }
        }
    }

    fn open(
        self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, rustls::Error> {
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        match self {
            Self::Aes128Gcm => {
                use aes_gcm::{Aes128Gcm, KeyInit as _};
                let cipher = Aes128Gcm::new_from_slice(key)
                    .map_err(|_| general("hpke: aes-128-gcm key length"))?;
                cipher
                    .decrypt(aes_gcm::Nonce::from_slice(nonce), payload)
                    .map_err(|_| general("hpke: aes-128-gcm open"))
            }
            Self::Aes256Gcm => {
                use aes_gcm::{Aes256Gcm, KeyInit as _};
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|_| general("hpke: aes-256-gcm key length"))?;
                cipher
                    .decrypt(aes_gcm::Nonce::from_slice(nonce), payload)
                    .map_err(|_| general("hpke: aes-256-gcm open"))
            }
            Self::ChaCha20Poly1305 => {
                use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _};
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| general("hpke: chacha20poly1305 key length"))?;
                cipher
                    .decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
                    .map_err(|_| general("hpke: chacha20poly1305 open"))
            }
        }
    }
}

fn general(why: &str) -> rustls::Error {
    rustls::Error::General(why.to_owned())
}

fn suite_id(kem: u16, kdf: u16, aead: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    out.extend_from_slice(b"HPKE");
    out.extend_from_slice(&kem.to_be_bytes());
    out.extend_from_slice(&kdf.to_be_bytes());
    out.extend_from_slice(&aead.to_be_bytes());
    out
}

fn kem_suite_id() -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.extend_from_slice(b"KEM");
    out.extend_from_slice(&KEM_ID.to_be_bytes());
    out
}

fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8], suite: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(7 + suite.len() + label.len() + ikm.len());
    input.extend_from_slice(b"HPKE-v1");
    input.extend_from_slice(suite);
    input.extend_from_slice(label);
    input.extend_from_slice(ikm);
    let salt = (!salt.is_empty()).then_some(salt);
    let (prk, _) = hkdf::Hkdf::<Sha256>::extract(salt, &input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

fn labeled_expand(prk: &[u8; 32], label: &[u8], info: &[u8], len: usize, suite: &[u8]) -> Vec<u8> {
    let mut labeled = Vec::with_capacity(2 + 7 + suite.len() + label.len() + info.len());
    labeled.extend_from_slice(&(len as u16).to_be_bytes());
    labeled.extend_from_slice(b"HPKE-v1");
    labeled.extend_from_slice(suite);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(info);
    let hk = hkdf::Hkdf::<Sha256>::from_prk(prk).expect("a 32-byte prk");
    let mut out = vec![0u8; len];
    hk.expand(&labeled, &mut out).expect("an expand that fits");
    out
}

fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> [u8; 32] {
    let suite = kem_suite_id();
    let eae_prk = labeled_extract(&[], b"eae_prk", dh, &suite);
    let out = labeled_expand(&eae_prk, b"shared_secret", kem_context, SECRET_LEN, &suite);
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&out);
    secret
}

fn dh(sk: &[u8; 32], pk: &[u8; 32]) -> [u8; 32] {
    StaticSecret::from(*sk)
        .diffie_hellman(&PublicKey::from(*pk))
        .to_bytes()
}

#[derive(Debug)]
struct Context {
    aead: Aead,
    key: Vec<u8>,
    base_nonce: [u8; 12],
}

impl Context {
    fn new(shared_secret: &[u8; 32], info: &[u8], aead: Aead) -> Self {
        let suite = suite_id(KEM_ID, KDF_ID, aead.id());
        let psk_id_hash = labeled_extract(&[], b"psk_id_hash", &[], &suite);
        let info_hash = labeled_extract(&[], b"info_hash", info, &suite);
        let mut context = Vec::with_capacity(1 + 64);
        context.push(0);
        context.extend_from_slice(&psk_id_hash);
        context.extend_from_slice(&info_hash);
        let secret = labeled_extract(shared_secret, b"secret", &[], &suite);
        let key = labeled_expand(&secret, b"key", &context, aead.key_len(), &suite);
        let base_nonce = labeled_expand(&secret, b"base_nonce", &context, 12, &suite);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&base_nonce);
        Self {
            aead,
            key,
            base_nonce: nonce,
        }
    }

    fn nonce(&self, sequence: u64) -> [u8; 12] {
        let mut nonce = self.base_nonce;
        for (slot, byte) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
            *slot ^= byte;
        }
        nonce
    }

    fn seal(&self, aad: &[u8], plaintext: &[u8], sequence: u64) -> Result<Vec<u8>, rustls::Error> {
        self.aead
            .seal(&self.key, &self.nonce(sequence), aad, plaintext)
    }

    fn open(&self, aad: &[u8], ciphertext: &[u8], sequence: u64) -> Result<Vec<u8>, rustls::Error> {
        self.aead
            .open(&self.key, &self.nonce(sequence), aad, ciphertext)
    }
}

fn encapsulate(pk_r: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), rustls::Error> {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|_| general("hpke: no randomness"))?;
    let sk_e = StaticSecret::from(raw);
    let enc = PublicKey::from(&sk_e).to_bytes();
    let mut kem_context = [0u8; 64];
    kem_context[..32].copy_from_slice(&enc);
    kem_context[32..].copy_from_slice(pk_r);
    let secret = extract_and_expand(&dh(&raw, pk_r), &kem_context);
    Ok((enc, secret))
}

fn decapsulate(enc: &[u8], sk_r: &[u8; 32]) -> Result<[u8; 32], rustls::Error> {
    let enc: [u8; 32] = enc
        .try_into()
        .map_err(|_| general("hpke: encapsulated secret length"))?;
    let pk_r = PublicKey::from(&StaticSecret::from(*sk_r)).to_bytes();
    let mut kem_context = [0u8; 64];
    kem_context[..32].copy_from_slice(&enc);
    kem_context[32..].copy_from_slice(&pk_r);
    Ok(extract_and_expand(&dh(sk_r, &enc), &kem_context))
}

fn public_key(bytes: &HpkePublicKey) -> Result<[u8; 32], rustls::Error> {
    bytes
        .0
        .as_slice()
        .try_into()
        .map_err(|_| general("hpke: public key length"))
}

fn secret_key(bytes: &[u8]) -> Result<[u8; 32], rustls::Error> {
    bytes
        .try_into()
        .map_err(|_| general("hpke: private key length"))
}

#[derive(Debug)]
struct Sealer {
    context: Context,
    sequence: u64,
}

impl HpkeSealer for Sealer {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let out = self.context.seal(aad, plaintext, self.sequence)?;
        self.sequence = self.sequence.wrapping_add(1);
        Ok(out)
    }
}

#[derive(Debug)]
struct Opener {
    context: Context,
    sequence: u64,
}

impl HpkeOpener for Opener {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let out = self.context.open(aad, ciphertext, self.sequence)?;
        self.sequence = self.sequence.wrapping_add(1);
        Ok(out)
    }
}

#[derive(Debug)]
pub(crate) struct X25519Hpke {
    aead: Aead,
}

impl Hpke for X25519Hpke {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), rustls::Error> {
        let (enc, secret) = encapsulate(&public_key(pub_key)?)?;
        let context = Context::new(&secret, info, self.aead);
        let ciphertext = context.seal(aad, plaintext, 0)?;
        Ok((EncapsulatedSecret(enc.to_vec()), ciphertext))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), rustls::Error> {
        let (enc, secret) = encapsulate(&public_key(pub_key)?)?;
        Ok((
            EncapsulatedSecret(enc.to_vec()),
            Box::new(Sealer {
                context: Context::new(&secret, info, self.aead),
                sequence: 0,
            }),
        ))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key_bytes: &rustls::crypto::hpke::HpkePrivateKey,
    ) -> Result<Vec<u8>, rustls::Error> {
        let secret = decapsulate(&enc.0, &secret_key(secret_key_bytes.secret_bytes())?)?;
        Context::new(&secret, info, self.aead).open(aad, ciphertext, 0)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key_bytes: &rustls::crypto::hpke::HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, rustls::Error> {
        let secret = decapsulate(&enc.0, &secret_key(secret_key_bytes.secret_bytes())?)?;
        Ok(Box::new(Opener {
            context: Context::new(&secret, info, self.aead),
            sequence: 0,
        }))
    }

    fn generate_key_pair(
        &self,
    ) -> Result<(HpkePublicKey, rustls::crypto::hpke::HpkePrivateKey), rustls::Error> {
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).map_err(|_| general("hpke: no randomness"))?;
        let secret = StaticSecret::from(raw);
        let public = PublicKey::from(&secret);
        Ok((
            HpkePublicKey(public.to_bytes().to_vec()),
            rustls::crypto::hpke::HpkePrivateKey::from(raw.to_vec()),
        ))
    }

    fn suite(&self) -> HpkeSuite {
        HpkeSuite {
            kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: self.aead.key_id(),
            },
        }
    }
}

pub(crate) static AES128_GCM: X25519Hpke = X25519Hpke {
    aead: Aead::Aes128Gcm,
};
pub(crate) static AES256_GCM: X25519Hpke = X25519Hpke {
    aead: Aead::Aes256Gcm,
};
pub(crate) static CHACHA20_POLY1305: X25519Hpke = X25519Hpke {
    aead: Aead::ChaCha20Poly1305,
};

pub(crate) static SUITES: [&'static dyn Hpke; 3] = [&AES128_GCM, &AES256_GCM, &CHACHA20_POLY1305];

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let clean: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        clean
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn array(text: &str) -> [u8; 32] {
        hex(text).try_into().unwrap()
    }

    #[test]
    fn rfc9180_a1_base_matches() {
        let sk_e = array("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
        let pk_e = array("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
        let sk_r = array("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
        let pk_r = array("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        let info = hex("4f6465206f6e2061204772656369616e2055726e");

        let mut context = [0u8; 64];
        context[..32].copy_from_slice(&pk_e);
        context[32..].copy_from_slice(&pk_r);
        let shared = extract_and_expand(&dh(&sk_e, &pk_r), &context);
        assert_eq!(
            shared.as_slice(),
            hex("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc")
        );
        assert_eq!(decapsulate(&pk_e, &sk_r).unwrap(), shared);

        let context = Context::new(&shared, &info, Aead::Aes128Gcm);
        assert_eq!(context.key, hex("4531685d41d65f03dc48f6b8302c05b0"));
        assert_eq!(
            context.base_nonce.as_slice(),
            hex("56d890e5accaaf011cff4b7d")
        );
        let plaintext = hex("4265617574792069732074727574682c20747275746820626561757479");
        assert_eq!(
            context.seal(b"Count-0", &plaintext, 0).unwrap(),
            hex("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a")
        );
        assert_eq!(
            context.seal(b"Count-1", &plaintext, 1).unwrap(),
            hex("af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84")
        );
        assert_eq!(
            context.seal(b"Count-256", &plaintext, 256).unwrap(),
            hex("957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2")
        );
    }

    #[test]
    fn rfc9180_a2_base_matches() {
        let sk_e = array("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600");
        let pk_e = array("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        let sk_r = array("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        let pk_r = array("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
        let info = hex("4f6465206f6e2061204772656369616e2055726e");

        let mut context = [0u8; 64];
        context[..32].copy_from_slice(&pk_e);
        context[32..].copy_from_slice(&pk_r);
        let shared = extract_and_expand(&dh(&sk_e, &pk_r), &context);
        assert_eq!(
            shared.as_slice(),
            hex("0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7")
        );
        assert_eq!(decapsulate(&pk_e, &sk_r).unwrap(), shared);

        let context = Context::new(&shared, &info, Aead::ChaCha20Poly1305);
        assert_eq!(
            context.key,
            hex("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91")
        );
        assert_eq!(
            context.base_nonce.as_slice(),
            hex("5c4d98150661b848853b547f")
        );
        let plaintext = hex("4265617574792069732074727574682c20747275746820626561757479");
        assert_eq!(
            context.seal(b"Count-0", &plaintext, 0).unwrap(),
            hex("1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28")
        );
    }

    #[cfg_attr(miri, ignore = "uses the OS random source")]
    #[test]
    fn seal_and_open_round_trip_every_suite() {
        for suite in SUITES {
            let (public, private) = suite.generate_key_pair().unwrap();
            let (enc, ciphertext) = suite.seal(b"info", b"aad", b"hello", &public).unwrap();
            assert_eq!(
                suite
                    .open(&enc, b"info", b"aad", &ciphertext, &private)
                    .unwrap(),
                b"hello"
            );
            let (enc, mut sealer) = suite.setup_sealer(b"info", &public).unwrap();
            let mut opener = suite.setup_opener(&enc, b"info", &private).unwrap();
            for i in 0..3 {
                let record = [i as u8; 7];
                let output = sealer.seal(b"aad", &record).unwrap();
                assert_eq!(opener.open(b"aad", &output).unwrap(), record);
            }
        }
    }
}
