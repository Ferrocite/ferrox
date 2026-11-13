use boring::bn::{BigNum, BigNumContext};
use boring::error::ErrorStack;
use boring::pkey::Private;
use boring::rsa::Rsa;
use sha2::{Digest, Sha256};
use std::io;

const EXPONENT: u32 = 65537;
const PRIME_BYTES: usize = 64;

struct Sha256Stream {
    seed: Vec<u8>,
    counter: u64,
    buffer: Vec<u8>,
}

impl Sha256Stream {
    fn new(seed: Vec<u8>) -> Self {
        Self {
            seed,
            counter: 0,
            buffer: Vec::new(),
        }
    }

    fn fill(&mut self, output: &mut [u8]) {
        while self.buffer.len() < output.len() {
            let mut hasher = Sha256::new();
            hasher.update(&self.seed);
            hasher.update(format!("-{}", self.counter).as_bytes());
            self.counter += 1;
            self.buffer.extend_from_slice(&hasher.finalize());
        }
        output.copy_from_slice(&self.buffer[..output.len()]);
        self.buffer.drain(..output.len());
    }
}

fn derive_prime(stream: &mut Sha256Stream) -> Result<BigNum, ErrorStack> {
    let mut bytes = [0; PRIME_BYTES];
    stream.fill(&mut bytes);
    bytes[0] |= 0xc0;
    bytes[PRIME_BYTES - 1] |= 0x01;

    let mut prime = BigNum::from_slice(&bytes)?;
    let mut context = BigNumContext::new()?;
    let one = BigNum::from_u32(1)?;
    let exponent = BigNum::from_u32(EXPONENT)?;
    let two = BigNum::from_u32(2)?;
    let mut candidate = BigNum::new()?;
    let mut gcd = BigNum::new()?;
    loop {
        if prime.is_prime(20, &mut context)? {
            candidate.checked_sub(&prime, &one)?;
            gcd.gcd(&candidate, &exponent, &mut context)?;
            if gcd.ucmp(&one) == std::cmp::Ordering::Equal {
                return Ok(prime);
            }
        }
        candidate.checked_add(&prime, &two)?;
        std::mem::swap(&mut prime, &mut candidate);
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}

pub fn derive_rsa_key(password: &str) -> Result<Rsa<Private>, io::Error> {
    let seed = password.as_bytes();
    let mut p_stream = Sha256Stream::new([seed, b"-p-prime"].concat());
    let mut q_stream = Sha256Stream::new([seed, b"-q-prime"].concat());

    let p = derive_prime(&mut p_stream).map_err(|error| invalid(&error.to_string()))?;
    let mut q = derive_prime(&mut q_stream).map_err(|error| invalid(&error.to_string()))?;

    let mut context = BigNumContext::new().map_err(|error| invalid(&error.to_string()))?;
    let one = BigNum::from_u32(1).map_err(|error| invalid(&error.to_string()))?;
    let two = BigNum::from_u32(2).map_err(|error| invalid(&error.to_string()))?;
    let exponent = BigNum::from_u32(EXPONENT).map_err(|error| invalid(&error.to_string()))?;
    let mut candidate = BigNum::new().map_err(|error| invalid(&error.to_string()))?;
    let mut gcd = BigNum::new().map_err(|error| invalid(&error.to_string()))?;

    while p.ucmp(&q) == std::cmp::Ordering::Equal {
        candidate
            .checked_add(&q, &two)
            .map_err(|error| invalid(&error.to_string()))?;
        std::mem::swap(&mut q, &mut candidate);
        loop {
            if q.is_prime(20, &mut context)
                .map_err(|error| invalid(&error.to_string()))?
            {
                candidate
                    .checked_sub(&q, &one)
                    .map_err(|error| invalid(&error.to_string()))?;
                gcd.gcd(&candidate, &exponent, &mut context)
                    .map_err(|error| invalid(&error.to_string()))?;
                if gcd.ucmp(&one) == std::cmp::Ordering::Equal {
                    break;
                }
            }
            candidate
                .checked_add(&q, &two)
                .map_err(|error| invalid(&error.to_string()))?;
            std::mem::swap(&mut q, &mut candidate);
        }
    }

    let mut n = BigNum::new().map_err(|error| invalid(&error.to_string()))?;
    n.checked_mul(&p, &q, &mut context)
        .map_err(|error| invalid(&error.to_string()))?;
    let mut p_minus_one = BigNum::new().map_err(|error| invalid(&error.to_string()))?;
    p_minus_one
        .checked_sub(&p, &one)
        .map_err(|error| invalid(&error.to_string()))?;
    let mut q_minus_one = BigNum::new().map_err(|error| invalid(&error.to_string()))?;
    q_minus_one
        .checked_sub(&q, &one)
        .map_err(|error| invalid(&error.to_string()))?;
    let mut totient = BigNum::new().map_err(|error| invalid(&error.to_string()))?;
    totient
        .checked_mul(&p_minus_one, &q_minus_one, &mut context)
        .map_err(|error| invalid(&error.to_string()))?;

    let mut d = BigNum::new().map_err(|error| invalid(&error.to_string()))?;
    d.mod_inverse(&exponent, &totient, &mut context)
        .map_err(|_| invalid("failed to compute mod inverse"))?;

    let mut d_mod_p = BigNum::new().map_err(|error| invalid(&error.to_string()))?;
    d_mod_p
        .checked_rem(&d, &p_minus_one, &mut context)
        .map_err(|error| invalid(&error.to_string()))?;
    let mut d_mod_q = BigNum::new().map_err(|error| invalid(&error.to_string()))?;
    d_mod_q
        .checked_rem(&d, &q_minus_one, &mut context)
        .map_err(|error| invalid(&error.to_string()))?;
    let mut iqmp = BigNum::new().map_err(|error| invalid(&error.to_string()))?;
    iqmp.mod_inverse(&q, &p, &mut context)
        .map_err(|_| invalid("failed to compute crt coefficient"))?;

    Rsa::from_private_components(n, exponent, d, p, q, d_mod_p, d_mod_q, iqmp)
        .map_err(|error| invalid(&error.to_string()))
}

pub fn private_key_der(key: &Rsa<Private>) -> Result<Vec<u8>, io::Error> {
    key.private_key_to_der()
        .map_err(|error| invalid(&error.to_string()))
}

pub fn public_key_der(key: &Rsa<Private>) -> Result<Vec<u8>, io::Error> {
    key.public_key_to_der()
        .map_err(|error| invalid(&error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_for_a_password() {
        let first = derive_rsa_key("my-very-secret-password-12345").expect("derives");
        let second = derive_rsa_key("my-very-secret-password-12345").expect("derives again");

        assert_eq!(first.n().to_vec(), second.n().to_vec());
        assert_eq!(
            first.p().expect("p").to_vec(),
            second.p().expect("p").to_vec()
        );
        assert_eq!(
            first.q().expect("q").to_vec(),
            second.q().expect("q").to_vec()
        );
        assert_eq!(first.d().to_vec(), second.d().to_vec());
    }

    #[test]
    fn golden_private_key_matches_the_reference_der_hash() {
        let key = derive_rsa_key("deterministic-rsa-key-golden").expect("derives");
        let der = private_key_der(&key).expect("DER");
        let digest = Sha256::digest(&der);
        assert_eq!(
            digest.as_slice(),
            [
                0x3a, 0x8c, 0x4a, 0xd5, 0x6a, 0x6f, 0xb4, 0x2d, 0xab, 0x73, 0xc4, 0xd5, 0xfc, 0x3a,
                0xf7, 0x54, 0x46, 0x0a, 0x2d, 0xb1, 0x44, 0x1e, 0xdc, 0x09, 0x70, 0xcb, 0xc7, 0xf4,
                0xe0, 0x79, 0x8d, 0x2f,
            ]
        );
    }

    #[test]
    fn different_passwords_derive_different_keys() {
        let first = derive_rsa_key("password-a").expect("derives");
        let second = derive_rsa_key("password-b").expect("derives");
        assert_ne!(first.n().to_vec(), second.n().to_vec());
    }

    #[test]
    fn the_key_is_1024_bits_and_serializes_both_ways() {
        let key = derive_rsa_key("serialization-password").expect("derives");
        assert_eq!(key.n().num_bits(), 1024);
        assert!(key.p().is_some() && key.q().is_some());
        assert_ne!(private_key_der(&key).expect("private DER"), Vec::new());
        assert_ne!(public_key_der(&key).expect("public DER"), Vec::new());
    }
}
