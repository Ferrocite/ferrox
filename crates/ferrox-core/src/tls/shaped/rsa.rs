// TLS 1.2's static-RSA key transport: PKCS#1 v1.5's encoding and the exponentiation over it.
use super::client::tlv;
use crate::tls::TlsError;
use std::cmp::Ordering;

/// The modulus and public exponent of an `RSAPublicKey`, the DER an RSA leaf's `SubjectPublicKeyInfo` carries.
pub(crate) fn public_key(der: &[u8]) -> Option<(&[u8], u64)> {
    let (tag, body, _) = tlv(der)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, modulus, rest) = tlv(body)?;
    if tag != 0x02 {
        return None;
    }
    let (tag, exponent, _) = tlv(rest)?;
    if tag != 0x02 || exponent.is_empty() || exponent.len() > 8 {
        return None;
    }
    let mut e = 0u64;
    for byte in exponent {
        e = (e << 8) | u64::from(*byte);
    }
    Some((unsigned(modulus), e))
}

/// A DER `INTEGER`'s leading zero, which the encoding writes when the value's top bit is set.
fn unsigned(mut bytes: &[u8]) -> &[u8] {
    while bytes.first() == Some(&0) {
        bytes = &bytes[1..];
    }
    bytes
}

/// `EM = 0x00 || 0x02 || PS || 0x00 || M` raised to `e`, the PKCS#1 v1.5 encryption Go's
/// `EncryptPKCS1v15` performs: PS is at least eight random bytes, none of them zero.
pub(crate) fn encrypt(
    modulus: &[u8],
    exponent: u64,
    msg: &[u8],
    random: &mut dyn FnMut(&mut [u8]) -> Result<(), TlsError>,
    out: &mut Vec<u8>,
) -> Result<(), TlsError> {
    let len = modulus.len();
    if msg.len() + 11 > len {
        return Err(TlsError::Other(
            "RSA modulus is too small for the premaster".to_owned(),
        ));
    }
    let mut em = vec![0u8; len];
    em[1] = 2;
    let ps_end = len - msg.len() - 1;
    let mut at = 2;
    while at < ps_end {
        random(&mut em[at..ps_end])?;
        while at < ps_end && em[at] != 0 {
            at += 1;
        }
    }
    em[len - msg.len()..].copy_from_slice(msg);
    modexp(&em, exponent, modulus, out)
}

/// `base^exponent mod modulus`, all three big-endian; the ciphertext is the modulus's own length.
pub(crate) fn modexp(
    base: &[u8],
    exponent: u64,
    modulus: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), TlsError> {
    if exponent < 2 {
        return Err(TlsError::Other(
            "RSA exponent is not a public one".to_owned(),
        ));
    }
    let n = limbs(modulus);
    if n[0] & 1 == 0 {
        return Err(TlsError::Other(
            "RSA modulus is not an odd number".to_owned(),
        ));
    }
    let value = Mont::new(n).pow(base, exponent);
    out.clear();
    big_endian(&value, modulus.len(), out);
    Ok(())
}

/// Little-endian limbs written back as big-endian bytes, the modulus's own length: the stream of
/// `len`-times-8 is the value's full width, so a shorter modulus drops the high bytes it cannot reach.
fn big_endian(value: &[u64], len: usize, out: &mut Vec<u8>) {
    out.extend(value.iter().rev().flat_map(|word| word.to_be_bytes()));
    out.drain(..out.len() - len);
}

/// Montgomery arithmetic modulo an odd `n`: a value lives as `x·R mod n` with `R` the base past
/// `n`'s last limb, so a multiply never divides — each step adds the multiple of `n` that zeroes
/// the low limb, and the limbs shift out under it.
struct Mont {
    n: Vec<u64>,
    /// `-n⁻¹ mod 2^64`, the multiplier that kills one limb per step.
    inv: u64,
    /// `R² mod n`, the jump into the domain.
    r2: Vec<u64>,
}

impl Mont {
    fn new(n: Vec<u64>) -> Self {
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n[0].wrapping_mul(inv)));
        }
        let r2 = expand(&n);
        Self {
            n,
            inv: inv.wrapping_neg(),
            r2,
        }
    }

    /// `(a·b·R⁻¹) mod n` for two limb runs of `n`'s length, below `n`. Each step adds the multiple
    /// of `n` that zeroes limb `i`, so after `n`'s length in steps the low half is gone and the
    /// high half, plus its carry word, is one subtraction from the answer. `wide` is the
    /// accumulator, cleared here rather than reallocated: every limb of it is read before the
    /// step that first writes it, so a stale word above `n`'s width would survive as the answer.
    fn mul(&self, left: &[u64], right: &[u64], wide: &mut [u64], out: &mut [u64]) {
        let size = self.n.len();
        wide[..2 * size + 1].fill(0);
        for (word_index, word) in right.iter().enumerate() {
            let mut carry = 0u128;
            for limb in 0..size {
                let sum = wide[limb + word_index] as u128
                    + (left[limb] as u128) * (*word as u128)
                    + carry;
                wide[limb + word_index] = sum as u64;
                carry = sum >> 64;
            }
            shift(&mut wide[..2 * size + 1], word_index + size, carry);
        }
        for limb_index in 0..size {
            let factor = wide[limb_index].wrapping_mul(self.inv);
            let mut carry = 0u128;
            for limb in 0..size {
                let sum = wide[limb + limb_index] as u128
                    + (factor as u128) * (self.n[limb] as u128)
                    + carry;
                wide[limb + limb_index] = sum as u64;
                carry = sum >> 64;
            }
            shift(&mut wide[..2 * size + 1], limb_index + size, carry);
        }
        out.copy_from_slice(&wide[size..2 * size]);
        if wide[2 * size] != 0 || order(out, &self.n) != Ordering::Less {
            subtract(out, &self.n);
        }
    }

    /// Square and multiply, most significant bit first: a public exponent is short, so a window
    /// table costs more than the multiplies it saves. One accumulator serves every step, and the
    /// answer swaps into the scratch it came from.
    fn pow(&self, base: &[u8], exponent: u64) -> Vec<u64> {
        let k = self.n.len();
        let mut wide = vec![0u64; 2 * k + 1];
        let mut one = vec![0u64; k];
        one[0] = 1;
        let mut acc = vec![0u64; k];
        let mut m = limbs(base);
        m.resize(k, 0);
        let mut scratch = vec![0u64; k];
        self.mul(&one, &self.r2, &mut wide, &mut acc);
        self.mul(&m, &self.r2, &mut wide, &mut scratch);
        std::mem::swap(&mut m, &mut scratch);
        for bit in (0..(64 - exponent.leading_zeros())).rev() {
            self.mul(&acc, &acc, &mut wide, &mut scratch);
            std::mem::swap(&mut acc, &mut scratch);
            if (exponent >> bit) & 1 == 1 {
                self.mul(&acc, &m, &mut wide, &mut scratch);
                std::mem::swap(&mut acc, &mut scratch);
            }
        }
        self.mul(&acc, &one, &mut wide, &mut scratch);
        scratch
    }
}

/// `R² mod n` by doubling from one: a shift carries out at most one bit, and the doubled value is
/// within one subtraction of `n` because it started below it. `n` occupies `k` limbs, so the first
/// `64·(k − 1)` doublings hold a bare power of two below `n`'s own floor — that far is jumped to
/// the top limb, and only the remaining shifts can wrap.
fn expand(n: &[u64]) -> Vec<u64> {
    let mut v = vec![0u64; n.len()];
    v[n.len() - 1] = 1;
    for _ in 0..64 * (n.len() + 1) {
        let mut carry = 0u64;
        for slot in &mut v {
            let next = *slot >> 63;
            *slot = (*slot << 1) | carry;
            carry = next;
        }
        if carry != 0 || order(&v, n) != Ordering::Less {
            subtract(&mut v, n);
        }
    }
    v
}

/// Big-endian bytes to little-endian base-2^64 limbs.
fn limbs(bytes: &[u8]) -> Vec<u64> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(8));
    let mut at = bytes.len();
    while at > 0 {
        let start = at - 8usize.min(at);
        let mut word = 0u64;
        for byte in &bytes[start..at] {
            word = (word << 8) | u64::from(*byte);
        }
        out.push(word);
        at = start;
    }
    out
}

/// Carries a sum above the limb at `at`. The running value stays under `2R` there, so the walk
/// stops inside the one carry word past the limbs.
fn shift(t: &mut [u64], mut at: usize, mut carry: u128) {
    while carry != 0 {
        let v = t[at] as u128 + carry;
        t[at] = v as u64;
        carry = v >> 64;
        at += 1;
    }
}

fn order(a: &[u64], b: &[u64]) -> Ordering {
    for (x, y) in a.iter().rev().zip(b.iter().rev()) {
        if x != y {
            return x.cmp(y);
        }
    }
    Ordering::Equal
}

/// `a -= b` over limbs of the same length. REDC's last step reaches this short by the carry word
/// it dropped, so the wraparound out of the top limb is the subtraction it did not have room for.
fn subtract(a: &mut [u64], b: &[u64]) {
    let mut borrow = 0i128;
    for (slot, y) in a.iter_mut().zip(b) {
        borrow += *slot as i128 - *y as i128;
        *slot = borrow as u64;
        borrow >>= 64;
    }
}
