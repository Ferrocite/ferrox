//! Hand-rolled BLAKE2s (`WireGuard`'s KDF hash, kept off the dependency policy): 64-byte blocks, eight chaining words, ten four-way-mix rounds, and a keyed first block that counts sixty-four bytes.

/// The eight initial chaining words: fractional bits of the square roots of the first eight primes.
const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The message-word schedule, read modulo ten across the twelve rounds.
const SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Mixer: two half-rounds over the four lanes the column and diagonal share — `a+=b, d^=a rotr16, c+=d, b^=c rotr12`, then `a+=b, d^=a rotr8, c+=d, b^=c rotr7`.
fn mix(state: &mut [u32; 16], lanes: [usize; 4], word0: u32, word1: u32) {
    let [a, b, c, d] = lanes;
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(word0);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(word1);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

/// One 64-byte block: sixteen little-endian words, counter folded into `v[12..14]`, final flag into `v[14]`, ten rounds, result back into `h`.
fn compress(h: &mut [u32; 8], block: &[u8; 64], counter: u64, last: bool) {
    let mut m = [0u32; 16];
    for (word, bytes) in m.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }

    let mut state = [0u32; 16];
    state[..8].copy_from_slice(&h[..]);
    state[8..].copy_from_slice(&IV);
    state[12] ^= counter as u32;
    state[13] ^= (counter >> 32) as u32;
    if last {
        state[14] ^= 0xffff_ffff;
    }

    for round in 0..10 {
        let s = &SIGMA[round % 10];
        mix(
            &mut state,
            [0, 4, 8, 12],
            m[s[0] as usize],
            m[s[1] as usize],
        );
        mix(
            &mut state,
            [1, 5, 9, 13],
            m[s[2] as usize],
            m[s[3] as usize],
        );
        mix(
            &mut state,
            [2, 6, 10, 14],
            m[s[4] as usize],
            m[s[5] as usize],
        );
        mix(
            &mut state,
            [3, 7, 11, 15],
            m[s[6] as usize],
            m[s[7] as usize],
        );
        mix(
            &mut state,
            [0, 5, 10, 15],
            m[s[8] as usize],
            m[s[9] as usize],
        );
        mix(
            &mut state,
            [1, 6, 11, 12],
            m[s[10] as usize],
            m[s[11] as usize],
        );
        mix(
            &mut state,
            [2, 7, 8, 13],
            m[s[12] as usize],
            m[s[13] as usize],
        );
        mix(
            &mut state,
            [3, 4, 9, 14],
            m[s[14] as usize],
            m[s[15] as usize],
        );
    }

    for (chain, (top, bottom)) in h.iter_mut().zip(state[..8].iter().zip(state[8..].iter())) {
        *chain ^= top ^ bottom;
    }
}

/// Incremental BLAKE2s: a full 64-byte buffer compresses only when a further byte arrives, so the last block is never absorbed early.
#[derive(Debug)]
pub struct Blake2s {
    h: [u32; 8],
    buffer: [u8; 64],
    filled: usize,
    counter: u64,
    output: usize,
}

impl Blake2s {
    /// Digest of `output` bytes (1..=32) under `key` (up to 32): a non-empty key is a zero-padded 64-byte first block counting sixty-four bytes.
    #[must_use]
    pub fn new(key: &[u8], output: usize) -> Self {
        assert!(key.len() <= 32, "a BLAKE2s key is at most 32 bytes");
        assert!(
            (1..=32).contains(&output),
            "a BLAKE2s digest is 1..=32 bytes"
        );
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ ((key.len() as u32) << 8) ^ output as u32;
        let mut state = Self {
            h,
            buffer: [0u8; 64],
            filled: 0,
            counter: 0,
            output,
        };
        if !key.is_empty() {
            let mut key_block = [0u8; 64];
            key_block[..key.len()].copy_from_slice(key);
            state.update(&key_block);
        }
        state
    }

    /// Feed bytes, holding the last block back so finalisation can flag it.
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.filled == 64 {
                self.counter += 64;
                let block = self.buffer;
                compress(&mut self.h, &block, self.counter, false);
                self.filled = 0;
            }
            let take = (64 - self.filled).min(input.len());
            self.buffer[self.filled..self.filled + take].copy_from_slice(&input[..take]);
            self.filled += take;
            input = &input[take..];
        }
    }

    /// Compress the held-back block as final and write the leading `output` chaining bytes, little-endian.
    pub fn finalize(mut self) -> [u8; 32] {
        self.counter += self.filled as u64;
        let mut block = [0u8; 64];
        block[..self.filled].copy_from_slice(&self.buffer[..self.filled]);
        compress(&mut self.h, &block, self.counter, true);

        let mut digest = [0u8; 32];
        for (bytes, word) in digest.as_chunks_mut::<4>().0.iter_mut().zip(self.h) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        let output = self.output;
        digest[output..].fill(0);
        digest
    }
}

/// The unkeyed 32-byte BLAKE2s of `input`.
#[must_use]
pub fn hash(input: &[u8]) -> [u8; 32] {
    let mut state = Blake2s::new(&[], 32);
    state.update(input);
    state.finalize()
}

/// 32-byte keyed BLAKE2s of `input` — `WireGuard`'s `mac1`/cookie shape; its KDF is HMAC over the *unkeyed* hash, in `wireguard::kdf`.
#[must_use]
pub fn keyed(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut state = Blake2s::new(key, 32);
    state.update(input);
    state.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes
            .iter()
            .fold(String::with_capacity(2 * bytes.len()), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            })
    }

    /// Reference keyed BLAKE2s-256 vectors: key `00..1f` over the first `len` counting bytes, at block-crossing lengths 0, 1, 2, 32, 63, 64, 65, 128.
    #[test]
    fn blake2s_matches_the_reference_keyed_kat() {
        let key: Vec<u8> = (0u8..32).collect();
        let vectors: [(usize, &str); 8] = [
            (
                0,
                "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
            ),
            (
                1,
                "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1",
            ),
            (
                2,
                "6bb71300644cd3991b26ccd4d274acd1adeab8b1d7914546c1198bbe9fc9d803",
            ),
            (
                32,
                "c03bc642b20959cbe133a0303e0c1abff3e31ec8e1a328ec8565c36decff5265",
            ),
            (
                63,
                "c65382513f07460da39833cb666c5ed82e61b9e998f4b0c4287cee56c3cc9bcd",
            ),
            (
                64,
                "8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4",
            ),
            (
                65,
                "21fe0ceb0052be7fb0f004187cacd7de67fa6eb0938d927677f2398c132317a8",
            ),
            (
                128,
                "0c311f38c35a4fb90d651c289d486856cd1413df9b0677f53ece2cd9e477c60a",
            ),
        ];
        for (len, expected) in vectors {
            let input: Vec<u8> = (0..len).map(|i| i as u8).collect();
            assert_eq!(hex(&keyed(&key, &input)), expected, "keyed len {len}");
        }
    }

    /// Chunking at an awkward boundary hashes the same as feeding whole: the held-back last block must not fold early or mis-count.
    #[test]
    fn blake2s_streams_the_whole_at_any_split() {
        let input: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let whole = hash(&input);
        for split in [1, 63, 64, 65, 127, 199] {
            let mut state = Blake2s::new(&[], 32);
            state.update(&input[..split]);
            state.update(&input[split..]);
            assert_eq!(state.finalize(), whole, "split {split}");
        }
    }

    /// `BLAKE2s-256("")` from the reference table — the vector witnessing the unkeyed parameter block and zero-block finalisation.
    #[test]
    fn blake2s_hashes_the_empty_input() {
        assert_eq!(
            hex(&hash(&[])),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        );
    }
}
