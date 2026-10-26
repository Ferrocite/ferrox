const LIMB_MASK: u64 = (1 << 44) - 1;

const LIMB2_MASK: u64 = (1 << 42) - 1;

const HIBIT: u64 = 1 << 40;

const CLAMP_LO: u64 = 0x0fff_fffc_0fff_ffff;

const CLAMP_HI: u64 = 0x0fff_fffc_0fff_fffc;

const LOW_40: u64 = (1 << 40) - 1;

#[cfg(all(test, target_arch = "aarch64"))]
const NEON_THRESHOLD_BYTES: usize = 512;

const STRIDE2_THRESHOLD_BYTES: usize = 64;

#[cfg(target_arch = "aarch64")]
const NEON4_THRESHOLD_BYTES: usize = 1024;

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const M26: u64 = 0x03ff_ffff;

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const M26_U32: u32 = 0x03ff_ffff;

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const HIBIT26: u32 = 1 << 24;

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn reduce_split(mut low: u128, mut over: u64) -> (u128, u64) {
    while over >= 4 || (over == 3 && low.overflowing_add(5).1) {
        let (sum, carry) = low.overflowing_add(5);
        low = sum;
        over = over + u64::from(carry) - 4;
    }
    (low, over)
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn to_26(h: [u64; 3]) -> [u32; 5] {
    let top = h[2] + (h[1] >> 44);
    let (wide, over) = reduce_split(
        u128::from(h[0]) | (u128::from(h[1] & LIMB_MASK) << 44) | (u128::from(top & LOW_40) << 88),
        top >> 40,
    );
    [
        (wide as u64 & M26) as u32,
        ((wide >> 26) as u64 & M26) as u32,
        ((wide >> 52) as u64 & M26) as u32,
        ((wide >> 78) as u64 & M26) as u32,
        ((wide >> 104) as u32 & 0x00ff_ffff) | ((over as u32) << 24),
    ]
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn from_26(h: [u32; 5]) -> [u64; 3] {
    let mut wide = u128::from(h[0]);
    let mut carry = u64::from(h[1] >> 26);
    wide += u128::from(h[1] & M26_U32) << 26;
    let mut limb2 = u64::from(h[2]) + carry;
    carry = limb2 >> 26;
    limb2 &= M26;
    wide += u128::from(limb2) << 52;
    let mut limb3 = u64::from(h[3]) + carry;
    carry = limb3 >> 26;
    limb3 &= M26;
    wide += u128::from(limb3) << 78;
    let limb4 = u64::from(h[4]) + carry;
    wide += u128::from(limb4 & 0x00ff_ffff) << 104;
    let (wide, over) = reduce_split(wide, limb4 >> 24);
    [
        (wide as u64) & LIMB_MASK,
        ((wide >> 44) as u64) & LIMB_MASK,
        (((wide >> 88) as u64) & LIMB2_MASK) | ((over & 0x3) << 40),
    ]
}

#[cfg(target_arch = "x86_64")]
const AVX2_THRESHOLD_BYTES: usize = 1024;

/// A four-byte window at `offset` of each block in the low dword of each 64-bit lane, zeroed above.
#[cfg(target_arch = "x86_64")]
const fn window_mask(offset: usize) -> [i8; 32] {
    let mut mask = [i8::MIN; 32];
    let mut lane = 0;
    while lane < 2 {
        let mut byte = 0;
        while byte < 4 {
            mask[lane * 16 + byte] = (offset + byte) as i8;
            byte += 1;
        }
        lane += 1;
    }
    mask
}

#[cfg(target_arch = "x86_64")]
static WINDOW_MASKS: [[i8; 32]; 5] = [
    window_mask(0),
    window_mask(3),
    window_mask(6),
    window_mask(9),
    window_mask(12),
];

/// A four-byte window at `offset` of each of four blocks, zeroed past, for one TBL4.
#[cfg(target_arch = "aarch64")]
const fn neon_window(offset: usize) -> [u8; 16] {
    let mut index = [0x80u8; 16];
    let mut lane = 0;
    while lane < 4 {
        let mut byte = 0;
        while byte < 4 {
            index[lane * 4 + byte] = (lane * 16 + offset + byte) as u8;
            byte += 1;
        }
        lane += 1;
    }
    index
}

#[cfg(target_arch = "aarch64")]
static NEON_WINDOWS: [[u8; 16]; 5] = [
    neon_window(0),
    neon_window(3),
    neon_window(6),
    neon_window(9),
    neon_window(12),
];

/// The low limb of four consecutive blocks: its window starts on a byte, so no shift.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
#[allow(clippy::wildcard_imports, reason = "flat lane primitives")]
fn neon_low_limb(
    blocks: core::arch::aarch64::uint8x16x4_t,
    m26: core::arch::aarch64::uint32x4_t,
) -> core::arch::aarch64::uint32x4_t {
    use core::arch::aarch64::*;
    unsafe {
        let index = vld1q_u8(NEON_WINDOWS[0].as_ptr());
        vandq_u32(vreinterpretq_u32_u8(vqtbl4q_u8(blocks, index)), m26)
    }
}

/// One limb of four consecutive blocks out of one TBL4, its window cut mid-byte.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
#[allow(clippy::wildcard_imports, reason = "flat lane primitives")]
fn neon_limb_window<const SHIFT: i32, const WINDOW: usize>(
    blocks: core::arch::aarch64::uint8x16x4_t,
    m26: core::arch::aarch64::uint32x4_t,
) -> core::arch::aarch64::uint32x4_t {
    use core::arch::aarch64::*;
    unsafe {
        let index = vld1q_u8(NEON_WINDOWS[WINDOW].as_ptr());
        vandq_u32(
            vshrq_n_u32::<SHIFT>(vreinterpretq_u32_u8(vqtbl4q_u8(blocks, index))),
            m26,
        )
    }
}

/// One limb of four consecutive blocks, four lanes wide, the window mask as the shuffle operand.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(clippy::wildcard_imports, reason = "flat lane primitives")]
fn limb_window<const SHIFT: i32, const WINDOW: usize>(
    lo: core::arch::x86_64::__m256i,
    hi: core::arch::x86_64::__m256i,
    mask26: core::arch::x86_64::__m256i,
) -> core::arch::x86_64::__m256i {
    use core::arch::x86_64::*;
    unsafe {
        let mask = _mm256_loadu_si256(WINDOW_MASKS[WINDOW].as_ptr().cast());
        let a = _mm256_srli_epi64::<SHIFT>(_mm256_shuffle_epi8(lo, mask));
        let b = _mm256_srli_epi64::<SHIFT>(_mm256_shuffle_epi8(hi, mask));
        _mm256_and_si256(_mm256_unpacklo_epi64(a, b), mask26)
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
#[allow(clippy::wildcard_imports, reason = "flat lane primitives")]
fn fold64(
    d0: core::arch::aarch64::uint64x2_t,
    mut d1: core::arch::aarch64::uint64x2_t,
    mut d2: core::arch::aarch64::uint64x2_t,
    mut d3: core::arch::aarch64::uint64x2_t,
    mut d4: core::arch::aarch64::uint64x2_t,
    mask64: core::arch::aarch64::uint64x2_t,
) -> (
    core::arch::aarch64::uint64x2_t,
    core::arch::aarch64::uint64x2_t,
    core::arch::aarch64::uint64x2_t,
    core::arch::aarch64::uint64x2_t,
    core::arch::aarch64::uint64x2_t,
) {
    use core::arch::aarch64::*;
    unsafe {
        let c = vshrq_n_u64::<26>(d0);
        let o0 = vandq_u64(d0, mask64);
        d1 = vaddq_u64(d1, c);
        let c = vshrq_n_u64::<26>(d1);
        let o1 = vandq_u64(d1, mask64);
        d2 = vaddq_u64(d2, c);
        let c = vshrq_n_u64::<26>(d2);
        let o2 = vandq_u64(d2, mask64);
        d3 = vaddq_u64(d3, c);
        let c = vshrq_n_u64::<26>(d3);
        let o3 = vandq_u64(d3, mask64);
        d4 = vaddq_u64(d4, c);
        let c = vshrq_n_u64::<26>(d4);
        let o4 = vandq_u64(d4, mask64);
        let wrapped = vaddq_u64(o0, vaddq_u64(vshlq_n_u64::<2>(c), c));
        let h0 = vandq_u64(wrapped, mask64);
        let h1 = vaddq_u64(o1, vshrq_n_u64::<26>(wrapped));
        (h0, h1, o2, o3, o4)
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn combine4(
    h_in: [u64; 3],
    lanes: &[[u32; 5]; 4],
    r26: &[u32; 5],
    powers: &[[u32; 5]; 3],
    k: usize,
) -> [u64; 3] {
    let (r2, r3, r4) = (&powers[0], &powers[1], &powers[2]);
    let t0 = field_mul(&lanes[0], r4);
    let t1 = field_mul(&lanes[1], r3);
    let t2 = field_mul(&lanes[2], r2);
    let t3 = field_mul(&lanes[3], r26);
    let t4 = if h_in == [0; 3] {
        [0u32; 5]
    } else {
        field_mul(&to_26(h_in), &field_pow(*r4, k))
    };
    let joined = add_three_normalized(&add_three_normalized(&t0, &t1, &t2), &t3, &t4);
    from_26(joined)
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn powers4(r26: &[u32; 5]) -> [[u32; 5]; 3] {
    let r2 = field_mul(r26, r26);
    let r3 = field_mul(&r2, r26);
    let r4 = field_mul(&r2, &r2);
    [r2, r3, r4]
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn field_mul(a: &[u32; 5], b: &[u32; 5]) -> [u32; 5] {
    let (r0, r1, r2, r3, r4) = (
        u64::from(b[0]),
        u64::from(b[1]),
        u64::from(b[2]),
        u64::from(b[3]),
        u64::from(b[4]),
    );
    let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
    let (h0, h1, h2, h3, h4) = (
        u64::from(a[0]),
        u64::from(a[1]),
        u64::from(a[2]),
        u64::from(a[3]),
        u64::from(a[4]),
    );
    let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
    let c = d0 >> 26;
    let o0 = d0 & M26;
    d1 += c;
    let c = d1 >> 26;
    let o1 = d1 & M26;
    d2 += c;
    let c = d2 >> 26;
    let o2 = d2 & M26;
    d3 += c;
    let c = d3 >> 26;
    let o3 = d3 & M26;
    d4 += c;
    let c = d4 >> 26;
    let o4 = d4 & M26;
    let wrapped = o0 + c * 5;
    [
        (wrapped as u32) & M26_U32,
        (o1 + (wrapped >> 26)) as u32,
        o2 as u32,
        o3 as u32,
        o4 as u32,
    ]
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn field_pow(mut base: [u32; 5], mut exp: usize) -> [u32; 5] {
    let mut acc = [0u32; 5];
    acc[0] = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = field_mul(&acc, &base);
        }
        base = field_mul(&base, &base);
        exp >>= 1;
    }
    acc
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn add_three_normalized(a: &[u32; 5], b: &[u32; 5], c: &[u32; 5]) -> [u32; 5] {
    let mut v = [
        u64::from(a[0]) + u64::from(b[0]) + u64::from(c[0]),
        u64::from(a[1]) + u64::from(b[1]) + u64::from(c[1]),
        u64::from(a[2]) + u64::from(b[2]) + u64::from(c[2]),
        u64::from(a[3]) + u64::from(b[3]) + u64::from(c[3]),
        u64::from(a[4]) + u64::from(b[4]) + u64::from(c[4]),
    ];
    let mut carry = v[0] >> 26;
    v[0] &= M26;
    v[1] += carry;
    carry = v[1] >> 26;
    v[1] &= M26;
    v[2] += carry;
    carry = v[2] >> 26;
    v[2] &= M26;
    v[3] += carry;
    carry = v[3] >> 26;
    v[3] &= M26;
    v[4] += carry;
    carry = v[4] >> 26;
    v[4] &= M26;
    let wrapped = v[0] + carry * 5;
    [
        (wrapped as u32) & M26_U32,
        (v[1] + (wrapped >> 26)) as u32,
        v[2] as u32,
        v[3] as u32,
        v[4] as u32,
    ]
}

#[derive(Clone)]
pub struct Poly1305 {
    r0: u64,
    r1: u64,
    r2: u64,
    s1: u64,
    s2: u64,
    h: [u64; 3],
    pad: [u64; 2],
    buffer: [u8; 16],
    held: usize,
}

impl core::fmt::Debug for Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Poly1305")
            .field("h", &self.h)
            .field("held", &self.held)
            .finish_non_exhaustive()
    }
}

impl Poly1305 {
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let w0 = u64::from_le_bytes([
            key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
        ]);
        let w1 = u64::from_le_bytes([
            key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
        ]);
        let w2 = u64::from_le_bytes([
            key[16], key[17], key[18], key[19], key[20], key[21], key[22], key[23],
        ]);
        let w3 = u64::from_le_bytes([
            key[24], key[25], key[26], key[27], key[28], key[29], key[30], key[31],
        ]);
        let lo = w0 & CLAMP_LO;
        let hi = w1 & CLAMP_HI;
        let r0 = lo & LIMB_MASK;
        let r1 = ((lo >> 44) | (hi << 20)) & LIMB_MASK;
        let r2 = hi >> 24;
        Self {
            r0,
            r1,
            r2,
            s1: r1 * 20,
            s2: r2 * 20,
            h: [0; 3],
            pad: [w2, w3],
            buffer: [0; 16],
            held: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if self.held > 0 {
            let take = data.len().min(16 - self.held);
            self.buffer[self.held..self.held + take].copy_from_slice(&data[..take]);
            self.held += take;
            data = &data[take..];
            if self.held < 16 {
                return;
            }
            let block = self.buffer;
            self.absorb(&block, HIBIT);
            self.held = 0;
        }
        let whole = data.len() / 16 * 16;
        if whole > 0 {
            self.absorb(&data[..whole], HIBIT);
        }
        let rest = &data[whole..];
        if !rest.is_empty() {
            self.buffer[..rest.len()].copy_from_slice(rest);
            self.held = rest.len();
        }
        debug_assert_eq!(self.held, rest.len(), "an empty tail leaves `held` at zero");
    }

    /// Zero-pads `buffer` to a whole block and absorbs it, so padding costs one block, not an extra `update` and merge.
    pub fn pad_to_block(&mut self) {
        if self.held == 0 {
            return;
        }
        self.buffer[self.held..].fill(0);
        let block = self.buffer;
        self.absorb(&block, HIBIT);
        self.held = 0;
    }

    #[must_use]
    pub fn finish(mut self) -> [u8; 16] {
        if self.held > 0 {
            let n = self.held;
            self.buffer[n] = 1;
            for b in &mut self.buffer[n + 1..] {
                *b = 0;
            }
            let block = self.buffer;
            self.absorb(&block, 0);
        }

        let pad = u128::from(self.pad[0]) | (u128::from(self.pad[1]) << 64);

        let mut out = [0u8; 16];
        out.copy_from_slice(&reduce(self.h, pad).to_le_bytes());
        out
    }

    fn absorb(&mut self, data: &[u8], hibit: u64) {
        #[cfg(target_arch = "aarch64")]
        if hibit == HIBIT && data.len() >= NEON4_THRESHOLD_BYTES {
            self.absorb_neon4(data);
            return;
        }
        #[cfg(target_arch = "x86_64")]
        if hibit == HIBIT
            && data.len() >= AVX2_THRESHOLD_BYTES
            && std::is_x86_feature_detected!("avx2")
        {
            unsafe { self.absorb_avx2(data) };
            return;
        }
        if hibit == HIBIT && data.len() >= STRIDE2_THRESHOLD_BYTES {
            self.absorb_stride2(data);
            return;
        }
        self.absorb_one_block_chain(data, hibit);
    }

    fn absorb_one_block_chain(&mut self, data: &[u8], hibit: u64) {
        let (r0, r1, r2, s1, s2) = (self.r0, self.r1, self.r2, self.s1, self.s2);
        let (mut h0, mut h1, mut h2) = (self.h[0], self.h[1], self.h[2]);

        let mut rest = data;
        while let Some(m) = rest.first_chunk::<16>() {
            let t0 = u64::from_le_bytes(m[0..8].try_into().expect("a whole 16-byte block"));
            let t1 = u64::from_le_bytes(m[8..16].try_into().expect("a whole 16-byte block"));

            h0 += t0 & LIMB_MASK;
            h1 += ((t0 >> 44) | (t1 << 20)) & LIMB_MASK;
            h2 += (t1 >> 24) & LIMB2_MASK;
            h2 += hibit;

            let (x0, x1, x2) = (h0 as u128, h1 as u128, h2 as u128);
            let (y0, y1, y2) = (r0 as u128, r1 as u128, r2 as u128);

            let d0 = x0 * y0 + x1 * (s2 as u128) + x2 * (s1 as u128);
            let mut d1 = x0 * y1 + x1 * y0 + x2 * (s2 as u128);
            let mut d2 = x0 * y2 + x1 * y1 + x2 * y0;

            let c = (d0 >> 44) as u64;
            h0 = (d0 as u64) & LIMB_MASK;
            d1 += u128::from(c);
            let c = (d1 >> 44) as u64;
            h1 = (d1 as u64) & LIMB_MASK;
            d2 += u128::from(c);
            let c = (d2 >> 42) as u64;
            h2 = (d2 as u64) & LIMB2_MASK;
            h0 += c * 5;
            let c = h0 >> 44;
            h0 &= LIMB_MASK;
            h1 += c;

            rest = &rest[16..];
        }

        self.h = [h0, h1, h2];
    }

    #[inline]
    fn mul_unfolded(x: [u64; 3], y: (u64, u64, u64), s: (u64, u64)) -> [u128; 3] {
        let (y0, y1, y2) = (y.0 as u128, y.1 as u128, y.2 as u128);
        let (x0, x1, x2) = (x[0] as u128, x[1] as u128, x[2] as u128);
        let d0 = x0 * y0 + x1 * (s.1 as u128) + x2 * (s.0 as u128);
        let d1 = x0 * y1 + x1 * y0 + x2 * (s.1 as u128);
        let d2 = x0 * y2 + x1 * y1 + x2 * y0;
        [d0, d1, d2]
    }

    #[inline]
    fn fold_unfolded(d: [u128; 3]) -> [u64; 3] {
        let c = (d[0] >> 44) as u64;
        let h0 = (d[0] as u64) & LIMB_MASK;
        let d1 = d[1] + u128::from(c);
        let c = (d1 >> 44) as u64;
        let h1 = (d1 as u64) & LIMB_MASK;
        let d2 = d[2] + u128::from(c);
        let c = (d2 >> 42) as u64;
        let h2 = (d2 as u64) & LIMB2_MASK;
        let h0 = h0 + c * 5;
        let c = h0 >> 44;
        [h0 & LIMB_MASK, h1 + c, h2]
    }

    fn absorb_stride2(&mut self, data: &[u8]) {
        debug_assert!(data.len().is_multiple_of(16), "absorb takes whole blocks");
        let r2 = Self::fold_unfolded(Self::mul_unfolded(
            [self.r0, self.r1, self.r2],
            (self.r0, self.r1, self.r2),
            (self.s1, self.s2),
        ));
        let r2s = (r2[1].wrapping_mul(20), r2[2].wrapping_mul(20));

        let r = (self.r0, self.r1, self.r2);
        let rs = (self.s1, self.s2);
        let r2t = (r2[0], r2[1], r2[2]);
        let (mut h0, mut h1, mut h2) = (self.h[0], self.h[1], self.h[2]);

        let (pairs, rest) = data.as_chunks::<32>();
        for pair in pairs {
            let read = |m: &[u8]| {
                let t0 = u64::from_le_bytes(m[0..8].try_into().expect("whole block"));
                let t1 = u64::from_le_bytes(m[8..16].try_into().expect("whole block"));
                [
                    t0 & LIMB_MASK,
                    ((t0 >> 44) | (t1 << 20)) & LIMB_MASK,
                    ((t1 >> 24) & LIMB2_MASK) + HIBIT,
                ]
            };
            let b0 = read(&pair[..16]);
            let b1 = read(&pair[16..]);

            let d_a = Self::mul_unfolded([h0 + b0[0], h1 + b0[1], h2 + b0[2]], r2t, r2s);
            let d_b = Self::mul_unfolded(b1, r, rs);
            let d = [d_a[0] + d_b[0], d_a[1] + d_b[1], d_a[2] + d_b[2]];
            [h0, h1, h2] = Self::fold_unfolded(d);
        }
        if let Some(m) = rest.first_chunk::<16>() {
            let t0 = u64::from_le_bytes(m[0..8].try_into().expect("whole block"));
            let t1 = u64::from_le_bytes(m[8..16].try_into().expect("whole block"));
            let b = [
                t0 & LIMB_MASK,
                ((t0 >> 44) | (t1 << 20)) & LIMB_MASK,
                ((t1 >> 24) & LIMB2_MASK) + HIBIT,
            ];
            let d = Self::mul_unfolded([h0 + b[0], h1 + b[1], h2 + b[2]], r, rs);
            [h0, h1, h2] = Self::fold_unfolded(d);
        }

        self.h = [h0, h1, h2];
    }

    #[cfg(target_arch = "x86_64")]
    #[allow(
        clippy::too_many_lines,
        reason = "one four-lane Horner step; factoring the per-group body into a helper would put a call per sixty-four bytes, the same cost the three-limb absorb keeps inline"
    )]
    #[target_feature(enable = "avx2")]
    unsafe fn absorb_avx2(&mut self, data: &[u8]) {
        #[allow(clippy::wildcard_imports, reason = "flat lane primitives")]
        use core::arch::x86_64::*;

        debug_assert!(data.len().is_multiple_of(16), "absorb takes whole blocks");
        let n = data.len() / 16;
        let e = n % 4;

        // A block count that is a multiple of four needs no head: an empty-slice dispatch costs eight loads and three stores.
        if e > 0 {
            self.absorb_one_block_chain(&data[..e * 16], HIBIT);
        }

        let r26 = to_26([self.r0, self.r1, self.r2]);
        let powers = powers4(&r26);
        let r4 = &powers[2];

        let r0v = _mm256_set1_epi64x(r4[0].cast_signed().into());
        let r1v = _mm256_set1_epi64x(r4[1].cast_signed().into());
        let r2v = _mm256_set1_epi64x(r4[2].cast_signed().into());
        let r3v = _mm256_set1_epi64x(r4[3].cast_signed().into());
        let r4v = _mm256_set1_epi64x(r4[4].cast_signed().into());
        let s1v = _mm256_set1_epi64x(r4[1].wrapping_mul(5).cast_signed().into());
        let s2v = _mm256_set1_epi64x(r4[2].wrapping_mul(5).cast_signed().into());
        let s3v = _mm256_set1_epi64x(r4[3].wrapping_mul(5).cast_signed().into());
        let s4v = _mm256_set1_epi64x(r4[4].wrapping_mul(5).cast_signed().into());
        let mask26 = _mm256_set1_epi64x(M26.cast_signed());

        let mut hv = [_mm256_setzero_si256(); 5];

        let mut groups = &data[e * 16..];
        while let Some(g) = groups.first_chunk::<64>() {
            let mut d0 = _mm256_mul_epu32(hv[0], r0v);
            d0 = _mm256_add_epi64(d0, _mm256_mul_epu32(hv[1], s4v));
            d0 = _mm256_add_epi64(d0, _mm256_mul_epu32(hv[2], s3v));
            d0 = _mm256_add_epi64(d0, _mm256_mul_epu32(hv[3], s2v));
            d0 = _mm256_add_epi64(d0, _mm256_mul_epu32(hv[4], s1v));
            let mut d1 = _mm256_mul_epu32(hv[0], r1v);
            d1 = _mm256_add_epi64(d1, _mm256_mul_epu32(hv[1], r0v));
            d1 = _mm256_add_epi64(d1, _mm256_mul_epu32(hv[2], s4v));
            d1 = _mm256_add_epi64(d1, _mm256_mul_epu32(hv[3], s3v));
            d1 = _mm256_add_epi64(d1, _mm256_mul_epu32(hv[4], s2v));
            let mut d2 = _mm256_mul_epu32(hv[0], r2v);
            d2 = _mm256_add_epi64(d2, _mm256_mul_epu32(hv[1], r1v));
            d2 = _mm256_add_epi64(d2, _mm256_mul_epu32(hv[2], r0v));
            d2 = _mm256_add_epi64(d2, _mm256_mul_epu32(hv[3], s4v));
            d2 = _mm256_add_epi64(d2, _mm256_mul_epu32(hv[4], s3v));
            let mut d3 = _mm256_mul_epu32(hv[0], r3v);
            d3 = _mm256_add_epi64(d3, _mm256_mul_epu32(hv[1], r2v));
            d3 = _mm256_add_epi64(d3, _mm256_mul_epu32(hv[2], r1v));
            d3 = _mm256_add_epi64(d3, _mm256_mul_epu32(hv[3], r0v));
            d3 = _mm256_add_epi64(d3, _mm256_mul_epu32(hv[4], s4v));
            let mut d4 = _mm256_mul_epu32(hv[0], r4v);
            d4 = _mm256_add_epi64(d4, _mm256_mul_epu32(hv[1], r3v));
            d4 = _mm256_add_epi64(d4, _mm256_mul_epu32(hv[2], r2v));
            d4 = _mm256_add_epi64(d4, _mm256_mul_epu32(hv[3], r1v));
            d4 = _mm256_add_epi64(d4, _mm256_mul_epu32(hv[4], r0v));

            let c = _mm256_srli_epi64::<26>(d0);
            let o0 = _mm256_and_si256(d0, mask26);
            d1 = _mm256_add_epi64(d1, c);
            let c = _mm256_srli_epi64::<26>(d1);
            let o1 = _mm256_and_si256(d1, mask26);
            d2 = _mm256_add_epi64(d2, c);
            let c = _mm256_srli_epi64::<26>(d2);
            let o2 = _mm256_and_si256(d2, mask26);
            d3 = _mm256_add_epi64(d3, c);
            let c = _mm256_srli_epi64::<26>(d3);
            let o3 = _mm256_and_si256(d3, mask26);
            d4 = _mm256_add_epi64(d4, c);
            let c = _mm256_srli_epi64::<26>(d4);
            let o4 = _mm256_and_si256(d4, mask26);
            let wrapped = _mm256_add_epi64(o0, _mm256_add_epi64(_mm256_slli_epi64::<2>(c), c));
            hv[0] = _mm256_and_si256(wrapped, mask26);
            hv[1] = _mm256_add_epi64(o1, _mm256_srli_epi64::<26>(wrapped));
            hv[2] = o2;
            hv[3] = o3;
            hv[4] = o4;

            let lo = unsafe { _mm256_loadu_si256(g.as_ptr().cast()) };
            let hi = unsafe { _mm256_loadu_si256(g.as_ptr().add(32).cast()) };
            hv[0] = _mm256_add_epi64(hv[0], limb_window::<0, 0>(lo, hi, mask26));
            hv[1] = _mm256_add_epi64(hv[1], limb_window::<2, 1>(lo, hi, mask26));
            hv[2] = _mm256_add_epi64(hv[2], limb_window::<4, 2>(lo, hi, mask26));
            hv[3] = _mm256_add_epi64(hv[3], limb_window::<6, 3>(lo, hi, mask26));
            hv[4] = _mm256_add_epi64(
                hv[4],
                _mm256_add_epi64(
                    limb_window::<8, 4>(lo, hi, mask26),
                    _mm256_set1_epi64x(HIBIT26.cast_signed().into()),
                ),
            );

            groups = &groups[64..];
        }

        let mut lanes = [[0u32; 5]; 4];
        for (j, lane) in hv.iter().enumerate() {
            let mut arr = [0u64; 4];
            unsafe { _mm256_storeu_si256(arr.as_mut_ptr().cast(), *lane) };
            // the unpack interleaves as blocks 0, 2, 1, 3; undo it once here
            lanes[0][j] = arr[0] as u32;
            lanes[1][j] = arr[2] as u32;
            lanes[2][j] = arr[1] as u32;
            lanes[3][j] = arr[3] as u32;
        }

        self.h = combine4(self.h, &lanes, &r26, &powers, n / 4);
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(
        clippy::too_many_lines,
        reason = "one four-lane Horner step; factoring the per-group body into a helper would put a call per sixty-four bytes, the same cost the three-limb absorb keeps inline"
    )]
    fn absorb_neon4(&mut self, data: &[u8]) {
        #[allow(clippy::wildcard_imports, reason = "flat lane primitives")]
        use core::arch::aarch64::*;

        debug_assert!(data.len().is_multiple_of(16), "absorb takes whole blocks");
        let n = data.len() / 16;
        let e = n % 4;

        // A block count that is a multiple of four needs no head: an empty-slice dispatch costs eight loads and three stores.
        if e > 0 {
            self.absorb_one_block_chain(&data[..e * 16], HIBIT);
        }

        let r26 = to_26([self.r0, self.r1, self.r2]);
        let powers = powers4(&r26);
        let r4 = &powers[2];

        let (r0v, r1v, r2v, r3v, r4v, s1v, s2v, s3v, s4v, mask64) = unsafe {
            (
                vdup_n_u32(r4[0]),
                vdup_n_u32(r4[1]),
                vdup_n_u32(r4[2]),
                vdup_n_u32(r4[3]),
                vdup_n_u32(r4[4]),
                vdup_n_u32(r4[1].wrapping_mul(5)),
                vdup_n_u32(r4[2].wrapping_mul(5)),
                vdup_n_u32(r4[3].wrapping_mul(5)),
                vdup_n_u32(r4[4].wrapping_mul(5)),
                vdupq_n_u64(M26),
            )
        };

        let mut hv: [uint32x4_t; 5] = unsafe { [vdupq_n_u32(0); 5] };
        let mask26: uint32x4_t = unsafe { vdupq_n_u32(M26_U32) };

        let mut groups = &data[e * 16..];
        while let Some(g) = groups.first_chunk::<64>() {
            let (d0_lo, d1_lo, d2_lo, d3_lo, d4_lo, d0_hi, d1_hi, d2_hi, d3_hi, d4_hi) = unsafe {
                let a0 = vget_low_u32(hv[0]);
                let a1 = vget_low_u32(hv[1]);
                let a2 = vget_low_u32(hv[2]);
                let a3 = vget_low_u32(hv[3]);
                let a4 = vget_low_u32(hv[4]);
                let b0 = vget_high_u32(hv[0]);
                let b1 = vget_high_u32(hv[1]);
                let b2 = vget_high_u32(hv[2]);
                let b3 = vget_high_u32(hv[3]);
                let b4 = vget_high_u32(hv[4]);
                let mut d0_lo = vmull_u32(a0, r0v);
                d0_lo = vmlal_u32(d0_lo, a1, s4v);
                d0_lo = vmlal_u32(d0_lo, a2, s3v);
                d0_lo = vmlal_u32(d0_lo, a3, s2v);
                d0_lo = vmlal_u32(d0_lo, a4, s1v);
                let mut d1_lo = vmull_u32(a0, r1v);
                d1_lo = vmlal_u32(d1_lo, a1, r0v);
                d1_lo = vmlal_u32(d1_lo, a2, s4v);
                d1_lo = vmlal_u32(d1_lo, a3, s3v);
                d1_lo = vmlal_u32(d1_lo, a4, s2v);
                let mut d2_lo = vmull_u32(a0, r2v);
                d2_lo = vmlal_u32(d2_lo, a1, r1v);
                d2_lo = vmlal_u32(d2_lo, a2, r0v);
                d2_lo = vmlal_u32(d2_lo, a3, s4v);
                d2_lo = vmlal_u32(d2_lo, a4, s3v);
                let mut d3_lo = vmull_u32(a0, r3v);
                d3_lo = vmlal_u32(d3_lo, a1, r2v);
                d3_lo = vmlal_u32(d3_lo, a2, r1v);
                d3_lo = vmlal_u32(d3_lo, a3, r0v);
                d3_lo = vmlal_u32(d3_lo, a4, s4v);
                let mut d4_lo = vmull_u32(a0, r4v);
                d4_lo = vmlal_u32(d4_lo, a1, r3v);
                d4_lo = vmlal_u32(d4_lo, a2, r2v);
                d4_lo = vmlal_u32(d4_lo, a3, r1v);
                d4_lo = vmlal_u32(d4_lo, a4, r0v);
                let mut d0_hi = vmull_u32(b0, r0v);
                d0_hi = vmlal_u32(d0_hi, b1, s4v);
                d0_hi = vmlal_u32(d0_hi, b2, s3v);
                d0_hi = vmlal_u32(d0_hi, b3, s2v);
                d0_hi = vmlal_u32(d0_hi, b4, s1v);
                let mut d1_hi = vmull_u32(b0, r1v);
                d1_hi = vmlal_u32(d1_hi, b1, r0v);
                d1_hi = vmlal_u32(d1_hi, b2, s4v);
                d1_hi = vmlal_u32(d1_hi, b3, s3v);
                d1_hi = vmlal_u32(d1_hi, b4, s2v);
                let mut d2_hi = vmull_u32(b0, r2v);
                d2_hi = vmlal_u32(d2_hi, b1, r1v);
                d2_hi = vmlal_u32(d2_hi, b2, r0v);
                d2_hi = vmlal_u32(d2_hi, b3, s4v);
                d2_hi = vmlal_u32(d2_hi, b4, s3v);
                let mut d3_hi = vmull_u32(b0, r3v);
                d3_hi = vmlal_u32(d3_hi, b1, r2v);
                d3_hi = vmlal_u32(d3_hi, b2, r1v);
                d3_hi = vmlal_u32(d3_hi, b3, r0v);
                d3_hi = vmlal_u32(d3_hi, b4, s4v);
                let mut d4_hi = vmull_u32(b0, r4v);
                d4_hi = vmlal_u32(d4_hi, b1, r3v);
                d4_hi = vmlal_u32(d4_hi, b2, r2v);
                d4_hi = vmlal_u32(d4_hi, b3, r1v);
                d4_hi = vmlal_u32(d4_hi, b4, r0v);
                (
                    d0_lo, d1_lo, d2_lo, d3_lo, d4_lo, d0_hi, d1_hi, d2_hi, d3_hi, d4_hi,
                )
            };

            let lo = fold64(d0_lo, d1_lo, d2_lo, d3_lo, d4_lo, mask64);
            let hi = fold64(d0_hi, d1_hi, d2_hi, d3_hi, d4_hi, mask64);
            hv = unsafe {
                [
                    vcombine_u32(vmovn_u64(lo.0), vmovn_u64(hi.0)),
                    vcombine_u32(vmovn_u64(lo.1), vmovn_u64(hi.1)),
                    vcombine_u32(vmovn_u64(lo.2), vmovn_u64(hi.2)),
                    vcombine_u32(vmovn_u64(lo.3), vmovn_u64(hi.3)),
                    vcombine_u32(vmovn_u64(lo.4), vmovn_u64(hi.4)),
                ]
            };

            let blocks = unsafe {
                uint8x16x4_t(
                    vld1q_u8(g[0..16].as_ptr()),
                    vld1q_u8(g[16..32].as_ptr()),
                    vld1q_u8(g[32..48].as_ptr()),
                    vld1q_u8(g[48..64].as_ptr()),
                )
            };
            unsafe {
                hv[0] = vaddq_u32(hv[0], neon_low_limb(blocks, mask26));
                hv[1] = vaddq_u32(hv[1], neon_limb_window::<2, 1>(blocks, mask26));
                hv[2] = vaddq_u32(hv[2], neon_limb_window::<4, 2>(blocks, mask26));
                hv[3] = vaddq_u32(hv[3], neon_limb_window::<6, 3>(blocks, mask26));
                hv[4] = vaddq_u32(
                    hv[4],
                    vaddq_u32(
                        neon_limb_window::<8, 4>(blocks, mask26),
                        vdupq_n_u32(HIBIT26),
                    ),
                );
            }

            groups = &groups[64..];
        }

        let mut lanes = [[0u32; 5]; 4];
        for (j, lane) in hv.iter().enumerate() {
            let mut arr = [0u32; 4];
            unsafe { vst1q_u32(arr.as_mut_ptr(), *lane) };
            for (i, value) in arr.into_iter().enumerate() {
                lanes[i][j] = value;
            }
        }

        self.h = combine4(self.h, &lanes, &r26, &powers, n / 4);
    }

    #[cfg(all(test, target_arch = "aarch64"))]
    #[allow(
        clippy::too_many_lines,
        reason = "one two-lane Horner step; factoring the per-block body into a helper would put a call per thirty-two bytes, the same cost the three-limb absorb keeps inline"
    )]
    fn absorb_neon(&mut self, data: &[u8]) {
        #[allow(
            clippy::wildcard_imports,
            reason = "flat lane primitives, as in chacha::neon"
        )]
        use core::arch::aarch64::*;

        let n = data.len() / 16;
        let k1 = n / 2;
        let k2 = n - k1;
        let (first, rest) = data.split_at(k1 * 16);
        let (second_prefix, tail) = rest.split_at(k1 * 16);

        let r = to_26([self.r0, self.r1, self.r2]);
        let h_in = to_26(self.h);
        let r0v;
        let r1v;
        let r2v;
        let r3v;
        let r4v;
        let s1v;
        let s2v;
        let s3v;
        let s4v;
        unsafe {
            r0v = vdup_n_u32(r[0]);
            r1v = vdup_n_u32(r[1]);
            r2v = vdup_n_u32(r[2]);
            r3v = vdup_n_u32(r[3]);
            r4v = vdup_n_u32(r[4]);
            s1v = vdup_n_u32(r[1].wrapping_mul(5));
            s2v = vdup_n_u32(r[2].wrapping_mul(5));
            s3v = vdup_n_u32(r[3].wrapping_mul(5));
            s4v = vdup_n_u32(r[4].wrapping_mul(5));
        }

        let mut hv: [uint32x2_t; 5] = unsafe { [vdup_n_u32(0); 5] };
        let mask64: uint64x2_t = unsafe { vdupq_n_u64(M26) };

        for i in 0..k1 {
            let a_blk: &[u8; 16] = first[i * 16..i * 16 + 16]
                .try_into()
                .expect("first half is whole blocks");
            let b_blk: &[u8; 16] = second_prefix[i * 16..i * 16 + 16]
                .try_into()
                .expect("second prefix is whole blocks");
            let w = |m: &[u8; 16], at: usize| {
                u32::from_le_bytes([m[at], m[at + 1], m[at + 2], m[at + 3]])
            };
            let ma = [
                w(a_blk, 0) & M26_U32,
                (w(a_blk, 3) >> 2) & M26_U32,
                (w(a_blk, 6) >> 4) & M26_U32,
                (w(a_blk, 9) >> 6) & M26_U32,
                (w(a_blk, 12) >> 8) + HIBIT26,
            ];
            let mb = [
                w(b_blk, 0) & M26_U32,
                (w(b_blk, 3) >> 2) & M26_U32,
                (w(b_blk, 6) >> 4) & M26_U32,
                (w(b_blk, 9) >> 6) & M26_U32,
                (w(b_blk, 12) >> 8) + HIBIT26,
            ];
            unsafe {
                for (j, lane) in hv.iter_mut().enumerate() {
                    let pair = [ma[j], mb[j]];
                    let mv = vld1_u32(pair.as_ptr());
                    *lane = vadd_u32(*lane, mv);
                }
            }

            let (d0, mut d1, mut d2, mut d3, mut d4) = unsafe {
                let mut d0 = vmull_u32(hv[0], r0v);
                d0 = vmlal_u32(d0, hv[1], s4v);
                d0 = vmlal_u32(d0, hv[2], s3v);
                d0 = vmlal_u32(d0, hv[3], s2v);
                d0 = vmlal_u32(d0, hv[4], s1v);
                let mut d1 = vmull_u32(hv[0], r1v);
                d1 = vmlal_u32(d1, hv[1], r0v);
                d1 = vmlal_u32(d1, hv[2], s4v);
                d1 = vmlal_u32(d1, hv[3], s3v);
                d1 = vmlal_u32(d1, hv[4], s2v);
                let mut d2 = vmull_u32(hv[0], r2v);
                d2 = vmlal_u32(d2, hv[1], r1v);
                d2 = vmlal_u32(d2, hv[2], r0v);
                d2 = vmlal_u32(d2, hv[3], s4v);
                d2 = vmlal_u32(d2, hv[4], s3v);
                let mut d3 = vmull_u32(hv[0], r3v);
                d3 = vmlal_u32(d3, hv[1], r2v);
                d3 = vmlal_u32(d3, hv[2], r1v);
                d3 = vmlal_u32(d3, hv[3], r0v);
                d3 = vmlal_u32(d3, hv[4], s4v);
                let mut d4 = vmull_u32(hv[0], r4v);
                d4 = vmlal_u32(d4, hv[1], r3v);
                d4 = vmlal_u32(d4, hv[2], r2v);
                d4 = vmlal_u32(d4, hv[3], r1v);
                d4 = vmlal_u32(d4, hv[4], r0v);
                (d0, d1, d2, d3, d4)
            };

            unsafe {
                let c0 = vshrq_n_u64::<26>(d0);
                let o0 = vandq_u64(d0, mask64);
                d1 = vaddq_u64(d1, c0);
                let c1 = vshrq_n_u64::<26>(d1);
                let o1 = vandq_u64(d1, mask64);
                d2 = vaddq_u64(d2, c1);
                let c2 = vshrq_n_u64::<26>(d2);
                let o2 = vandq_u64(d2, mask64);
                d3 = vaddq_u64(d3, c2);
                let c3 = vshrq_n_u64::<26>(d3);
                let o3 = vandq_u64(d3, mask64);
                d4 = vaddq_u64(d4, c3);
                let c4 = vshrq_n_u64::<26>(d4);
                let o4 = vandq_u64(d4, mask64);
                let wrapped = vaddq_u64(o0, vaddq_u64(vshlq_n_u64::<2>(c4), c4));
                let wrapped_carry = vshrq_n_u64::<26>(wrapped);
                let wrapped_masked = vandq_u64(wrapped, mask64);
                hv[0] = vmovn_u64(wrapped_masked);
                hv[1] = vmovn_u64(vaddq_u64(o1, wrapped_carry));
                hv[2] = vmovn_u64(o2);
                hv[3] = vmovn_u64(o3);
                hv[4] = vmovn_u64(o4);
            }
        }

        let mut ha = [0u32; 5];
        let mut hb_part = [0u32; 5];
        unsafe {
            for (j, lane) in hv.iter().enumerate() {
                let mut pair = [0u32; 2];
                vst1_u32(pair.as_mut_ptr(), *lane);
                ha[j] = pair[0];
                hb_part[j] = pair[1];
            }
        }

        let mut hb = hb_part;
        if !tail.is_empty() {
            let tail_blk: &[u8; 16] = tail.try_into().expect("odd tail is one block");
            let w = |at: usize| {
                u32::from_le_bytes([
                    tail_blk[at],
                    tail_blk[at + 1],
                    tail_blk[at + 2],
                    tail_blk[at + 3],
                ])
            };
            let m = [
                w(0) & M26_U32,
                (w(3) >> 2) & M26_U32,
                (w(6) >> 4) & M26_U32,
                (w(9) >> 6) & M26_U32,
                (w(12) >> 8) + HIBIT26,
            ];
            let mut sum = [0u32; 5];
            for (i, limb) in sum.iter_mut().enumerate() {
                *limb = hb[i].wrapping_add(m[i]);
            }
            hb = field_mul(&sum, &r);
        }

        let (r_pow_n, r_pow_k2) = if k1 == k2 {
            let rk = field_pow(r, k2);
            let rn = field_mul(&rk, &rk);
            (rn, rk)
        } else {
            let rk1 = field_pow(r, k1);
            let rk2 = field_mul(&rk1, &r);
            let rn = field_mul(&rk1, &rk2);
            (rn, rk2)
        };
        let t1 = field_mul(&h_in, &r_pow_n);
        let t2 = field_mul(&ha, &r_pow_k2);
        let joined = add_three_normalized(&t1, &t2, &hb);
        self.h = from_26(joined);
    }
}

fn reduce(h: [u64; 3], pad: u128) -> u128 {
    let [h0, h1, h2] = h;

    let top = h2 + (h1 >> 44);
    debug_assert!(
        top <= LIMB2_MASK + 1,
        "the block loop's fold must keep h under 2^130 + 2^44"
    );

    let hi = top >> 40;
    let low =
        u128::from(h0) | (u128::from(h1 & LIMB_MASK) << 44) | (u128::from(top & LOW_40) << 88);

    let (lifted, carry) = low.overflowing_add(5);
    let above_p = u128::from(hi).wrapping_add(u128::from(carry)) >= 4;
    let lift = 0u128.wrapping_sub(u128::from(above_p));
    let acc = (low & !lift) | (lifted & lift);

    acc.wrapping_add(pad)
}

#[allow(
    clippy::too_many_lines,
    reason = "this is the previous implementation kept verbatim so it can measure the new one; splitting it would stop it being the same code"
)]
pub fn tag_via_26_bit_horner(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    const M: u64 = 0x03ff_ffff;
    const WORD: u64 = 0xffff_ffff;

    let word = |at: usize| u32::from_le_bytes([key[at], key[at + 1], key[at + 2], key[at + 3]]);
    let r = [
        word(0) & 0x03ff_ffff,
        (word(3) >> 2) & 0x03ff_ff03,
        (word(6) >> 4) & 0x03ff_c0ff,
        (word(9) >> 6) & 0x03f0_3fff,
        (word(12) >> 8) & 0x000f_ffff,
    ];
    let pad = [word(16), word(20), word(24), word(28)];
    let (s1, s2, s3, s4) = (
        u64::from(r[1]) * 5,
        u64::from(r[2]) * 5,
        u64::from(r[3]) * 5,
        u64::from(r[4]) * 5,
    );
    let r = [
        u64::from(r[0]),
        u64::from(r[1]),
        u64::from(r[2]),
        u64::from(r[3]),
        u64::from(r[4]),
    ];

    let mut h = [0u64; 5];

    let absorb = |data: &[u8], hibit: u64, h: &mut [u64; 5]| {
        let mut rest = data;
        while let Some(m) = rest.first_chunk::<16>() {
            let w = |at: usize| u32::from_le_bytes([m[at], m[at + 1], m[at + 2], m[at + 3]]);
            let h0 = h[0] + (u64::from(w(0)) & M);
            let h1 = h[1] + ((u64::from(w(3)) >> 2) & M);
            let h2 = h[2] + ((u64::from(w(6)) >> 4) & M);
            let h3 = h[3] + ((u64::from(w(9)) >> 6) & M);
            let h4 = h[4] + ((u64::from(w(12)) >> 8) & M) + hibit;

            let d0 = h0 * r[0] + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
            let mut d1 = h0 * r[1] + h1 * r[0] + h2 * s4 + h3 * s3 + h4 * s2;
            let mut d2 = h0 * r[2] + h1 * r[1] + h2 * r[0] + h3 * s4 + h4 * s3;
            let mut d3 = h0 * r[3] + h1 * r[2] + h2 * r[1] + h3 * r[0] + h4 * s4;
            let mut d4 = h0 * r[4] + h1 * r[3] + h2 * r[2] + h3 * r[1] + h4 * r[0];

            let c = d0 >> 26;
            let o0 = d0 & M;
            d1 += c;
            let c = d1 >> 26;
            let o1 = d1 & M;
            d2 += c;
            let c = d2 >> 26;
            let o2 = d2 & M;
            d3 += c;
            let c = d3 >> 26;
            let o3 = d3 & M;
            d4 += c;
            let c = d4 >> 26;
            let o4 = d4 & M;
            let wrapped = o0 + c * 5;
            *h = [wrapped & M, o1 + (wrapped >> 26), o2, o3, o4];
            rest = &rest[16..];
        }
    };

    let whole = data.len() / 16 * 16;
    absorb(&data[..whole], 1 << 24, &mut h);

    let tail = &data[whole..];
    if !tail.is_empty() {
        let mut block = [0u8; 16];
        block[..tail.len()].copy_from_slice(tail);
        block[tail.len()] = 1;
        absorb(&block, 0, &mut h);
    }

    let [mut h0, mut h1, mut h2, mut h3, mut h4] = h;
    let mut c;
    c = h1 >> 26;
    h1 &= M;
    h2 += c;
    c = h2 >> 26;
    h2 &= M;
    h3 += c;
    c = h3 >> 26;
    h3 &= M;
    h4 += c;
    c = h4 >> 26;
    h4 &= M;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= M;
    h1 += c;

    let mut g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= M;
    let mut g1 = h1 + c;
    c = g1 >> 26;
    g1 &= M;
    let mut g2 = h2 + c;
    c = g2 >> 26;
    g2 &= M;
    let mut g3 = h3 + c;
    c = g3 >> 26;
    g3 &= M;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);
    let mut mask = (g4 >> 63).wrapping_sub(1);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    let g4 = g4 & mask;
    mask = !mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    let h4 = (h4 & mask) | g4;

    let f0 = (h0 | (h1 << 26)) & WORD;
    let f1 = ((h1 >> 6) | (h2 << 20)) & WORD;
    let f2 = ((h2 >> 12) | (h3 << 14)) & WORD;
    let f3 = ((h3 >> 18) | (h4 << 8)) & WORD;

    let mut carry = f0 + u64::from(pad[0]);
    let f0 = carry as u32;
    carry = f1 + u64::from(pad[1]) + (carry >> 32);
    let f1 = carry as u32;
    carry = f2 + u64::from(pad[2]) + (carry >> 32);
    let f2 = carry as u32;
    carry = f3 + u64::from(pad[3]) + (carry >> 32);
    let f3 = carry as u32;

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&f0.to_le_bytes());
    out[4..8].copy_from_slice(&f1.to_le_bytes());
    out[8..12].copy_from_slice(&f2.to_le_bytes());
    out[12..16].copy_from_slice(&f3.to_le_bytes());
    out
}

#[must_use]
pub fn tag(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let mut state = Poly1305::new(key);
    state.update(data);
    state.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reduction_is_right_where_the_limbs_are_worst() {
        const EDGE0: [u64; 8] = [
            0,
            1,
            2,
            1 << 20,
            (1 << 43) - 1,
            LIMB_MASK - 1,
            LIMB_MASK - 2,
            LIMB_MASK,
        ];
        const EDGE1: [u64; 9] = [
            0,
            1,
            2,
            1 << 20,
            (1 << 43) - 1,
            LIMB_MASK - 1,
            LIMB_MASK - 2,
            LIMB_MASK,
            1 << 44,
        ];
        const EDGE2: [u64; 10] = [
            0,
            1,
            2,
            1 << 20,
            (1 << 39) - 1,
            1 << 40,
            (1 << 40) + 1,
            (1 << 41) - 1,
            LIMB2_MASK - 1,
            LIMB2_MASK,
        ];

        let mut checked = 0usize;
        for &h0 in &EDGE0 {
            for &h1 in &EDGE1 {
                for &h2 in &EDGE2 {
                    checked += 1;
                    assert_eq!(
                        reduce([h0, h1, h2], 0),
                        reference([h0, h1, h2], 0),
                        "h0 {h0:#x} h1 {h1:#x} h2 {h2:#x}"
                    );
                    let pad = u128::MAX - u128::from(h0);
                    assert_eq!(
                        reduce([h0, h1, h2], pad),
                        reference([h0, h1, h2], pad),
                        "h0 {h0:#x} h1 {h1:#x} h2 {h2:#x} with a carrying pad"
                    );
                }
            }
        }
        assert!(checked >= 720, "the cross product is the sweep");
    }

    fn reference(h: [u64; 3], pad: u128) -> u128 {
        let [h0, h1, h2] = h;
        let top = h2 + (h1 >> 44);
        let hi = u128::from(top >> 40);
        let low =
            u128::from(h0) | (u128::from(h1 & LIMB_MASK) << 44) | (u128::from(top & LOW_40) << 88);
        let (p_hi, p_lo) = (3u128, u128::MAX - 4);
        let above = hi > p_hi || (hi == p_hi && low >= p_lo);
        let acc = if above { low.wrapping_add(5) } else { low };
        acc.wrapping_add(pad)
    }

    #[test]
    fn three_limbs_agree_with_the_26_bit_horner_at_every_length() {
        let mut checked = 0usize;
        for seed in 0..4u8 {
            let key: [u8; 32] =
                std::array::from_fn(|i| (i as u8).wrapping_mul(197).wrapping_add(seed * 61));
            for len in (0..=200usize).chain([255, 256, 257, 512, 513, 1024, 8192]) {
                let data: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
                    .collect();
                assert_eq!(
                    tag(&key, &data),
                    tag_via_26_bit_horner(&key, &data),
                    "seed {seed} length {len}"
                );
                checked += 1;
            }
        }
        assert!(checked > 800, "the sweep should be dense, not a sample");
    }

    #[test]
    fn one_block_and_one_byte_agree_with_the_split_form() {
        let key = [0x42u8; 32];
        for len in 0..=48usize {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(29)).collect();
            let one_shot = tag(&key, &data);
            let mut split = Poly1305::new(&key);
            for chunk in data.chunks(7) {
                split.update(chunk);
            }
            assert_eq!(one_shot, split.finish(), "length {len} fed in sevens");
        }
    }

    #[test]
    fn byte_at_a_time_matches_one_shot() {
        let key = [0x11u8; 32];
        for len in 0..=80usize {
            let data: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(251).wrapping_add(3))
                .collect();
            let mut dribble = Poly1305::new(&key);
            for byte in &data {
                dribble.update(std::slice::from_ref(byte));
            }
            assert_eq!(tag(&key, &data), dribble.finish(), "length {len}");
        }
    }

    #[test]
    fn every_threshold_reaches_the_same_tag_from_both_sides() {
        let mut lengths: Vec<usize> = (0..=200usize).collect();
        #[cfg(target_arch = "aarch64")]
        let thresholds: [usize; 3] = [
            STRIDE2_THRESHOLD_BYTES,
            NEON_THRESHOLD_BYTES,
            NEON4_THRESHOLD_BYTES,
        ];
        #[cfg(target_arch = "x86_64")]
        let thresholds: [usize; 2] = [STRIDE2_THRESHOLD_BYTES, AVX2_THRESHOLD_BYTES];
        for threshold in thresholds {
            lengths.extend(
                [
                    threshold.saturating_sub(32),
                    threshold.saturating_sub(16),
                    threshold,
                    threshold + 16,
                    threshold + 32,
                    threshold + 48,
                ]
                .into_iter()
                .filter(|len| *len > 200),
            );
        }
        lengths.sort_unstable();
        lengths.dedup();

        let mut checked = 0usize;
        for seed in 0..4u8 {
            let key: [u8; 32] =
                std::array::from_fn(|i| (i as u8).wrapping_mul(197).wrapping_add(seed * 61));
            for len in &lengths {
                let data: Vec<u8> = (0..*len)
                    .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
                    .collect();
                assert_eq!(
                    tag(&key, &data),
                    tag_via_26_bit_horner(&key, &data),
                    "seed {seed} length {len}"
                );
                checked += 1;
            }
        }
        assert_eq!(
            checked,
            lengths.len() * 4,
            "the sweep should be every length at every seed"
        );
    }

    #[test]
    fn every_loop_matches_the_one_block_chain_at_every_block_count() {
        let key = [0xa7u8; 32];
        for blocks in 0..108usize {
            let data: Vec<u8> = (0..blocks * 16)
                .map(|i| (i as u8).wrapping_mul(17))
                .collect();
            let mut chain = Poly1305::new(&key);
            chain.absorb_one_block_chain(&data, HIBIT);
            let expected = chain.finish();

            #[cfg(target_arch = "aarch64")]
            {
                let mut stride2 = Poly1305::new(&key);
                stride2.absorb_stride2(&data);
                assert_eq!(
                    expected,
                    stride2.finish(),
                    "{blocks} blocks: stride-two must match the one-block chain"
                );

                let mut two_way = Poly1305::new(&key);
                two_way.absorb_neon(&data);
                assert_eq!(
                    expected,
                    two_way.finish(),
                    "{blocks} blocks: the two-way NEON path must match the one-block chain"
                );

                if blocks >= 4 {
                    let mut four_way = Poly1305::new(&key);
                    four_way.absorb_neon4(&data);
                    assert_eq!(
                        expected,
                        four_way.finish(),
                        "{blocks} blocks: the four-way NEON path must match the one-block chain"
                    );
                }
            }

            #[cfg(target_arch = "x86_64")]
            if std::is_x86_feature_detected!("avx2") && blocks >= 4 {
                let mut four_way = Poly1305::new(&key);
                unsafe { four_way.absorb_avx2(&data) };
                assert_eq!(
                    expected,
                    four_way.finish(),
                    "{blocks} blocks: the four-way AVX2 path must match the one-block chain"
                );
            }
        }
    }

    #[test]
    fn every_loop_leaves_the_invariant_reduce_asserts() {
        let keys: [[u8; 32]; 2] = [[0x5au8; 32], [0xa7u8; 32]];
        for key in &keys {
            for blocks in 0..70usize {
                let data: Vec<u8> = (0..blocks * 16)
                    .map(|i| (i as u8).wrapping_mul(53))
                    .collect();
                let mut chain = Poly1305::new(key);
                chain.absorb_one_block_chain(&data, HIBIT);
                let mut lanes: Vec<Poly1305> = vec![chain];

                #[cfg(target_arch = "aarch64")]
                {
                    let mut stride2 = Poly1305::new(key);
                    stride2.absorb_stride2(&data);
                    lanes.push(stride2);

                    let mut two_way = Poly1305::new(key);
                    two_way.absorb_neon(&data);
                    lanes.push(two_way);

                    if blocks >= 4 {
                        let mut four_way = Poly1305::new(key);
                        four_way.absorb_neon4(&data);
                        lanes.push(four_way);
                    }
                }

                #[cfg(target_arch = "x86_64")]
                if std::is_x86_feature_detected!("avx2") && blocks >= 4 {
                    let mut four_way = Poly1305::new(key);
                    unsafe { four_way.absorb_avx2(&data) };
                    lanes.push(four_way);
                }

                for (lane, state) in lanes.iter().enumerate() {
                    let top = state.h[2] + (state.h[1] >> 44);
                    assert!(
                        top <= LIMB2_MASK + 1,
                        "lane {lane}, {blocks} blocks: top limb {top:#x} is over the \
                         invariant `reduce` asserts"
                    );
                    assert_eq!(state.h[0] & !LIMB_MASK, 0, "lane {lane}: h0 is unmasked");
                    assert_eq!(state.h[2] & !LIMB2_MASK, 0, "lane {lane}: h2 is unmasked");
                }
            }
        }
    }

    #[test]
    fn several_updates_are_one_run() {
        let key = [0x5au8; 32];
        let mut checked = 0usize;
        for total in [128usize, 256, 2048, 4096, 8192] {
            let data: Vec<u8> = (0..total)
                .map(|i| (i as u8).wrapping_mul(53).wrapping_add(7))
                .collect();
            let mut one = Poly1305::new(&key);
            one.update(&data);
            let one = one.finish();
            for split in [
                1usize, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 511, 512, 513, 1023, 1024,
                1025, 2047, 2048, 2049, 4095, 4096,
            ] {
                if split >= total {
                    continue;
                }
                let mut two = Poly1305::new(&key);
                two.update(&data[..split]);
                two.update(&data[split..]);
                assert_eq!(
                    one,
                    two.finish(),
                    "total {total} split {split}: a continuation must absorb the same value"
                );
                checked += 1;
            }
            let mut dribbled = Poly1305::new(&key);
            for byte in &data {
                dribbled.update(std::slice::from_ref(byte));
            }
            assert_eq!(one, dribbled.finish(), "total {total}, one byte at a time");
        }
        assert!(
            checked > 60,
            "the split sweep should be dense, not a sample"
        );
    }

    #[test]
    fn the_clamp_is_the_specification_and_not_this_implementation() {
        for seed in 0..=255u8 {
            let key: [u8; 32] =
                std::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(seed));
            let wide = u128::from_le_bytes(key[..16].try_into().expect("16 bytes"));
            let clamped = wide & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff;

            let state = Poly1305::new(&key);
            let packed =
                u128::from(state.r0) | (u128::from(state.r1) << 44) | (u128::from(state.r2) << 88);
            assert_eq!(packed, clamped, "clamp for key seed {seed}");
        }
    }

    #[test]
    fn the_accumulator_is_the_crate_it_replaces() {
        use poly1305::universal_hash::KeyInit as _;

        fn theirs(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
            let k: &poly1305::Key = poly1305::Key::from_slice(&key[..]);
            poly1305::Poly1305::new(k).compute_unpadded(data).into()
        }

        let mut checked = 0usize;
        for seed in 0..3u8 {
            let key: [u8; 32] =
                std::array::from_fn(|i| (i as u8).wrapping_mul(197).wrapping_add(seed * 61));
            for len in (0..=48usize).chain([
                63, 64, 65, 127, 128, 129, 240, 256, 272, 512, 528, 1024, 4097,
            ]) {
                let data: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
                    .collect();
                let want = theirs(&key, &data);
                assert_eq!(tag(&key, &data), want, "seed {seed} length {len}");
                for split in 0..=len {
                    let mut state = Poly1305::new(&key);
                    state.update(&data[..split]);
                    state.update(&data[split..]);
                    assert_eq!(
                        state.finish(),
                        want,
                        "seed {seed} length {len} split {split}"
                    );
                }
                checked += 1;
            }
        }
        assert!(checked > 150, "the sweep should be dense, not a sample");
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn the_two_repackings_are_the_same_integer_three_ways() {
        fn reference(h: [u64; 3]) -> (u128, u64) {
            let top = h[2] + (h[1] >> 44);
            let mut low = u128::from(h[0])
                | (u128::from(h[1] & LIMB_MASK) << 44)
                | (u128::from(top & LOW_40) << 88);
            let mut over = top >> 40;
            while over >= 4 || (over == 3 && low.overflowing_add(5).1) {
                let (sum, carry) = low.overflowing_add(5);
                low = sum;
                over = over + u64::from(carry) - 4;
            }
            (low, over)
        }

        fn value_of_five(f: [u32; 5]) -> (u128, u64) {
            let mut low = u128::from(f[0]);
            let mut carry = u64::from(f[1] >> 26);
            low += u128::from(f[1] & M26_U32) << 26;
            let mut limb2 = u64::from(f[2]) + carry;
            carry = limb2 >> 26;
            limb2 &= M26;
            low += u128::from(limb2) << 52;
            let mut limb3 = u64::from(f[3]) + carry;
            carry = limb3 >> 26;
            limb3 &= M26;
            low += u128::from(limb3) << 78;
            let limb4 = u64::from(f[4]) + carry;
            low += u128::from(limb4 & 0x00ff_ffff) << 104;
            let mut over = limb4 >> 24;
            while over >= 4 || (over == 3 && low.overflowing_add(5).1) {
                let (sum, c) = low.overflowing_add(5);
                low = sum;
                over = over + u64::from(c) - 4;
            }
            (low, over)
        }

        const EDGE0: [u64; 5] = [0, 1, (1 << 43) - 1, LIMB_MASK - 1, LIMB_MASK];
        const EDGE1: [u64; 6] = [0, 1, (1 << 43) - 1, LIMB_MASK - 1, LIMB_MASK, 1 << 44];
        const EDGE2: [u64; 6] = [0, 1, 1 << 40, (1 << 41) - 1, LIMB2_MASK - 1, LIMB2_MASK];

        let mut checked = 0usize;
        let mut over_130 = 0usize;
        for &h0 in &EDGE0 {
            for &h1 in &EDGE1 {
                for &h2 in &EDGE2 {
                    let three = [h0, h1, h2];
                    let five = to_26(three);
                    let want = reference(three);
                    if three[2] + (three[1] >> 44) >= 1 << 42 {
                        over_130 += 1;
                    }

                    assert_eq!(
                        value_of_five(five),
                        want,
                        "to_26 of {three:?} is a different integer"
                    );

                    let (low, over) = want;
                    for (limb, expected) in [
                        low as u32 & M26_U32,
                        (low >> 26) as u32 & M26_U32,
                        (low >> 52) as u32 & M26_U32,
                        (low >> 78) as u32 & M26_U32,
                        (low >> 104) as u32 | ((over as u32) << 24),
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        assert_eq!(five[limb], expected, "limb {limb} of {three:?}");
                    }

                    assert_eq!(reference(from_26(five)), want, "round trip of {three:?}");
                    checked += 1;
                }
            }
        }
        assert!(checked > 100, "the edge walk should be dense, not a sample");
        assert!(
            over_130 > 0,
            "the walk must include the values that need reducing before a repack, \
             or it is not testing the thing it exists for"
        );
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn the_neon_halves_are_the_three_limbs_at_every_length_around_the_threshold() {
        for seed in 0..3u8 {
            let key: [u8; 32] =
                std::array::from_fn(|i| (i as u8).wrapping_mul(197).wrapping_add(seed * 61));
            for len in (0..=64usize).chain([
                127, 128, 129, 143, 144, 145, 160, 496, 500, 511, 512, 513, 528, 1024, 2048, 8208,
            ]) {
                let data: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
                    .collect();

                let mut vector = Poly1305::new(&key);
                let whole = len / 16 * 16;
                vector.absorb_neon(&data[..whole]);
                if whole < len {
                    let mut block = [0u8; 16];
                    block[..len - whole].copy_from_slice(&data[whole..]);
                    block[len - whole] = 1;
                    vector.absorb(&block, 0);
                }
                let vector = vector.finish();

                let shipped = tag(&key, &data);

                assert_eq!(shipped, vector, "seed {seed} length {len}");
                assert_eq!(
                    shipped,
                    tag_via_26_bit_horner(&key, &data),
                    "seed {seed} length {len} against the 26-bit horner"
                );

                if len >= NEON_THRESHOLD_BYTES {
                    for split in 0..=len {
                        let mut split_state = Poly1305::new(&key);
                        split_state.update(&data[..split]);
                        split_state.update(&data[split..]);
                        assert_eq!(
                            split_state.finish(),
                            shipped,
                            "seed {seed} length {len} split {split}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn large_lengths_and_awkward_splits_are_the_crate_too() {
        use poly1305::universal_hash::KeyInit as _;

        fn theirs(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
            let k: &poly1305::Key = poly1305::Key::from_slice(&key[..]);
            poly1305::Poly1305::new(k).compute_unpadded(data).into()
        }

        let mut checked = 0usize;
        for seed in 0..4u8 {
            let key: [u8; 32] =
                std::array::from_fn(|i| (i as u8).wrapping_mul(197).wrapping_add(seed * 61));
            for len in (0..=844usize).chain([2048, 4096, 8192, 8208]) {
                let data: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
                    .collect();
                let want = theirs(&key, &data);
                assert_eq!(tag(&key, &data), want, "seed {seed} length {len}");
                checked += 1;
            }
            for len in [2048usize, 4096, 8192, 8208] {
                let data: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
                    .collect();
                let want = theirs(&key, &data);
                let mut splits = vec![
                    0,
                    1,
                    15,
                    16,
                    17,
                    31,
                    32,
                    len - 17,
                    len - 16,
                    len - 15,
                    len - 1,
                    len,
                ];
                let half = len / 2;
                splits.extend([
                    half - 17,
                    half - 16,
                    half - 15,
                    half - 1,
                    half,
                    half + 1,
                    half + 15,
                    half + 16,
                    half + 17,
                ]);
                splits.sort_unstable();
                splits.dedup();
                for split in splits {
                    let mut state = Poly1305::new(&key);
                    state.update(&data[..split]);
                    state.update(&data[split..]);
                    assert_eq!(
                        state.finish(),
                        want,
                        "seed {seed} length {len} split {split}"
                    );
                }
            }
        }
        assert!(checked > 3000, "the sweep should be dense, not a sample");
    }
}
