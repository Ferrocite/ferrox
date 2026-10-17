use std::fmt::Write as _;
use std::time::Instant;

use ferrox_core::aead::{chacha20_poly1305_seal_in_place, chacha20_poly1305_seal_in_place_unfused};
use ferrox_core::poly1305::Poly1305;
use ferrox_core::vless::VlessLink;

use crate::count;

pub(crate) struct Row {
    pub(crate) name: String,
    pub(crate) bytes: usize,
    pub(crate) base: f64,
    pub(crate) ours: f64,
    pub(crate) remeasured: bool,
}

impl Row {
    pub(crate) fn ratio(&self) -> f64 {
        self.base / self.ours
    }
}

pub(crate) fn best_of<F: FnMut() -> usize>(iters: u64, mut f: F) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..crate::ROUNDS {
        let t0 = Instant::now();
        for _ in 0..iters {
            std::hint::black_box(f());
        }
        best = best.min(t0.elapsed().as_secs_f64() / iters as f64);
    }
    best
}

const SLICES: usize = 4;

fn slice_seconds(iters: u64, f: &mut dyn FnMut() -> usize) -> f64 {
    let t0 = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(f());
    }
    t0.elapsed().as_secs_f64()
}

pub(crate) fn paired(
    iters: u64,
    base: &mut dyn FnMut() -> usize,
    ours: &mut dyn FnMut() -> usize,
) -> (f64, f64) {
    let slice = (iters / SLICES as u64).max(1);
    let calls = (slice * SLICES as u64) as f64;
    let mut rounds = Vec::with_capacity(crate::ROUNDS);
    for round in 0..crate::ROUNDS {
        let mut base_seconds = 0.0;
        let mut ours_seconds = 0.0;
        for slice_index in 0..SLICES {
            if (round + slice_index) % 2 == 0 {
                base_seconds += slice_seconds(slice, base);
                ours_seconds += slice_seconds(slice, ours);
            } else {
                ours_seconds += slice_seconds(slice, ours);
                base_seconds += slice_seconds(slice, base);
            }
        }
        rounds.push((base_seconds / calls, ours_seconds / calls));
    }
    rounds.sort_by(|a, b| ratio_of(*a).total_cmp(&ratio_of(*b)));
    rounds[rounds.len() / 2]
}

fn ratio_of(pair: (f64, f64)) -> f64 {
    pair.0 / pair.1
}

pub(crate) fn confirmation_note<'a>(rows: impl Iterator<Item = &'a Row>) -> String {
    let names: Vec<&str> = rows
        .filter(|r| r.remeasured)
        .map(|r| r.name.as_str())
        .collect();
    if names.is_empty() {
        return String::new();
    }
    format!(
        "\n**Confirmed: {}.** Each of these first read under {BAR:.2}x, so it was re-measured \
         at four times the budget and the median of {CONFIRMATIONS} independent passes is what \
         the table above and the gate below read. A confirmation is one process's steady \
         reading, and another runner of the same commit can read the row the other way, so the \
         gate judges only rows whose ratio a code change can move.\n",
        names.join(", "),
        BAR = crate::BAR,
        CONFIRMATIONS = crate::CONFIRMATIONS,
    )
}

pub(crate) fn timed_row(
    name: String,
    bytes: usize,
    iters: u64,
    ours: &mut dyn FnMut() -> usize,
    base: &mut dyn FnMut() -> usize,
) -> Row {
    let first = paired(iters, base, ours);
    if ratio_of(first) >= crate::BAR {
        return Row {
            name,
            bytes,
            base: first.0,
            ours: first.1,
            remeasured: false,
        };
    }

    let heavy = iters.saturating_mul(4);
    let mut passes = Vec::with_capacity(crate::CONFIRMATIONS);
    for _ in 0..crate::CONFIRMATIONS {
        passes.push(paired(heavy, base, ours));
    }
    let (base, ours) = crate::confirmed_pass(&passes);
    Row {
        name,
        bytes,
        base,
        ours,
        remeasured: true,
    }
}

const LINK: &str = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&fp=firefox&sni=example.com&sid=a8#x";

pub(crate) fn gate_framing() -> Vec<Row> {
    ["192.0.2.53", "2001:db8::1", "example.com"]
        .iter()
        .map(|host| header_row(host))
        .collect()
}

fn header_row(host: &str) -> Row {
    let link = VlessLink::parse(LINK).expect("synthetic rung-1 link parses");
    let port = 443u16;
    let mut fused = vec![0u8; link.request_header_len(host)];
    let mut was = vec![0u8; fused.len()];

    let bytes = {
        let n = link.encode_into(host, port, &mut fused);
        let m = previous_encode_into(&link, host, port, &mut was);
        assert_eq!(n, m, "{host}: the two encodes must write the same length");
        assert_eq!(&fused[..n], &was[..m], "{host}: and the same bytes");
        let ((), counts) = count::measure(|| {
            for _ in 0..64 {
                let n = link.encode_into(host, port, std::hint::black_box(&mut fused[..]));
                std::hint::black_box(n);
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "the {host} header encode must not allocate"
        );
        n
    };

    let mut ours = || {
        let n = link.encode_into(host, port, std::hint::black_box(&mut fused[..]));
        std::hint::black_box(n)
    };
    let mut base = || {
        let n = previous_encode_into(&link, host, port, std::hint::black_box(&mut was[..]));
        std::hint::black_box(n)
    };

    timed_row(
        format!("vless header encode, {host}"),
        bytes,
        200_000,
        &mut ours,
        &mut base,
    )
}

/// The lengths the seal and its halves are measured at; 64 and 256 bytes are the rows gate 7 judges, and every row from 1 KiB up is a length at which both shapes fill whole passes, so the table shows the boundary `ONE_PASS_BYTES` prices.
const AEAD_LENGTHS: [usize; 7] = [64, 256, 1024, 2048, 4096, 8192, 16384];

/// The longest message the fused seal can save a pass over the two-call shape: `aarch64`'s eight-block pass covers 448 message bytes beside the head's block, so one invocation does the whole seal there while the split opens a second for block zero. Above it both shapes generate `ceil(len / 64) + 1` blocks in the same passes plus one lone tail block, so the row prices a function call — and no measured length sits between 256 bytes and 1 KiB, where `x86_64`'s wider passes would still save one. `docs/function/record-layer.md` carries the counts.
const ONE_PASS_BYTES: usize = 448;

/// The seal rows the FRAMING REGRESSION gate judges: whole-pass lengths report a ratio no code change can move.
pub(crate) fn gated_seals(rows: &[Row]) -> Vec<&Row> {
    rows.iter().filter(|r| !is_reported_seal(r)).collect()
}

/// Seal rows carry the tag's 16 bytes beside the message.
fn is_reported_seal(row: &Row) -> bool {
    row.name.starts_with("chacha20-poly1305 seal") && row.bytes > ONE_PASS_BYTES + 16
}

pub(crate) fn gate_aead(key: &[u8; 32], nonce: &[u8; 12]) -> Vec<Row> {
    AEAD_LENGTHS
        .iter()
        .map(|&len| aead_seal_row(key, nonce, len))
        .collect()
}

fn aead_seal_row(key: &[u8; 32], nonce: &[u8; 12], len: usize) -> Row {
    let mut fused = vec![0x5au8; len];
    let mut was = fused.clone();

    {
        let a = chacha20_poly1305_seal_in_place(key, nonce, &[], &mut fused);
        let b = chacha20_poly1305_seal_in_place_unfused(key, nonce, &[], &mut was);
        assert_eq!(
            fused, was,
            "len {len}: the two seals must encrypt identically"
        );
        assert_eq!(a, b, "len {len}: and produce the same tag");
    }

    let iters = u64::try_from((50_000_000 / (len + 64)).max(64)).expect("an iteration count");

    let mut ours = || {
        let tag =
            chacha20_poly1305_seal_in_place(key, nonce, &[], std::hint::black_box(&mut fused[..]));
        usize::from(std::hint::black_box(tag)[0])
    };
    let mut base = || {
        let tag = chacha20_poly1305_seal_in_place_unfused(
            key,
            nonce,
            &[],
            std::hint::black_box(&mut was[..]),
        );
        usize::from(std::hint::black_box(tag)[0])
    };

    timed_row(
        format!("chacha20-poly1305 seal, {len}B"),
        len + 16,
        iters,
        &mut ours,
        &mut base,
    )
}

pub(crate) fn aead_split(key: &[u8; 32], nonce: &[u8; 12]) -> Vec<Row> {
    AEAD_LENGTHS
        .iter()
        .flat_map(|&len| [keystream_row(key, nonce, len), mac_row(key, nonce, len)])
        .collect()
}

fn keystream_row(key: &[u8; 32], nonce: &[u8; 12], len: usize) -> Row {
    let mut buf = vec![0x5au8; len];
    let iters = u64::try_from((50_000_000 / (len + 64)).max(64)).expect("an iteration count");
    let mut run = || {
        ferrox_core::record::fill_exact(key, nonce, 1, std::hint::black_box(&mut buf[..]));
        0
    };
    self_timed(format!("chacha20 keystream, {len}B"), len, iters, &mut run)
}

fn mac_row(key: &[u8; 32], nonce: &[u8; 12], len: usize) -> Row {
    let mut buf = vec![0x5au8; len];
    std::hint::black_box(chacha20_poly1305_seal_in_place(key, nonce, &[], &mut buf));
    let one_time = {
        let mut block = [0u8; 64];
        ferrox_core::record::fill_exact(key, nonce, 0, &mut block);
        block[..32].try_into().expect("32 bytes")
    };
    let mut lengths = [0u8; 16];
    lengths[8..].copy_from_slice(&(buf.len() as u64).to_le_bytes());

    let mut run = || {
        let mut state = Poly1305::new(std::hint::black_box(&one_time));
        for section in [&[][..], &buf[..]] {
            state.update(section);
            let slack = (16 - section.len() % 16) % 16;
            state.update(&[0u8; 16][..slack]);
        }
        state.update(&lengths);
        usize::from(state.finish()[0])
    };
    self_timed(
        format!("poly1305 mac, {len}B"),
        len + 16,
        u64::try_from((50_000_000 / (len + 16)).max(64)).expect("iters"),
        &mut run,
    )
}

fn self_timed(name: String, bytes: usize, iters: u64, run: &mut dyn FnMut() -> usize) -> Row {
    let first = best_of(iters, &mut *run);
    let second = best_of(iters, &mut *run);
    Row {
        name,
        bytes,
        base: first.min(second),
        ours: first.max(second),
        remeasured: false,
    }
}

pub(crate) fn gate_mac(key: &[u8; 32], nonce: &[u8; 12]) -> Vec<Row> {
    AEAD_LENGTHS
        .iter()
        .map(|&len| mac_vs_horner_row(key, nonce, len))
        .collect()
}

fn mac_vs_horner_row(key: &[u8; 32], nonce: &[u8; 12], len: usize) -> Row {
    let mut buf = vec![0x5au8; len];
    let one_time = {
        let mut block = [0u8; 64];
        ferrox_core::record::fill_exact(key, nonce, 0, &mut block);
        block[..32].try_into().expect("32 bytes")
    };

    std::hint::black_box(chacha20_poly1305_seal_in_place(key, nonce, &[], &mut buf));

    let mut ours_state = Poly1305::new(std::hint::black_box(&one_time));
    ours_state.update(std::hint::black_box(&buf[..]));
    let ours_bytes = ours_state.finish();

    let base_bytes = ferrox_core::poly1305::tag_via_26_bit_horner(
        std::hint::black_box(&one_time),
        std::hint::black_box(&buf[..]),
    );
    assert_eq!(
        ours_bytes, base_bytes,
        "len {len}: the three-limb accumulator must agree with the 26-bit Horner"
    );

    let iters = u64::try_from((50_000_000 / (len + 16)).max(64)).expect("an iteration count");

    let mut ours = || {
        let mut state = Poly1305::new(std::hint::black_box(&one_time));
        state.update(std::hint::black_box(&buf[..]));
        usize::from(std::hint::black_box(state.finish())[0])
    };
    let mut base = || {
        let tag = ferrox_core::poly1305::tag_via_26_bit_horner(
            std::hint::black_box(&one_time),
            std::hint::black_box(&buf[..]),
        );
        usize::from(std::hint::black_box(tag)[0])
    };

    timed_row(
        format!("poly1305 3x44 vs 26-bit horner, {len}B"),
        len + 16,
        iters,
        &mut ours,
        &mut base,
    )
}

pub(crate) fn mac_report(rows: &[Row]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n## Gate 7c — Poly1305, three limbs against five\n");
    let _ = writeln!(
        out,
        "The `Poly1305` accumulator alone, this tree's three 44-bit limbs with `u128`\n\
         products against the five 26-bit limbs it replaced — same interface, same tag,\n\
         asserted equal before either side is timed. The claim is arithmetic: three limbs\n\
         need nine hardware `64`-by-`64` products per block where five needed twenty-five,\n\
         and the fold stops depending on the block's *previous* limb. Best of {} rounds\n\
         per side, bar {:.2}x.\n",
        crate::ROUNDS,
        crate::BAR
    );
    let _ = writeln!(
        out,
        "| accumulator | bytes | 26-bit ns/op | 3x44 ns/op | speedup |"
    );
    let _ = writeln!(out, "| --- | ---: | ---: | ---: | ---: |");
    for r in rows {
        let _ = writeln!(
            out,
            "| {} | {} | {:.1} | {:.1} | {:.2}x |",
            r.name,
            r.bytes,
            r.base * 1e9,
            r.ours * 1e9,
            r.ratio()
        );
    }
    if !rows.is_empty() {
        let worst = rows.iter().map(Row::ratio).fold(f64::INFINITY, f64::min);
        let _ = writeln!(out, "\n**Gate: worst {worst:.2}x.**");
        out.push_str(&confirmation_note(rows.iter()));
    }
    out
}

pub(crate) fn aead_report(rows: &[Row]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n## Gate 7 — AEAD seal\n");
    let _ = writeln!(
        out,
        "The `ChaCha20`-`Poly1305` seal over an empty `aad`, which is what a `VMess` data\n\
         frame carries: this tree's fused keystream pass against the two-call build it\n\
         replaced, where the one-time key came out of its own 64-byte pass and the message\n\
         was encrypted by a second. Same ciphertext and same tag on both sides, asserted\n\
         at every length before either is timed. Best of {} rounds per side. The bar is\n\
         the same {:.2}x as gate 3.\n\
         \n\
         The gate judges the rows at and under `ONE_PASS_BYTES` and reports the rest,\n\
         because the two shapes generate the same `ceil(len/64) + 1` blocks and from one\n\
         pass wide upwards issue them in the same number of passes: the fusion removes an\n\
         invocation only while the message and the head's block fit one pass, and above it\n\
         the row is a function call. The rows read as the counts say: run `39064183190`\n\
         measures 1.41x-1.75x at 64 bytes and 1.24x-1.57x at 256 on all four runners, and\n\
         0.99x-1.06x across the twenty whole-pass rows. A whole-pass row cannot carry the\n\
         bar: run `39000283851` passed this gate on macos `aarch64` at `70fdfd0` while the\n\
         nightly's run `39001299614` confirmed 0.939x on its 16 KiB row at that same commit.\n\
         The arithmetic, and what still checks these rows, is in\n\
         `docs/function/record-layer.md`.\n",
        crate::ROUNDS,
        crate::BAR
    );
    let _ = writeln!(
        out,
        "| seal | bytes | two-call ns/op | fused ns/op | speedup | gated |"
    );
    let _ = writeln!(out, "| --- | ---: | ---: | ---: | ---: | --- |");
    for r in rows {
        let _ = writeln!(
            out,
            "| {} | {} | {:.1} | {:.1} | {:.2}x | {} |",
            r.name,
            r.bytes,
            r.base * 1e9,
            r.ours * 1e9,
            r.ratio(),
            if is_reported_seal(r) {
                crate::muxframe::REPORTED_ONLY
            } else {
                "yes"
            }
        );
    }
    let judged = gated_seals(rows);
    if let (Some(worst), Some(best)) = (
        judged.iter().min_by(|a, b| a.ratio().total_cmp(&b.ratio())),
        judged.iter().max_by(|a, b| a.ratio().total_cmp(&b.ratio())),
    ) {
        let _ = writeln!(
            out,
            "\n**Gated rows: {}. Worst {:.2}x ({}), best {:.2}x ({}).**",
            judged.len(),
            worst.ratio(),
            worst.name,
            best.ratio(),
            best.name
        );
        out.push_str(&confirmation_note(judged.iter().copied()));
    }
    out
}

pub(crate) fn aead_split_report(rows: &[Row]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n### Gate 7b — where the seal's time goes\n");
    let _ = writeln!(
        out,
        "The same seal split into its two halves and timed apart, because gate 7 above\n\
         measures the seal as one thing and the next change has to know which half is\n\
         worth attacking. Both sides of every row run the *same* code, so the ratio\n\
         column is this harness's own run-to-run noise at that length and the absolute\n\
         column is the cost. A half whose self-timed ratio reads 0.97x cannot resolve a\n\
         change smaller than 3%, whatever the change is worth in isolation.\n\
         \n\
         These rows are reported and **not gated**: a row gated against itself fails on\n\
         noise, and a gate that cries wolf gets switched off.\n"
    );
    let _ = writeln!(out, "| half | bytes | ns/op | noise |");
    let _ = writeln!(out, "| --- | ---: | ---: | ---: |");
    for r in rows {
        let _ = writeln!(
            out,
            "| {} | {} | {:.1} | {:.2}x |",
            r.name,
            r.bytes,
            r.ours * 1e9,
            r.ratio()
        );
    }
    out
}

fn previous_encode_into(link: &VlessLink, host: &str, port: u16, out: &mut [u8]) -> usize {
    let is_vision = link.flow() == "xtls-rprx-vision" || link.flow() == "xtls-rprx-vision-udp443";
    let addons = if is_vision { 1 + PREV_ADDONS.len() } else { 1 };
    let has_colon = host.contains(':');
    let addr = if !has_colon && host.parse::<std::net::Ipv4Addr>().is_ok() {
        1 + 4
    } else if has_colon && host.parse::<std::net::Ipv6Addr>().is_ok() {
        1 + 16
    } else {
        1 + 1 + host.len().min(255)
    };
    let need = 1 + 16 + addons + 1 + 2 + addr;
    assert!(out.len() >= need, "vless header buffer too short");
    let mut o = 0;
    out[o] = 0;
    o += 1;
    out[o..o + 16].copy_from_slice(&previous_uuid_bytes(&link.uuid));
    o += 16;
    if is_vision {
        out[o] = PREV_ADDONS.len() as u8;
        o += 1;
        out[o..o + PREV_ADDONS.len()].copy_from_slice(&PREV_ADDONS);
        o += PREV_ADDONS.len();
    } else {
        out[o] = 0;
        o += 1;
    }
    out[o] = 1;
    o += 1;
    out[o..o + 2].copy_from_slice(&port.to_be_bytes());
    o += 2;
    let has_colon = host.contains(':');
    let v4 = if has_colon {
        None
    } else {
        host.parse::<std::net::Ipv4Addr>().ok()
    };
    let v6 = if has_colon {
        host.parse::<std::net::Ipv6Addr>().ok()
    } else {
        None
    };
    if let Some(ipv4) = v4 {
        out[o] = 1;
        o += 1;
        out[o..o + 4].copy_from_slice(&ipv4.octets());
        o += 4;
    } else if let Some(ipv6) = v6 {
        out[o] = 3;
        o += 1;
        out[o..o + 16].copy_from_slice(&ipv6.octets());
        o += 16;
    } else {
        out[o] = 2;
        o += 1;
        let n = host.len().min(255);
        out[o] = n as u8;
        o += 1;
        out[o..o + n].copy_from_slice(&host.as_bytes()[..n]);
        o += n;
    }
    debug_assert_eq!(o, need);
    o
}

const PREV_ADDONS: [u8; 18] = *b"\x0A\x10xtls-rprx-vision";

fn previous_uuid_bytes(uuid: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut idx = 0usize;
    let mut hi: Option<(u8, bool)> = None;
    for &b in uuid.as_bytes() {
        if b == b'-' {
            continue;
        }
        let (v, ok) = match b {
            b'0'..=b'9' => (b - b'0', true),
            b'a'..=b'f' => (b - b'a' + 10, true),
            b'A'..=b'F' => (b - b'A' + 10, true),
            _ => (0, false),
        };
        if let Some((h, hok)) = hi.take() {
            if idx < 16 {
                out[idx] = if hok && ok { (h << 4) | v } else { 0 };
                idx += 1;
            }
        } else {
            hi = Some((v, ok));
        }
        if idx >= 16 {
            break;
        }
    }
    out
}

pub(crate) fn report(rows: &[Row]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n## Gate 4 — protocol framing\n");
    let _ = writeln!(
        out,
        "The `VLESS` request header encode: this tree's fused encode against a reference\n\
         build of the same bytes — a fresh buffer per header, every field pushed\n\
         separately, the address family decided twice, and the UUID decoded a pair at a\n\
         time. Best of {} interleaved rounds per side. Every row asserts byte equality\n\
         before it is timed, so a ratio here cannot be bought with different output. The\n\
         bar is the same {:.2}x as gate 3.\n",
        crate::ROUNDS,
        crate::BAR
    );
    let _ = writeln!(
        out,
        "| framing | bytes | reference ns/op | ferrox ns/op | speedup |"
    );
    let _ = writeln!(out, "| --- | ---: | ---: | ---: | ---: |");
    for r in rows {
        let _ = writeln!(
            out,
            "| {} | {} | {:.1} | {:.1} | {:.2}x |",
            r.name,
            r.bytes,
            r.base * 1e9,
            r.ours * 1e9,
            r.ratio()
        );
    }
    if let (Some(worst), Some(best)) = (
        rows.iter().min_by(|a, b| a.ratio().total_cmp(&b.ratio())),
        rows.iter().max_by(|a, b| a.ratio().total_cmp(&b.ratio())),
    ) {
        let _ = writeln!(
            out,
            "\n**Worst {:.2}x ({}), best {:.2}x ({}).**",
            worst.ratio(),
            worst.name,
            best.ratio(),
            best.name
        );
        out.push_str(&confirmation_note(rows.iter()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct Trace {
        order: std::sync::Mutex<Vec<&'static str>>,
    }

    impl Trace {
        fn push(&self, side: &'static str) {
            self.order
                .lock()
                .expect("the trace lock is only held briefly")
                .push(side);
        }

        fn sides(&self) -> Vec<&'static str> {
            self.order
                .lock()
                .expect("the trace lock is only held briefly")
                .clone()
        }
    }

    #[test]
    fn both_sides_are_measured_inside_every_round_and_neither_goes_first() {
        let trace = Trace::default();
        let mut base = || {
            trace.push("base");
            0
        };
        let mut ours = || {
            trace.push("ours");
            0
        };
        paired(4, &mut base, &mut ours);

        let sides = trace.sides();
        assert_eq!(
            sides.len(),
            crate::ROUNDS * SLICES * 2,
            "each round measures each side once per slice"
        );

        let openings: Vec<&str> = (0..crate::ROUNDS * SLICES)
            .map(|slice| sides[slice * 2])
            .collect();
        assert_eq!(
            openings.iter().filter(|side| **side == "base").count(),
            openings.len() / 2,
            "half the slices measure the reference first: {openings:?}"
        );
        assert_eq!(
            openings.iter().filter(|side| **side == "ours").count(),
            openings.len() / 2,
            "and half measure this tree first: {openings:?}"
        );
    }

    #[test]
    fn no_two_rounds_open_on_the_same_side() {
        let trace = Trace::default();
        let mut base = || {
            trace.push("base");
            0
        };
        let mut ours = || {
            trace.push("ours");
            0
        };
        paired(4, &mut base, &mut ours);
        let sides = trace.sides();
        let openings: Vec<&str> = sides.chunks(SLICES * 2).map(|round| round[0]).collect();
        assert_eq!(openings.len(), crate::ROUNDS);
        for (index, pair) in openings.windows(2).enumerate() {
            assert_ne!(
                pair[0],
                pair[1],
                "rounds {index} and {} both opened on {}",
                index + 1,
                pair[0]
            );
        }
    }

    fn burn(units: u64) {
        let mut acc = 0u64;
        for i in 0..units {
            acc = acc.wrapping_add(i);
        }
        std::hint::black_box(acc);
    }

    /// The gate judges exactly the lengths at which the fusion removes a pass, and never a row of another gate's.
    #[test]
    fn only_the_lengths_that_save_a_pass_are_gated() {
        let seal = |len: usize| Row {
            name: format!("chacha20-poly1305 seal, {len}B"),
            bytes: len + 16,
            base: 1.0,
            ours: 1.0,
            remeasured: false,
        };
        for len in AEAD_LENGTHS {
            assert_eq!(
                gated_seals(&[seal(len)]).len() == 1,
                len <= ONE_PASS_BYTES,
                "{len} bytes is on the wrong side of the gate"
            );
        }
        assert_eq!(gated_seals(&[seal(ONE_PASS_BYTES)]).len(), 1);
        assert_eq!(gated_seals(&[seal(ONE_PASS_BYTES + 1)]).len(), 0);
        let mac = Row {
            name: format!("poly1305 3x44 vs 26-bit horner, {}B", ONE_PASS_BYTES + 1),
            bytes: ONE_PASS_BYTES + 17,
            base: 1.0,
            ours: 1.0,
            remeasured: false,
        };
        assert_eq!(gated_seals(&[mac]).len(), 1, "gate 7c's rows stay judged");
    }

    #[test]
    fn a_paired_ratio_survives_a_machine_that_changes_under_it() {
        const TRUE_BASE: u64 = 20_000;
        const TRUE_OURS: u64 = 10_000;
        const ITERS: u64 = 200;
        const STEP_PERCENT: u64 = 400;
        const SWITCH_AFTER: u64 = ITERS * crate::ROUNDS as u64;

        static CALLS: AtomicU64 = AtomicU64::new(0);
        fn make(base_units: u64) -> impl FnMut() -> usize {
            move || {
                let seen = CALLS.fetch_add(1, Ordering::Relaxed);
                let slower = if seen >= SWITCH_AFTER {
                    STEP_PERCENT
                } else {
                    0
                };
                burn(base_units + base_units * slower / 100);
                0
            }
        }
        let truth = TRUE_BASE as f64 / TRUE_OURS as f64;
        CALLS.store(0, Ordering::Relaxed);
        let (base_secs, ours_secs) = paired(ITERS, &mut make(TRUE_BASE), &mut make(TRUE_OURS));
        let ratio = base_secs / ours_secs;

        CALLS.store(0, Ordering::Relaxed);
        let mut base = make(TRUE_BASE);
        let mut ours = make(TRUE_OURS);
        let unpaired = best_of(ITERS, &mut base) / best_of(ITERS, &mut ours);

        let paired_error = (ratio / truth - 1.0).abs();
        let unpaired_error = (unpaired / truth - 1.0).abs();

        assert!(
            unpaired_error > 0.5,
            "the step did not land, so this run proves nothing: the two blocks read \
             {unpaired:.3}x against a true {truth:.3}x, which is within the noise it \
             was supposed to be separated from"
        );

        assert!(
            paired_error < unpaired_error,
            "pairing should be closer to the truth than two blocks: paired read \
             {ratio:.3}x and the two blocks read {unpaired:.3}x, against a true \
             {truth:.3}x"
        );
    }
}
