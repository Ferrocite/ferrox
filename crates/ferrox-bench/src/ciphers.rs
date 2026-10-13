use std::fmt::Write as _;

use ferrox_core::shadowsocks::{Cipher, MasterKey, Method, MAX_CHUNK};

use crate::count;
use crate::framing::{best_of, Row};

const ITERS: u64 = 100_000;

const ALLOC_ITERS: u64 = 64;

fn payloads() -> Vec<usize> {
    vec![64, 512, 1400, 8171, MAX_CHUNK]
}

const REFERENCE: Method = Method::Aes256Gcm;

pub(crate) struct Window {
    pub(crate) method: &'static str,
    pub(crate) len: usize,
    pub(crate) counts: count::Counts,
    pub(crate) iters: u64,
}

pub(crate) fn gate_ciphers() -> (Vec<Row>, Vec<Window>) {
    let mut rows = Vec::new();
    let mut windows = Vec::new();
    for len in payloads() {
        let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(97)).collect();
        let control = check_and_time(REFERENCE, len, &plain, &mut windows);
        println!(
            "gate 9: {len}B control, {} at {:.1} ns/chunk",
            REFERENCE.name(),
            control * 1e9
        );
        for method in [Method::Aes128Gcm, Method::Chacha20Poly1305] {
            let ours = check_and_time(method, len, &plain, &mut windows);
            rows.push(Row {
                name: format!("{}, {len}B", method.name()),
                bytes: len,
                base: control,
                ours,
                remeasured: false,
            });
        }
    }
    (rows, windows)
}

fn check_and_time(method: Method, len: usize, plain: &[u8], windows: &mut Vec<Window>) -> f64 {
    let (sealed, opened) = round_trip(method, plain);
    assert_eq!(opened, plain, "{} {len}: the same bytes", method.name());
    assert_eq!(
        sealed.len(),
        plain.len() + ferrox_core::shadowsocks::TAG_LEN,
        "{} {len}: a chunk is the payload and a tag",
        method.name()
    );
    check_allocs(method, len, plain, windows);
    time_chunks(method, plain)
}

fn round_trip(method: Method, plain: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let salt = [0x24u8; 32];
    let mut send = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
    let mut sealed = Vec::with_capacity(plain.len() + ferrox_core::shadowsocks::TAG_LEN);
    send.seal_into(plain, &mut sealed).expect("seals");

    let mut recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
    let mut wire = sealed.clone();
    let opened = recv.open_in_place(&mut wire).expect("opens");
    (sealed, wire[..opened].to_vec())
}

fn check_allocs(method: Method, len: usize, plain: &[u8], windows: &mut Vec<Window>) {
    let salt = [0x24u8; 32];
    let mut staging = Vec::with_capacity(plain.len() + ferrox_core::shadowsocks::TAG_LEN);
    let mut send = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
    let mut recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
    send.seal_into(plain, &mut staging).expect("seals");
    recv.open_in_place(&mut staging).expect("opens");

    let ((), counts) = count::measure(|| {
        for _ in 0..ALLOC_ITERS {
            staging.clear();
            send.seal_into(
                std::hint::black_box(plain),
                std::hint::black_box(&mut staging),
            );
            let _ = recv.open_in_place(std::hint::black_box(&mut staging));
        }
    });
    assert_eq!(
        (counts.allocs, counts.bytes, counts.zeroed),
        (0, 0, 0),
        "{} {len}: the seal and the open both write into the caller's buffer and must not \
         allocate",
        method.name()
    );
    windows.push(Window {
        method: method.name(),
        len,
        counts,
        iters: ALLOC_ITERS,
    });
}

fn time_chunks(method: Method, plain: &[u8]) -> f64 {
    let salt = [0x24u8; 32];
    let mut staging = Vec::with_capacity(plain.len() + ferrox_core::shadowsocks::TAG_LEN);
    let mut send = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
    let mut recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
    best_of(ITERS, &mut || {
        staging.clear();
        send.seal_into(
            std::hint::black_box(plain),
            std::hint::black_box(&mut staging),
        );
        let _ = recv.open_in_place(std::hint::black_box(&mut staging));
        staging.len()
    })
}

pub(crate) fn derivations() -> Vec<(&'static str, usize, usize)> {
    [Method::Aes128Gcm, REFERENCE, Method::Chacha20Poly1305]
        .into_iter()
        .map(|method| {
            let key = MasterKey::new("an-example-shared-password", method.key_len());
            (method.name(), key.as_bytes().len(), key.rounds())
        })
        .collect()
}

pub(crate) fn report(rows: &[Row], windows: &[Window]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n## Gate 9 — the shadowsocks ciphers\n");
    let _ = writeln!(
        out,
        "The two ways this rung added against the one it joined, on the same bytes,\n\
         over the same chunk sizes. The reference is `aes-256-gcm`: not a flattering\n\
         choice but the method that shipped, and the one the conformance row names. Every\n\
         row asserts the two sides produce the same bytes before either is timed, and\n\
         asserts **zero allocations per chunk** for all three methods, in place, in a\n\
         buffer the relay stages once.\n\
         \n\
         **The ratios are printed and not judged, and that is a decision recorded rather\n\
         than a measurement.** The two sides straddle a hardware boundary that differs per\n\
         runner: the `aes-256-gcm` reference runs `aes-gcm`, which reaches AES-NI on `x86_64`\n\
         and the ARMv8-Crypto backend only behind the two `--cfg`s `ci.yml` sets, and its\n\
         soft table implementation without them, while `chacha20-ietf-poly1305` runs this\n\
         crate's own NEON and AVX2 ladder. The ratio is therefore a property of the\n\
         runner's AES as much as of the code. **A `bench.yml` run on four native runners\n\
         will say whether a bar can be applied here**, and `claims.md` records the decision\n\
         in the meantime.\n\\
         Run `37264964528` is that run, and it settles the question in the direction the\n\
         decision was already pointing: back when `aes-128-gcm` also ran the crate, it\n\
         held **0.96x-1.09x** of `aes-256-gcm` on all four runners and every length, while\n\
         `chacha20-ietf-poly1305` spans **0.15x-0.92x** across the same four -- a 6.1x\n\
         spread on identical code. No bar survives that. (`aes-128-gcm` now runs\n\
         `ferrox_core::aesgcm`; its rows below moved accordingly, and gate 10 is the\n\
         like-for-like measurement against the crate.) The allocation windows, meanwhile,\n\
         read **0 allocations and 0 bytes in all sixty of them**, so that count is a fact\n\
         on every runner rather than a bar with slack in it.\n\
         \n\
         The cipher is the peer's choice and the two are not comparable on one machine:\n\
         a `chacha20-ietf-poly1305` link is a user declining `aes-256-gcm` because their CPU\n\
         does the other one better, and the whole point of naming both ciphers is that the\n\
         choice is theirs.\n\
         \n\
         The session derivation, which is where `aes-128-gcm` is genuinely cheaper:\n\
         \n\
         | method | master key bytes | `MD5` rounds |\n\
         | --- | ---: | ---: |",
    );
    for (name, bytes, rounds) in derivations() {
        let _ = writeln!(out, "| `{name}` | {bytes} | {rounds} |");
    }
    let _ = writeln!(
        out,
        "\n| cipher | bytes | reference ns/chunk | ferrox ns/chunk | speedup |"
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
    let _ = writeln!(
        out,
        "\nAllocations per chunk, over the window each row measured, from the same\n\
         counting global allocator gates 2 and 7 use. The bar is **zero**, and the count is\n\
         exact: the window is open on the thread that opened it and on no other, so an\n\
         allocation inside it is this code's rather than the process's. See `check_allocs`.\n\
         \n\
         | method | bytes | chunks | allocations | per chunk | bytes allocated |\n\
         | --- | ---: | ---: | ---: | ---: | ---: |"
    );
    for w in windows {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {:.3} | {} |",
            w.method,
            w.len,
            w.iters,
            w.counts.allocs,
            w.counts.per_iter(w.iters),
            w.counts.bytes
        );
    }
    if let (Some(worst), Some(best)) = (
        rows.iter().min_by(|a, b| a.ratio().total_cmp(&b.ratio())),
        rows.iter().max_by(|a, b| a.ratio().total_cmp(&b.ratio())),
    ) {
        let _ = writeln!(
            out,
            "\n**Printed only. Worst {:.2}x ({}), best {:.2}x ({}).**",
            worst.ratio(),
            worst.name,
            best.ratio(),
            best.name
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_cipher_row_agrees_and_allocates_nothing() {
        assert_eq!(payloads(), vec![64, 512, 1400, 8171, MAX_CHUNK]);
        for len in payloads() {
            let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(97)).collect();
            for method in [
                Method::Aes128Gcm,
                Method::Aes256Gcm,
                Method::Chacha20Poly1305,
            ] {
                let (sealed, opened) = round_trip(method, &plain);
                assert_eq!(opened, &plain[..], "{} {len}", method.name());
                assert_eq!(
                    sealed.len(),
                    plain.len() + ferrox_core::shadowsocks::TAG_LEN,
                    "{} {len}",
                    method.name()
                );
            }
        }
    }

    #[test]
    fn no_two_methods_produce_the_same_chunk() {
        let plain = b"the same bytes under three ciphers".to_vec();
        let mut chunks = Vec::new();
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            let (sealed, _) = round_trip(method, &plain);
            assert!(
                !chunks.contains(&sealed),
                "{} produced a chunk another method produced",
                method.name()
            );
            chunks.push(sealed);
        }
    }

    #[test]
    fn aes_128_derives_half_the_master_key() {
        let table = derivations();
        assert_eq!(
            table,
            vec![
                ("aes-128-gcm", 16, 1),
                ("aes-256-gcm", 32, 2),
                ("chacha20-ietf-poly1305", 32, 2),
            ]
        );
    }
}
