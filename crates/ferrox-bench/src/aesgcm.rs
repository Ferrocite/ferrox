use std::fmt::Write as _;

use aes_gcm::aead::AeadInPlace as _;
use aes_gcm::KeyInit as _;

use ferrox_core::aesgcm::{Aes128Gcm, Aes256Gcm};

use crate::count;
use crate::framing::{timed_row, Row};

fn payloads() -> Vec<usize> {
    vec![64, 256, 512, 1400, 4096, 8171, 16_383]
}

const BYTE_BUDGET: u64 = 4 * 1024 * 1024;

pub(crate) struct Window {
    len: usize,
    counts: count::Counts,
    iters: u64,
}

fn reference_backend() -> &'static str {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("pclmulqdq") {
            "aes-gcm 0.10 / aes-ni + pclmulqdq"
        } else {
            "aes-gcm 0.10 / soft tables"
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("pmull")
        {
            "aes-gcm 0.10 / armv8 crypto (behind the build's two cfgs)"
        } else {
            "aes-gcm 0.10 / soft tables"
        }
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "aes-gcm 0.10 / soft tables"
    }
}

pub(crate) fn gate_aesgcm() -> (Vec<Row>, Vec<Window>) {
    let mut rows = Vec::new();
    let mut windows = Vec::new();
    for len in payloads() {
        let plain: Vec<u8> = (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(3))
            .collect();
        rows.push(check_and_time(len, &plain, &mut windows));
        rows.push(check_and_time_256(len, &plain, &mut windows));
    }
    (rows, windows)
}

fn check_and_time(len: usize, plain: &[u8], windows: &mut Vec<Window>) -> Row {
    let key: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(5));
    let nonce: [u8; 12] = std::array::from_fn(|i| (i as u8).wrapping_mul(41).wrapping_add(1));
    let aad: &[u8] = b"";

    let ours = Aes128Gcm::new(&key);
    let reference = aes_gcm::Aes128Gcm::new_from_slice(&key).expect("key");

    let mut sealed_ours = plain.to_vec();
    let tag_ours = ours.seal_in_place(&nonce, aad, &mut sealed_ours);
    let mut sealed_ref = plain.to_vec();
    let tag_ref: [u8; 16] = reference
        .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&nonce), aad, &mut sealed_ref)
        .expect("seals")
        .into();
    assert_eq!(sealed_ours, sealed_ref, "{len}: the same ciphertext");
    assert_eq!(tag_ours, tag_ref, "{len}: the same tag");
    let mut opened = sealed_ours.clone();
    assert_eq!(
        ours.open_in_place(&nonce, aad, &mut opened, &tag_ours),
        Some(len),
        "{len}: opens"
    );
    assert_eq!(opened, plain, "{len}: the same bytes back");

    check_allocs(len, plain, &ours, windows);

    let iters = (BYTE_BUDGET / len.max(1) as u64).clamp(64, 200_000);

    let mut ref_buf = plain.to_vec();
    let mut reference_run = || {
        let tag = reference
            .encrypt_in_place_detached(
                aes_gcm::Nonce::from_slice(std::hint::black_box(&nonce)),
                aad,
                std::hint::black_box(&mut ref_buf),
            )
            .expect("seals");
        reference
            .decrypt_in_place_detached(
                aes_gcm::Nonce::from_slice(&nonce),
                aad,
                std::hint::black_box(&mut ref_buf),
                &tag,
            )
            .expect("opens");
        ref_buf.len()
    };

    let mut our_buf = plain.to_vec();
    let mut ours_run = || {
        let tag = ours.seal_in_place(
            std::hint::black_box(&nonce),
            aad,
            std::hint::black_box(&mut our_buf),
        );
        let opened = ours.open_in_place(&nonce, aad, std::hint::black_box(&mut our_buf), &tag);
        opened.expect("opens")
    };

    timed_row(
        format!("aes-128-gcm, {len}B"),
        len,
        iters,
        &mut ours_run,
        &mut reference_run,
    )
}

fn check_and_time_256(len: usize, plain: &[u8], _windows: &mut Vec<Window>) -> Row {
    let key: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(5));
    let nonce: [u8; 12] = std::array::from_fn(|i| (i as u8).wrapping_mul(41).wrapping_add(1));
    let aad: &[u8] = b"";

    let ours = Aes256Gcm::new(&key);
    let reference = aes_gcm::Aes256Gcm::new_from_slice(&key).expect("key");

    let mut sealed_ours = plain.to_vec();
    let tag_ours = ours.seal_in_place(&nonce, aad, &mut sealed_ours);
    let mut sealed_ref = plain.to_vec();
    let tag_ref: [u8; 16] = reference
        .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&nonce), aad, &mut sealed_ref)
        .expect("seals")
        .into();
    assert_eq!(sealed_ours, sealed_ref, "{len}: the same ciphertext");
    assert_eq!(tag_ours, tag_ref, "{len}: the same tag");
    let mut opened = sealed_ours.clone();
    assert_eq!(
        ours.open_in_place(&nonce, aad, &mut opened, &tag_ours),
        Some(len),
        "{len}: opens"
    );
    assert_eq!(opened, plain, "{len}: the same bytes back");

    let iters = (BYTE_BUDGET / len.max(1) as u64).clamp(64, 200_000);

    let mut ref_buf = plain.to_vec();
    let mut reference_run = || {
        let tag = reference
            .encrypt_in_place_detached(
                aes_gcm::Nonce::from_slice(std::hint::black_box(&nonce)),
                aad,
                std::hint::black_box(&mut ref_buf),
            )
            .expect("seals");
        reference
            .decrypt_in_place_detached(
                aes_gcm::Nonce::from_slice(&nonce),
                aad,
                std::hint::black_box(&mut ref_buf),
                &tag,
            )
            .expect("opens");
        ref_buf.len()
    };

    let mut our_buf = plain.to_vec();
    let mut ours_run = || {
        let tag = ours.seal_in_place(
            std::hint::black_box(&nonce),
            aad,
            std::hint::black_box(&mut our_buf),
        );
        let opened = ours.open_in_place(&nonce, aad, std::hint::black_box(&mut our_buf), &tag);
        opened.expect("opens")
    };

    timed_row(
        format!("aes-256-gcm, {len}B"),
        len,
        iters,
        &mut ours_run,
        &mut reference_run,
    )
}

const ALLOC_ITERS: u64 = 64;

fn check_allocs(len: usize, plain: &[u8], ours: &Aes128Gcm, windows: &mut Vec<Window>) {
    let nonce = [0xabu8; 12];
    let mut buf = plain.to_vec();
    let tag = ours.seal_in_place(&nonce, b"", &mut buf);
    let _ = ours.open_in_place(&nonce, b"", &mut buf, &tag);
    let ((), counts) = count::measure(|| {
        for _ in 0..ALLOC_ITERS {
            let tag = ours.seal_in_place(
                std::hint::black_box(&nonce),
                b"",
                std::hint::black_box(&mut buf),
            );
            let _ = ours.open_in_place(&nonce, b"", std::hint::black_box(&mut buf), &tag);
        }
    });
    assert_eq!(
        (counts.allocs, counts.bytes, counts.zeroed),
        (0, 0, 0),
        "aes-128-gcm {len}: the seal and the open are in place in the caller's buffer and must \
         not allocate"
    );
    windows.push(Window {
        len,
        counts,
        iters: ALLOC_ITERS,
    });
}

pub(crate) fn report(rows: &[Row], windows: &[Window], engine_backend: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n## Gate 10 — the fused AES-128-GCM engine\n");
    let _ = writeln!(
        out,
        "The crate both hot paths used to seal with, against the fused engine that\n\
         replaces it: the same arithmetic re-associated so four blocks share one\n\
         reduction, with the `CTR` pass fused into the `GHASH` pass so the message is\n\
         read once. Every row asserts equal ciphertext and equal tag *before* either\n\
         side is timed, and the rows go to the same 0.95x bar as gates 3, 4, 7 and 8.\n\
         \n\
         | | |\n\
         | --- | --- |\n\
         | reference | `{}` |\n\
         | ferrox | `{engine_backend}` |\n",
        reference_backend()
    );
    let _ = writeln!(
        out,
        "\n| bytes | reference ns/seal+open | ferrox ns/seal+open | speedup |"
    );
    let _ = writeln!(out, "| ---: | ---: | ---: | ---: |");
    for r in rows {
        let _ = writeln!(
            out,
            "| {} | {:.1} | {:.1} | {:.2}x |",
            r.bytes,
            r.base * 1e9,
            r.ours * 1e9,
            r.ratio()
        );
    }
    let _ = writeln!(
        out,
        "\nAllocations per seal+open pair, from the same counting global allocator the\n\
         other gates use. The bar is **zero**, and the count is exact: the window is open on\n\
         the thread that opened it and on no other, so an allocation inside it is this\n\
         code's rather than the process's.\n\
         \n\
         | bytes | pairs | allocations | per pair | bytes allocated |\n\
         | ---: | ---: | ---: | ---: | ---: |"
    );
    for w in windows {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {:.3} | {} |",
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
            "\n**Worst {:.2}x ({}), best {:.2}x ({}).**",
            worst.ratio(),
            worst.name,
            best.ratio(),
            best.name
        );
        out.push_str(&crate::framing::confirmation_note(rows.iter()));
    }
    out
}
