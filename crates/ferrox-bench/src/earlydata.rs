use std::fmt::Write as _;

use ferrox_core::transport::{early_decode, early_encode_into};

use crate::count;
use crate::framing::{timed_row, Row};

const ITERS: u64 = 200_000;

const ALLOC_ITERS: u64 = 64;

const PAYLOADS: [usize; 4] = [8, 120, 256, 2048];

pub(crate) fn gate_early_data() -> Vec<Row> {
    PAYLOADS
        .iter()
        .map(|&len| {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(61)).collect();
            check_encode(len, &data);
            let (ours, theirs) = check_encode_allocs(len, &data);
            assert!(
                theirs >= ALLOC_ITERS as usize,
                "{len}: the reference must keep costing two Strings per call, or the \
                 ratio stops meaning what this file says"
            );
            println!(
                "gate 8: {len}B early data — {ours} allocations over {ALLOC_ITERS} encodes here, \
                 {theirs} in the shape the four have"
            );
            encode_row(len, &data)
        })
        .collect()
}

fn check_encode(len: usize, data: &[u8]) {
    let mut ours_out = String::with_capacity(len * 2);
    early_line_into(&mut ours_out, data);
    let theirs = previous_line(data);
    assert_eq!(ours_out, theirs, "{len}: same header line");
    let digits = ours_out
        .strip_prefix("Sec-WebSocket-Protocol: ")
        .and_then(|line| line.strip_suffix("\r\n"))
        .unwrap_or_default();
    assert_eq!(
        early_decode(digits).as_deref(),
        Some(data),
        "{len}: and they decode back"
    );
    assert!(
        !digits.contains('+') && !digits.contains('/'),
        "{len}: url alphabet"
    );
    assert!(!digits.contains('='), "{len}: unpadded");
}

/// The room the shipped path already has: encode may only spend what it is handed — the digits, the header name and the CRLF at worst.
fn request(len: usize) -> String {
    String::with_capacity(len * 2 + 32)
}

fn check_encode_allocs(len: usize, data: &[u8]) -> (usize, usize) {
    let mut out = request(len);
    let ((), ours) = count::measure(|| {
        for _ in 0..ALLOC_ITERS {
            out.clear();
            early_line_into(std::hint::black_box(&mut out), std::hint::black_box(data));
        }
    });
    let ((), theirs) = count::measure(|| {
        for _ in 0..ALLOC_ITERS {
            out.clear();
            previous_line_into(std::hint::black_box(&mut out), std::hint::black_box(data));
        }
    });
    assert_eq!(
        (ours.allocs, ours.bytes, ours.zeroed),
        (0, 0, 0),
        "{len}: the shipped encode appends into the caller's room and must not allocate"
    );
    assert!(
        theirs.allocs >= 2 * ALLOC_ITERS as usize,
        "{len}: the reference must keep costing two Strings per call, and it spent {} over \
         {ALLOC_ITERS}",
        theirs.allocs
    );
    (ours.allocs, theirs.allocs)
}

fn encode_row(len: usize, data: &[u8]) -> Row {
    let mut ours_out = String::with_capacity(len * 2);
    let mut ref_out = String::with_capacity(len * 2);
    let mut ours = || {
        ours_out.clear();
        early_line_into(&mut ours_out, std::hint::black_box(data));
        ours_out.len()
    };
    let mut base = || {
        ref_out.clear();
        previous_line_into(
            std::hint::black_box(&mut ref_out),
            std::hint::black_box(data),
        );
        ref_out.len()
    };
    timed_row(
        format!("early encode, {len}B"),
        len,
        ITERS,
        &mut ours,
        &mut base,
    )
}

fn early_line_into(out: &mut String, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    out.push_str("Sec-WebSocket-Protocol: ");
    early_encode_into(out, data);
    out.push_str("\r\n");
}

#[inline(never)]
fn previous_line(data: &[u8]) -> String {
    let mut out = String::new();
    previous_line_into(&mut out, data);
    out
}

#[allow(
    clippy::format_push_string,
    reason = "the reference's shape is the second string this gate measures"
)]
#[inline(never)]
fn previous_line_into(out: &mut String, data: &[u8]) {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    if data.is_empty() {
        return;
    }
    let mut encoded = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut word = 0u32;
        for &byte in chunk {
            word = (word << 8) | u32::from(byte);
        }
        word <<= 8 * (3 - chunk.len());
        encoded.push(ALPHABET[(word >> 18 & 0x3F) as usize] as char);
        encoded.push(ALPHABET[(word >> 12 & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            encoded.push(ALPHABET[(word >> 6 & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            encoded.push(ALPHABET[(word & 0x3F) as usize] as char);
        }
    }
    out.push_str(&format!("Sec-WebSocket-Protocol: {encoded}\r\n"));
}

pub(crate) fn report(rows: &[Row]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n## Gate 8 — the early-data encode\n");
    let _ = writeln!(
        out,
        "The `?ed=` budget's whole cost, against a build shaped the way the four\n\
         implementations shape it: an `encode` into a fresh `String`, then a\n\
         `format!` into a second, then a copy of that into the request already being\n\
         built. Ours appends the digits to that request, so the reference makes two\n\
         allocations and two copies for one header line that this side makes none of.\n\
         Every row asserts the finished line is equal and decodes back before it is timed, and\n\
         holds this side to **zero** allocations per encode with the counting allocator while\n\
         the reference's shape stays at two or more, both printed on every row. The zero is\n\
         exact because the window counts the thread that opened it: the encode appends into\n\
         room the request already holds, so an allocation here would be a buffer it grew\n\
         itself. Best of {} interleaved rounds per side.\n\
         \n\
         **This is not a differential against a pinned in-process oracle** — the four\n\
         cannot be, and `docs/conformance.md` measures why per suite. The identity half\n\
         of this rung is `conformance.yml`: two upstream `xray-rust` oracle tests that\n\
         exercise the setting against real `Xray-core` at the pin, unmodified. This gate\n\
         is the cost half, and the cost half is a count.\n\
         \n\
         There is no decode row because there is nothing to gate: every implementation\n\
         decodes into the buffer it returns, so both sides are at one allocation and the\n\
         same bytes. The decode is proved by the round-trip vectors in\n\
         `transport::tests` instead, which cover every length 0-192 and both alphabets.\n",
        crate::ROUNDS
    );
    let _ = writeln!(
        out,
        "| early encode | bytes | reference ns/op | ferrox ns/op | speedup |"
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
            "\n**Gated: {}. Worst {:.2}x ({}), best {:.2}x ({}).**",
            rows.len(),
            worst.ratio(),
            worst.name,
            best.ratio(),
            best.name
        );
        out.push_str(&crate::framing::confirmation_note(rows.iter()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_early_data_row_agrees_with_its_reference_before_anything_is_timed() {
        assert_eq!(PAYLOADS, [8, 120, 256, 2048]);
        for len in PAYLOADS {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(61)).collect();
            check_encode(len, &data);
        }
    }

    #[test]
    fn the_line_is_nothing_then_two_digits_then_four() {
        for (payload, want) in [
            (&b""[..], ""),
            (&b"f"[..], "Zg"),
            (&b"fo"[..], "Zm8"),
            (&b"foo"[..], "Zm9v"),
        ] {
            let mut got = String::new();
            early_line_into(&mut got, payload);
            assert_eq!(
                got,
                if want.is_empty() {
                    String::new()
                } else {
                    format!("Sec-WebSocket-Protocol: {want}\r\n")
                },
                "{payload:?}"
            );
        }
    }
}
