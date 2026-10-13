use std::fmt::Write as _;

use super::roundtrip::RoundTripInfo;
use super::segment::{AckSegment, Segment, SegmentOption};
use super::window::{AckList, SendingWindow};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The oracle writes through the *shipped* sender path — `SendingWindow::flush` builds each segment in the arena and hands over these bytes — so the pinned Go output is compared against what goes on the wire, not a test-only wrapper.
fn emit_data(lines: &mut Vec<String>, segment: &[u8]) {
    lines.push(format!("SEG {}", hex(segment)));
}

fn emit_ack(lines: &mut Vec<String>, seg: &mut AckSegment) {
    let mut buf = Vec::new();
    Segment::Ack(seg.clone()).serialize(&mut buf);
    lines.push(format!("SEG {}", hex(&buf)));
}

#[test]
fn the_scripted_core_matches_the_pinned_go() {
    // The fixture is embedded rather than read, so the shipped flush/serialize paths stay under Miri instead of aborting on `open`.
    let script = include_str!("../../../../scripts/kcp-oracle/script.txt");
    let expected = include_str!("../../../../scripts/kcp-oracle/expected.txt");

    let mut sw = SendingWindow::default();
    let mut al = AckList::default();
    let mut rtt = RoundTripInfo::default();
    let mut lines = Vec::new();

    for line in script.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts[0] {
            "sw_new" => {
                sw = SendingWindow::new();
            }
            "sw_push" => {
                let n: u32 = parts[1].parse().unwrap();
                sw.push(n, parts[2..].join(" ").as_bytes());
            }
            "sw_flush" => {
                let cur: u32 = parts[1].parse().unwrap();
                let rto: u32 = parts[2].parse().unwrap();
                let max: u32 = parts[3].parse().unwrap();
                let rate = sw.flush(
                    cur,
                    rto,
                    max,
                    0,
                    0,
                    SegmentOption::default(),
                    &mut |segment| {
                        emit_data(&mut lines, segment);
                    },
                );
                if let Some(rate) = rate {
                    lines.push(format!("loss {rate}"));
                }
            }
            "sw_fastack" => {
                let n: u32 = parts[1].parse().unwrap();
                let rto: u32 = parts[2].parse().unwrap();
                sw.handle_fast_ack(n, rto);
            }
            "sw_remove" => {
                let n: u32 = parts[1].parse().unwrap();
                lines.push(format!("removed {}", sw.remove(n)));
            }
            "sw_clear" => {
                let una: u32 = parts[1].parse().unwrap();
                sw.clear(una);
            }
            "sw_len" => {
                lines.push(format!("len {}", sw.len()));
            }
            "sw_first" => {
                lines.push(format!("first {}", sw.first_number()));
            }
            "al_new" => {
                al = AckList::new();
            }
            "al_add" => {
                let n: u32 = parts[1].parse().unwrap();
                let ts: u32 = parts[2].parse().unwrap();
                al.add(n, ts);
            }
            "al_clear" => {
                let una: u32 = parts[1].parse().unwrap();
                al.clear(una);
            }
            "al_flush" => {
                let cur: u32 = parts[1].parse().unwrap();
                let rto: u32 = parts[2].parse().unwrap();
                al.flush(cur, rto, (1350 - 17) / 4, &mut |seg: &mut AckSegment| {
                    emit_ack(&mut lines, seg);
                });
            }
            "rtt_update" => {
                let a: u32 = parts[1].parse().unwrap();
                let b: u32 = parts[2].parse().unwrap();
                rtt.update(a, b);
            }
            "rtt_peer" => {
                let a: u32 = parts[1].parse().unwrap();
                let b: u32 = parts[2].parse().unwrap();
                rtt.update_peer_rto(a, b);
            }
            "rtt_timeout" => {
                lines.push(format!("timeout {}", rtt.timeout()));
            }
            other => panic!("unknown op {other}"),
        }
    }
    assert_eq!(lines.join("\n") + "\n", expected);
}
