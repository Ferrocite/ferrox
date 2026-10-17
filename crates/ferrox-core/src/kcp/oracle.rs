use std::fmt::Write as _;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes128Gcm;
use sha2::{Digest as _, Sha256};

use super::mask::{Encoder, HeaderKind, Mask, Spec};
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

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// The header family behind an id digit, the reference's `header.Config`.
fn hdr_spec(id: &str, domain: &str) -> Spec {
    match id {
        "0" => Spec::HeaderDns {
            domain: if domain == "-" {
                "www.baidu.com".to_owned()
            } else {
                domain.to_owned()
            },
        },
        "1" => Spec::Header(HeaderKind::Dtls),
        "2" => Spec::Header(HeaderKind::Srtp),
        "3" => Spec::Header(HeaderKind::Utp),
        "4" => Spec::Header(HeaderKind::Wechat),
        _ => Spec::Header(HeaderKind::WireGuard),
    }
}

/// The chain behind a comma-separated mask token list, in the reference's
/// configuration order; the wire order is that list reversed, outermost
/// first, which is what [`Mask::from_spec`] takes.
fn chain_specs(list: &str) -> Vec<Spec> {
    list.split(',')
        .map(|token| match token {
            "orig" => Spec::Original,
            "srtp" => Spec::Header(HeaderKind::Srtp),
            "dtls" => Spec::Header(HeaderKind::Dtls),
            "utp" => Spec::Header(HeaderKind::Utp),
            "wechat" => Spec::Header(HeaderKind::Wechat),
            "wireguard" => Spec::Header(HeaderKind::WireGuard),
            "dns" => Spec::HeaderDns {
                domain: "www.baidu.com".to_owned(),
            },
            domain => Spec::HeaderDns {
                domain: domain.strip_prefix("dns:").unwrap_or(domain).to_owned(),
            },
        })
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn open_line(prefix: &str, mask: &Mask, frame: &[u8], out: &mut Vec<String>) {
    let mut buf = frame.to_vec();
    match mask.decode_in_place(&mut buf) {
        Some(plain) => {
            let plain = plain.to_vec();
            out.push(format!("{prefix} {}", hex(&plain)));
        }
        None => out.push(format!("{prefix} err")),
    }
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
#[allow(clippy::too_many_lines)]
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
            "orig_seal" | "compose_seal" => {
                let specs = if parts[0] == "orig_seal" {
                    vec![Spec::Original]
                } else {
                    chain_specs(parts[1])
                };
                let mask = Mask::from_spec(&specs).expect("mask builds");
                let mut enc = Encoder::new(&mask);
                let wire = enc.encode(&unhex(parts[parts.len() - 1])).expect("encodes");
                let wire = wire.to_vec();
                lines.push(format!(
                    "{} {}",
                    if parts[0] == "orig_seal" {
                        "ORIG_SEAL"
                    } else {
                        "COMPOSE"
                    },
                    hex(&wire)
                ));
            }
            "orig_open" | "compose_open" | "aes_open" => {
                let (prefix, specs, frame_at) = match parts[0] {
                    "orig_open" => ("ORIG_OPEN", vec![Spec::Original], 1),
                    "compose_open" => ("COMPOSE_OPEN", chain_specs(parts[1]), 2),
                    _ => (
                        "AES_OPEN",
                        vec![Spec::Aes {
                            password: parts[1].to_owned(),
                        }],
                        2,
                    ),
                };
                let mask = Mask::from_spec(&specs).expect("mask builds");
                open_line(prefix, &mask, &unhex(parts[frame_at]), &mut lines);
            }
            "hdr_size" => {
                let mask = Mask::from_spec(&[hdr_spec(parts[1], parts[2])]).expect("builds");
                let mut enc = Encoder::new(&mask);
                let n = enc.encode(b"").expect("encodes").len();
                lines.push(format!("HDR_SIZE {n}"));
            }
            "hdr_frame" => {
                let spec = hdr_spec(parts[1], parts[2]);
                let mask = Mask::from_spec(std::slice::from_ref(&spec)).expect("builds");
                let payload = unhex(parts[3]);
                let count: usize = parts[4].parse().unwrap();
                let mut enc = Encoder::new(&mask);
                for i in 0..count {
                    let frame = enc.encode(&payload).expect("encodes").to_vec();
                    let mut text = hex(&frame);
                    if matches!(spec, Spec::HeaderDns { .. }) {
                        // The transaction id is random per datagram; the driver masks the same two bytes the Go side does.
                        text = format!("????{}", &text[4..]);
                    }
                    lines.push(format!("HDR_FRAME {i} {text}"));
                }
            }
            "aes_size" => {
                let mask = Mask::from_spec(&[Spec::Aes {
                    password: parts[1].to_owned(),
                }])
                .expect("builds");
                let mut enc = Encoder::new(&mask);
                let n = enc.encode(b"").expect("encodes").len() - 16; // the tag is not the gap
                lines.push(format!("AES_SIZE {n}"));
            }
            "aes_fixed" => {
                // The pinned derivation and framing with a fixed nonce: what the reference's seal side puts on the wire byte for byte.
                let hashed = Sha256::digest(parts[1].as_bytes());
                let cipher = Aes128Gcm::new_from_slice(&hashed[..16]).expect("key");
                let nonce = unhex(parts[2]);
                let plain = unhex(parts[3]);
                let mut body = plain.clone();
                let tag = cipher
                    .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&nonce), &[], &mut body)
                    .expect("seals");
                let mut wire = nonce;
                wire.extend_from_slice(&body);
                wire.extend_from_slice(&tag[..]);
                lines.push(format!("AES_WIRE {}", hex(&wire)));
            }
            other => panic!("unknown op {other}"),
        }
    }
    assert_eq!(lines.join("\n") + "\n", expected);
}
