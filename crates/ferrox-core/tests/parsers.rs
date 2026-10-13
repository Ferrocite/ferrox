#![allow(
    clippy::cast_precision_loss,
    reason = "seed arithmetic, not a measurement"
)]

#[derive(Debug, Clone)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn byte(&mut self) -> u8 {
        {
            self.next_u64() as u8
        }
    }

    fn below(&mut self, bound: u8) -> u8 {
        if bound == 0 {
            return 0;
        }
        let zone = 256 - (256 % u32::from(bound));
        loop {
            let draw = self.next_u64() as u8;
            if u32::from(draw) < zone {
                return draw % bound;
            }
        }
    }

    fn bytes(&mut self, count: usize) -> Vec<u8> {
        (0..count).map(|_| self.byte()).collect()
    }
}

const SEED_MUX: u64 = 0x243f_6a88_85a3_08d3;
const SEED_LINK: u64 = 0x1319_8a2e_0370_7344;
const SEED_EARLY: u64 = 0x082e_fa98_ec4e_6c89;

const CASES: usize = 4_096;

#[cfg(test)]
mod parsers {
    use super::{Rng, CASES, SEED_EARLY, SEED_LINK, SEED_MUX};
    use ferrox_core::addr::Addr;
    use ferrox_core::mux::{self, NewTail};
    use ferrox_core::transport::EarlyData;
    use ferrox_core::vless::VlessLink;

    #[test]
    fn mux_decode_survives_arbitrary_bytes() {
        for case in 0..CASES {
            let seed = SEED_MUX.wrapping_add(case as u64);
            let mut rng = Rng::new(seed);
            let len = usize::from(rng.below(96));
            let mut buf = rng.bytes(len);

            if case % 2 == 0 && buf.len() >= 2 {
                let declared = 4u16 + u16::from(rng.below(24));
                buf[0..2].copy_from_slice(&declared.to_be_bytes());
            }
            if case % 2 == 1 && buf.len() >= 6 {
                buf[5] = 1 + rng.below(3);
            }

            let _ = mux::decode(&buf, NewTail::Forward);
        }
    }

    #[test]
    fn mux_decode_never_consumes_past_its_input() {
        for case in 0..CASES {
            let seed = SEED_MUX.wrapping_add(case as u64);
            let mut rng = Rng::new(seed);
            let len = 4 + usize::from(rng.below(120));
            let mut buf = rng.bytes(len);
            let declared = 4u16 + u16::from(rng.below(16));
            buf[0..2].copy_from_slice(&declared.to_be_bytes());

            if let Ok((_, consumed)) = mux::decode(&buf, NewTail::Forward) {
                assert!(
                    consumed <= buf.len(),
                    "seed {seed:#x}: consumed {consumed} of a {} byte frame",
                    buf.len()
                );
            }
        }
    }

    #[test]
    fn vless_link_parse_survives_damaged_links() {
        const GOOD: &str = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443?security=reality&encryption=none&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&host=%2Ftest-path&headerType=none&fp=firefox&type=tcp&flow=xtls-rprx-vision&sni=example.com&sid=a8#tag";

        for case in 0..CASES {
            let seed = SEED_LINK.wrapping_add(case as u64);
            let mut rng = Rng::new(seed);

            let mut damaged = String::from(GOOD);
            match case % 4 {
                0 => {
                    let at = usize::from(rng.below(damaged.len() as u8));
                    damaged.replace_range(at..=at, &char::from(rng.byte()).to_string());
                }
                1 => {
                    let keep = rng.below(damaged.len() as u8) as usize;
                    damaged.truncate(keep);
                }
                2 => {
                    let at = rng.below((damaged.len() - 1) as u8) as usize;
                    damaged.insert(at, '%');
                }
                _ => {}
            }

            let _ = VlessLink::parse(&damaged);
        }
    }

    #[test]
    fn addr_take_is_total_over_every_family_and_length() {
        for family in 0u8..=255 {
            for len in 0..=(ferrox_core::addr::MAX_DOMAIN + 8) {
                let mut buf = Vec::with_capacity(len + 1);
                buf.push(family);
                buf.extend(std::iter::repeat_n(0xa5u8, len));

                let _ = Addr::take(&buf);
            }
        }
    }

    #[test]
    fn early_data_survives_every_budget_position_and_length() {
        for case in 0..CASES {
            let seed = SEED_EARLY.wrapping_add(case as u64);
            let mut rng = Rng::new(seed);

            let mut path = String::from("/realistic");
            match case % 6 {
                0 => {}
                1 => path.push_str("?ed=0"),
                2 => path.push_str("?ed=1000"),
                3 => {
                    let digits: String = (0..rng.below(9) as usize)
                        .map(|_| char::from(b'0' + rng.below(10)))
                        .collect();
                    path.push_str("?ed=");
                    path.push_str(&digits);
                }
                4 => path.push_str("?ed="),
                _ => path.push_str("?ed"),
            }
            if case % 2 == 0 {
                path.push_str(if path.contains('?') { "&a=b" } else { "?a=b" });
            }

            let split = EarlyData::split(&path);
            assert!(
                split.path.len() <= path.len() + split.budget as usize,
                "seed {seed:#x}: a {}-byte path became {} with a budget of {}",
                path.len(),
                split.path.len(),
                split.budget
            );
            if !path.contains("ed=") {
                assert_eq!(
                    split.path, path,
                    "seed {seed:#x}: a path with no ed= was rewritten",
                );
            }
        }
    }
}
