use super::padding::{
    random_index, DelayRange, Direction, Turn, Variant, MAX_PADDING_CHUNK_LENGTH,
};
use std::io;

const STARTUP_TURNS: usize = 6;

const REGISTRY_CHUNKS: &[usize] = &[
    1590, 226, 329, 229, 186, 151, 78, 81, 79, 235, 67, 67, 78, 71, 82, 74, 982, 117, 1118, 1038,
    970, 400, 239, 49, 50, 95, 65, 104, 32320, 2,
];

const PLAY_START_CHUNKS: &[&[usize]] = &[
    &[4941, 252, 259, 267, 268, 251, 303, 259, 264, 54, 346],
    &[
        4941, 262, 284, 272, 260, 260, 313, 264, 151, 224, 207, 215, 224, 390,
    ],
    &[
        4941, 257, 272, 275, 260, 260, 313, 283, 274, 226, 207, 230, 215, 204, 221, 352,
    ],
    &[
        4941, 259, 272, 288, 260, 260, 311, 270, 70, 236, 223, 201, 210, 352,
    ],
    &[4941, 255, 269, 277, 263, 260, 136, 207, 210, 232, 325],
    &[4941, 259, 270, 274, 263, 258, 327, 170, 210, 375],
    &[
        4941, 257, 275, 291, 260, 260, 325, 269, 70, 230, 226, 207, 221, 352,
    ],
    &[4941, 252, 273, 262, 252, 254, 306, 93],
    &[4941, 273, 270, 269, 258, 256, 322, 221, 207, 215, 438],
    &[
        4941, 259, 275, 274, 250, 258, 308, 267, 154, 233, 209, 207, 213, 393,
    ],
    &[
        4941, 254, 267, 272, 260, 253, 311, 167, 204, 232, 207, 481, 8,
    ],
    &[4941, 259, 269, 272, 261, 313, 207, 213, 500, 19],
    &[
        4941, 262, 269, 274, 263, 274, 311, 270, 242, 210, 229, 221, 210, 431,
    ],
    &[
        4941, 259, 265, 277, 263, 277, 316, 269, 156, 204, 210, 226, 207, 413,
    ],
    &[4941, 215, 251, 249, 317, 260, 270, 249, 52],
    &[
        4941, 224, 263, 277, 316, 267, 272, 260, 138, 230, 226, 207, 204, 352,
    ],
    &[
        4941, 221, 258, 263, 319, 269, 288, 263, 136, 204, 210, 220, 207, 378,
    ],
    &[
        4941, 221, 258, 260, 316, 273, 291, 226, 204, 229, 213, 489, 8,
    ],
    &[
        4941, 238, 260, 261, 306, 272, 277, 260, 224, 241, 212, 207, 204, 393,
    ],
    &[
        4941, 224, 260, 260, 309, 272, 277, 277, 138, 207, 207, 212, 241, 352,
    ],
];

const PLAY_JOIN_TURNS: &[(bool, usize, usize)] = &[
    (true, 6, 883),
    (false, 346, 58_638),
    (true, 6, 887),
    (false, 388, 61_077),
    (true, 2, 50),
    (false, 575, 65_584),
    (true, 6, 45),
    (false, 86, 63_563),
    (true, 2, 44),
    (false, 42, 51_983),
    (true, 2, 851),
    (false, 309, 25_083),
    (true, 2, 19),
    (false, 74, 63_885),
    (true, 8, 24),
    (false, 30, 66_128),
    (true, 2, 19),
    (false, 26, 35_818),
    (true, 6, 19),
    (false, 35, 59_407),
    (true, 6, 19),
    (false, 37, 65_328),
    (true, 2, 19),
    (false, 26, 60_622),
    (true, 6, 19),
    (false, 11, 60_808),
    (true, 8, 43),
    (false, 55, 62_027),
    (true, 2, 19),
    (false, 427, 65_622),
    (true, 5, 19),
    (false, 35, 59_401),
    (true, 6, 19),
];

type Range = (usize, usize);
type Branch = (Range, Range);
type Burst = (usize, Range, Range);

const SERVER_BRANCHES: &[Branch] = &[
    ((346, 18_812), (51_702, 58_638)),
    ((388, 20_689), (51_445, 61_077)),
    ((575, 20_915), (41_428, 65_584)),
    ((86, 2_772), (41_428, 63_563)),
    ((42, 26_813), (51_983, 51_983)),
    ((309, 19_484), (24_837, 25_083)),
    ((74, 40_686), (63_885, 63_885)),
    ((30, 44_114), (66_128, 66_128)),
    ((26, 1_464), (9_941, 35_818)),
    ((35, 42_885), (52_194, 59_407)),
    ((37, 47_553), (61_765, 65_328)),
    ((26, 1_121), (16_162, 60_622)),
    ((11, 45_629), (60_808, 60_808)),
    ((55, 10_035), (30_237, 62_027)),
    ((427, 52_536), (64_014, 65_622)),
    ((35, 22_708), (38_987, 59_401)),
];

const SERVER_BRANCH_MASKS: &[u32] = &[
    0x011c, 0x090a, 0x0821, 0xe921, 0x2102, 0x0844, 0xa101, 0x1106, 0x2e00, 0xab01, 0xe900, 0xac01,
    0xab01, 0x8b80, 0x0808, 0x2001, 0x0901, 0x000a, 0x2c01, 0x0801,
];

const CLIENT_BURSTS: &[Burst] = &[
    (0, (6, 44), (877, 883)),
    (2, (6, 45), (884, 887)),
    (10, (2, 19), (851, 851)),
];

const CLIENT_BURST_CHOICES: &[usize] =
    &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2];

fn variant(chunks: &[usize]) -> Variant {
    Variant {
        chunks: chunks.to_vec(),
        delays: Vec::new(),
    }
}

fn paced(chunks: &[usize], pauses: &[(usize, DelayRange)]) -> Variant {
    let mut delays = vec![DelayRange::default(); chunks.len()];
    for (index, delay) in pauses {
        if let Some(slot) = delays.get_mut(*index) {
            *slot = *delay;
        }
    }
    Variant {
        chunks: chunks.to_vec(),
        delays,
    }
}

fn registry_variant() -> Variant {
    paced(
        REGISTRY_CHUNKS,
        &[
            (28, DelayRange::millis(1, 4)),
            (29, DelayRange::millis(44, 61)),
        ],
    )
}

fn play_start_variant(chunks: &[usize]) -> Variant {
    paced(
        chunks,
        &[
            (chunks.len() / 2, DelayRange::millis(1, 5)),
            (chunks.len() - 1, DelayRange::millis(9, 20)),
        ],
    )
}

fn client_play_turn(min_length: usize, max_length: usize) -> Turn {
    Turn {
        direction: Direction::ClientToServer,
        min_length,
        max_length,
        start_delay: DelayRange::millis(1, 30),
        write_chunk_length: 1024,
        ..Turn::default()
    }
}

fn server_play_turn(min_length: usize, max_length: usize) -> Turn {
    Turn {
        direction: Direction::ServerToClient,
        min_length,
        max_length,
        start_delay: DelayRange::millis(1, 45),
        chunk_delay: DelayRange::millis(1, 4),
        write_chunk_min_length: 32 * 1024,
        write_chunk_length: MAX_PADDING_CHUNK_LENGTH,
        ..Turn::default()
    }
}

#[must_use]
pub fn base_schedule() -> Vec<Turn> {
    let mut schedule = Vec::with_capacity(STARTUP_TURNS + PLAY_JOIN_TURNS.len());
    schedule.push(Turn {
        direction: Direction::ClientToServer,
        variants: vec![variant(&[2, 26, 16])],
        ..Turn::default()
    });
    schedule.push(Turn {
        direction: Direction::ServerToClient,
        variants: vec![variant(&[26, 21, 25])],
        start_delay: DelayRange::millis(0, 20),
        ..Turn::default()
    });
    schedule.push(Turn {
        direction: Direction::ClientToServer,
        variants: vec![variant(&[25])],
        start_delay: DelayRange::millis(2, 22),
        ..Turn::default()
    });
    schedule.push(Turn {
        direction: Direction::ServerToClient,
        variants: vec![registry_variant()],
        start_delay: DelayRange::millis(20, 50),
        ..Turn::default()
    });
    schedule.push(Turn {
        direction: Direction::ClientToServer,
        variants: vec![variant(&[2])],
        start_delay: DelayRange::millis(10, 35),
        ..Turn::default()
    });
    schedule.push(Turn {
        direction: Direction::ServerToClient,
        variants: PLAY_START_CHUNKS
            .iter()
            .map(|chunks| play_start_variant(chunks))
            .collect(),
        start_delay: DelayRange::millis(35, 50),
        ..Turn::default()
    });

    for (client, min_length, max_length) in PLAY_JOIN_TURNS {
        schedule.push(if *client {
            client_play_turn(*min_length, *max_length)
        } else {
            server_play_turn(*min_length, *max_length)
        });
    }
    schedule
}

pub fn new_client_schedule() -> io::Result<Vec<Turn>> {
    let choice = random_index(CLIENT_BURST_CHOICES.len())?;
    let selected_burst = CLIENT_BURST_CHOICES[choice];
    let mut schedule = base_schedule();

    for (index, (play_index, regular, burst)) in CLIENT_BURSTS.iter().enumerate() {
        let range = if index == selected_burst {
            burst
        } else {
            regular
        };
        let turn = &mut schedule[STARTUP_TURNS + play_index];
        turn.send_min_length = range.0;
        turn.send_max_length = range.1;
    }
    Ok(schedule)
}

pub fn new_server_schedule() -> io::Result<Vec<Turn>> {
    let profile_index = random_index(SERVER_BRANCH_MASKS.len())?;
    let profile = SERVER_BRANCH_MASKS[profile_index];
    let mut schedule = base_schedule();

    for (index, (small, large)) in SERVER_BRANCHES.iter().enumerate() {
        let range = if profile & (1u32 << index) != 0 {
            large
        } else {
            small
        };
        let turn = &mut schedule[STARTUP_TURNS + 1 + index * 2];
        turn.send_min_length = range.0;
        turn.send_max_length = range.1;
    }
    Ok(schedule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalmask::xmc::padding::validate_schedule;

    fn length(variant: &Variant) -> usize {
        variant.chunks.iter().sum()
    }

    #[test]
    fn both_builders_return_a_valid_schedule_that_starts_client_to_server() {
        for schedule in [
            new_client_schedule().expect("client"),
            new_server_schedule().expect("server"),
        ] {
            assert_ne!(schedule.len(), 0);
            assert_eq!(schedule[0].direction, Direction::ClientToServer);
            assert!(validate_schedule(&schedule, 2).is_ok());
        }
    }

    #[test]
    fn captured_startup_lengths_are_preserved() {
        let schedule = base_schedule();
        assert_eq!(schedule.len(), STARTUP_TURNS + PLAY_JOIN_TURNS.len());
        let expected: &[&[usize]] = &[
            &[44],
            &[72],
            &[25],
            &[41_172],
            &[2],
            &[
                7_464, 8_267, 8_790, 8_153, 7_375, 7_347, 8_184, 6_633, 7_670, 8_241, 7_857, 7_254,
                8_407, 8_283, 6_804, 8_177, 8_177, 7_929, 8_296, 8_177,
            ],
        ];
        for (turn, lengths) in schedule.iter().take(STARTUP_TURNS).zip(expected) {
            let actual: Vec<usize> = turn.variants.iter().map(length).collect();
            assert_eq!(actual.as_slice(), *lengths);
        }
        assert_eq!(schedule[0].variants[0].chunks.as_slice(), &[2, 26, 16]);
        assert_eq!(schedule[3].variants[0].chunks.len(), 30);
        let play_start: Vec<usize> = schedule[5].variants.iter().map(length).collect();
        assert_eq!(
            play_start.iter().min(),
            Some(&6_633),
            "shortest play start variant"
        );
        assert_eq!(play_start.iter().max(), Some(&8_790));
    }
}
