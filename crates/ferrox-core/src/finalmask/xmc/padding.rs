use super::protocol::{read_varint_with_length, write_varint};
use std::io::{self, Read, Write};
use std::time::Duration;

pub const PADDING_BUFFER_LENGTH: usize = 16 * 1024;
pub const MAX_PADDING_CHUNK_LENGTH: usize = 48 * 1024;
pub const MAX_PADDING_TURN_LENGTH: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    #[default]
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DelayRange {
    pub min: Duration,
    pub max: Duration,
}

impl DelayRange {
    #[must_use]
    pub fn millis(min: u64, max: u64) -> Self {
        Self {
            min: Duration::from_millis(min),
            max: Duration::from_millis(max),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Variant {
    pub chunks: Vec<usize>,
    pub delays: Vec<DelayRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Turn {
    pub direction: Direction,
    pub min_length: usize,
    pub max_length: usize,
    pub variants: Vec<Variant>,
    pub start_delay: DelayRange,
    pub chunk_delay: DelayRange,
    pub write_chunk_min_length: usize,
    pub write_chunk_length: usize,
    pub send_min_length: usize,
    pub send_max_length: usize,
    pub send_variants: Vec<usize>,
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub fn run<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    is_client: bool,
    first_turn_prefix_length: i64,
    schedule: &[Turn],
) -> io::Result<()> {
    validate_schedule(schedule, first_turn_prefix_length)?;
    let prefix = usize::try_from(first_turn_prefix_length).unwrap_or(usize::MAX);

    for (index, turn) in schedule.iter().enumerate() {
        let turn_prefix = if index == 0 { prefix } else { 0 };
        let local_sends = is_client == (turn.direction == Direction::ClientToServer);
        if local_sends {
            write_turn(writer, turn, turn_prefix).map_err(|error| {
                io::Error::other(format!("write padding turn {index}: {error}"))
            })?;
        } else {
            read_turn(reader, turn, turn_prefix)
                .map_err(|error| io::Error::other(format!("read padding turn {index}: {error}")))?;
        }
    }
    Ok(())
}

pub fn validate_schedule(schedule: &[Turn], first_turn_prefix_length: i64) -> io::Result<()> {
    if schedule.is_empty() {
        return Err(invalid_input("empty padding schedule"));
    }
    if first_turn_prefix_length < 0 {
        return Err(invalid_input(format!(
            "negative first turn prefix length: {first_turn_prefix_length}"
        )));
    }
    if first_turn_prefix_length > 0 && schedule[0].direction != Direction::ClientToServer {
        return Err(invalid_input(
            "first prefixed padding turn is not client-to-server",
        ));
    }

    for (index, turn) in schedule.iter().enumerate() {
        validate_delay(turn.start_delay).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("padding turn {index} has an invalid start delay: {error}"),
            )
        })?;
        validate_delay(turn.chunk_delay).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("padding turn {index} has an invalid chunk delay: {error}"),
            )
        })?;
        if turn.write_chunk_min_length > turn.write_chunk_length
            || turn.write_chunk_length > MAX_PADDING_CHUNK_LENGTH
        {
            return Err(invalid_input(format!(
                "padding turn {index} has an invalid write chunk range: {}-{}",
                turn.write_chunk_min_length, turn.write_chunk_length
            )));
        }
        if !turn.variants.is_empty() && turn.write_chunk_length != 0 {
            return Err(invalid_input(format!(
                "padding turn {index} combines variants with generated write chunks"
            )));
        }

        let (min_length, max_length) = turn_bounds(turn).map_err(|error| {
            io::Error::new(error.kind(), format!("padding turn {index}: {error}"))
        })?;
        let has_send_range = turn.send_min_length != 0 || turn.send_max_length != 0;
        if has_send_range {
            if !turn.variants.is_empty() {
                return Err(invalid_input(format!(
                    "padding turn {index} combines variants with a send range"
                )));
            }
            if turn.send_min_length < min_length
                || turn.send_max_length < turn.send_min_length
                || turn.send_max_length > max_length
            {
                return Err(invalid_input(format!(
                    "padding turn {index} has an invalid send range: {}-{}",
                    turn.send_min_length, turn.send_max_length
                )));
            }
        }
        if index == 0
            && i64::try_from(min_length).unwrap_or(i64::MAX) - first_turn_prefix_length < 1
        {
            return Err(invalid_input(format!(
                "padding turn 0 is too short for {first_turn_prefix_length} prefix bytes"
            )));
        }
        if index == 0 && !turn.variants.is_empty() {
            let prefix = usize::try_from(first_turn_prefix_length).unwrap_or(usize::MAX);
            for (variant_index, variant) in turn.variants.iter().enumerate() {
                trim_prefix(variant, prefix).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("padding turn 0 variant {variant_index}: {error}"),
                    )
                })?;
            }
        }
        if index > 0 && turn.direction == schedule[index - 1].direction {
            return Err(invalid_input(format!(
                "padding turns {} and {index} have the same direction",
                index - 1
            )));
        }
    }
    Ok(())
}

fn write_turn<W: Write>(writer: &mut W, turn: &Turn, prefix_length: usize) -> io::Result<()> {
    let start_delay = random_delay(turn.start_delay)?;
    if !start_delay.is_zero() {
        std::thread::sleep(start_delay);
    }

    let (target_length, chunks, delays) = select_variant(turn, prefix_length)?;
    let record_length = target_length
        .checked_sub(prefix_length)
        .filter(|length| *length >= 1)
        .ok_or_else(|| {
            invalid_data(format!(
                "target length {target_length} leaves an invalid record length"
            ))
        })?;

    let mut header = Vec::new();
    write_varint(
        &mut header,
        i32::try_from(record_length)
            .map_err(|_| invalid_data("padding record length exceeds a varint"))?,
    )?;

    let (chunks, delays) = if chunks.is_empty() {
        let mut write_chunk_length = turn.write_chunk_length;
        if write_chunk_length == 0 {
            write_chunk_length = PADDING_BUFFER_LENGTH;
        } else if turn.write_chunk_min_length > 0 {
            write_chunk_length = random_target(turn.write_chunk_min_length, write_chunk_length)?;
        }
        let chunks = default_chunks(record_length, write_chunk_length);
        let mut delays = vec![DelayRange::default(); chunks.len()];
        for delay in delays.iter_mut().skip(1) {
            *delay = turn.chunk_delay;
        }
        (chunks, delays)
    } else {
        (chunks, delays)
    };

    if chunks[0] < header.len() {
        return Err(invalid_data(format!(
            "first padding chunk {} is shorter than header {}",
            chunks[0],
            header.len()
        )));
    }

    let mut max_chunk_length = 0;
    for chunk_length in &chunks {
        if *chunk_length < 1 || *chunk_length > MAX_PADDING_CHUNK_LENGTH {
            return Err(invalid_data(format!(
                "invalid padding chunk length: {chunk_length}"
            )));
        }
        max_chunk_length = max_chunk_length.max(*chunk_length);
    }

    let mut buffer = vec![0; max_chunk_length];
    buffer[..header.len()].copy_from_slice(&header);
    let mut written = 0;
    for (index, chunk_length) in chunks.iter().enumerate() {
        if let Some(delay) = delays.get(index) {
            let delay = random_delay(*delay)?;
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
        }
        writer.write_all(&buffer[..*chunk_length])?;
        written += *chunk_length;
        if index == 0 {
            buffer[..header.len()].fill(0);
        }
    }

    if written != record_length {
        return Err(invalid_data(format!(
            "padding chunks total {written}, want {record_length}"
        )));
    }
    Ok(())
}

fn read_turn<R: Read>(reader: &mut R, turn: &Turn, prefix_length: usize) -> io::Result<()> {
    let (encoded_length, header_length) = read_varint_with_length(reader)
        .map_err(|error| io::Error::new(error.kind(), format!("read padding header: {error}")))?;
    let record_length = i64::from(encoded_length);
    let header_length = i64::try_from(header_length).unwrap_or(i64::MAX);
    if record_length < header_length
        || record_length > i64::try_from(MAX_PADDING_TURN_LENGTH).unwrap_or(i64::MAX)
    {
        return Err(invalid_data(format!(
            "invalid padding record length: {record_length}"
        )));
    }
    let record_length = record_length as usize;
    let total_length = prefix_length + record_length;
    if !turn_accepts_length(turn, total_length) {
        if !turn.variants.is_empty() {
            return Err(invalid_data(format!(
                "padding turn length {total_length} is not an allowed variant"
            )));
        }
        return Err(invalid_data(format!(
            "padding turn length {total_length} is outside {}-{}",
            turn.min_length, turn.max_length
        )));
    }

    let mut buffer = [0; PADDING_BUFFER_LENGTH];
    let header_length = usize::try_from(header_length).unwrap_or(usize::MAX);
    let mut remaining = record_length.saturating_sub(header_length);
    while remaining > 0 {
        let chunk_length = remaining.min(buffer.len());
        reader
            .read_exact(&mut buffer[..chunk_length])
            .map_err(|error| io::Error::new(error.kind(), format!("read padding body: {error}")))?;
        remaining -= chunk_length;
    }
    Ok(())
}

fn select_variant(
    turn: &Turn,
    prefix_length: usize,
) -> io::Result<(usize, Vec<usize>, Vec<DelayRange>)> {
    if turn.variants.is_empty() {
        let (minimum, maximum) = if turn.send_min_length != 0 || turn.send_max_length != 0 {
            (turn.send_min_length, turn.send_max_length)
        } else {
            (turn.min_length, turn.max_length)
        };
        return Ok((random_target(minimum, maximum)?, Vec::new(), Vec::new()));
    }

    let indices = if turn.send_variants.is_empty() {
        (0..turn.variants.len()).collect::<Vec<_>>()
    } else {
        turn.send_variants.clone()
    };
    let selected = random_index(indices.len())?;
    let variant_index = indices[selected];
    let variant = turn
        .variants
        .get(variant_index)
        .ok_or_else(|| invalid_data(format!("invalid send variant index: {variant_index}")))?;
    let target_length = variant_length(variant);
    let (chunks, delays) = trim_prefix(variant, prefix_length)?;
    Ok((target_length, chunks, delays))
}

fn trim_prefix(
    variant: &Variant,
    prefix_length: usize,
) -> io::Result<(Vec<usize>, Vec<DelayRange>)> {
    let mut remaining_prefix = prefix_length;
    let mut first_chunk = 0;
    while first_chunk < variant.chunks.len() && remaining_prefix > 0 {
        let chunk_length = variant.chunks[first_chunk];
        if remaining_prefix < chunk_length {
            return Err(invalid_data(format!(
                "prefix length {prefix_length} splits chunk {first_chunk}"
            )));
        }
        remaining_prefix -= chunk_length;
        first_chunk += 1;
    }
    if remaining_prefix != 0 || first_chunk == variant.chunks.len() {
        return Err(invalid_data(format!(
            "prefix length {prefix_length} leaves no padding record"
        )));
    }

    let chunks = variant.chunks[first_chunk..].to_vec();
    let mut delays = vec![DelayRange::default(); chunks.len()];
    if !variant.delays.is_empty() {
        delays.copy_from_slice(&variant.delays[first_chunk..first_chunk + chunks.len()]);
    }
    Ok((chunks, delays))
}

fn default_chunks(record_length: usize, write_chunk_length: usize) -> Vec<usize> {
    let mut chunks = Vec::with_capacity(record_length.div_ceil(write_chunk_length));
    let mut remaining = record_length;
    while remaining > 0 {
        let chunk_length = remaining.min(write_chunk_length);
        chunks.push(chunk_length);
        remaining -= chunk_length;
    }
    chunks
}

fn turn_bounds(turn: &Turn) -> io::Result<(usize, usize)> {
    if turn.variants.is_empty() {
        if turn.min_length < 1
            || turn.max_length < turn.min_length
            || turn.max_length > MAX_PADDING_TURN_LENGTH
        {
            return Err(invalid_input(format!(
                "invalid range: {}-{}",
                turn.min_length, turn.max_length
            )));
        }
        return Ok((turn.min_length, turn.max_length));
    }
    if turn.min_length != 0 || turn.max_length != 0 {
        return Err(invalid_input(
            "variants cannot be combined with a length range",
        ));
    }

    let mut min_length = MAX_PADDING_TURN_LENGTH + 1;
    let mut max_length = 0;
    for (index, variant) in turn.variants.iter().enumerate() {
        if variant.chunks.is_empty() {
            return Err(invalid_input(format!("variant {index} has no chunks")));
        }
        if !variant.delays.is_empty() && variant.delays.len() != variant.chunks.len() {
            return Err(invalid_input(format!(
                "variant {index} has {} chunks and {} delays",
                variant.chunks.len(),
                variant.delays.len()
            )));
        }
        for (chunk_index, chunk_length) in variant.chunks.iter().enumerate() {
            if *chunk_length < 1 || *chunk_length > MAX_PADDING_CHUNK_LENGTH {
                return Err(invalid_input(format!(
                    "variant {index} chunk {chunk_index} has invalid length: {chunk_length}"
                )));
            }
            if !variant.delays.is_empty() {
                validate_delay(variant.delays[chunk_index]).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!(
                            "variant {index} chunk {chunk_index} has an invalid delay: {error}"
                        ),
                    )
                })?;
            }
        }
        let length = variant_length(variant);
        if length > MAX_PADDING_TURN_LENGTH {
            return Err(invalid_input(format!(
                "variant {index} is too long: {length}"
            )));
        }
        min_length = min_length.min(length);
        max_length = max_length.max(length);
    }
    for index in &turn.send_variants {
        if *index >= turn.variants.len() {
            return Err(invalid_input(format!(
                "invalid send variant index: {index}"
            )));
        }
    }
    Ok((min_length, max_length))
}

fn turn_accepts_length(turn: &Turn, length: usize) -> bool {
    if turn.variants.is_empty() {
        return length >= turn.min_length && length <= turn.max_length;
    }
    turn.variants
        .iter()
        .any(|variant| variant_length(variant) == length)
}

fn variant_length(variant: &Variant) -> usize {
    variant.chunks.iter().sum()
}

fn validate_delay(delay: DelayRange) -> io::Result<()> {
    if delay.max < delay.min {
        return Err(invalid_input(format!(
            "invalid range: {:?}-{:?}",
            delay.min, delay.max
        )));
    }
    Ok(())
}

fn random_delay(delay: DelayRange) -> io::Result<Duration> {
    validate_delay(delay)?;
    if delay.min == delay.max {
        return Ok(delay.min);
    }
    let span = u64::try_from(delay.max.saturating_sub(delay.min).as_millis())
        .ok()
        .and_then(|millis| millis.checked_add(1))
        .ok_or_else(|| io::Error::other("select padding delay: span too large"))?;
    let offset = random_below(span)?;
    Ok(delay.min + Duration::from_millis(offset))
}

pub(crate) fn random_index(length: usize) -> io::Result<usize> {
    if length < 1 {
        return Err(io::Error::other("select from empty padding choices"));
    }
    if length == 1 {
        return Ok(0);
    }
    let bound = u64::try_from(length).map_err(|_| io::Error::other("padding choice too large"))?;
    usize::try_from(random_below(bound)?).map_err(|_| io::Error::other("padding choice too large"))
}

fn random_target(min_length: usize, max_length: usize) -> io::Result<usize> {
    if min_length == max_length {
        return Ok(min_length);
    }
    let span = u64::try_from(max_length - min_length)
        .ok()
        .and_then(|span| span.checked_add(1))
        .ok_or_else(|| io::Error::other("select padding length: span too large"))?;
    let offset = random_below(span)?;
    let offset = usize::try_from(offset)
        .map_err(|_| io::Error::other("select padding length: span too large"))?;
    Ok(min_length + offset)
}

fn random_below(bound: u64) -> io::Result<u64> {
    if bound <= 1 {
        return Ok(0);
    }
    let limit = u64::MAX - u64::MAX % bound;
    loop {
        let mut raw = [0; 8];
        getrandom::fill(&mut raw)
            .map_err(|_| io::Error::other("select padding choice: no entropy"))?;
        let value = u64::from_le_bytes(raw);
        if value < limit {
            return Ok(value % bound);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Condvar, Mutex};

    #[derive(Clone)]
    struct Pipe {
        bytes: Arc<(Mutex<VecDeque<u8>>, Condvar)>,
    }

    impl Pipe {
        fn new() -> Self {
            Self {
                bytes: Arc::new((Mutex::new(VecDeque::new()), Condvar::new())),
            }
        }
    }

    impl Read for Pipe {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let (lock, ready) = &*self.bytes;
            let mut bytes = lock.lock().expect("pipe");
            while bytes.is_empty() {
                bytes = ready.wait(bytes).expect("pipe");
            }
            let taken = output.len().min(bytes.len());
            for (slot, byte) in output.iter_mut().zip(bytes.drain(..taken)) {
                *slot = byte;
            }
            Ok(taken)
        }
    }

    impl Write for Pipe {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            let (lock, ready) = &*self.bytes;
            lock.lock().expect("pipe").extend(input);
            ready.notify_all();
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn turn(direction: Direction, min_length: usize, max_length: usize) -> Turn {
        Turn {
            direction,
            min_length,
            max_length,
            ..Turn::default()
        }
    }

    #[test]
    fn empty_and_bad_prefix_schedules_are_rejected() {
        assert!(validate_schedule(&[], 0).is_err());
        assert!(validate_schedule(&[turn(Direction::ClientToServer, 8, 8)], -1).is_err());
        assert!(validate_schedule(&[turn(Direction::ServerToClient, 8, 8)], 3).is_err());
        assert!(validate_schedule(&[turn(Direction::ClientToServer, 8, 8)], 8).is_err());
    }

    #[test]
    fn adjacent_turns_in_the_same_direction_are_rejected() {
        let schedule = [
            turn(Direction::ClientToServer, 8, 8),
            turn(Direction::ClientToServer, 8, 8),
        ];
        let error = validate_schedule(&schedule, 0).expect_err("same direction");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn malformed_variants_and_ranges_are_rejected() {
        let bad_chunk = Turn {
            direction: Direction::ClientToServer,
            variants: vec![Variant {
                chunks: vec![MAX_PADDING_CHUNK_LENGTH + 1],
                delays: Vec::new(),
            }],
            ..Turn::default()
        };
        assert!(validate_schedule(&[bad_chunk], 0).is_err());

        let empty_variant = Turn {
            direction: Direction::ClientToServer,
            variants: vec![Variant::default()],
            ..Turn::default()
        };
        assert!(validate_schedule(&[empty_variant], 0).is_err());

        let mixed = Turn {
            direction: Direction::ClientToServer,
            min_length: 8,
            max_length: 8,
            variants: vec![Variant {
                chunks: vec![8],
                delays: Vec::new(),
            }],
            ..Turn::default()
        };
        assert!(validate_schedule(&[mixed], 0).is_err());

        let reversed = Turn {
            direction: Direction::ClientToServer,
            min_length: 8,
            max_length: 8,
            start_delay: DelayRange::millis(2, 1),
            ..Turn::default()
        };
        assert!(validate_schedule(&[reversed], 0).is_err());
    }

    #[test]
    fn a_small_schedule_round_trips_in_both_directions() {
        let schedule = [
            turn(Direction::ClientToServer, 33, 33),
            turn(Direction::ServerToClient, 4097, 4097),
            turn(Direction::ClientToServer, 16_385, 16_385),
        ];
        let client_to_server = Pipe::new();
        let server_to_client = Pipe::new();

        std::thread::scope(|scope| {
            let client_writer = client_to_server.clone();
            let client_reader = server_to_client.clone();
            let server_writer = server_to_client.clone();
            let server_reader = client_to_server.clone();
            let server_schedule = &schedule;
            scope.spawn(move || {
                let mut reader = server_reader;
                let mut writer = server_writer;
                run(&mut reader, &mut writer, false, 3, server_schedule).expect("server");
            });

            let mut reader = client_reader;
            let mut writer = client_writer;
            run(&mut reader, &mut writer, true, 3, &schedule).expect("client");
        });
    }

    #[test]
    fn a_first_turn_variant_is_trimmed_by_the_prefix() {
        let schedule = [Turn {
            direction: Direction::ClientToServer,
            variants: vec![Variant {
                chunks: vec![2, 26, 16],
                delays: Vec::new(),
            }],
            ..Turn::default()
        }];
        assert!(validate_schedule(&schedule, 2).is_ok());
        assert!(validate_schedule(&schedule, 3).is_err());
    }
}
