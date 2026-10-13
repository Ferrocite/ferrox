use std::cell::RefCell;

use crate::proxy::RELAY_BUFFER;
use ferrox_core::tls::RecordAlignment;
use std::io::{Read, Write};
use std::net::TcpStream;

const BUFFER: usize = 2048;
const SEED: [u32; 4] = [900, 500, 900, 256];
const FILTER_PACKETS: i32 = 8;
const CMD_DIRECT: u8 = 2;
pub(crate) const FLOW: &str = "xtls-rprx-vision";

const TLS_SERVER_HELLO: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_APPLICATION_DATA: [u8; 3] = [0x17, 0x03, 0x03];
const TLS13_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;
const SHORTEST_FRAME: usize = 21;

pub(crate) struct Link<S: Read + Write + RecordAlignment> {
    session: S,
    raw: Option<TcpStream>,
    uuid: [u8; 16],
    have: Vec<u8>,
    hat: usize,
    out: Vec<u8>,
    oat: usize,
    staging: Vec<u8>,
    #[cfg_attr(not(test), allow(dead_code, reason = "read by the staging gate"))]
    staged: usize,
    read: Reading,
    write: Writing,
    tls: Tls,
}

struct Reading {
    padding: bool,
    mid_frame: bool,
    raw: bool,
    want_header: i32,
    want_content: usize,
    want_padding: usize,
    command: u8,
}

struct Writing {
    padding: bool,
    sent_uuid: bool,
    raw: bool,
}

struct Tls {
    present: bool,
    twelve_or_above: bool,
    enable_xtls: bool,
    budget: i32,
    server_hello_left: usize,
    cipher: u16,
}

impl<S: Read + Write + RecordAlignment> Link<S> {
    pub(crate) fn new(session: S, raw: Option<TcpStream>, uuid: &[u8; 16]) -> Self {
        Self {
            session,
            raw,
            uuid: *uuid,
            have: Vec::with_capacity(RELAY_BUFFER),
            hat: 0,
            out: Vec::with_capacity(RELAY_BUFFER),
            oat: 0,
            staging: Vec::with_capacity(BUFFER + SHORTEST_FRAME),
            staged: 0,
            read: Reading {
                padding: true,
                mid_frame: false,
                raw: false,
                want_header: 0,
                want_content: 0,
                want_padding: 0,
                command: 0,
            },
            write: Writing {
                padding: true,
                sent_uuid: false,
                raw: false,
            },
            tls: Tls {
                present: false,
                twelve_or_above: false,
                enable_xtls: false,
                budget: FILTER_PACKETS,
                server_hello_left: 0,
                cipher: 0,
            },
        }
    }
}

impl<S: Read + Write + RecordAlignment> RecordAlignment for Link<S> {
    fn engage_record_alignment(&mut self) {
        self.session.engage_record_alignment();
    }
}

impl<S: Read + Write + RecordAlignment> Read for Link<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.oat >= self.out.len() {
            self.out.clear();
            self.oat = 0;
        }
        if !self.read.padding {
            if self.oat < self.out.len() {
                return Ok(self.copy_out(buf));
            }
            if buf.is_empty() {
                return Ok(0);
            }
            return self.read_direct(buf);
        }
        while self.oat >= self.out.len() {
            if !self.fill()? {
                return Ok(0);
            }
        }
        Ok(self.copy_out(buf))
    }
}

impl<S: Read + Write + RecordAlignment> Link<S> {
    fn copy_out(&mut self, buf: &mut [u8]) -> usize {
        let n = (self.out.len() - self.oat).min(buf.len());
        buf[..n].copy_from_slice(&self.out[self.oat..self.oat + n]);
        self.oat += n;
        n
    }

    /// Past the framing the payload lands in the caller's buffer: no copy, where the staged path needed two.
    fn read_direct(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let raw = self.read.raw;
        let n = match self.raw.as_mut() {
            Some(handle) if raw => handle.read(buf)?,
            _ => self.session.read(buf)?,
        };
        if n > 0 && !raw && self.tls.budget > 0 {
            self.tls.observe(&buf[..n]);
            self.engage();
        }
        Ok(n)
    }

    fn engage(&mut self) {
        if self.tls.enable_xtls {
            self.session.engage_record_alignment();
        }
    }

    fn pending(&self) -> usize {
        self.have.len() - self.hat
    }

    /// Bytes that were staged; after the switch out of Vision framing everything is delivered uncopied.
    #[cfg(test)]
    pub(crate) fn staged(&self) -> usize {
        self.staged
    }

    fn compact(&mut self) {
        if self.hat > 0 {
            self.have.drain(..self.hat);
            self.hat = 0;
        }
    }

    /// Reached only while the framing is live, so every byte here was staged; `staged()` counts them.
    fn fill(&mut self) -> std::io::Result<bool> {
        loop {
            self.compact();
            let base = self.have.len();
            self.have.reserve_exact(RELAY_BUFFER);
            // The read lands in spare capacity; staging here copied every framed byte twice.
            let read = unsafe {
                self.have.set_len(base + RELAY_BUFFER);
                self.session.read(&mut self.have[base..])
            };
            let n = match read {
                Ok(n) => {
                    self.have.truncate(base + n);
                    n
                }
                Err(error) => {
                    self.have.truncate(base);
                    return Err(error);
                }
            };
            if n == 0 {
                self.flush_truncated();
                return Ok(self.oat < self.out.len());
            }
            self.staged += n;
            let was = self.out.len();
            let framed = self.unpad();
            if self.tls.budget > 0 && self.out.len() > was {
                self.tls.observe(&self.out[was..]);
                self.engage();
            }
            if !framed {
                if self.out.len() > was {
                    return Ok(true);
                }
                continue;
            }
            if self.oat < self.out.len() {
                return Ok(true);
            }
        }
    }

    fn unpad(&mut self) -> bool {
        if !self.read.mid_frame {
            if self.pending() < SHORTEST_FRAME {
                return false;
            }
            if self.have[self.hat..self.hat + 16] != self.uuid {
                self.read.padding = false;
                let tail = self.have.len();
                let taken = tail - self.hat;
                self.out.extend_from_slice(&self.have[self.hat..tail]);
                self.staged += taken;
                self.hat = tail;
                return true;
            }
            self.hat += 16;
            self.read.mid_frame = true;
            self.read.want_header = 5;
        }
        while self.read.want_header > 0 || self.read.want_content > 0 || self.read.want_padding > 0
        {
            if self.pending() == 0 {
                return false;
            }
            if self.read.want_header == 5 && self.pending() >= 5 {
                // Five header iterations with no observable in between read as one load.
                let head = &self.have[self.hat..self.hat + 5];
                self.read.command = head[0];
                self.read.want_content = (usize::from(head[1]) << 8) | usize::from(head[2]);
                self.read.want_padding = (usize::from(head[3]) << 8) | usize::from(head[4]);
                self.hat += 5;
                self.read.want_header = 0;
                continue;
            }
            if self.read.want_header > 0 {
                let byte = self.have[self.hat];
                match self.read.want_header {
                    5 => self.read.command = byte,
                    4 => self.read.want_content = usize::from(byte) << 8,
                    3 => self.read.want_content |= usize::from(byte),
                    2 => self.read.want_padding = usize::from(byte) << 8,
                    _ => self.read.want_padding |= usize::from(byte),
                }
                self.hat += 1;
                self.read.want_header -= 1;
                continue;
            }
            if self.read.want_content > 0 {
                let take = self.read.want_content.min(self.pending());
                self.out
                    .extend_from_slice(&self.have[self.hat..self.hat + take]);
                self.staged += take;
                self.hat += take;
                self.read.want_content -= take;
                continue;
            }
            let take = self.read.want_padding.min(self.pending());
            self.hat += take;
            self.read.want_padding -= take;
        }
        if self.read.command == 0 {
            self.read.want_header = 5;
            return self.unpad();
        }
        self.read.mid_frame = false;
        self.read.padding = false;
        self.read.raw = self.read.command == CMD_DIRECT && self.raw.is_some();
        let tail = self.have.len();
        let taken = tail - self.hat;
        self.out.extend_from_slice(&self.have[self.hat..tail]);
        self.staged += taken;
        self.hat = tail;
        true
    }

    fn flush_truncated(&mut self) {
        if !self.read.mid_frame {
            let tail = self.have.len();
            let taken = tail - self.hat;
            self.out.extend_from_slice(&self.have[self.hat..tail]);
            self.staged += taken;
            self.hat = tail;
        }
    }

    fn frame(
        uuid: &[u8; 16],
        tls: &Tls,
        sent_uuid: &mut bool,
        into: &mut Vec<u8>,
        buf: &[u8],
    ) -> u8 {
        let complete =
            tls.present && buf.len() >= 6 && buf[..3] == TLS_APPLICATION_DATA && is_record_run(buf);
        let ends = complete || (!tls.twelve_or_above && tls.budget <= 1);
        let command = match (complete && tls.enable_xtls, ends) {
            (true, _) => CMD_DIRECT,
            (_, true) => 1,
            _ => 0,
        };
        if !*sent_uuid {
            into.extend_from_slice(uuid);
            *sent_uuid = true;
        }
        let padding = padding_len(buf.len(), tls.present);
        into.push(command);
        into.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        into.extend_from_slice(&(padding as u16).to_be_bytes());
        into.extend_from_slice(buf);
        into.resize(into.len() + padding, 0);
        command
    }
}

impl Tls {
    fn observe(&mut self, bytes: &[u8]) {
        self.budget -= 1;
        if bytes.len() >= 6 {
            let head = &bytes[..6];
            if head[..3] == TLS_SERVER_HELLO && head[5] == 0x02 {
                self.server_hello_left = (usize::from(head[3]) << 8 | usize::from(head[4])) + 5;
                self.present = true;
                self.twelve_or_above = true;
                if bytes.len() >= 79 && self.server_hello_left >= 79 {
                    let at = 44 + usize::from(bytes[43]);
                    self.cipher = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
                }
            } else if head[..2] == TLS_HANDSHAKE_START && head[5] == 0x01 {
                self.present = true;
            }
        }
        if self.server_hello_left == 0 {
            return;
        }
        let scan = self.server_hello_left.min(bytes.len());
        self.server_hello_left = self.server_hello_left.saturating_sub(bytes.len());
        if bytes[..scan]
            .windows(TLS13_VERSIONS.len())
            .any(|w| w == TLS13_VERSIONS)
        {
            self.enable_xtls = self.cipher != TLS_AES_128_CCM_8_SHA256;
            self.budget = 0;
        } else if self.server_hello_left == 0 {
            self.budget = 0;
        }
    }
}

impl<S: Read + Write + RecordAlignment> Write for Link<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.write.padding {
            self.write_out(buf)?;
            return Ok(buf.len());
        }
        if self.tls.budget > 0 {
            self.tls.observe(buf);
            self.engage();
        }
        self.staging.clear();
        let command = Self::frame(
            &self.uuid,
            &self.tls,
            &mut self.write.sent_uuid,
            &mut self.staging,
            buf,
        );
        self.session.write_all(&self.staging)?;
        if command != 0 {
            self.write.padding = false;
            self.write.raw = self.raw.is_some() && self.tls.enable_xtls && command == CMD_DIRECT;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.raw.as_mut() {
            Some(raw) if self.write.raw => raw.flush(),
            _ => self.session.flush(),
        }
    }
}

impl<S: Read + Write + RecordAlignment> Link<S> {
    fn write_out(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self.raw.as_mut() {
            Some(raw) if self.write.raw => raw.write_all(buf),
            _ => self.session.write_all(buf),
        }
    }
}

fn padding_len(content: usize, long: bool) -> usize {
    let drawn = if long && content < SEED[0] as usize {
        random_below(SEED[1]) + SEED[2] as usize - content
    } else {
        random_below(SEED[3])
    };
    drawn.min(BUFFER.saturating_sub(SHORTEST_FRAME + content))
}

fn random_below(bound: u32) -> usize {
    if bound == 0 {
        return 0;
    }
    thread_local! {
        static BATCH: RefCell<([u8; 2048], usize)> = const { RefCell::new(([0u8; 2048], 2048)) };
    }
    let Some(word) = BATCH
        .try_with(|cell| {
            let (buf, at) = &mut *cell.borrow_mut();
            if *at + 4 > buf.len() {
                getrandom::getrandom(&mut buf[..]).ok()?;
                *at = 0;
            }
            let word = u32::from_be_bytes(buf[*at..*at + 4].try_into().ok()?);
            *at += 4;
            Some(word)
        })
        .ok()
        .flatten()
    else {
        return 0;
    };
    usize::try_from(word % bound).unwrap_or(0)
}

fn is_record_run(buf: &[u8]) -> bool {
    let mut at = 0;
    let mut head = 5;
    let mut left = 0;
    while at < buf.len() {
        if head > 0 {
            let byte = buf[at];
            at += 1;
            match head {
                3..=5 => {
                    if byte != TLS_APPLICATION_DATA[5 - head as usize] {
                        return false;
                    }
                }
                2 => left = usize::from(byte) << 8,
                _ => left |= usize::from(byte),
            }
            head -= 1;
        } else if left > 0 {
            if buf.len() - at < left {
                return false;
            }
            at += left;
            left = 0;
            head = 5;
        } else {
            return false;
        }
    }
    head == 5 && left == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Fake {
        read: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Fake {
        fn new(input: &[u8]) -> Self {
            Self {
                read: Cursor::new(input.to_vec()),
                written: Vec::new(),
            }
        }
    }

    impl Read for Fake {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read.read(buf)
        }
    }

    impl Write for Fake {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl RecordAlignment for Fake {}

    const UUID: [u8; 16] = [0x11; 16];

    fn link(input: &[u8]) -> Link<Fake> {
        Link::new(Fake::new(input), None, &UUID)
    }

    fn frame(first: bool, command: u8, content: &[u8], padding: usize) -> Vec<u8> {
        let mut out = Vec::new();
        if first {
            out.extend_from_slice(&UUID);
        }
        out.push(command);
        out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        out.extend_from_slice(&(padding as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + padding, 0);
        out
    }

    #[test]
    fn a_continue_then_end_sequence_reads_back_as_content() {
        let mut input = frame(true, 0, b"first", 40);
        input.extend(frame(false, 0, b"second", 10));
        input.extend(frame(false, 1, b"third", 0));
        input.extend_from_slice(b"raw tail");
        let mut link = link(&input);
        let mut out = Vec::new();
        link.read_to_end(&mut out).expect("reads");
        assert_eq!(out, b"firstsecondthirdraw tail");
    }

    #[test]
    fn a_frame_split_across_reads_is_reassembled() {
        let mut input = frame(true, 0, b"split", 30);
        input.extend(frame(false, 1, b"tail", 4));
        let mut link = link(&input);
        let mut out = Vec::new();
        link.read_to_end(&mut out).expect("reads");
        assert_eq!(out, b"splittail");
    }

    #[test]
    fn a_stream_without_the_uuid_is_content_from_the_start() {
        let mut link = link(b"no framing here at all");
        let mut out = Vec::new();
        link.read_to_end(&mut out).expect("reads");
        assert_eq!(out, b"no framing here at all");
    }

    /// Past the switch the tail is delivered with zero copies, where the framed path copied it twice.
    #[test]
    fn the_framing_switch_ends_the_staging() {
        /// Hands out `step` bytes at a time so a read boundary lands on the end of the framing.
        struct Drip<'a> {
            left: &'a [u8],
            step: usize,
        }
        impl Read for Drip<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.left.len().min(buf.len()).min(self.step);
                buf[..n].copy_from_slice(&self.left[..n]);
                self.left = &self.left[n..];
                Ok(n)
            }
        }
        impl Write for Drip<'_> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl RecordAlignment for Drip<'_> {}

        let tail = b"straight through, never staged";
        let mut input = frame(true, 0, b"padded", 8);
        input.extend(frame(false, 1, b"end", 0));
        input.extend_from_slice(tail);
        let framed = input.len() - tail.len();
        let mut link = Link::new(
            Drip {
                left: &input,
                step: framed,
            },
            None,
            &UUID,
        );

        let mut got = Vec::new();
        let mut buf = [0u8; 16];
        loop {
            let n = link.read(&mut buf).expect("reads");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, [b"paddedend".as_slice(), tail.as_slice()].concat());
        assert_eq!(
            link.staged(),
            framed + b"paddedend".len(),
            "only framed bytes are staged: {} in, {} more out",
            framed,
            b"paddedend".len()
        );
    }

    /// A reader that answers in seeded chunks, so a red run replays anywhere.
    struct Seeded<'a> {
        left: &'a [u8],
        state: u32,
    }

    impl Read for Seeded<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.left.is_empty() {
                return Ok(0);
            }
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.state = x;
            // Framed like the core sweep: whole UUID prefix first, splits after.
            let take = (x as usize % 48 + 21).min(buf.len()).min(self.left.len());
            buf[..take].copy_from_slice(&self.left[..take]);
            self.left = &self.left[take..];
            Ok(take)
        }
    }

    impl Write for Seeded<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl RecordAlignment for Seeded<'_> {}

    #[test]
    fn seeded_splits_read_back_as_whole_content() {
        let content: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
        let mut input = frame(true, 0, &content, 37);
        input.extend(frame(false, 1, b"tail", 3));
        input.extend_from_slice(b"raw tail");
        let mut link = Link::new(
            Seeded {
                left: &input,
                state: 0x9e37_79b9,
            },
            None,
            &UUID,
        );
        let mut got = Vec::new();
        link.read_to_end(&mut got).expect("reads");
        let mut want = content;
        want.extend_from_slice(b"tailraw tail");
        assert_eq!(got, want);
    }

    #[test]
    fn a_direct_command_switches_the_reading_direction() {
        let mut input = frame(true, 0, b"padded", 8);
        input.extend(frame(false, 2, b"", 0));
        input.extend_from_slice(b"after the switch");
        let mut link = link(&input);
        let mut out = Vec::new();
        link.read_to_end(&mut out).expect("reads");
        assert_eq!(out, b"paddedafter the switch");
        assert!(!link.read.raw);
        assert!(!link.read.padding);
    }

    #[test]
    fn a_truncated_frame_is_dropped_not_delivered() {
        let mut input = frame(true, 0, b"kept", 0);
        input.extend_from_slice(&[0x00, 0x00, 0x40]);
        let mut link = link(&input);
        let mut out = Vec::new();
        link.read_to_end(&mut out).expect("reads");
        assert_eq!(out, b"kept");
    }

    #[test]
    fn bytes_after_padding_arrive_without_waiting_for_close() {
        use std::net::TcpListener;
        use std::time::Duration;
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let writer = std::thread::spawn(move || {
            use std::io::Write as _;
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut input = frame(true, 1, b"end", 0);
            input.extend_from_slice(b"tail-part-one");
            stream.write_all(&input).expect("writes");
            std::thread::sleep(Duration::from_millis(200));
            stream.write_all(b"tail-part-two").expect("writes");
            std::thread::sleep(Duration::from_millis(200));
        });
        let stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let mut link = Link::new(stream, None, &UUID);
        let mut first = [0u8; 16];
        link.read_exact(&mut first).expect("part one needs no EOF");
        assert_eq!(&first, b"endtail-part-one");
        let mut rest = Vec::new();
        link.read_to_end(&mut rest).expect("rest arrives at close");
        assert_eq!(rest, b"tail-part-two");
        writer.join().expect("joins");
    }

    #[test]
    fn writing_frames_the_payload_and_heads_the_first_with_the_uuid() {
        let mut link = link(&[]);
        link.write_all(b"hello").expect("writes");
        let out = &link.session.written;
        assert_eq!(&out[..16], &UUID);
        assert_eq!(out[16], 0, "padding is still running");
        let len = usize::from(u16::from_be_bytes([out[17], out[18]]));
        let pad = usize::from(u16::from_be_bytes([out[19], out[20]]));
        assert_eq!(len, 5);
        assert_eq!(&out[21..26], b"hello");
        assert_eq!(out.len(), 26 + pad);
        assert!(pad < BUFFER);
    }

    #[test]
    fn a_non_tls_stream_stops_padding_inside_the_filter_window() {
        let mut link = link(&[]);
        let mut commands = Vec::new();
        let mut at = 0;
        for round in 0..FILTER_PACKETS - 1 {
            link.write_all(b"x").expect("writes");
            commands.push(link.session.written[at + if round == 0 { 16 } else { 0 }]);
            at = link.session.written.len();
        }
        assert_eq!(commands, vec![0, 0, 0, 0, 0, 0, 1]);
        assert!(!link.write.padding);
        assert_eq!(link.tls.budget, 1, "the last buffer of the window is spent");
        link.write_all(b"y").expect("writes");
        assert!(link.session.written.ends_with(b"y"), "unframed from here");
    }

    #[test]
    fn an_inner_tls13_stream_switches_to_raw_at_its_first_record() {
        let mut link = link(&[]);
        link.write_all(&server_hello()).expect("writes");
        assert!(
            link.tls.enable_xtls,
            "a 1.3 ServerHello is worth switching for"
        );
        assert!(link.write.padding, "the handshake is still padded");
        let at = link.session.written.len();
        link.write_all(&application_record()).expect("writes");
        assert_eq!(link.session.written[at], 2, "command two");
        assert!(!link.write.padding);
        assert!(!link.write.raw, "no raw socket was wired, so no raw switch");
    }

    fn server_hello() -> Vec<u8> {
        let mut payload = vec![0x02, 0x00, 0x00, 0x00];
        payload.extend_from_slice(&[0x03, 0x03]);
        payload.extend_from_slice(&[0x7fu8; 32]);
        payload.push(32);
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&[0x00, 0x13, 0x01]);
        payload.push(0);
        payload.extend_from_slice(&[0x00, 0x00]);
        payload.extend_from_slice(&TLS13_VERSIONS);
        let len = u32::try_from(payload.len() - 4).unwrap();
        payload[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
        let mut out = vec![0x16, 0x03, 0x03];
        out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    fn application_record() -> Vec<u8> {
        let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x05];
        record.extend_from_slice(b"inner");
        record
    }

    #[test]
    fn a_record_boundary_is_only_a_boundary_between_records() {
        let record = application_record();
        assert!(is_record_run(&record));
        assert!(!is_record_run(&record[..8]));
        let mut two = record.clone();
        two.extend_from_slice(&record);
        assert!(is_record_run(&two));
        let mut partial = record.clone();
        partial.pop();
        assert!(!is_record_run(&partial));
        assert!(!is_record_run(&[0x16, 0x03, 0x03, 0x00, 0x05, 0]));
        assert!(!is_record_run(&[0x17, 0x03, 0x04, 0x00, 0x01, 0]));
    }

    #[test]
    fn padding_is_bounded_and_scales_with_the_payload() {
        for len in [0usize, 1, 100, 899, 900, 2000, 5000, 100_000] {
            let pad = padding_len(len, false);
            assert!(pad < SEED[3] as usize, "len {len} padded by {pad}");
        }
        assert!(padding_len(10, true) >= SEED[2] as usize - 10);
        assert!(padding_len(2000, true) < SEED[3] as usize);
    }

    #[test]
    fn both_directions_spend_the_same_filter_budget() {
        let mut link = link(&[]);
        link.write_all(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x01])
            .expect("writes");
        assert_eq!(link.tls.budget, FILTER_PACKETS - 1);
        assert!(
            link.tls.present,
            "a ClientHello record makes the stream TLS"
        );
        assert!(
            !link.tls.twelve_or_above,
            "a ClientHello says nothing about a version"
        );
    }
}
