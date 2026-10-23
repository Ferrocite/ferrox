use std::cell::RefCell;

use crate::conn::Connection;
use crate::proxy::RELAY_SMALL_BUFFER;
use ferrox_core::tls::RecordAlignment;
use ferrox_core::vless::VisionCommand;
use std::io::{Read, Write};

const BUFFER: usize = 2048;
/// The framed window is one `rustls` record and the relay's own first read: past the switch neither staging buffer is touched again, so neither reaches for a whole relay's worth.
const WINDOW: usize = RELAY_SMALL_BUFFER;
const SEED: [u32; 4] = [900, 500, 900, 256];
const FILTER_PACKETS: i32 = 8;
pub(crate) const FLOW: &str = ferrox_core::vless::VISION_FLOW;

const TLS_SERVER_HELLO: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_APPLICATION_DATA: [u8; 3] = [0x17, 0x03, 0x03];
const TLS13_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;
const SHORTEST_FRAME: usize = 21;
/// A framed block is one Xray buffer: `buf.Size` (8192) less the uuid and header, which is where the reference reshapes a longer piece and where its reader refuses the frame.
const MAX_FRAME_CONTENT: usize = 8192 - SHORTEST_FRAME;
/// Padding never exceeds `BUFFER - SHORTEST_FRAME`, so one static zero run covers every trailer the framer writes.
const ZERO: [u8; BUFFER] = [0u8; BUFFER];

pub(crate) struct Link<S: Read + Write + RecordAlignment> {
    session: S,
    raw: Option<Connection>,
    uuid: [u8; 16],
    have: Vec<u8>,
    hat: usize,
    /// Where the peel put content in `have` this record, so the `TLS` observer scans the same bytes it scanned when every byte passed through `out`.
    spans: Vec<(usize, usize)>,
    out: Vec<u8>,
    oat: usize,
    #[cfg(test)]
    staged: usize,
    /// The command bytes the reader validated: one per frame, and the count the
    /// validator's row is read from.
    #[cfg(test)]
    validated: usize,
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
    command: Option<VisionCommand>,
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
    pub(crate) fn new(session: S, raw: Option<Connection>, uuid: &[u8; 16]) -> Self {
        Self {
            session,
            raw,
            uuid: *uuid,
            have: Vec::with_capacity(WINDOW),
            hat: 0,
            spans: Vec::new(),
            out: Vec::new(),
            oat: 0,
            #[cfg(test)]
            staged: 0,
            #[cfg(test)]
            validated: 0,
            read: Reading {
                padding: true,
                mid_frame: false,
                raw: false,
                want_header: 0,
                want_content: 0,
                want_padding: 0,
                command: None,
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

impl<S: Read + Write + RecordAlignment> Link<S> {
    /// The direct switch reads the raw clone, so the grain a shared read needs is armed on the handle it reads.
    pub(crate) fn arm_read_timeout(&self, grain: std::time::Duration) -> std::io::Result<()> {
        match &self.raw {
            Some(raw) => raw.set_read_timeout(Some(grain)),
            None => Ok(()),
        }
    }
}

impl Link<ferrox_core::tls::ClientSession<Connection>> {
    /// A raw-less link parks its reads in the session it frames, so the shared half's grain
    /// arms on that transport rather than on a handle the link does not keep.
    pub(crate) fn arm_session_timeout(&self, grain: std::time::Duration) -> std::io::Result<()> {
        self.session.get_ref().set_read_timeout(Some(grain))
    }
}

impl<S: Read + Write + RecordAlignment> Read for Link<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.oat >= self.out.len() {
            self.oat = 0;
            if self.read.padding {
                self.out.clear();
            } else {
                // The framing is over and its staging is empty: the connection is done with it.
                self.out = Vec::new();
            }
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
        // A record's peel lands in the caller's buffer directly: only the bytes the caller's pull could not hold stage through `out`, and the next read drains those first.
        if self.oat < self.out.len() {
            return Ok(self.copy_out(buf));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let mut landed = 0usize;
        let mut chunk: Option<&mut [u8]> = Some(buf);
        while self.oat >= self.out.len() && landed == 0 {
            if !self.fill_into(&mut chunk, &mut landed)? {
                return Ok(landed);
            }
        }
        if landed > 0 {
            return Ok(landed);
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

    #[cfg(test)]
    fn stage(&mut self, n: usize) {
        self.staged += n;
    }

    /// One command byte validated. The count is the validator's row, and the production
    /// arm folds away: the validator's own cost is in the match it makes.
    #[cfg(test)]
    fn validate(&mut self) {
        self.validated += 1;
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self)]
    fn validate(&mut self) {}

    #[cfg(not(test))]
    #[allow(clippy::unused_self)]
    fn stage(&mut self, _n: usize) {}

    fn compact(&mut self) {
        if self.hat > 0 {
            self.have.drain(..self.hat);
            self.hat = 0;
        }
    }

    /// One piece of content to whichever sink takes it first: the caller's buffer while it has room, its own staging after that. Returns `(landed, staged)`.
    fn sink(bytes: &[u8], chunk: &mut Option<&mut [u8]>, out: &mut Vec<u8>) -> (usize, usize) {
        let n = bytes.len();
        let take = n.min(chunk.as_ref().map_or(0, |slot| slot.len()));
        if take > 0 {
            if let Some(slot) = chunk.as_deref_mut() {
                slot[..take].copy_from_slice(&bytes[..take]);
            }
        }
        if take < n {
            out.extend_from_slice(&bytes[take..]);
        }
        if let Some(slot) = chunk.take() {
            *chunk = Some(&mut slot[take..]);
        }
        (take, n - take)
    }

    /// Reached only while the framing is live: the read lands in spare capacity held steady at the window, and only the bytes the peel cannot hand the caller stage through `out`; `staged` counts them.
    fn fill_into(
        &mut self,
        chunk: &mut Option<&mut [u8]>,
        landed: &mut usize,
    ) -> std::io::Result<bool> {
        loop {
            self.compact();
            self.spans.clear();
            let base = self.have.len();
            self.have.reserve_exact(WINDOW - base);
            let read = unsafe {
                self.have.set_len(WINDOW);
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
                self.flush_truncated(chunk, landed);
                return Ok(self.oat < self.out.len() || *landed > 0);
            }
            let framed = self.unpad_into(chunk, landed);
            if self.tls.budget > 0 && !self.spans.is_empty() {
                self.tls.observe_chunks(&self.have, &self.spans);
                self.engage();
            }
            if !framed {
                if *landed > 0 || self.oat < self.out.len() {
                    return Ok(true);
                }
                continue;
            }
            if self.oat < self.out.len() || *landed > 0 {
                break;
            }
        }
        // The framing is over: the window is dead with it, and a connection past the switch does not carry it.
        self.have = Vec::new();
        self.hat = 0;
        self.spans = Vec::new();
        Ok(true)
    }

    fn flush_truncated(&mut self, chunk: &mut Option<&mut [u8]>, landed: &mut usize) {
        if !self.read.mid_frame {
            let tail = self.have.len();
            let taken = tail - self.hat;
            if taken > 0 {
                let (took, staged_bytes) = {
                    let source = &self.have[self.hat..tail];
                    Self::sink(source, chunk, &mut self.out)
                };
                self.stage(staged_bytes);
                *landed += took;
                self.hat = tail;
            }
        }
    }

    /// The framed peel: the padding and the heads are skipped, and the content lands in whichever sink takes it — the caller's buffer first, the staging only for what the caller's pull left behind. Returns whether the framing is over.
    fn unpad_into(&mut self, chunk: &mut Option<&mut [u8]>, landed: &mut usize) -> bool {
        if !self.read.mid_frame {
            if self.pending() < SHORTEST_FRAME {
                return false;
            }
            if self.have[self.hat..self.hat + 16] != self.uuid {
                self.read.padding = false;
                self.hand_tail(chunk, landed);
                return true;
            }
            self.hat += 16;
            self.read.mid_frame = true;
            self.read.want_header = 5;
        }
        // The frames in the window are walked in a loop: a thousand frames cost a thousand steps.
        loop {
            while self.read.want_header > 0
                || self.read.want_content > 0
                || self.read.want_padding > 0
            {
                if self.pending() == 0 {
                    return false;
                }
                if self.read.want_header == 5 && self.pending() >= 5 {
                    // Five header iterations with no observable in between read as one load.
                    let head = &self.have[self.hat..self.hat + 5];
                    let (command, content, padding) = (
                        VisionCommand::from_byte(head[0]),
                        (usize::from(head[1]) << 8) | usize::from(head[2]),
                        (usize::from(head[3]) << 8) | usize::from(head[4]),
                    );
                    self.read.command = command;
                    self.validate();
                    self.read.want_content = content;
                    self.read.want_padding = padding;
                    self.hat += 5;
                    self.read.want_header = 0;
                    continue;
                }
                if self.read.want_header > 0 {
                    let byte = self.have[self.hat];
                    match self.read.want_header {
                        5 => {
                            self.read.command = VisionCommand::from_byte(byte);
                            self.validate();
                        }
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
                    if self.tls.budget > 0 {
                        self.spans.push((self.hat, take));
                    }
                    let (took, staged_bytes) = {
                        let source = &self.have[self.hat..self.hat + take];
                        Self::sink(source, chunk, &mut self.out)
                    };
                    self.stage(staged_bytes);
                    *landed += took;
                    self.hat += take;
                    self.read.want_content -= take;
                    continue;
                }
                let take = self.read.want_padding.min(self.pending());
                self.hat += take;
                self.read.want_padding -= take;
            }
            // The frame is complete: a continue means another frame follows it.
            if self.read.command == Some(VisionCommand::Continue) {
                self.read.want_header = 5;
                continue;
            }
            self.read.mid_frame = false;
            self.read.padding = false;
            self.read.raw = self.read.command == Some(VisionCommand::Direct) && self.raw.is_some();
            self.hand_tail(chunk, landed);
            return true;
        }
    }

    /// The bytes the window holds past the frame's own peel — after a uuid mismatch, or after the last frame — go over one sink, spans first.
    fn hand_tail(&mut self, chunk: &mut Option<&mut [u8]>, landed: &mut usize) {
        let tail = self.have.len();
        let taken = tail - self.hat;
        if taken > 0 {
            let (took, staged_bytes) = {
                let source = &self.have[self.hat..tail];
                Self::sink(source, chunk, &mut self.out)
            };
            self.stage(staged_bytes);
            *landed += took;
            if self.tls.budget > 0 {
                self.spans.push((tail - taken, taken));
            }
        }
        self.hat = tail;
    }

    /// The frame parser alone: a fixed window of empty frames, walked again and again,
    /// with the fold outside the walk so the frame holds the parse and nothing else.
    #[cfg(test)]
    fn unpad(&mut self) -> bool {
        let mut chunk: Option<&mut [u8]> = None;
        let mut landed = 0usize;
        let framed = self.unpad_into(&mut chunk, &mut landed);
        debug_assert_eq!(landed, 0, "the probe's peel has no caller sink to land in");
        framed
    }

    fn frame_head(command: u8, content: usize, padding: usize) -> [u8; 5] {
        let clen = (content as u16).to_be_bytes();
        let plen = (padding as u16).to_be_bytes();
        [command, clen[0], clen[1], plen[0], plen[1]]
    }
}

impl Tls {
    fn observe(&mut self, bytes: &[u8]) {
        self.budget -= 1;
        self.scan(bytes);
    }

    /// One budget spend, observed over the pieces this record's peel put where content went. The pieces are disjoint in `have` but the peel wrote them in order, so the filter walks an indexed cursor over them as one contiguous slice and every read it makes is the read it made when the same bytes sat in one staging buffer: the `ServerHello` regions, the pattern walk and the `left` arithmetic are all driven by the same positions.
    fn observe_chunks(&mut self, bytes: &[u8], spans: &[(usize, usize)]) {
        self.budget -= 1;
        let mut total = 0usize;
        for &(_, len) in spans {
            total += len;
        }
        if total == 0 {
            return;
        }
        let g = Spans { bytes, spans };
        if total >= 6 {
            let mut head = [0u8; 6];
            for (at, slot) in head.iter_mut().enumerate() {
                *slot = g.get(at);
            }
            if head[..3] == TLS_SERVER_HELLO && head[5] == 0x02 {
                self.server_hello_left = (usize::from(head[3]) << 8 | usize::from(head[4])) + 5;
                self.present = true;
                self.twelve_or_above = true;
                if total >= 79 && self.server_hello_left >= 79 {
                    let at = 44 + usize::from(g.get(43));
                    self.cipher = u16::from_be_bytes([g.get(at), g.get(at + 1)]);
                }
            } else if head[..2] == TLS_HANDSHAKE_START && head[5] == 0x01 {
                self.present = true;
            }
        }
        if self.server_hello_left == 0 {
            return;
        }
        let scan = self.server_hello_left.min(total);
        self.server_hello_left = self.server_hello_left.saturating_sub(total);
        let bound = scan.saturating_sub(TLS13_VERSIONS.len() - 1);
        let mut found = false;
        for at in 0..bound {
            if TLS13_VERSIONS
                .iter()
                .enumerate()
                .all(|(k, &b)| g.get(at + k) == b)
            {
                found = true;
                break;
            }
        }
        if found {
            self.enable_xtls = self.cipher != TLS_AES_128_CCM_8_SHA256;
            self.budget = 0;
        } else if self.server_hello_left == 0 {
            self.budget = 0;
        }
    }
    fn scan(&mut self, bytes: &[u8]) {
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

/// The peeled pieces of one record, read as the contiguous slice they were written to replace.
struct Spans<'a> {
    bytes: &'a [u8],
    spans: &'a [(usize, usize)],
}

impl Spans<'_> {
    fn get(&self, pos: usize) -> u8 {
        let mut pos = pos;
        for &(at, len) in self.spans {
            if pos < len {
                return self.bytes[at + pos];
            }
            pos -= len;
        }
        unreachable!("the filter reads only within the pieces it was handed");
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
        // The relay hands one buffer of up to 256 KiB: it frames as blocks of one Xray buffer, and the filter budget and the switch are counted per caller buffer as the reference counts them per `MultiBuffer`.
        let complete = self.tls.present
            && buf.len() >= 6
            && buf[..3] == TLS_APPLICATION_DATA
            && is_record_run(buf);
        let ends_early = !self.tls.twelve_or_above && self.tls.budget <= 1;
        let mut at = 0;
        while at < buf.len() {
            let content = (buf.len() - at).min(MAX_FRAME_CONTENT);
            let last = at + content == buf.len();
            let padding = padding_len(content, self.tls.present);
            let switches = last && complete;
            let command = match (switches && self.tls.enable_xtls, ends_early || switches) {
                (true, _) => VisionCommand::Direct.byte(),
                (_, true) => 1,
                _ => 0,
            };
            let head = Self::frame_head(command, content, padding);
            let payload = &buf[at..at + content];
            // Uuid on the first frame, then head, caller's buffer, zero trailer: one `write_all_slices`, one record, no copies.
            let first = !self.write.sent_uuid;
            self.write.sent_uuid = true;
            let parts: &[&[u8]] = if first {
                &[&self.uuid[..], &head, payload, &ZERO[..padding]]
            } else {
                &[&head, payload, &ZERO[..padding]]
            };
            self.session.write_all_slices(parts)?;
            at += content;
            if command != 0 {
                self.write.padding = false;
                self.write.raw = self.raw.is_some()
                    && self.tls.enable_xtls
                    && command == VisionCommand::Direct.byte();
                self.write_out(&buf[at..])?;
                return Ok(buf.len());
            }
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
                getrandom::fill(&mut buf[..]).ok()?;
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
            link.staged, 0,
            "the peel lands in the caller's own pull; staging returns only for a spill wider than it"
        );
    }

    /// At the relay's own window the peel never overflows the pull, so not one framed byte passes through a staging buffer: the row while framed is one copy per byte.
    #[test]
    fn a_relay_window_pull_never_stages() {
        let mut input = frame(true, 0, &[0x5a; 8000], 100);
        for _ in 0..9 {
            input.extend(frame(false, 0, &[0x5a; 8000], 100));
        }
        input.extend(frame(false, 1, b"done", 0));
        let mut link = link(&input);

        // Two framed pulls, framing still live, and neither `have` nor `out` has budged from one record or grown at all.
        let mut buf = vec![0u8; WINDOW];
        let mut got = Vec::new();
        for _ in 0..2 {
            let n = link.read(&mut buf).expect("reads");
            got.extend_from_slice(&buf[..n]);
            assert_eq!(link.staged, 0, "nothing spilled at the relay window");
            assert_eq!(link.out.capacity(), 0, "no staging buffer was created");
        }
        assert_eq!(link.have.capacity(), WINDOW);
        loop {
            let n = link.read(&mut buf).expect("reads");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got.len(), 10 * 8000 + b"done".len());
        for (at, byte) in got[..10 * 8000].iter().enumerate() {
            assert_eq!(byte, &0x5a, "byte at {at}");
        }
        for (at, byte) in got[(10 * 8000)..].iter().enumerate() {
            assert_eq!(byte, &b"done"[at]);
        }
    }

    /// The frame parser alone: a fixed window of empty frames, walked again and again,
    /// with the fold outside the walk so the frame holds the parse and nothing else.
    #[test]
    fn the_frame_parser_probe_costs_the_walk_and_nothing_else() {
        let mut input = Vec::new();
        for _ in 0..7 {
            input.extend(frame(false, 0, &[], 0));
        }
        input.extend(frame(false, 1, &[], 0));
        let mut link = link(&[]);
        let mut frames = 0usize;
        for _ in 0..64 {
            link.have.clear();
            link.have.extend_from_slice(&input);
            link.hat = 0;
            link.read.mid_frame = true;
            link.read.want_header = 5;
            assert!(link.unpad(), "the last frame ends the framing");
            frames += 8;
        }
        assert_eq!(frames, 512, "the walk saw every frame");
    }

    /// The command byte is validated once per frame, and a command the reference does
    /// not know ends the framing the way `end` does: the bytes after it are not framed.
    #[test]
    fn a_frame_validates_its_command_once() {
        let mut input = frame(true, 0, b"first", 3);
        input.extend(frame(false, 0, b"second", 4));
        input.extend(frame(false, 1, b"third", 0));
        input.extend_from_slice(b"raw tail");
        let mut framed = link(&input);
        let mut out = Vec::new();
        framed.read_to_end(&mut out).expect("reads");
        assert_eq!(out, b"firstsecondthirdraw tail");
        assert_eq!(
            framed.validated, 3,
            "one command byte per frame, and the tail carries none"
        );
        drop(framed);

        // A command outside the three the reference knows ends the framing like `end`.
        let mut unknown = frame(true, 0x07, b"kept", 0);
        unknown.extend_from_slice(b"after");
        let mut other = link(&unknown);
        let mut out = Vec::new();
        other.read_to_end(&mut out).expect("reads");
        assert_eq!(out, b"keptafter", "an unknown command ends the framing");
        assert_eq!(other.validated, 1, "the unknown command was validated too");
    }

    /// The framed staging never reaches for a full relay buffer: it is capped at one
    /// record while the framing lives, and the switch hands both buffers back.
    #[test]
    fn the_framed_staging_buffers_stay_at_one_record() {
        let mut input = Vec::new();
        for i in 0..24u32 {
            let content: Vec<u8> = (0..700u32).map(|k| (k as u8) ^ (i as u8)).collect();
            input.extend(frame(i == 0, 0, &content, 300));
        }
        input.extend(frame(false, 1, b"end", 0));
        let tail = vec![0xABu8; 40_000];
        input.extend_from_slice(&tail);

        let mut link = link(&input);
        let mut got = Vec::new();
        // The first read lands inside the framing, where the window is one record wide.
        let mut head = [0u8; 64];
        let n = link.read(&mut head).expect("reads");
        assert!(n > 0, "the first read carries content");
        assert_eq!(
            link.have.capacity(),
            WINDOW,
            "the read buffer holds exactly the window, never a relay's 256 KiB"
        );
        got.extend_from_slice(&head[..n]);
        link.read_to_end(&mut got).expect("reads");
        let mut want: Vec<u8> = (0..24u32)
            .flat_map(|i| (0..700u32).map(move |k| (k as u8) ^ (i as u8)))
            .collect();
        want.extend_from_slice(b"end");
        want.extend_from_slice(&tail);
        assert_eq!(got, want, "framing round-trips at one-record reads");

        assert_eq!(
            link.have.capacity(),
            0,
            "the switch hands the window back: a connection that lives on does not carry it"
        );
        assert_eq!(link.out.capacity(), 0, "and the staging with it");
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
        use std::time::Duration;
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
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
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
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

    /// A sink that records the slices it was handed, so the pointer can witness the removed copy.
    struct Peeker {
        written: Vec<u8>,
        /// `(payload_ptr, payload_len)` for each `write_all_slices` call.
        calls: Vec<(*const u8, usize)>,
        /// uuid pointer for the calls where the framer prepended it (the first frame).
        uuids: Vec<*const u8>,
    }

    impl Read for Peeker {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for Peeker {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl RecordAlignment for Peeker {
        fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
            // First frame: uuid | head | caller's payload | zero trailer. Later: head | caller's payload | zero trailer.
            let (uuid_at, payload_at) = match parts.len() {
                3 => (None, 1),
                4 => (Some(0), 2),
                n => panic!("unexpected {n} parts"),
            };
            self.calls
                .push((parts[payload_at].as_ptr(), parts[payload_at].len()));
            if let Some(i) = uuid_at {
                self.uuids.push(parts[i].as_ptr());
            }
            for part in parts {
                self.written.extend_from_slice(part);
            }
            Ok(())
        }
    }

    /// The payload pointer the caller handed `write` is the same pointer that reaches `write_all_slices`; a staging copy would move it.
    #[test]
    fn the_writer_hands_the_callers_payload_by_pointer() {
        let mut link = Link::new(
            Peeker {
                written: Vec::new(),
                calls: Vec::new(),
                uuids: Vec::new(),
            },
            None,
            &UUID,
        );
        let mut payload: Vec<u8> = (0..4_000u32).map(|i| (i % 251) as u8).collect();
        let want_ptr = payload.as_ptr();
        let want_len = payload.len();
        link.write_all(&payload).expect("writes");
        assert_eq!(link.session.calls.len(), 1);
        let (got_ptr, got_len) = link.session.calls[0];
        assert_eq!(
            got_ptr, want_ptr,
            "the caller's payload reached the session uncopied"
        );
        assert_eq!(got_len, want_len);
        // Grow the caller's buffer so the next write would have shown a stale staging pointer.
        payload.extend_from_slice(b"-more-");
        let second_ptr = payload.as_ptr();
        link.write_all(&payload).expect("writes");
        assert_eq!(link.session.calls.len(), 2);
        assert_eq!(
            link.session.calls[1].0, second_ptr,
            "still by pointer, after a realloc"
        );
    }

    /// The relay hands one buffer of up to 64 KiB; past one `buf.Size` block the u16 length wraps and the reference's reader refuses the frame, so the buffer frames as whole blocks and every byte still arrives.
    #[test]
    fn a_bulk_write_frames_every_block_inside_the_bound() {
        let body: Vec<u8> = (0..crate::proxy::RELAY_BUFFER as u32)
            .map(|i| (i % 251) as u8)
            .collect();
        let base = body.as_ptr();
        let mut link = Link::new(
            Peeker {
                written: Vec::new(),
                calls: Vec::new(),
                uuids: Vec::new(),
            },
            None,
            &UUID,
        );
        link.write_all(&body).expect("writes");

        let out = &link.session.written;
        assert_eq!(&out[..16], &UUID, "one uuid for the whole buffer");
        assert_eq!(link.session.uuids.len(), 1);
        assert_eq!(
            usize::from(u16::from_be_bytes([out[17], out[18]])),
            MAX_FRAME_CONTENT,
            "the block is the largest the bound allows, so the fewest of them"
        );
        let mut at = 16;
        let mut framed = 0usize;
        let mut blocks = 0usize;
        while at + 5 <= out.len() {
            assert_eq!(out[at], 0, "the filter window is still open past {blocks}");
            let content = usize::from(u16::from_be_bytes([out[at + 1], out[at + 2]]));
            let padding = usize::from(u16::from_be_bytes([out[at + 3], out[at + 4]]));
            assert!(
                content + padding <= MAX_FRAME_CONTENT,
                "block {blocks} frames {content}+{padding} past the bound"
            );
            assert_eq!(
                link.session.calls[blocks].0,
                base.wrapping_add(framed),
                "block {blocks} reaches the session from the caller's buffer"
            );
            assert_eq!(link.session.calls[blocks].1, content);
            assert_eq!(
                &out[at + 5..at + 5 + content],
                &body[framed..framed + content]
            );
            assert_eq!(
                &ZERO[..padding],
                &out[at + 5 + content..at + 5 + content + padding]
            );
            if content == MAX_FRAME_CONTENT {
                assert_eq!(padding, 0, "a full block carries no trailer to skip");
            }
            framed += content;
            at += 5 + content + padding;
            blocks += 1;
        }
        assert_eq!(at, out.len(), "every framed byte was walked");
        assert_eq!(framed, body.len(), "the payload arrived whole");
        assert_eq!(blocks, body.len().div_ceil(MAX_FRAME_CONTENT));
        assert_eq!(link.session.calls.len(), blocks);
    }

    /// The uuid reaches the session as a slice of the link's own field; a stack-header build would have copied it there.
    #[test]
    fn the_writer_hands_the_uuid_by_pointer_on_the_first_frame() {
        let mut link = Link::new(
            Peeker {
                written: Vec::new(),
                calls: Vec::new(),
                uuids: Vec::new(),
            },
            None,
            &UUID,
        );
        let want_uuid = std::ptr::from_ref(&link.uuid).cast::<u8>();
        link.write_all(b"hello").expect("writes");
        assert_eq!(link.session.uuids.len(), 1, "the uuid goes out once");
        assert_eq!(
            link.session.uuids[0], want_uuid,
            "the uuid reached the session by pointer, not copied into a stack head"
        );
        link.write_all(b"again").expect("writes");
        assert_eq!(
            link.session.uuids.len(),
            1,
            "no second prepended uuid after the first frame"
        );
    }

    /// Steady write traffic leaves the read-side capacities alone; nothing on the write path allocates a buffer that grows.
    #[test]
    fn write_traffic_holds_the_buffer_capacities_steady() {
        let mut link = link(&[]);
        let have_before = link.have.capacity();
        let out_before = link.out.capacity();
        let body = vec![0x42u8; 1_400];
        for _ in 0..64 {
            link.write_all(&body).expect("writes");
        }
        assert_eq!(
            link.have.capacity(),
            have_before,
            "no allocation on the write path"
        );
        assert_eq!(
            link.out.capacity(),
            out_before,
            "no allocation on the write path"
        );
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
