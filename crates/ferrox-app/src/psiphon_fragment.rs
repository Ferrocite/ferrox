//! DPI-resistant TCP fragmentation, the synchronous shape of the reference's
//! `fragmentor.Conn`: the first bytes of a dial leave in several small writes
//! with random pauses, then the stream resumes its ordinary width.
//!
//! The bytes and their order are unchanged. Only the size and timing of the
//! initial TCP writes move, which is what a middlebox that reassembles an
//! application message across segments observes.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::psiphon_ssh::dial_random;

/// The reference's largest default fragment.
const DEFAULT_MAX_WRITE: usize = 1500;

/// The `Fragmentor*` parameters one dial may use.
#[derive(Clone, Debug)]
pub(crate) struct Fragmentor {
    probability: f64,
    protocols: Vec<String>,
    min_total: usize,
    max_total: usize,
    min_write: usize,
    max_write: usize,
    min_delay: Duration,
    max_delay: Duration,
    allow_with_prefix: bool,
}

impl Default for Fragmentor {
    /// The reference defaults: half the dials, no protocol limit, 1500-byte writes, 10 ms pauses.
    fn default() -> Self {
        Self {
            probability: 0.5,
            protocols: Vec::new(),
            min_total: 0,
            max_total: 0,
            min_write: 1,
            max_write: DEFAULT_MAX_WRITE,
            min_delay: Duration::ZERO,
            max_delay: Duration::from_millis(10),
            allow_with_prefix: false,
        }
    }
}

impl Fragmentor {
    /// Store the reference parameters, clamping each to its valid range.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        probability: f64,
        protocols: Vec<String>,
        min_total: usize,
        max_total: usize,
        min_write: usize,
        max_write: usize,
        min_delay: Duration,
        max_delay: Duration,
        allow_with_prefix: bool,
    ) -> Self {
        Self {
            probability: probability.clamp(0.0, 1.0),
            protocols,
            min_total: min_total.min(max_total),
            max_total,
            min_write: min_write.max(1).min(max_write.max(1)),
            max_write: max_write.max(1),
            min_delay: min_delay.min(max_delay),
            max_delay,
            allow_with_prefix,
        }
    }

    /// Whether this dial may fragment. An OSSH prefix suppresses the fragmentor
    /// unless `OSSHPrefixEnableFragmentor` turns it back on, as the reference does.
    pub(crate) fn may_fragment(&self, protocol: &str, prefixed: bool) -> bool {
        if self.max_total == 0 || (prefixed && !self.allow_with_prefix) {
            return false;
        }
        self.protocols.is_empty()
            || self
                .protocols
                .iter()
                .any(|name| name.eq_ignore_ascii_case(protocol))
    }

    /// How many leading bytes this dial fragments, zero when the coin fails.
    fn plan(&self) -> usize {
        if !coin(self.probability) {
            return 0;
        }
        random_range(self.min_total, self.max_total)
    }

    /// One fragment size, never wider than what remains.
    fn write_size(&self, remaining: usize) -> usize {
        let low = self.min_write.min(remaining).max(1);
        let high = self.max_write.min(remaining).max(low);
        random_range(low, high)
    }

    /// A random pause between this dial's bounds.
    fn delay(&self) -> Duration {
        let low = duration_nanos(self.min_delay);
        let high = duration_nanos(self.max_delay).max(low);
        if high == low {
            return Duration::from_nanos(low);
        }
        Duration::from_nanos(low + random_below(high - low + 1))
    }
}

/// A duration in nanoseconds, saturating at the type limit.
fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// A random value in `0..bound`.
fn random_below(bound: u64) -> u64 {
    if bound <= 1 {
        return 0;
    }
    u64::from_be_bytes(dial_random::<8>()) % bound
}

/// A random value in the inclusive range.
fn random_range(low: usize, high: usize) -> usize {
    if high <= low {
        return low;
    }
    low + usize::try_from(random_below(
        u64::try_from(high - low).unwrap_or(u64::MAX) + 1,
    ))
    .unwrap_or(0)
}

/// One random coin with the given probability.
fn coin(probability: f64) -> bool {
    if probability <= 0.0 {
        return false;
    }
    if probability >= 1.0 {
        return true;
    }
    f64::from(u16::from_be_bytes(dial_random::<2>())) / 65_536.0 < probability
}

struct State {
    bytes_to_fragment: i64,
    fragmented: usize,
}

/// A TCP stream whose initial writes are split and paced.
pub(crate) struct FragmentStream {
    socket: TcpStream,
    config: Arc<Fragmentor>,
    state: Arc<Mutex<State>>,
}

impl FragmentStream {
    /// Wrap a dial in the fragmentor's first-write plan.
    pub(crate) fn new(socket: TcpStream, config: Fragmentor) -> Self {
        Self {
            socket,
            config: Arc::new(config),
            state: Arc::new(Mutex::new(State {
                bytes_to_fragment: -1,
                fragmented: 0,
            })),
        }
    }

    /// Clone the socket and its remaining fragment plan.
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
            config: Arc::clone(&self.config),
            state: Arc::clone(&self.state),
        })
    }

    /// The socket beneath the fragment writes.
    pub(crate) fn get_ref(&self) -> &TcpStream {
        &self.socket
    }

    /// Forward the read timeout to the socket.
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    /// Forward the write timeout to the socket.
    pub(crate) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_write_timeout(timeout)
    }

    /// Forward the shutdown to the socket.
    pub(crate) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.socket.shutdown(how)
    }
}

impl ferrox_core::tls::RecordAlignment for FragmentStream {}

impl Read for FragmentStream {
    /// Reads pass straight through; only writes are fragmented.
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.socket.read(buffer)
    }
}

impl Write for FragmentStream {
    /// Write the planned leading bytes in fragments, then the rest ordinarily.
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("psiphon fragmentor lock"))?;
        if state.bytes_to_fragment < 0 {
            state.bytes_to_fragment = i64::try_from(self.config.plan()).unwrap_or(i64::MAX);
        }
        if state.fragmented >= usize::try_from(state.bytes_to_fragment).unwrap_or(usize::MAX) {
            return self.socket.write(buffer);
        }
        let mut written = 0;
        while written < buffer.len() {
            std::thread::sleep(self.config.delay());
            let size = self.config.write_size(buffer.len() - written);
            let end = written + size;
            match self.socket.write(&buffer[written..end]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "psiphon fragmentor wrote zero bytes",
                    ));
                }
                Ok(count) => {
                    written += count;
                    state.fragmented += count;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) if written > 0 => return Ok(written),
                Err(error) => return Err(error),
            }
            let target = usize::try_from(state.bytes_to_fragment).unwrap_or(usize::MAX);
            if state.fragmented >= target {
                break;
            }
        }
        Ok(written)
    }

    /// Flatten the slices once, then use the ordinary write path.
    fn write_vectored(&mut self, buffers: &[io::IoSlice<'_>]) -> io::Result<usize> {
        if buffers.len() == 1 {
            return self.write(&buffers[0]);
        }
        let mut all = Vec::new();
        for buffer in buffers {
            all.extend_from_slice(buffer);
        }
        self.write(&all)
    }

    /// Flush the underlying socket.
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

/// A stream that splits the first TLS record carrying a `ClientHello` at the
/// start of the SNI host name, writing the two records separately.
pub(crate) struct TlsHelloFragmentor<S> {
    inner: S,
    fragment: bool,
    sent: bool,
}

impl<S> TlsHelloFragmentor<S> {
    /// Wrap a stream, fragmenting its first `ClientHello` when `fragment` is set.
    pub(crate) fn new(inner: S, fragment: bool) -> Self {
        Self {
            inner,
            fragment,
            sent: false,
        }
    }

    /// The stream beneath the fragment writes.
    pub(crate) fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: Read + Write> Read for TlsHelloFragmentor<S> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl<S: Read + Write> Write for TlsHelloFragmentor<S> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.fragment && !self.sent {
            self.sent = true;
            let (first, second) = split_client_hello(buffer)?;
            self.inner.write_all(&first)?;
            self.inner.write_all(&second)?;
            return Ok(buffer.len());
        }
        self.inner.write(buffer)
    }

    fn write_vectored(&mut self, buffers: &[io::IoSlice<'_>]) -> io::Result<usize> {
        if self.fragment && !self.sent {
            let mut all = Vec::new();
            for buffer in buffers {
                all.extend_from_slice(buffer);
            }
            return self.write(&all);
        }
        self.inner.write_vectored(buffers)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<S: Read + Write + ferrox_core::tls::RecordAlignment> ferrox_core::tls::RecordAlignment
    for TlsHelloFragmentor<S>
{
    fn engage_record_alignment(&mut self) {
        self.inner.engage_record_alignment();
    }

    fn disarm_record_alignment(&mut self) {
        self.inner.disarm_record_alignment();
    }

    fn write_all_slices(&mut self, parts: &[&[u8]]) -> io::Result<()>
    where
        Self: Write,
    {
        if self.fragment && !self.sent {
            let mut all = Vec::new();
            for part in parts {
                all.extend_from_slice(part);
            }
            return self.write_all(&all);
        }
        self.inner.write_all_slices(parts)
    }
}

/// Split the first TLS record at the start of the SNI host name, wrapping each
/// half in its own record of the same content type and version.
fn split_client_hello(record: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let split = client_hello_sni_start(record).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "psiphon tls fragmentor: expected a ClientHello with SNI",
        )
    })?;
    let payload = record.get(5..).unwrap_or_default();
    let first = tls_record(
        record[0],
        [record[1], record[2]],
        payload.get(..split - 5).unwrap_or_default(),
    );
    let second = tls_record(
        record[0],
        [record[1], record[2]],
        payload.get(split - 5..).unwrap_or_default(),
    );
    Ok((first, second))
}

fn tls_record(content_type: u8, version: [u8; 2], payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + payload.len());
    record.push(content_type);
    record.extend_from_slice(&version);
    record.extend_from_slice(
        &u16::try_from(payload.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    record.extend_from_slice(payload);
    record
}

/// The offset in `record` of the SNI host name, or `None` when the record is
/// not a complete `ClientHello` carrying one.
fn client_hello_sni_start(record: &[u8]) -> Option<usize> {
    if record.len() < 5 || record[0] != 0x16 {
        return None;
    }
    let record_len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    if record.len() != 5 + record_len {
        return None;
    }
    let payload = record.get(5..)?;
    if payload.first().copied()? != 0x01 {
        return None;
    }
    let handshake = payload.get(1..4)?;
    let handshake_len = (usize::from(handshake[0]) << 16)
        | (usize::from(handshake[1]) << 8)
        | usize::from(handshake[2]);
    if handshake_len + 4 != payload.len() {
        return None;
    }
    let mut at = 4;
    if payload.get(at..at + 2)? != [0x03, 0x03].as_slice() {
        return None;
    }
    at += 2;
    at += 32;
    let session = usize::from(*payload.get(at)?);
    at += 1;
    if session > 32 {
        return None;
    }
    at += session;
    let ciphers = usize::from(u16::from_be_bytes([
        *payload.get(at)?,
        *payload.get(at + 1)?,
    ]));
    at += 2;
    if ciphers < 2 || ciphers % 2 != 0 {
        return None;
    }
    at += ciphers;
    let compression = usize::from(*payload.get(at)?);
    at += 1;
    if compression == 0 {
        return None;
    }
    at += compression;
    let extensions = usize::from(u16::from_be_bytes([
        *payload.get(at)?,
        *payload.get(at + 1)?,
    ]));
    at += 2;
    let end = at.checked_add(extensions)?;
    if end > payload.len() {
        return None;
    }
    while at + 4 <= end {
        let kind = u16::from_be_bytes([payload[at], payload[at + 1]]);
        let len = usize::from(u16::from_be_bytes([payload[at + 2], payload[at + 3]]));
        at += 4;
        if at + len > end {
            return None;
        }
        if kind == 0 {
            let list = usize::from(u16::from_be_bytes([payload[at], payload[at + 1]]));
            if len < 5 || list + 2 != len {
                return None;
            }
            if payload[at + 2] != 0 {
                return None;
            }
            let name = usize::from(u16::from_be_bytes([payload[at + 3], payload[at + 4]]));
            if name == 0 || name + 5 != len {
                return None;
            }
            return Some(5 + at + 5);
        }
        at += len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// A connected loopback pair for fragment tests.
    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let client = TcpStream::connect(address).expect("client");
        let (server, _) = listener.accept().expect("server");
        (client, server)
    }

    #[test]
    /// A zero total disables fragmentation.
    fn a_zero_total_never_fragments() {
        let config = Fragmentor::default();
        assert!(!config.may_fragment("OSSH", false));
    }

    #[test]
    /// A prefixed dial fragments only when the switch allows it.
    fn a_prefixed_dial_needs_the_switch() {
        let mut config = Fragmentor::new(
            1.0,
            Vec::new(),
            4,
            8,
            1,
            2,
            Duration::ZERO,
            Duration::ZERO,
            false,
        );
        assert!(!config.may_fragment("OSSH", true));
        config.allow_with_prefix = true;
        assert!(config.may_fragment("OSSH", true));
        assert!(config.may_fragment("SSH", false));
    }

    #[test]
    /// A protocol list fragments only the protocols it names.
    fn a_protocol_limit_names_only_its_protocols() {
        let config = Fragmentor::new(
            1.0,
            vec!["OSSH".to_owned()],
            4,
            8,
            1,
            2,
            Duration::ZERO,
            Duration::ZERO,
            true,
        );
        assert!(config.may_fragment("ossh", false));
        assert!(!config.may_fragment("TLS-OSSH", false));
    }

    #[test]
    /// Fragmentation changes the writes, not the bytes or their order.
    fn the_bytes_and_their_order_are_unchanged() {
        let (mut client, mut server) = pair();
        let config = Fragmentor::new(
            1.0,
            Vec::new(),
            64,
            64,
            1,
            3,
            Duration::ZERO,
            Duration::ZERO,
            true,
        );
        let mut stream = FragmentStream::new(client.try_clone().expect("clone"), config);
        let payload: Vec<u8> = (0..200u8).collect();
        stream.write_all(&payload).expect("write");
        drop(stream);
        let mut received = vec![0u8; payload.len()];
        server.read_exact(&mut received).expect("read");
        assert_eq!(received, payload);
        client.write_all(b"x").ok();
    }

    #[test]
    /// A failed coin leaves the dial as one ordinary write.
    fn a_failed_coin_is_a_plain_write() {
        let config = Fragmentor::new(
            0.0,
            Vec::new(),
            64,
            64,
            1,
            1,
            Duration::ZERO,
            Duration::ZERO,
            true,
        );
        assert_eq!(config.plan(), 0);
    }

    /// A minimal `ClientHello`, with one SNI name when asked.
    fn client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(name) = sni {
            let mut data = Vec::new();
            data.extend_from_slice(&u16::try_from(name.len() + 3).expect("list").to_be_bytes());
            data.push(0);
            data.extend_from_slice(&u16::try_from(name.len()).expect("name").to_be_bytes());
            data.extend_from_slice(name.as_bytes());
            extensions.extend_from_slice(&0u16.to_be_bytes());
            extensions.extend_from_slice(&u16::try_from(data.len()).expect("data").to_be_bytes());
            extensions.extend_from_slice(&data);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&u16::try_from(extensions.len()).expect("ext").to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut payload = Vec::new();
        payload.push(1);
        payload.extend_from_slice(&u32::try_from(body.len()).expect("body").to_be_bytes()[1..]);
        payload.extend_from_slice(&body);
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&u16::try_from(payload.len()).expect("payload").to_be_bytes());
        record.extend_from_slice(&payload);
        record
    }

    #[test]
    /// The split leaves the SNI host name at the head of the second record.
    fn a_client_hello_splits_at_the_sni_host_name() {
        let record = client_hello(Some("example.com"));
        let (first, second) = split_client_hello(&record).expect("split");
        let mut joined = Vec::new();
        joined.extend_from_slice(&first[5..]);
        joined.extend_from_slice(&second[5..]);
        assert_eq!(joined, record[5..]);
        assert_eq!(first[0], 0x16);
        assert_eq!(second[0], 0x16);
        assert!(second[5..].starts_with(b"example.com"));
    }

    #[test]
    /// The fragmentor writes the two records once, then passes writes through.
    fn the_fragmentor_writes_two_records_once() {
        let record = client_hello(Some("example.com"));
        let mut inner = std::io::Cursor::new(Vec::new());
        {
            let mut stream = TlsHelloFragmentor::new(&mut inner, true);
            stream.write_all(&record).expect("write");
            stream.write_all(b"next").expect("next");
        }
        let (first, second) = split_client_hello(&record).expect("split");
        let mut expected = first;
        expected.extend_from_slice(&second);
        expected.extend_from_slice(b"next");
        assert_eq!(inner.get_ref(), &expected);
    }

    #[test]
    /// A disabled fragmentor leaves the record and the writes untouched.
    fn a_disabled_fragmentor_is_a_plain_write() {
        let record = client_hello(Some("example.com"));
        let mut inner = std::io::Cursor::new(Vec::new());
        {
            let mut stream = TlsHelloFragmentor::new(&mut inner, false);
            stream.write_all(&record).expect("write");
        }
        assert_eq!(inner.get_ref(), &record);
    }

    #[test]
    /// A hello without SNI is refused rather than sent unsplit.
    fn a_hello_without_sni_is_refused() {
        let record = client_hello(None);
        assert!(split_client_hello(&record).is_err());
    }
}
