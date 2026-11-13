use std::io::{self, Read};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// A read source whose clock can be re-armed for one read, so a handshake can hold a
/// single deadline across every read it makes instead of restarting a per-read timeout.
pub trait ReadClock: Read {
    fn arm(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl ReadClock for std::net::TcpStream {
    fn arm(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)
    }
}

/// One absolute deadline shared by the reader a handshake reads through.
#[derive(Clone, Default)]
pub struct HandshakeDeadline(Arc<Mutex<Option<Instant>>>);

impl HandshakeDeadline {
    pub fn begin(budget: Duration) -> Self {
        Self(Arc::new(Mutex::new(Some(Instant::now() + budget))))
    }

    fn gate(&self) -> MutexGuard<'_, Option<Instant>> {
        self.0.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    pub fn end(&self) {
        *self.gate() = None;
    }
}

/// Reads never wait past the shared deadline: each read is clocked to the time that is left,
/// and a deadline that has passed fails the read instead of arming another clock.
pub struct DeadlineReader<R> {
    reader: R,
    deadline: HandshakeDeadline,
}

impl<R: ReadClock> DeadlineReader<R> {
    pub fn new(reader: R, deadline: HandshakeDeadline) -> Self {
        Self { reader, deadline }
    }

    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl<R: ReadClock> Read for DeadlineReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let at = *self.deadline.gate();
        if let Some(at) = at {
            let left = at.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "xmc: handshake deadline passed",
                ));
            }
            self.reader.arm(Some(left))?;
        }
        self.reader.read(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Stalled {
        armed: Arc<Mutex<Option<Duration>>>,
    }

    impl Read for Stalled {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    impl ReadClock for Stalled {
        fn arm(&self, timeout: Option<Duration>) -> io::Result<()> {
            *self.armed.lock().unwrap() = timeout;
            Ok(())
        }
    }

    #[test]
    fn a_read_past_the_deadline_never_arms_another_clock() {
        let armed = Arc::new(Mutex::new(None));
        let deadline = HandshakeDeadline::begin(Duration::from_millis(30));
        let mut reader = DeadlineReader::new(
            Stalled {
                armed: Arc::clone(&armed),
            },
            deadline.clone(),
        );
        let mut byte = [0u8; 1];
        let first = reader.read(&mut byte).unwrap_err();
        assert_eq!(first.kind(), io::ErrorKind::WouldBlock);
        let first_clock = armed.lock().unwrap().expect("the first read arms a clock");
        assert!(first_clock <= Duration::from_millis(30) && !first_clock.is_zero());

        std::thread::sleep(Duration::from_millis(40));
        let past = reader.read(&mut byte).unwrap_err();
        assert_eq!(past.kind(), io::ErrorKind::TimedOut);
        assert!(armed.lock().unwrap().is_some(), "the clock is left alone");

        deadline.end();
        let after = reader.read(&mut byte).unwrap_err();
        assert_eq!(after.kind(), io::ErrorKind::WouldBlock);
    }
}
