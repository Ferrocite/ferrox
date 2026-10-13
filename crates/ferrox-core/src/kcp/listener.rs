use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use super::config::Config;

use super::connection::{ConnMetadata, Connection, State};
use super::segment::{read_segment, Command, Segment};

type Writer = Box<dyn FnMut(&[u8]) -> io::Result<()> + Send>;

static NEXT_CONVERSATION: AtomicU16 = AtomicU16::new(1);

fn next_conversation() -> u16 {
    NEXT_CONVERSATION.fetch_add(1, Ordering::Relaxed).max(1)
}

fn parse_segments(buf: &[u8], out: &mut Vec<Segment>, take: &super::segment::TakePayload<'_>) {
    out.clear();
    let mut rest = buf;
    while let Some((seg, tail)) = read_segment(rest, take) {
        out.push(seg);
        rest = tail;
    }
}

/// The conversation a datagram belongs to, from its first four bytes, so the accept loop has a session to lend payload buffers from before parsing.
fn peek_conversation(buf: &[u8]) -> Option<(u16, bool)> {
    if buf.len() < 4 {
        return None;
    }
    let conv = u16::from_be_bytes(buf[0..2].try_into().ok()?);
    Some((conv, buf[2] == Command::Terminate.to_byte()))
}

fn feed(sock: &UdpSocket, conn: &Connection) {
    let mut buf = vec![0u8; 65536];
    let mut segs: Vec<Segment> = Vec::new();
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                parse_segments(&buf[..n], &mut segs, &|| conn.take_payload());
                conn.input(&mut segs);
            }
            Err(ref e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if conn.state() == State::Terminated {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

pub fn dial(addr: SocketAddr, config: Config, conv: u16) -> io::Result<Arc<Connection>> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(addr)?;
    let local = sock.local_addr()?;
    let sock_w = sock.try_clone()?;
    let writer = Box::new(move |data: &[u8]| sock_w.send(data).map(|_| ()));
    let sock_c = sock.try_clone()?;
    let closer = Box::new(move || drop(sock_c));
    let connection = Connection::new(
        ConnMetadata {
            local,
            remote: addr,
            conversation: conv,
        },
        writer,
        closer,
        config,
    );
    let sock_r = sock.try_clone()?;
    sock_r.set_read_timeout(Some(Duration::from_millis(50)))?;
    let c2 = Arc::clone(&connection);
    thread::spawn(move || feed(&sock_r, &c2));
    Ok(connection)
}

#[must_use]
pub fn fresh_conversation() -> u16 {
    next_conversation()
}

pub struct Listener {
    inner: Arc<ListenerInner>,
}

struct ListenerInner {
    sessions: Mutex<HashMap<(SocketAddr, u16), Arc<Connection>>>,
    ready: Mutex<VecDeque<Arc<Connection>>>,
    ready_cv: Condvar,
    config: Config,
    closed: AtomicBool,
    addr: SocketAddr,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener").finish_non_exhaustive()
    }
}

impl Listener {
    pub fn bind(addr: SocketAddr, config: Config) -> io::Result<Self> {
        let sock = UdpSocket::bind(addr)?;
        let local = sock.local_addr()?;
        let inner = Arc::new(ListenerInner {
            sessions: Mutex::new(HashMap::new()),
            ready: Mutex::new(VecDeque::new()),
            ready_cv: Condvar::new(),
            config,
            closed: AtomicBool::new(false),
            addr: local,
        });
        let sock_r = sock.try_clone()?;
        sock_r.set_read_timeout(Some(Duration::from_millis(50)))?;
        let weak = Arc::downgrade(&inner);
        thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            let mut segs: Vec<Segment> = Vec::new();
            loop {
                {
                    let Some(inner) = weak.upgrade() else { break };
                    if inner.closed.load(Ordering::SeqCst) {
                        break;
                    }
                }
                match sock_r.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        let Some(inner) = weak.upgrade() else { break };
                        let Some((conv, terminates)) = peek_conversation(&buf[..n]) else {
                            continue;
                        };
                        let key = (src, conv);
                        let existing = inner.sessions.lock().unwrap().get(&key).cloned();
                        if let Some(session) = existing {
                            parse_segments(&buf[..n], &mut segs, &|| session.take_payload());
                            if segs.is_empty() {
                                continue;
                            }
                            session.input(&mut segs);
                            continue;
                        }
                        if terminates {
                            continue;
                        }
                        let Ok(sock_w) = sock_r.try_clone() else {
                            continue;
                        };
                        let writer: Writer =
                            Box::new(move |data: &[u8]| sock_w.send_to(data, src).map(|_| ()));
                        let sessions_slot = Arc::downgrade(&inner);
                        let closer: Box<dyn FnOnce() + Send> = Box::new(move || {
                            if let Some(inner) = sessions_slot.upgrade() {
                                inner.sessions.lock().unwrap().remove(&key);
                            }
                        });
                        let local = inner.addr;
                        let session = Connection::new(
                            ConnMetadata {
                                local,
                                remote: src,
                                conversation: conv,
                            },
                            writer,
                            closer,
                            inner.config,
                        );
                        inner
                            .sessions
                            .lock()
                            .unwrap()
                            .insert(key, Arc::clone(&session));
                        parse_segments(&buf[..n], &mut segs, &|| session.take_payload());
                        if segs.is_empty() {
                            inner.sessions.lock().unwrap().remove(&key);
                            continue;
                        }
                        session.input(&mut segs);
                        inner.ready.lock().unwrap().push_back(session);
                        inner.ready_cv.notify_all();
                    }
                    Err(ref e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => break,
                }
            }
        });
        Ok(Self { inner })
    }

    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.addr
    }

    pub fn accept(&self) -> io::Result<Arc<Connection>> {
        let mut ready = self.inner.ready.lock().unwrap();
        loop {
            if let Some(conn) = ready.pop_front() {
                return Ok(conn);
            }
            if self.inner.closed.load(Ordering::SeqCst) {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "listener closed"));
            }
            ready = self.inner.ready_cv.wait(ready).unwrap();
        }
    }

    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        let sessions = std::mem::take(&mut *self.inner.sessions.lock().unwrap());
        for (_, conn) in sessions {
            conn.terminate();
        }
        self.inner.ready_cv.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;
    use crate::kcp::connection::ConnMetadata;

    #[cfg_attr(miri, ignore = "binds a loopback UDP socket")]
    #[test]
    fn close_returns_while_a_session_is_registered() {
        let listener = Listener::bind(([127, 0, 0, 1], 0).into(), Config::default()).expect("bind");
        let local = listener.local_addr();
        let key = (local, 1);
        let slot = Arc::downgrade(&listener.inner);
        let closer: Box<dyn FnOnce() + Send> = Box::new(move || {
            if let Some(inner) = slot.upgrade() {
                inner.sessions.lock().unwrap().remove(&key);
            }
        });
        let session = Connection::new(
            ConnMetadata {
                local,
                remote: local,
                conversation: 1,
            },
            Box::new(|_| Ok(())),
            closer,
            Config::default(),
        );
        listener
            .inner
            .sessions
            .lock()
            .unwrap()
            .insert(key, Arc::clone(&session));

        let (done, seen) = mpsc::channel();
        thread::spawn(move || {
            listener.close();
            let _ = done.send(());
        });
        assert!(
            seen.recv_timeout(Duration::from_secs(5)).is_ok(),
            "close did not return: it held the session lock across terminate"
        );
    }
}
