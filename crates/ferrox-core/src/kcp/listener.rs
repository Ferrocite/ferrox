use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread;
use std::time::Duration;

use super::config::Config;

/// The room a datagram is received into: the largest a KCP datagram can be.
const DATAGRAM_MAX: usize = 65_536;

use super::connection::{ConnMetadata, Connection};
use super::mask::Encoder;
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

/// The room a datagram is received into: the receive writes the bytes it got and the
/// rest of the room is never read, so the room is not zeroed first.
#[allow(
    clippy::uninit_vec,
    reason = "the room is a receive target: the receive writes the bytes it reports and no path reads a byte that was not written"
)]
fn datagram_room() -> Vec<u8> {
    let mut buf = Vec::with_capacity(DATAGRAM_MAX);
    // SAFETY: every path hands the room to a receive that initialises the bytes it reports, and no path reads a byte that was not written.
    unsafe { buf.set_len(DATAGRAM_MAX) };
    buf
}

/// Every conversation to one remote shares one UDP socket and one feed thread; the server keys
/// sessions by `(source, conversation)`, so the source port is the outbound's, not the flow's.
struct ClientSocket {
    sock: UdpSocket,
    local: SocketAddr,
    remote: SocketAddr,
    config: Config,
    sessions: Mutex<HashMap<u16, Weak<Connection>>>,
    live: AtomicU16,
}

static CLIENTS: Mutex<Vec<Arc<ClientSocket>>> = Mutex::new(Vec::new());

fn client_for(remote: SocketAddr, config: &Config) -> io::Result<Arc<ClientSocket>> {
    let mut clients = CLIENTS.lock().unwrap();
    if let Some(client) = clients
        .iter()
        .find(|client| client.remote == remote && &client.config == config)
    {
        client.live.fetch_add(1, Ordering::SeqCst);
        return Ok(Arc::clone(client));
    }
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(remote)?;
    let local = sock.local_addr()?;
    sock.set_read_timeout(Some(Duration::from_millis(50)))?;
    let client = Arc::new(ClientSocket {
        sock,
        local,
        remote,
        config: config.clone(),
        sessions: Mutex::new(HashMap::new()),
        live: AtomicU16::new(1),
    });
    let weak = Arc::downgrade(&client);
    thread::Builder::new()
        .name("kcp-feed".to_owned())
        .spawn(move || feed_client(&weak))
        .map_err(|e| io::Error::other(format!("kcp feed thread: {e}")))?;
    clients.push(Arc::clone(&client));
    Ok(client)
}

fn release_client(client: &Arc<ClientSocket>, conv: u16) {
    client.sessions.lock().unwrap().remove(&conv);
    let mut clients = CLIENTS.lock().unwrap();
    if client.live.fetch_sub(1, Ordering::SeqCst) == 1 {
        clients.retain(|held| !Arc::ptr_eq(held, client));
    }
}

fn feed_client(weak: &Weak<ClientSocket>) {
    let mut buf = datagram_room();
    let mut segs: Vec<Segment> = Vec::new();
    loop {
        let Some(client) = weak.upgrade() else {
            break;
        };
        match client.sock.recv(&mut buf) {
            Ok(n) => {
                let Some(framed) = client.config.mask.decode_in_place(&mut buf[..n]) else {
                    continue; // fails the mask's own check: the reference drops the packet
                };
                let Some((conv, _)) = peek_conversation(framed) else {
                    continue;
                };
                let session = client
                    .sessions
                    .lock()
                    .unwrap()
                    .get(&conv)
                    .and_then(Weak::upgrade);
                let Some(session) = session else {
                    continue;
                };
                parse_segments(framed, &mut segs, &|| session.take_payload());
                if !segs.is_empty() {
                    session.input(&mut segs);
                }
            }
            Err(ref e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
}

pub fn dial(addr: SocketAddr, config: Config, conv: u16) -> io::Result<Arc<Connection>> {
    let client = client_for(addr, &config)?;
    let sock_w = match client.sock.try_clone() {
        Ok(sock) => sock,
        Err(e) => {
            release_client(&client, conv);
            return Err(e);
        }
    };
    // A masked dial wraps the socket writer in the encoder; an unmasked dial keeps the previous closure untouched.
    let writer: Writer = if config.mask.is_empty() {
        Box::new(move |data: &[u8]| sock_w.send(data).map(|_| ()))
    } else {
        let mut enc = Encoder::new(&config.mask);
        Box::new(move |data: &[u8]| {
            let Some(wire) = enc.encode(data) else {
                return Err(io::Error::other("no entropy for the mask"));
            };
            sock_w.send(wire).map(|_| ())
        })
    };
    let closer_client = Arc::clone(&client);
    let closer = Box::new(move || release_client(&closer_client, conv));
    let connection = Connection::new(
        ConnMetadata {
            local: client.local,
            remote: addr,
            conversation: conv,
        },
        writer,
        closer,
        config,
    );
    client
        .sessions
        .lock()
        .unwrap()
        .insert(conv, Arc::downgrade(&connection));
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
            let mut buf = datagram_room();
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
                        // The mask strips in place before the conversation is read: a datagram failing the hash or the tag never reaches the session table.
                        let Some(framed) = inner.config.mask.decode_in_place(&mut buf[..n]) else {
                            continue;
                        };
                        let Some((conv, terminates)) = peek_conversation(framed) else {
                            continue;
                        };
                        let key = (src, conv);
                        let existing = inner.sessions.lock().unwrap().get(&key).cloned();
                        if let Some(session) = existing {
                            parse_segments(framed, &mut segs, &|| session.take_payload());
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
                        let writer: Writer = if inner.config.mask.is_empty() {
                            Box::new(move |data: &[u8]| sock_w.send_to(data, src).map(|_| ()))
                        } else {
                            let mut enc = Encoder::new(&inner.config.mask);
                            Box::new(move |data: &[u8]| {
                                let Some(wire) = enc.encode(data) else {
                                    return Err(io::Error::other("no entropy for the mask"));
                                };
                                sock_w.send_to(wire, src).map(|_| ())
                            })
                        };
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
                            inner.config.clone(),
                        );
                        inner
                            .sessions
                            .lock()
                            .unwrap()
                            .insert(key, Arc::clone(&session));
                        parse_segments(framed, &mut segs, &|| session.take_payload());
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
    use std::time::Instant;

    use super::*;
    use crate::kcp::connection::ConnMetadata;
    use crate::kcp::mask::{HeaderKind, Mask, Spec};

    #[cfg_attr(miri, ignore = "binds a loopback UDP socket")]
    /// The room a datagram is received into is not zeroed: the receive writes the bytes
    /// it got and the rest of the room is never read. The counting allocator's `zeroed`
    /// counter is the witness.
    #[test]
    fn the_datagram_room_is_not_zeroed() {
        let (room, counts) = crate::alloc_count::measure(datagram_room);
        assert_eq!(counts.zeroed, 0, "the room is not zeroed");
        assert_eq!(counts.allocs, 1, "the room is one buffer");
        assert_eq!(room.len(), DATAGRAM_MAX, "and it is the whole datagram");
    }

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

    fn masked_config(specs: &[Spec]) -> Config {
        Config {
            mask: Mask::from_spec(specs).expect("mask builds"),
            ..Config::default()
        }
    }

    /// One write/read echo over a masked session, in-process on one thread:
    /// the listener's own receive thread establishes the session before
    /// `accept`, so the sequence needs no handshake helper.
    fn echo_round_trip(specs: &[Spec]) {
        let config = masked_config(specs);
        let listener = Listener::bind(([127, 0, 0, 1], 0).into(), config.clone()).expect("bind");
        let conn = dial(listener.local_addr(), config, fresh_conversation()).expect("dial");
        let payload = b"the quick brown kcp";
        conn.write(payload).expect("write");
        let session = listener.accept().expect("masked session accepted");
        let mut buf = [0u8; 256];
        session.set_read_deadline(Instant::now() + Duration::from_secs(5));
        let n = session.read(&mut buf).expect("server read");
        session.write(&buf[..n]).expect("server echo");
        conn.set_read_deadline(Instant::now() + Duration::from_secs(5));
        let m = conn.read(&mut buf).expect("client echo");
        assert_eq!(&buf[..m], payload);
        listener.close();
    }

    #[cfg_attr(miri, ignore = "binds loopback UDP sockets")]
    #[test]
    fn every_mask_family_echoes_over_loopback() {
        let families: [&[Spec]; 9] = [
            &[Spec::Original],
            &[Spec::Header(HeaderKind::Srtp)],
            &[Spec::Header(HeaderKind::Wechat)],
            &[Spec::Header(HeaderKind::Dtls)],
            &[Spec::Header(HeaderKind::Utp)],
            &[Spec::Header(HeaderKind::WireGuard)],
            &[Spec::HeaderDns {
                domain: "www.baidu.com".to_owned(),
            }],
            &[
                Spec::Header(HeaderKind::Srtp),
                Spec::Aes {
                    password: "chain-pass".to_owned(),
                },
            ],
            &[
                Spec::Original,
                Spec::Header(HeaderKind::Dtls),
                Spec::Aes {
                    password: "p".to_owned(),
                },
            ],
        ];
        for specs in families {
            echo_round_trip(specs);
        }
    }

    #[cfg_attr(miri, ignore = "binds loopback UDP sockets")]
    #[test]
    fn a_raw_dial_never_establishes_a_masked_session() {
        // The framer's bytes under no mask fail the `original` hash check at the socket, so the session table stays empty.
        let config = masked_config(&[Spec::Original]);
        let listener = Listener::bind(([127, 0, 0, 1], 0).into(), config).expect("bind");
        let raw = dial(
            listener.local_addr(),
            Config::default(),
            fresh_conversation(),
        )
        .expect("dial");
        raw.write(b"unmasked").expect("write");
        let (tx, rx) = mpsc::channel();
        let probe = Listener {
            inner: Arc::clone(&listener.inner),
        };
        thread::spawn(move || {
            let _ = tx.send(probe.accept().is_ok());
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(700)).is_err(),
            "a raw dial must not reach a masked listener's accept queue"
        );
        listener.close();
    }

    #[cfg_attr(miri, ignore = "binds loopback UDP sockets")]
    #[test]
    fn the_wrong_password_echoes_nothing() {
        let server = masked_config(&[Spec::Aes {
            password: "right".to_owned(),
        }]);
        let listener = Listener::bind(([127, 0, 0, 1], 0).into(), server).expect("bind");
        let client = masked_config(&[Spec::Aes {
            password: "wrong".to_owned(),
        }]);
        let conn = dial(listener.local_addr(), client, fresh_conversation()).expect("dial");
        conn.write(b"secret").expect("write");
        let (tx, rx) = mpsc::channel();
        let probe = Listener {
            inner: Arc::clone(&listener.inner),
        };
        thread::spawn(move || {
            let _ = tx.send(probe.accept().is_ok());
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(700)).is_err(),
            "a tag that fails the key must be dropped unread"
        );
        listener.close();
    }

    #[cfg_attr(miri, ignore = "binds loopback UDP sockets, sleeps and joins threads")]
    #[test]
    fn the_wire_under_a_masked_session_carries_the_mask() {
        // A plain UDP relay records the first datagram of a masked session: it must open under the chain, reveal the conversation id, and the session must still echo through it.
        let mask = Mask::from_spec(&[
            Spec::Header(HeaderKind::Srtp),
            Spec::Aes {
                password: "relay".to_owned(),
            },
        ])
        .expect("chain builds");
        let config = Config {
            mask: mask.clone(),
            ..Config::default()
        };
        let listener = Listener::bind(([127, 0, 0, 1], 0).into(), config.clone()).expect("bind");
        let server_addr = listener.local_addr();
        let relay = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("relay bind");
        let recorded: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let rec = Arc::clone(&recorded);
        let relay_sock = relay.try_clone().expect("clone");
        let stop = Arc::new(AtomicBool::new(false));
        let relay_stop = Arc::clone(&stop);
        thread::spawn(move || {
            relay_sock
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("timeout");
            let mut buf = datagram_room();
            let mut client: Option<SocketAddr> = None;
            while !relay_stop.load(Ordering::Relaxed) {
                let Ok((n, src)) = relay_sock.recv_from(&mut buf) else {
                    continue;
                };
                if src == server_addr {
                    if let Some(to) = client {
                        relay_sock.send_to(&buf[..n], to).ok();
                    }
                    continue;
                }
                client = Some(src);
                let mut slot = rec.lock().unwrap();
                if slot.is_none() {
                    *slot = Some(buf[..n].to_vec());
                }
                drop(slot);
                relay_sock.send_to(&buf[..n], server_addr).ok();
            }
        });
        let conv = fresh_conversation();
        let client =
            dial(relay.local_addr().expect("relay addr"), config, conv).expect("dial via relay");
        let payload = b"relay witness";
        client.write(payload).expect("write");
        let session = listener.accept().expect("session through the relay");
        let mut buf = [0u8; 256];
        session.set_read_deadline(Instant::now() + Duration::from_secs(5));
        let n = session.read(&mut buf).expect("server read");
        session.write(&buf[..n]).expect("server echo");
        client.set_read_deadline(Instant::now() + Duration::from_secs(5));
        let m = client.read(&mut buf).expect("echo back through the relay");
        assert_eq!(&buf[..m], payload);
        // The recorded datagram: srtp counter outermost, opening to a segment carrying this session's conversation id.
        let wire = recorded
            .lock()
            .unwrap()
            .clone()
            .expect("relay saw a datagram");
        assert_eq!(&wire[..4], &[0, 0, 0, 1], "srtp outside on the wire");
        let mut copy = wire.clone();
        let segs = mask
            .decode_in_place(&mut copy)
            .expect("chain opens the wire");
        assert_eq!(
            u16::from_be_bytes([segs[0], segs[1]]),
            conv,
            "the decoded frame is the session's own segment"
        );
        // 4 (srtp) + 12 (nonce) + 16 (tag) of fixed overhead over the segment.
        assert_eq!(wire.len(), segs.len() + 32, "the mask's whole overhead");
        stop.store(true, Ordering::Relaxed);
        listener.close();
    }
}
