//! xray's sender-side mux carrier pool: one underlayer per `MaxConcurrency` flows, a serialized
//! writer under it, and a demux that hands each session's replies to its own flow.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

use ferrox_core::mux::{self, NewTail};

/// The reference's `MaxConnection`: a carrier is retired after this many sessions and a fresh one
/// dialed for the sessions that follow, while the flows it already carries drain.
pub(crate) const LIFETIME: usize = 1024;

/// A carrier's two halves and the close that tears its socket down.
pub(crate) struct Uplink {
    pub(crate) read: Box<dyn Read + Send>,
    pub(crate) write: Box<dyn Write + Send>,
    pub(crate) close: Arc<dyn Fn() + Send + Sync>,
}

/// What one demuxed frame hands its flow.
pub(crate) struct Msg {
    pub(crate) data: Vec<u8>,
    pub(crate) end: bool,
}

/// One TCP session on a carrier.
pub(crate) struct Flow {
    carrier: Arc<Carrier>,
    id: u16,
    replies: Option<Receiver<Msg>>,
}

impl Flow {
    /// One `Keep` frame; the carrier's writer lock keeps concurrent sessions from interleaving.
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        self.carrier
            .frame(self.id, mux::Status::Keep, mux::DATA, None, None, data)
    }

    /// Hands the reply lane to the downlink worker while this handle keeps the writer.
    pub(crate) fn take_replies(&mut self) -> Option<Receiver<Msg>> {
        self.replies.take()
    }

    pub(crate) fn close(self) {
        self.carrier
            .frame(self.id, mux::Status::End, 0, None, None, &[]);
        self.carrier.release(self.id);
    }
}

/// One datagram session; its replies go to the association's own relay socket.
pub(crate) struct UdpFlow {
    carrier: Arc<Carrier>,
    id: u16,
    ended: Arc<std::sync::atomic::AtomicBool>,
}

impl UdpFlow {
    pub(crate) fn send(&self, target: &mux::Target<'_>, data: &[u8]) -> bool {
        if self.ended.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        self.carrier.frame(
            self.id,
            mux::Status::Keep,
            mux::DATA,
            Some(*target),
            None,
            data,
        )
    }

    pub(crate) fn close(self) {
        if !self.ended.load(std::sync::atomic::Ordering::Relaxed) {
            self.carrier
                .frame(self.id, mux::Status::End, 0, None, None, &[]);
        }
        self.carrier.release(self.id);
    }
}

pub(crate) type Deliver = Arc<dyn Fn(&[u8], Option<SocketAddr>) + Send + Sync>;

#[derive(Clone)]
enum Sink {
    Tcp(Sender<Msg>),
    Udp(Deliver, Arc<std::sync::atomic::AtomicBool>),
}

struct Writer {
    out: Box<dyn Write + Send>,
    header: Vec<u8>,
}

impl Writer {
    fn frame(
        &mut self,
        id: u16,
        status: mux::Status,
        options: u8,
        target: Option<mux::Target<'_>>,
        global_id: Option<[u8; mux::GLOBAL_ID]>,
        data: &[u8],
    ) -> bool {
        let frame = mux::Outgoing {
            id,
            status,
            options,
            target,
            global_id,
        };
        let at = frame.encode_header_into(&mut self.header);
        if options & mux::DATA == 0 {
            self.header.truncate(at);
            return crate::proxy::write_all_parts::<2>(&mut *self.out, &[&self.header[..], &[]])
                .is_ok();
        }
        frame.patch_payload_len(&mut self.header, at, data.len());
        crate::proxy::write_all_parts::<2>(&mut *self.out, &[&self.header[..], data]).is_ok()
    }
}

struct Table {
    ids: mux::Ids,
    sinks: HashMap<u16, Sink>,
    full: bool,
}

struct Carrier {
    write: Mutex<Writer>,
    table: Mutex<Table>,
    cap: usize,
    lifetime: usize,
    dead: std::sync::atomic::AtomicBool,
    close: Arc<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for Carrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Carrier")
            .field("cap", &self.cap)
            .field("dead", &self.dead())
            .finish_non_exhaustive()
    }
}

impl Carrier {
    fn new(uplink: Uplink, cap: usize, lifetime: usize) -> Arc<Self> {
        let carrier = Arc::new(Carrier {
            write: Mutex::new(Writer {
                out: uplink.write,
                header: Vec::with_capacity(64),
            }),
            table: Mutex::new(Table {
                ids: mux::Ids::new(0),
                sinks: HashMap::new(),
                full: false,
            }),
            cap: cap.max(1),
            lifetime: lifetime.max(1),
            dead: std::sync::atomic::AtomicBool::new(false),
            close: uplink.close,
        });
        let reader = Arc::clone(&carrier);
        std::thread::spawn(move || reader.demux(uplink.read));
        carrier
    }

    fn dead(&self) -> bool {
        self.dead.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn accepts(&self) -> bool {
        if self.dead() {
            return false;
        }
        let Ok(table) = self.table.lock() else {
            return false;
        };
        !table.full && table.ids.live() < self.cap
    }

    fn frame(
        &self,
        id: u16,
        status: mux::Status,
        options: u8,
        target: Option<mux::Target<'_>>,
        global_id: Option<[u8; mux::GLOBAL_ID]>,
        data: &[u8],
    ) -> bool {
        if self.dead() {
            return false;
        }
        let Ok(mut writer) = self.write.lock() else {
            return false;
        };
        writer.frame(id, status, options, target, global_id, data)
    }

    fn release(&self, id: u16) {
        let retire = {
            let Ok(mut table) = self.table.lock() else {
                return;
            };
            if table.sinks.remove(&id).is_none() {
                return;
            }
            table.ids.give_back();
            table.full && table.ids.live() == 0
        };
        if retire {
            self.retire();
        }
    }

    fn retire(&self) {
        if self.dead.swap(true, std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        (self.close)();
        let mut table = match self.table.lock() {
            Ok(table) => table,
            Err(poisoned) => poisoned.into_inner(),
        };
        for (_, sink) in table.sinks.drain() {
            if let Sink::Tcp(sender) = sink {
                let _ = sender.send(Msg {
                    data: Vec::new(),
                    end: true,
                });
            }
        }
    }

    fn demux(self: Arc<Self>, mut read: Box<dyn Read + Send>) {
        let mut buf: Vec<u8> = Vec::with_capacity(crate::proxy::READ_SLICE);
        let mut at = 0;
        loop {
            let mut progressed = false;
            loop {
                match mux::decode(&buf[at..], NewTail::Forward) {
                    Err(mux::Error::Short { .. }) => break,
                    Err(_) => {
                        self.retire();
                        return;
                    }
                    Ok((frame, used)) => {
                        at += used;
                        progressed = true;
                        self.dispatch(&frame);
                    }
                }
            }
            if progressed {
                if at >= buf.len() {
                    buf.clear();
                } else if at > 0 {
                    buf.drain(..at);
                }
                at = 0;
            }
            match crate::proxy::read_into_tail(&mut read, &mut buf) {
                Ok(0) => {
                    self.retire();
                    return;
                }
                Ok(_) => {}
                Err(error) if crate::proxy::is_timeout(&error) => {}
                Err(_) => {
                    self.retire();
                    return;
                }
            }
        }
    }

    fn dispatch(&self, frame: &mux::Incoming<'_>) {
        let sink = self
            .table
            .lock()
            .ok()
            .and_then(|table| table.sinks.get(&frame.id).cloned());
        let Some(sink) = sink else {
            return;
        };
        let target = frame.target.as_ref().and_then(sockaddr);
        match sink {
            Sink::Tcp(sender) => {
                let data = frame.data.unwrap_or(&[]);
                let _ = sender.send(Msg {
                    data: data.to_vec(),
                    end: frame.status == mux::Status::End,
                });
            }
            Sink::Udp(deliver, ended) => {
                if frame.status == mux::Status::End {
                    ended.store(true, std::sync::atomic::Ordering::Relaxed);
                    self.release(frame.id);
                    return;
                }
                if let Some(data) = frame.data {
                    deliver(data, target);
                }
            }
        }
    }
}

/// A frame target as the SOCKS reply header can name it; a name has no address to report.
fn sockaddr(target: &mux::Target<'_>) -> Option<SocketAddr> {
    match target.addr {
        ferrox_core::addr::Addr::V4(octets) => {
            Some(SocketAddr::from((Ipv4Addr::from(octets), target.port)))
        }
        ferrox_core::addr::Addr::V6(octets) => {
            Some(SocketAddr::from((Ipv6Addr::from(octets), target.port)))
        }
        ferrox_core::addr::Addr::Name(_) => None,
    }
}

pub(crate) struct Manager {
    open: Box<dyn Fn() -> Option<Uplink> + Send + Sync>,
    cap: usize,
    lifetime: usize,
    carriers: Mutex<Vec<Arc<Carrier>>>,
}

impl std::fmt::Debug for Manager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Manager")
            .field("cap", &self.cap)
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

impl Manager {
    pub(crate) fn new(
        cap: usize,
        open: impl Fn() -> Option<Uplink> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Self::with_lifetime(cap, LIFETIME, open)
    }

    pub(crate) fn with_lifetime(
        cap: usize,
        lifetime: usize,
        open: impl Fn() -> Option<Uplink> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Manager {
            open: Box::new(open),
            cap: cap.max(1),
            lifetime: lifetime.max(1),
            carriers: Mutex::new(Vec::new()),
        })
    }

    fn pick(&self) -> Option<Arc<Carrier>> {
        let mut carriers = self.carriers.lock().ok()?;
        carriers.retain(|carrier| !carrier.dead());
        for carrier in carriers.iter() {
            if carrier.accepts() {
                return Some(Arc::clone(carrier));
            }
        }
        let uplink = (self.open)()?;
        let carrier = Carrier::new(uplink, self.cap, self.lifetime);
        carriers.push(Arc::clone(&carrier));
        Some(carrier)
    }

    /// One TCP session, on the first carrier with room or on a fresh one.
    pub(crate) fn dial(&self, target: &mux::Target<'_>) -> Option<Flow> {
        let carrier = self.pick()?;
        let (replies, id) = {
            let mut table = carrier.table.lock().ok()?;
            if table.full || table.ids.live() >= carrier.cap {
                return None;
            }
            let id = table.ids.take().ok()?;
            if table.ids.opened() as usize >= carrier.lifetime {
                table.full = true;
            }
            let (send, replies) = channel();
            table.sinks.insert(id, Sink::Tcp(send));
            (replies, id)
        };
        if !carrier.frame(id, mux::Status::New, mux::DATA, Some(*target), None, &[]) {
            carrier.release(id);
            return None;
        }
        Some(Flow {
            carrier,
            id,
            replies: Some(replies),
        })
    }

    /// One datagram session; its `New` frame carries the first payload and the deliver closure
    /// writes every reply back to the association.
    pub(crate) fn udp(
        &self,
        target: &mux::Target<'_>,
        global_id: Option<&[u8; mux::GLOBAL_ID]>,
        payload: &[u8],
        deliver: Deliver,
    ) -> Option<UdpFlow> {
        let carrier = self.pick()?;
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let id = {
            let mut table = carrier.table.lock().ok()?;
            if table.full || table.ids.live() >= carrier.cap {
                return None;
            }
            let id = table.ids.take().ok()?;
            if table.ids.opened() as usize >= carrier.lifetime {
                table.full = true;
            }
            table
                .sinks
                .insert(id, Sink::Udp(deliver, Arc::clone(&ended)));
            id
        };
        if !carrier.frame(
            id,
            mux::Status::New,
            mux::DATA,
            Some(*target),
            global_id.copied(),
            payload,
        ) {
            carrier.release(id);
            return None;
        }
        Some(UdpFlow { carrier, id, ended })
    }

    #[cfg(all(test, unix))]
    pub(crate) fn carrier_count(&self) -> usize {
        self.carriers.lock().map_or(0, |carriers| carriers.len())
    }

    /// The staging header's base and capacity, both unchanged by a push/drain cycle only if the
    /// frame encoder reuses its buffer instead of reallocating it.
    #[cfg(all(test, unix))]
    pub(crate) fn staged_identity(&self) -> (usize, usize) {
        self.carriers.lock().map_or((0, 0), |carriers| {
            carriers
                .iter()
                .map(|carrier| {
                    carrier.write.lock().map_or((0, 0), |writer| {
                        (writer.header.as_ptr() as usize, writer.header.capacity())
                    })
                })
                .max()
                .unwrap_or((0, 0))
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn target() -> mux::Target<'static> {
        mux::Target {
            network: mux::Network::Tcp,
            port: 80,
            addr: ferrox_core::addr::Addr::V4([127, 0, 0, 1]),
        }
    }

    fn datagram() -> mux::Target<'static> {
        mux::Target {
            network: mux::Network::Udp,
            port: 53,
            addr: ferrox_core::addr::Addr::V4([127, 0, 0, 1]),
        }
    }

    /// A manager whose carriers are loopback pairs the test keeps alive, so the demux never sees
    /// an end and the pool's own bookkeeping is what the assertions read.
    fn pooled(cap: usize, lifetime: usize) -> (Arc<Manager>, Arc<Mutex<Vec<UnixStream>>>) {
        let peers: Arc<Mutex<Vec<UnixStream>>> = Arc::new(Mutex::new(Vec::new()));
        let held = Arc::clone(&peers);
        let manager = Manager::with_lifetime(cap, lifetime, move || {
            let (mine, peer) = UnixStream::pair().ok()?;
            let read = mine.try_clone().ok()?;
            // The peer only has to stay open and drain, so a full socket buffer never parks a writer.
            let mut sink = peer.try_clone().ok()?;
            std::thread::spawn(move || std::io::copy(&mut sink, &mut std::io::sink()));
            held.lock().ok()?.push(peer);
            Some(Uplink {
                read: Box::new(read),
                write: Box::new(mine),
                close: Arc::new(|| {}),
            })
        });
        (manager, peers)
    }

    #[test]
    fn a_pool_runs_a_hundred_and_twenty_eight_flows_on_one_carrier() {
        let (manager, peers) = pooled(128, LIFETIME);
        let mut flows = Vec::new();
        for _ in 0..128 {
            flows.push(manager.dial(&target()).expect("a flow"));
        }
        assert_eq!(manager.carrier_count(), 1, "128 sessions share the carrier");
        flows.push(manager.dial(&target()).expect("a flow past the cap"));
        assert_eq!(manager.carrier_count(), 2, "the cap dials a fresh carrier");
        assert!(peers.lock().is_ok_and(|peers| peers.len() == 2));
    }

    #[test]
    fn a_lifetime_retires_the_carrier_once_its_sessions_are_opened() {
        let (manager, _peers) = pooled(128, 3);
        for _ in 0..3 {
            manager.dial(&target()).expect("a flow");
        }
        assert_eq!(manager.carrier_count(), 1);
        manager.dial(&target()).expect("a flow past the lifetime");
        assert_eq!(
            manager.carrier_count(),
            2,
            "the retired carrier takes no more"
        );
    }

    #[test]
    fn a_peer_end_frees_a_datagram_session() {
        let peer = Arc::new(Mutex::new(None));
        let held = Arc::clone(&peer);
        let manager = Manager::with_lifetime(1, LIFETIME, move || {
            let (mine, other) = UnixStream::pair().ok()?;
            let read = mine.try_clone().ok()?;
            if let Ok(mut slot) = held.lock() {
                *slot = Some(other);
            }
            Some(Uplink {
                read: Box::new(read),
                write: Box::new(mine),
                close: Arc::new(|| {}),
            })
        });
        let flow = manager
            .udp(&datagram(), None, b"first", Arc::new(|_, _| {}))
            .expect("a session");
        let mut header = Vec::new();
        let end = mux::Outgoing {
            id: 1,
            status: mux::Status::End,
            options: 0,
            target: None,
            global_id: None,
        };
        let at = end.encode_header_into(&mut header);
        header.truncate(at);
        {
            let mut slot = peer.lock().expect("the peer");
            slot.as_mut()
                .expect("a peer")
                .write_all(&header)
                .expect("the end frame");
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while flow.send(&datagram(), b"later") && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            !flow.send(&datagram(), b"later"),
            "the ended flow refuses a send"
        );
        assert!(
            manager
                .udp(&datagram(), None, b"next", Arc::new(|_, _| {}))
                .is_some(),
            "the id came back"
        );
    }

    #[test]
    fn the_frame_header_holds_its_staging_across_a_push_drain_cycle() {
        let (manager, _peers) = pooled(128, LIFETIME);
        let flow = manager.dial(&target()).expect("a flow");
        assert!(flow.send(b"first"));
        let before = manager.staged_identity();
        assert_ne!(before.0, 0, "a carrier has encoded a frame");
        for _ in 0..2_000 {
            assert!(flow.send(b"payload"));
        }
        assert_eq!(manager.staged_identity(), before, "the header reallocated");
    }
}
