//! The `WireGuard` tunnel above the handshake and record layers: one peer's
//! session keys, the counters and replay window, the message timers, endpoint
//! roaming, reserved bytes, and the queue a payload waits in while a handshake
//! runs.
//!
//! The device is deliberately not an I/O object. It is handed a monotonic
//! millisecond clock and the bytes a datagram carried, and it answers with the
//! datagrams a socket would send and the payloads the upper layer consumes. The
//! app owns the clock, the socket and the userspace IP stack; this owns the
//! protocol state that must be identical for every reader.
//!
//! Timers follow the pinned device: a handshake attempt is retried after five
//! seconds and abandoned after ninety, a session is rekeyed after two minutes
//! and rejected after three, and a configured persistent keepalive sends an
//! empty record after ten seconds of silence. A retry is a fresh initiation
//! with a fresh timestamp and ephemeral key, as the reference's
//! `SendHandshakeInitiation` makes; a cookie reply only supplies the `mac2` the
//! next attempt carries.

use std::collections::VecDeque;
use std::net::SocketAddr;
use zeroize::Zeroize as _;

use super::handshake::{self, Handshake, MAC_SIZE};
use super::transport::{
    self, Action, Counter, ReplayWindow, COOKIE_REPLY_SIZE, HEADER_SIZE, TAG_SIZE,
};

/// The interval a sent initiation waits before a fresh attempt.
pub const REKEY_TIMEOUT: u64 = 5_000;
/// How long an initiator keeps trying before it gives up on the peer.
pub const HANDSHAKE_ATTEMPT: u64 = 90_000;
/// The age at which a sending session is rekeyed.
pub const REKEY_AFTER: u64 = 120_000;
/// The age at which a session's keys are refused in either direction.
pub const REJECT_AFTER: u64 = 180_000;
/// The idle interval a configured persistent keepalive sends after.
pub const KEEPALIVE_TIMEOUT: u64 = 10_000;
/// How long a received cookie stays usable.
pub const COOKIE_REFRESH: u64 = 120_000;

/// The most payload bytes queued for one peer while a handshake runs. The
/// reference's pool is bounded too; past it the oldest packet is dropped, so a
/// stalled handshake cannot grow the process without a bound.
const QUEUE_BYTES: usize = 256 * 1024;

/// TAI64N's first second; the record adds Unix seconds to it.
const TAI64N_EPOCH: u64 = 0x4000_0000_0000_000a;

/// One outbound packet and where it goes, or one decrypted payload for the
/// upper layer.
#[derive(Debug)]
pub enum Event {
    Send {
        endpoint: SocketAddr,
        packet: Vec<u8>,
    },
    Data(Vec<u8>),
}

/// The `TAI64N` timestamp a handshake carries: seconds since the epoch with the
/// TAI offset, then nanoseconds, both big-endian. The record is ordered
/// lexicographically, which is how the responder refuses a replay.
#[must_use]
pub fn tai64n(seconds: u64, nanos: u32) -> [u8; 12] {
    let seconds = TAI64N_EPOCH.wrapping_add(seconds);
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&seconds.to_be_bytes());
    out[8..].copy_from_slice(&nanos.to_be_bytes());
    out
}

/// The public key of an X25519 private key, clamped by the primitive itself.
#[must_use]
pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*private, x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// One established session's keys and counters. The keys are zeroised when the
/// session is replaced or expires.
struct Session {
    send: [u8; 32],
    recv: [u8; 32],
    counter: Counter,
    replay: ReplayWindow,
    local_index: u32,
    remote_index: u32,
    created: u64,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.send.zeroize();
        self.recv.zeroize();
    }
}

/// One peer's tunnel, from either side. An initiator creates the first message;
/// a responder answers a consumed initiation through [`Tunnel::answer`].
pub struct Tunnel {
    private: [u8; 32],
    public: [u8; 32],
    peer: [u8; 32],
    preshared: [u8; 32],
    endpoint: SocketAddr,
    keepalive: u16,
    reserved: [u8; 3],
    handshake: Option<Handshake>,
    pending_mac1: Option<[u8; MAC_SIZE]>,
    cookie: Option<([u8; MAC_SIZE], u64)>,
    handshake_started: u64,
    handshake_sent: u64,
    last_timestamp: Option<[u8; 12]>,
    epoch: [u8; 12],
    session: Option<Session>,
    queue: VecDeque<Vec<u8>>,
    queued_bytes: usize,
    last_send: u64,
    last_recv: u64,
}

impl std::fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tunnel")
            .field("peer", &self.peer)
            .field("endpoint", &self.endpoint)
            .field("keepalive", &self.keepalive)
            .field("session", &self.session.is_some())
            .field("handshake", &self.handshake.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.private.zeroize();
        self.preshared.zeroize();
        if let Some((mut cookie, _)) = self.cookie.take() {
            cookie.zeroize();
        }
        if let Some(mut mac1) = self.pending_mac1.take() {
            mac1.zeroize();
        }
    }
}

impl Tunnel {
    /// A tunnel to one peer's static key, with the endpoint a handshake goes to
    /// and the keepalive the config asked for (zero for none).
    #[must_use]
    pub fn new(
        private: [u8; 32],
        peer: [u8; 32],
        preshared: [u8; 32],
        endpoint: SocketAddr,
        keepalive: u16,
        reserved: [u8; 3],
        epoch: [u8; 12],
    ) -> Self {
        let public = public_key(&private);
        Self {
            private,
            public,
            peer,
            preshared,
            endpoint,
            keepalive,
            reserved,
            handshake: None,
            pending_mac1: None,
            cookie: None,
            handshake_started: 0,
            handshake_sent: 0,
            last_timestamp: None,
            epoch,
            session: None,
            queue: VecDeque::new(),
            queued_bytes: 0,
            last_send: 0,
            last_recv: 0,
        }
    }

    /// The wall-clock base carried from startup plus the monotonic elapsed time, so a
    /// retry is newer than the initiation it replaces without a clock read here.
    fn timestamp_at(&self, now: u64) -> [u8; 12] {
        let seconds = u64::from_be_bytes(self.epoch[..8].try_into().expect("eight bytes"));
        let nanos = u64::from(u32::from_be_bytes(
            self.epoch[8..].try_into().expect("four bytes"),
        )) + now.saturating_mul(1_000_000);
        tai64n(
            seconds
                .wrapping_sub(TAI64N_EPOCH)
                .wrapping_add(nanos / 1_000_000_000),
            (nanos % 1_000_000_000) as u32,
        )
    }

    /// This side's static public key.
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// The peer's static public key.
    #[must_use]
    pub fn peer(&self) -> [u8; 32] {
        self.peer
    }

    /// The endpoint the peer last spoke from, or the configured one before any
    /// authenticated packet has arrived.
    #[must_use]
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Whether a usable session exists at `now`.
    #[must_use]
    pub fn established(&self, now: u64) -> bool {
        self.session
            .as_ref()
            .is_some_and(|session| now.saturating_sub(session.created) < REJECT_AFTER)
    }

    /// Start an initiation if this tunnel has no handshake in flight. Returns
    /// whether one is now in flight, so a caller can distinguish "queued" from
    /// "the entropy source failed".
    pub fn initiate(&mut self, now: u64, out: &mut Vec<Event>) -> bool {
        if self.handshake.is_some() {
            return true;
        }
        let Some(mut state) = Handshake::initiate(&self.private, &self.peer, &self.preshared)
        else {
            return false;
        };
        let Ok((index, ephemeral)) = random_index() else {
            return false;
        };
        let timestamp = self.timestamp_at(now);
        let mut message = state.create_initiation(&self.public, ephemeral, index, &timestamp);
        handshake::set_mac1(&mut message, &self.peer);
        if let Some((cookie, at)) = self.cookie {
            if now.saturating_sub(at) < COOKIE_REFRESH {
                transport::set_mac2(&mut message, &cookie);
            } else {
                self.cookie = None;
            }
        }
        let mut mac1 = [0u8; MAC_SIZE];
        mac1.copy_from_slice(&message[message.len() - 2 * MAC_SIZE..message.len() - MAC_SIZE]);
        self.pending_mac1 = Some(mac1);
        self.handshake = Some(state);
        self.handshake_started = now;
        self.handshake_sent = now;
        out.push(Event::Send {
            endpoint: self.endpoint,
            packet: self.apply_reserved(message.to_vec()),
        });
        true
    }

    /// Queue a payload (an IP packet) and send it if a session is ready. With
    /// no session the payload waits and an initiation starts; past the queue
    /// bound the oldest payload is dropped.
    pub fn send(&mut self, now: u64, payload: &[u8], out: &mut Vec<Event>) {
        if self.established(now) {
            if self
                .session
                .as_ref()
                .is_some_and(|session| now.saturating_sub(session.created) >= REKEY_AFTER)
            {
                self.initiate(now, out);
            }
            self.seal(now, payload, out);
            return;
        }
        if payload.len() > QUEUE_BYTES {
            return;
        }
        while self.queued_bytes + payload.len() > QUEUE_BYTES {
            let Some(old) = self.queue.pop_front() else {
                break;
            };
            self.queued_bytes -= old.len();
        }
        self.queue.push_back(payload.to_vec());
        self.queued_bytes += payload.len();
        self.initiate(now, out);
    }

    /// Feed one datagram from `src`. Handshake responses, cookie replies and
    /// transport records are accepted; anything else is ignored. A transport
    /// record's payload becomes [`Event::Data`].
    pub fn receive(&mut self, now: u64, src: SocketAddr, packet: &mut [u8], out: &mut Vec<Event>) {
        if packet.len() < 4 {
            return;
        }
        transport::clear_reserved(packet);
        let kind = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
        match kind {
            handshake::TYPE_RESPONSE => self.response(now, src, packet, out),
            transport::TYPE_COOKIE_REPLY => self.cookie_reply(now, packet, out),
            transport::TYPE_TRANSPORT => self.transport(now, src, packet, out),
            _ => {}
        }
    }

    fn response(&mut self, now: u64, src: SocketAddr, packet: &mut [u8], out: &mut Vec<Event>) {
        let local_index = self.local_index();
        let Some(state) = self.handshake.as_mut() else {
            return;
        };
        let Ok(message) = <&[u8; handshake::RESPONSE_SIZE]>::try_from(&*packet) else {
            return;
        };
        if u32::from_le_bytes(packet[8..12].try_into().unwrap_or([0; 4])) != local_index {
            return;
        }
        if !state.consume_response(&self.private, message) {
            return;
        }
        let remote_index = u32::from_le_bytes(packet[4..8].try_into().unwrap_or([0; 4]));
        let Some((send, recv)) = state.session_keys() else {
            return;
        };
        self.handshake = None;
        self.pending_mac1 = None;
        self.session = Some(Session {
            send,
            recv,
            counter: Counter::new(),
            replay: ReplayWindow::new(),
            local_index,
            remote_index,
            created: now,
        });
        self.endpoint = src;
        self.last_recv = now;
        self.last_send = now;
        self.flush(now, out);
    }

    fn cookie_reply(&mut self, now: u64, packet: &mut [u8], out: &mut Vec<Event>) {
        if packet.len() != COOKIE_REPLY_SIZE || packet[0] != transport::TYPE_COOKIE_REPLY as u8 {
            return;
        }
        if u32::from_le_bytes(packet[4..8].try_into().unwrap_or([0; 4])) != self.local_index() {
            return;
        }
        let Some(mac1) = self.pending_mac1 else {
            return;
        };
        let reply: &[u8; COOKIE_REPLY_SIZE] = (&*packet).try_into().expect("length was checked");
        let key = transport::cookie_encryption_key(&self.peer);
        let Some(cookie) = transport::consume_reply(reply, &key, &mac1) else {
            return;
        };
        self.cookie = Some((cookie, now));
        // The next initiation carries mac2, and the original attempt budget survives.
        let started = self.handshake_started;
        self.handshake = None;
        if self.initiate(now, out) {
            self.handshake_started = started;
        }
    }

    fn transport(&mut self, now: u64, src: SocketAddr, packet: &mut [u8], out: &mut Vec<Event>) {
        if self
            .session
            .as_ref()
            .is_none_or(|session| now.saturating_sub(session.created) >= REJECT_AFTER)
        {
            self.session = None;
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        if packet.len() < transport::MIN_SIZE {
            return;
        }
        let receiver = u32::from_le_bytes(packet[4..8].try_into().unwrap_or([0; 4]));
        if receiver != session.local_index {
            return;
        }
        let counter = u64::from_le_bytes(packet[8..16].try_into().unwrap_or([0; 8]));
        let action = session.replay.check(counter);
        if action == Action::Reject {
            return;
        }
        let Some((_, _, len)) = transport::open(&session.recv, packet, packet.len()) else {
            return;
        };
        session.replay.commit(counter, action);
        self.endpoint = src;
        self.last_recv = now;
        if len > 0 {
            out.push(Event::Data(packet[HEADER_SIZE..HEADER_SIZE + len].to_vec()));
        }
    }

    /// Consume an initiation with this device's static key, recovering the
    /// peer's static key so a server can look up the peer before answering.
    #[must_use]
    pub fn consume(&self, message: &[u8; handshake::INITIATION_SIZE]) -> Option<Handshake> {
        Handshake::consume_initiation(&self.private, &self.public, message)
    }

    /// Whether a handshake or session this side owns answers to `index`, which
    /// is how a server routes a transport packet to its peer without scanning
    /// every session's key material.
    #[must_use]
    pub fn owns(&self, index: u32) -> bool {
        self.local_index() == index
    }

    /// Answer a consumed initiation. The caller has already checked `mac1` and
    /// looked up the peer by the static key [`Self::consume`] recovered.
    /// Returns whether a response was sent.
    pub fn answer(
        &mut self,
        now: u64,
        src: SocketAddr,
        mut state: Handshake,
        out: &mut Vec<Event>,
    ) -> bool {
        if state.remote_static() != self.peer {
            return false;
        }
        if self
            .last_timestamp
            .is_some_and(|previous| previous >= state.timestamp())
        {
            return false;
        }
        let Ok((index, ephemeral)) = random_index() else {
            return false;
        };
        let Some(mut message) = state.create_response(ephemeral, index, &self.preshared) else {
            return false;
        };
        handshake::set_mac1(&mut message, &self.peer);
        let (local_index, remote_index) = state.indexes();
        let timestamp = state.timestamp();
        let Some((send, recv)) = state.session_keys() else {
            return false;
        };
        self.last_timestamp = Some(timestamp);
        self.session = Some(Session {
            send,
            recv,
            counter: Counter::new(),
            replay: ReplayWindow::new(),
            local_index,
            remote_index,
            created: now,
        });
        self.endpoint = src;
        self.last_recv = now;
        self.last_send = now;
        out.push(Event::Send {
            endpoint: src,
            packet: self.apply_reserved(message.to_vec()),
        });
        true
    }

    /// Run the timers: retry a handshake, abandon one that outlived the
    /// attempt budget, expire a session, or send a keepalive.
    pub fn poll(&mut self, now: u64, out: &mut Vec<Event>) {
        if self.handshake.is_some() {
            if now.saturating_sub(self.handshake_sent) >= REKEY_TIMEOUT {
                if now.saturating_sub(self.handshake_started) >= HANDSHAKE_ATTEMPT {
                    self.handshake = None;
                    self.pending_mac1 = None;
                    self.queue.clear();
                    self.queued_bytes = 0;
                } else {
                    let started = self.handshake_started;
                    self.handshake = None;
                    if self.initiate(now, out) {
                        self.handshake_started = started;
                    }
                }
            }
            return;
        }
        let Some(session) = self.session.as_ref() else {
            return;
        };
        if now.saturating_sub(session.created) >= REJECT_AFTER {
            self.session = None;
            return;
        }
        if self.keepalive > 0
            && now.saturating_sub(self.last_send) >= u64::from(self.keepalive) * 1000
        {
            self.seal(now, &[], out);
        }
    }

    /// Drop the session and any pending handshake, keeping the endpoint and
    /// configuration. The next send starts a fresh handshake.
    pub fn reset(&mut self) {
        self.session = None;
        self.handshake = None;
        self.pending_mac1 = None;
    }

    fn local_index(&self) -> u32 {
        self.handshake.as_ref().map_or_else(
            || self.session.as_ref().map_or(0, |s| s.local_index),
            |s| s.indexes().0,
        )
    }

    fn seal(&mut self, now: u64, payload: &[u8], out: &mut Vec<Event>) {
        let Some(counter) = self
            .session
            .as_mut()
            .and_then(|session| session.counter.advance())
        else {
            self.session = None;
            self.initiate(now, out);
            return;
        };
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let mut packet = vec![0u8; HEADER_SIZE + payload.len() + TAG_SIZE];
        packet[HEADER_SIZE..HEADER_SIZE + payload.len()].copy_from_slice(payload);
        let total = transport::seal(
            &session.send,
            session.remote_index,
            counter,
            payload.len(),
            &mut packet,
        );
        packet.truncate(total);
        let packet = self.apply_reserved(packet);
        self.last_send = now;
        out.push(Event::Send {
            endpoint: self.endpoint,
            packet,
        });
    }

    fn flush(&mut self, now: u64, out: &mut Vec<Event>) {
        while let Some(payload) = self.queue.pop_front() {
            self.queued_bytes -= payload.len();
            self.seal(now, &payload, out);
        }
    }

    fn apply_reserved(&self, mut packet: Vec<u8>) -> Vec<u8> {
        transport::set_reserved(&mut packet, self.reserved);
        packet
    }
}

/// A random local index and ephemeral private key. The index only has to be
/// unique among live sessions and is not a secret; the ephemeral is.
fn random_index() -> Result<(u32, [u8; 32]), ()> {
    let mut bytes = [0u8; 36];
    getrandom::fill(&mut bytes).map_err(|_| ())?;
    let mut index = [0u8; 4];
    index.copy_from_slice(&bytes[..4]);
    let mut ephemeral = [0u8; 32];
    ephemeral.copy_from_slice(&bytes[4..]);
    Ok((u32::from_le_bytes(index) | 1, ephemeral))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000;
    const ALICE: &str = "127.0.0.1:51820";
    const BOB: &str = "127.0.0.1:51821";

    fn pair_with_keepalive(keepalive: u16) -> (Tunnel, Tunnel) {
        let alice_private = [0x11; 32];
        let bob_private = [0x22; 32];
        let alice_public = public_key(&alice_private);
        let bob_public = public_key(&bob_private);
        (
            Tunnel::new(
                alice_private,
                bob_public,
                [0x99; 32],
                ALICE.parse().unwrap(),
                keepalive,
                [0; 3],
                [0; 12],
            ),
            Tunnel::new(
                bob_private,
                alice_public,
                [0x99; 32],
                BOB.parse().unwrap(),
                keepalive,
                [0; 3],
                [0; 12],
            ),
        )
    }

    fn pair() -> (Tunnel, Tunnel) {
        pair_with_keepalive(0)
    }

    fn packet(events: &[Event]) -> Vec<u8> {
        events
            .iter()
            .find_map(|event| match event {
                Event::Send { packet, .. } => Some(packet.clone()),
                Event::Data(_) => None,
            })
            .expect("an outbound packet")
    }

    fn consume(tunnel: &Tunnel, initiation: &[u8]) -> Handshake {
        let mut message = initiation.to_vec();
        transport::clear_reserved(&mut message);
        let message: [u8; handshake::INITIATION_SIZE] = message.try_into().unwrap();
        assert!(handshake::check_mac1(&message, &tunnel.public));
        Handshake::consume_initiation(&tunnel.private, &tunnel.public, &message).unwrap()
    }

    fn answer(tunnel: &mut Tunnel, initiation: &[u8], now: u64) -> Vec<Event> {
        let state = consume(tunnel, initiation);
        let mut out = Vec::new();
        assert!(tunnel.answer(now, BOB.parse().unwrap(), state, &mut out));
        out
    }

    fn establish(keepalive: u16) -> (Tunnel, Tunnel) {
        let (mut alice, mut bob) = pair_with_keepalive(keepalive);
        let mut out = Vec::new();
        alice.send(NOW, b"hello", &mut out);
        let initiation = packet(&out);
        let response = answer(&mut bob, &initiation, NOW + 1);
        let mut response = packet(&response);
        alice.receive(
            NOW + 2,
            BOB.parse().unwrap(),
            &mut response,
            &mut Vec::new(),
        );
        assert!(alice.established(NOW + 2));
        assert!(bob.established(NOW + 1));
        (alice, bob)
    }

    #[test]
    fn an_initiation_and_response_install_both_sessions_and_flush_the_queue() {
        let (mut alice, mut bob) = pair();
        let mut out = Vec::new();
        alice.send(NOW, b"first packet", &mut out);
        let initiation = packet(&out);
        let response = answer(&mut bob, &initiation, NOW + 1);
        let mut response = packet(&response);
        let mut flushed = Vec::new();
        alice.receive(NOW + 2, BOB.parse().unwrap(), &mut response, &mut flushed);
        assert!(alice.established(NOW + 2));
        let mut record = packet(&flushed);
        let mut received = Vec::new();
        bob.receive(NOW + 3, ALICE.parse().unwrap(), &mut record, &mut received);
        let Event::Data(payload) = &received[0] else {
            panic!("a data event");
        };
        assert_eq!(payload, b"first packet");
    }

    #[test]
    fn the_reference_message_sizes() {
        assert_eq!(transport::HEADER_SIZE, 16);
        assert_eq!(handshake::INITIATION_SIZE, 148);
        assert_eq!(handshake::RESPONSE_SIZE, 92);
    }

    #[test]
    fn a_replayed_transport_counter_is_refused() {
        let (mut alice, mut bob) = establish(0);
        let mut out = Vec::new();
        alice.send(NOW + 3, b"payload", &mut out);
        let mut record = packet(&out);
        let mut first = Vec::new();
        bob.receive(NOW + 4, ALICE.parse().unwrap(), &mut record, &mut first);
        assert!(matches!(&first[0], Event::Data(payload) if payload == b"payload"));
        let mut again = Vec::new();
        bob.receive(NOW + 5, ALICE.parse().unwrap(), &mut record, &mut again);
        assert!(again.is_empty(), "the same counter is a replay");
    }

    #[test]
    fn a_replayed_initiation_timestamp_is_refused() {
        let (mut alice, mut bob) = pair();
        let mut out = Vec::new();
        alice.send(NOW, b"x", &mut out);
        let initiation = packet(&out);
        let state = consume(&bob, &initiation);
        let mut first = Vec::new();
        assert!(bob.answer(NOW + 1, ALICE.parse().unwrap(), state, &mut first));
        let state = consume(&bob, &initiation);
        let mut second = Vec::new();
        assert!(
            !bob.answer(NOW + 2, ALICE.parse().unwrap(), state, &mut second),
            "the same timestamp is a replay"
        );
        assert!(second.is_empty());
    }

    #[test]
    fn a_session_expires_after_the_reject_threshold() {
        let (mut alice, _bob) = establish(0);
        let mut out = Vec::new();
        alice.poll(NOW + 2 + REJECT_AFTER, &mut out);
        assert!(!alice.established(NOW + 2 + REJECT_AFTER));
        assert!(out.is_empty());
        alice.send(NOW + 2 + REJECT_AFTER, b"x", &mut out);
        assert!(matches!(&out[0], Event::Send { .. }), "a fresh initiation");
    }

    #[test]
    fn a_configured_keepalive_is_an_empty_record() {
        let (mut alice, _bob) = establish(10);
        let mut out = Vec::new();
        alice.poll(NOW + 2 + KEEPALIVE_TIMEOUT, &mut out);
        let keepalive = packet(&out);
        assert_eq!(keepalive.len(), transport::MIN_SIZE);
        assert_eq!(&keepalive[0..4], &transport::TYPE_TRANSPORT.to_le_bytes());
        let mut again = Vec::new();
        alice.poll(NOW + 2 + KEEPALIVE_TIMEOUT, &mut again);
        assert!(again.is_empty(), "one keepalive per idle interval");
    }

    #[test]
    fn a_fresh_retry_is_a_new_timestamp_and_new_ephemeral() {
        let (mut alice, _bob) = pair();
        let mut first = Vec::new();
        alice.send(NOW, b"x", &mut first);
        let one = packet(&first);
        let mut second = Vec::new();
        alice.poll(NOW + REKEY_TIMEOUT, &mut second);
        let two = packet(&second);
        assert_ne!(&one[8..40], &two[8..40], "a fresh ephemeral");
        assert_ne!(&one[88..100], &two[88..100], "a fresh timestamp");
        assert_eq!(alice.handshake_started, NOW, "the attempt budget is kept");
    }

    #[test]
    fn a_handshake_is_abandoned_after_the_attempt_budget() {
        let (mut alice, _bob) = pair();
        let mut out = Vec::new();
        alice.send(NOW, b"x", &mut out);
        alice.poll(NOW + HANDSHAKE_ATTEMPT, &mut Vec::new());
        assert!(alice.handshake.is_none());
        assert!(alice.queue.is_empty());
        assert_eq!(alice.queued_bytes, 0);
    }

    #[test]
    fn a_cookie_reply_is_stored_and_the_next_initiation_carries_mac2() {
        let (mut alice, _bob) = pair();
        let mut out = Vec::new();
        alice.send(NOW, b"x", &mut out);
        let initiation = packet(&out);
        let secret = [0x77; 32];
        let src = b"203.0.113.7:51820";
        let encryption_key = transport::cookie_encryption_key(&public_key(&[0x22; 32]));
        let index = u32::from_le_bytes(initiation[4..8].try_into().unwrap());
        let reply = transport::create_reply(
            &initiation,
            index,
            &secret,
            src,
            &encryption_key,
            &[0x55; transport::COOKIE_NONCE_SIZE],
        )
        .unwrap();
        let mut reply = reply.to_vec();
        let mut retry = Vec::new();
        alice.receive(NOW + 1, BOB.parse().unwrap(), &mut reply, &mut retry);
        let cookie = transport::derive_cookie(&secret, src);
        assert_eq!(alice.cookie.map(|(cookie, _)| cookie), Some(cookie));
        let message = packet(&retry);
        assert!(
            transport::check_mac2(&message, &secret, src),
            "the retry proves the cookie"
        );
    }
}
