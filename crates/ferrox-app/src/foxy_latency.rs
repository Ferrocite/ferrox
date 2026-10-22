//! One TCP handshake per edge, measured in parallel: a location is only as near as the edge that answers it.

use ferrox_core::foxy::Candidate;
use std::net::{TcpStream, ToSocketAddrs as _};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// An edge that has not answered a handshake by now is not a location to pin a flow to.
const BUDGET: Duration = Duration::from_millis(1500);

/// Enough dials in flight to overlap the network's latency, and few enough that a listing stays a listing.
const WORKERS: usize = 16;

/// One reading per edge, in the order given: `None` is an edge that did not answer, which is itself the answer.
pub(crate) fn readings(edges: &[Candidate]) -> Vec<Option<u64>> {
    let next = AtomicUsize::new(0);
    let readings = Mutex::new(vec![None; edges.len()]);
    std::thread::scope(|scope| {
        for _ in 0..WORKERS.min(edges.len()) {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(edge) = edges.get(index) else {
                    break;
                };
                let reading = probe(&edge.host, edge.port, BUDGET);
                if let Ok(mut readings) = readings.lock() {
                    readings[index] = reading;
                }
            });
        }
    });
    readings.into_inner().unwrap_or_default()
}

/// The first address that answers, timed to the handshake; a name that does not resolve is a silence like any other.
fn probe(host: &str, port: u16, budget: Duration) -> Option<u64> {
    let deadline = Instant::now() + budget;
    for address in (host, port).to_socket_addrs().ok()? {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        let started = Instant::now();
        if TcpStream::connect_timeout(&address, left).is_ok() {
            return Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn edge(port: u16) -> Candidate {
        Candidate {
            host: std::sync::Arc::from("127.0.0.1"),
            port,
            country: "LO".to_owned(),
            city: "C".to_owned(),
        }
    }

    fn closed_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        listener.local_addr().expect("has an address").port()
    }

    #[test]
    fn a_handshake_reads_as_a_latency_and_a_refusal_as_silence() {
        // A bound listener completes the handshake from its backlog, so the reading needs no accept.
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let open = listener.local_addr().expect("has an address").port();
        let read = readings(&[edge(open), edge(closed_port())]);
        drop(listener);
        assert!(read[0].is_some(), "a listener answers in some milliseconds");
        assert_eq!(read[1], None, "a closed port is silence, not a zero");
    }

    #[test]
    fn no_edges_read_as_no_readings() {
        assert_eq!(readings(&[]), Vec::new());
    }
}
