#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use ferrox_core::vless_encryption::{
    generate_pair, Client, ClientConfig, Clock, Server, ServerConfig,
};

fn round_trip(server: &Arc<Server>, client: &Arc<Client>) {
    let (a, b) = UnixStream::pair().unwrap();
    let server = Arc::clone(server);
    let server_thread = std::thread::spawn(move || {
        let mut stream = server.handshake(b).unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
        stream.write_all(b"world").unwrap();
        stream.flush().unwrap();
    });
    let mut stream = client.handshake(a).unwrap();
    stream.write_all(b"hello").unwrap();
    stream.flush().unwrap();
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"world");
    server_thread.join().unwrap();
}

#[test]
fn random_zero_rtt_resumes_with_a_masked_reply() {
    let (encryption, decryption) = generate_pair(false, "random", "0rtt", "600s");
    let server = Server::new(ServerConfig::parse(&decryption).unwrap());
    let client = Client::new(ClientConfig::parse(&encryption).unwrap());
    round_trip(&server, &client);
    round_trip(&server, &client);
}

#[test]
fn an_expired_zero_rtt_ticket_is_not_resumed() {
    let (encryption, decryption) = generate_pair(false, "native", "0rtt", "300-300s");
    let server_now = Arc::new(AtomicI64::new(0));
    let client_now = Arc::new(AtomicI64::new(0));
    let server_clock: Clock = {
        let now = Arc::clone(&server_now);
        Arc::new(move || now.load(Ordering::Relaxed))
    };
    let client_clock: Clock = {
        let now = Arc::clone(&client_now);
        Arc::new(move || now.load(Ordering::Relaxed))
    };
    let server = Server::with_clock(ServerConfig::parse(&decryption).unwrap(), server_clock);
    let client = Client::with_clock(ClientConfig::parse(&encryption).unwrap(), client_clock);
    round_trip(&server, &client);

    server_now.store(1000, Ordering::Relaxed);
    let (a, b) = UnixStream::pair().unwrap();
    let server_thread = std::thread::spawn(move || server.handshake(b).map(|_| ()));
    if let Ok(mut stream) = client.handshake(a) {
        let _ = stream.write_all(b"hello");
        let _ = stream.flush();
    }
    assert!(
        server_thread.join().unwrap().is_err(),
        "an expired 0-RTT ticket must not resume"
    );
}
