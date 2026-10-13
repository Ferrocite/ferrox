use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ferrox_core::kcp::{read_segment, Config, ConnMetadata, Connection};

fn main() {
    let megabytes: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(64);

    let ssock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let slocal = ssock.local_addr().unwrap();
    let ssock_w = ssock.try_clone().unwrap();
    let speer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let speer_w = Arc::clone(&speer);
    let swriter = Box::new(move |datagram: &[u8]| -> io::Result<()> {
        match *speer_w.lock().unwrap() {
            Some(peer) => ssock_w.send_to(datagram, peer).map(|_| ()),
            None => Err(io::Error::other("no peer yet")),
        }
    });
    let scloser = Box::new(|| {});
    let sconn = Connection::new(
        ConnMetadata {
            local: slocal,
            remote: slocal,
            conversation: 7,
        },
        swriter,
        scloser,
        Config::default(),
    );
    {
        let c2 = Arc::clone(&sconn);
        let sr = ssock.try_clone().unwrap();
        thread::spawn(move || feed(&sr, &c2, &speer));
    }
    spawn_echo(Arc::clone(&sconn));

    let csock = UdpSocket::bind("127.0.0.1:0").unwrap();
    csock.connect(slocal).unwrap();
    let clocal = csock.local_addr().unwrap();
    let csock_w = csock.try_clone().unwrap();
    let cwriter =
        Box::new(move |datagram: &[u8]| -> io::Result<()> { csock_w.send(datagram).map(|_| ()) });
    let ccloser = Box::new(|| {});
    let cconn = Connection::new(
        ConnMetadata {
            local: clocal,
            remote: slocal,
            conversation: 7,
        },
        cwriter,
        ccloser,
        Config::default(),
    );
    {
        let c2 = Arc::clone(&cconn);
        let cr = csock.try_clone().unwrap();
        let cpeer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(Some(slocal)));
        thread::spawn(move || feed(&cr, &c2, &cpeer));
    }

    let payload: Arc<[u8]> = Arc::from(vec![b'x'; megabytes * 1024 * 1024].into_boxed_slice());
    let received = Arc::new(AtomicUsize::new(0));
    let recv2 = Arc::clone(&received);
    let p1 = Arc::clone(&payload);
    let rconn = Arc::clone(&cconn);
    let reader = thread::spawn(move || {
        let mut buf = vec![0u8; 1 << 20];
        rconn.set_read_deadline(Instant::now() + Duration::from_secs(60));
        loop {
            match rconn.read(&mut buf) {
                Ok(n) => {
                    let total = recv2.fetch_add(n, Ordering::SeqCst) + n;
                    if total >= p1.len() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });

    let start = Instant::now();
    let p2 = Arc::clone(&payload);
    let wconn = Arc::clone(&cconn);
    let writer_thread = thread::spawn(move || {
        wconn.write(&p2).unwrap();
    });
    writer_thread.join().unwrap();
    reader.join().unwrap();
    let elapsed = start.elapsed();
    let bytes = received.load(Ordering::SeqCst);
    let mib = f64::from(u32::try_from(bytes / 1_000_000).unwrap_or(u32::MAX));
    println!(
        "rust: {} bytes in {:?} -> {:.2} MB/s",
        bytes,
        elapsed,
        mib / elapsed.as_secs_f64()
    );
}

fn feed(sock: &UdpSocket, conn: &Connection, peer: &Mutex<Option<SocketAddr>>) {
    let mut buf = vec![0u8; 65536];
    while let Ok((n, src)) = sock.recv_from(&mut buf) {
        {
            let mut guard = peer.lock().unwrap();
            if guard.is_none() {
                *guard = Some(src);
            }
        }
        let mut rest = &buf[..n];
        let mut segs = Vec::new();
        while let Some((seg, tail)) = read_segment(rest, &|| conn.take_payload()) {
            segs.push(seg);
            rest = tail;
        }
        conn.input(&mut segs);
    }
}

/// What the server side does with what it reads: hands it straight back.
fn spawn_echo(conn: Arc<Connection>) {
    thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        while let Ok(n) = conn.read(&mut buf) {
            if n == 0 {
                break;
            }
            if conn.write(&buf[..n]).is_err() {
                break;
            }
        }
    });
}
