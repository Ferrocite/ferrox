use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ferrox_core::kcp::{dial, Config, Listener};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = &args[1];
    let peer_arg = &args[2];
    let payload: Option<&str> = args.get(3).map(String::as_str);

    match mode.as_str() {
        "server" => {
            let port: u16 = peer_arg.parse().unwrap();
            let listener =
                Listener::bind(([127, 0, 0, 1], port).into(), Config::default()).expect("bind");
            loop {
                let Ok(conn) = listener.accept() else { break };
                std::thread::spawn(move || {
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
        }
        "client" => {
            let peer: SocketAddr = peer_arg.parse().unwrap();
            let conn = dial(peer, Config::default(), 7).expect("dial");
            let payload = payload.unwrap();
            conn.write(payload.as_bytes()).unwrap();
            conn.set_read_deadline(Instant::now() + Duration::from_secs(10));
            let mut buf = vec![0u8; 65536];
            let n = conn.read(&mut buf).unwrap();
            println!("echo: {}", String::from_utf8_lossy(&buf[..n]));
            conn.close();
        }
        _ => {
            eprintln!("usage: kcp_interop <server|client> <port|peer> [payload]");
            std::process::exit(2);
        }
    }
}
