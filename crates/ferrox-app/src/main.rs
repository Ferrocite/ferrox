mod budgets;
mod config;
mod foxy;
mod foxy_account;
mod foxy_catalog;
mod foxy_challenge;
#[cfg(test)]
mod foxy_live;
mod grpc;
mod h2;
mod httpheader;
mod httpupgrade;
mod hysteria;
mod json;
mod proxy;
mod quic;
mod shadowsocks;
mod shadowsocks2022;
mod vision;
mod vmess;
mod ws;
mod xhttp;
mod xhttp_h2;

use ferrox_core::policy::UnsafeOptIn;
use ferrox_core::transport::Support;
use std::io::Write as _;
use std::time::Duration;

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  ferrox-app check <vless://...> [--allow-unsafe-fp]   parse + support + header len (no network)");
    eprintln!("  ferrox-app run <vless://...> [--allow-unsafe-fp]     check + TCP reachability (sends nothing)");
    eprintln!("  ferrox-app version                print the serving binary's version");
    eprintln!("  ferrox-app x25519                 print a fresh X25519 keypair");
    eprintln!("  ferrox-app run -c <config.json>   serve inbounds until killed");
    eprintln!("  ferrox-app mint-foxy-pass -c <config.json> -o <pass.json>");
    eprintln!("                                sign in once, store the proxy pass (0600)");
    std::process::exit(2);
}

/// One share link plus any out-of-band consent flags, in either order.
fn link_and_opt_in<I: Iterator<Item = String>>(args: &mut I) -> (String, UnsafeOptIn) {
    let mut link: Option<String> = None;
    let mut opt = UnsafeOptIn::none();
    for arg in args {
        match arg.as_str() {
            "--allow-unsafe-fp" => opt = opt.allow_unsafe_fingerprint(),
            _ if link.is_none() => link = Some(arg),
            _ => usage(),
        }
    }
    match link {
        Some(link) => (link, opt),
        None => usage(),
    }
}

fn describe(link: &ferrox_core::vless::VlessLink, opt_in: UnsafeOptIn) -> String {
    format!(
        "host={} port={} type={} security={} flow={} support=[{}]",
        link.host,
        link.port,
        link.param("type"),
        link.param("security"),
        link.flow(),
        link.support_opted(opt_in),
    )
}

fn cmd_check(link_str: &str, opt_in: UnsafeOptIn) {
    let link = ferrox_core::vless::VlessLink::parse(link_str).unwrap_or_else(|e| {
        eprintln!("bad link: {e}");
        std::process::exit(1);
    });
    println!("{}", describe(&link, opt_in));
    let hdr = link.encode_request_header("example.com", 443);
    println!(
        "header_len={} header_prefix={:02x?}",
        hdr.len(),
        &hdr[..8.min(hdr.len())]
    );
    match link.support_opted(opt_in) {
        Support::Implemented { method } => {
            println!("diallable: {method} (run checks tcp reachability; sends nothing)");
        }
        Support::Planned { reason } => println!("not yet diallable: {reason}"),
        Support::UnsafeRequiresOptIn { reason } => {
            println!("needs explicit opt-in (policy::UnsafeOptIn, or --allow-unsafe-fp): {reason}");
        }
    }
}

fn cmd_run(link_str: &str, opt_in: UnsafeOptIn) {
    let link = ferrox_core::vless::VlessLink::parse(link_str).unwrap_or_else(|e| {
        eprintln!("bad link: {e}");
        std::process::exit(1);
    });
    println!("{}", describe(&link, opt_in));
    match link.support_opted(opt_in) {
        Support::Implemented { .. } => {}
        other => {
            eprintln!("refusing to dial: {other}");
            eprintln!("(parse succeeded; the transport rung is not implemented yet)");
            std::process::exit(3);
        }
    }
    let addr = format!("{}:{}", link.host, link.port);
    let sock: std::net::SocketAddr = if let Ok(sock) = addr.parse() {
        sock
    } else {
        use std::net::ToSocketAddrs as _;
        addr.to_socket_addrs()
            .ok()
            .and_then(|mut it| it.next())
            .unwrap_or_else(|| {
                eprintln!("cannot resolve {addr}");
                std::process::exit(1);
            })
    };
    let t0 = std::time::Instant::now();
    match std::net::TcpStream::connect_timeout(&sock, Duration::from_secs(8)) {
        Ok(stream) => {
            let dt = t0.elapsed();
            println!("tcp reachable in {dt:?} (no bytes sent; session handshake is the next rung)");
            drop(stream);
        }
        Err(e) => {
            eprintln!("tcp unreachable: {e}");
            std::process::exit(4);
        }
    }
    let hdr = link.encode_request_header("example.com", 443);
    println!("header_len={} (encoded locally, not sent)", hdr.len());
    let _ = std::io::stdout().flush();
}

fn main() {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| usage());
    match cmd.as_str() {
        "check" => {
            let (link, opt_in) = link_and_opt_in(&mut args);
            cmd_check(&link, opt_in);
        }
        "run" => {
            let first = args.next().unwrap_or_else(|| usage());
            if first == "-c" || first == "-config" {
                let file = args.next().unwrap_or_else(|| usage());
                if args.next().is_some() {
                    usage();
                }
                proxy::serve_file(&file);
            }
            let mut iter = std::iter::once(first).chain(args);
            let (link, opt_in) = link_and_opt_in(&mut iter);
            cmd_run(&link, opt_in);
        }
        "version" => {
            if args.next().is_some() {
                usage();
            }
            proxy::print_version();
        }
        "mint-foxy-pass" => {
            let next = args.next().unwrap_or_else(|| usage());
            if next != "-c" && next != "-config" {
                usage();
            }
            let config = args.next().unwrap_or_else(|| usage());
            let flag = args.next().unwrap_or_else(|| usage());
            if flag != "-o" {
                usage();
            }
            let out = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            proxy::mint_foxy_pass(&config, &out);
        }
        "edges" => {
            let next = args.next().unwrap_or_else(|| usage());
            if next != "-c" && next != "-config" {
                usage();
            }
            let config = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            proxy::print_foxy_edges(&config);
        }
        "x25519" => {
            if args.next().is_some() {
                usage();
            }
            proxy::print_x25519();
        }
        _ => usage(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn shadowsocks_server_password_shape() {
        let root = crate::json::parse(
            r#"{"inbounds": [{"protocol": "shadowsocks", "settings": {"method": "aes-256-gcm",
            "password": "an-example-shared-password"}}]}"#,
        )
        .expect("parses");
        let inbound = &root
            .get("inbounds")
            .expect("inbounds")
            .as_arr()
            .expect("array")[0];
        assert_eq!(
            crate::proxy::inbound_ss_password(inbound),
            "an-example-shared-password"
        );
    }

    #[test]
    fn brief_link_checks() {
        let link = ferrox_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&host=%2Ftest-path&headerType=none&fp=firefox&type=tcp&flow=xtls-rprx-vision&sni=example.com&sid=a8#x",
        )
        .expect("parses");
        assert!(link.is_first_method());
    }
}
