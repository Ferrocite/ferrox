// The census is a test-shape instrument: here its call expands to nothing, so no shipped relay carries a map, a lock or a name.
#[cfg(not(test))]
macro_rules! census {
    ($name:literal, $fd:expr, $armed:expr) => {};
}

// The counting allocator is core's and the window is one thread's: installed only for the test binary, so a shipped flow keeps the system allocator.
#[cfg(test)]
#[global_allocator]
static ALLOC_COUNT: ferrox_core::alloc_count::Counting = ferrox_core::alloc_count::Counting;

mod budgets;
#[cfg(test)]
#[macro_use]
mod census;
mod blackhole;
mod config;
mod conn;
mod ech_dns;
mod foxy;
mod foxy_account;
mod foxy_catalog;
mod foxy_challenge;
mod foxy_latency;
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
mod router;
mod shadowsocks;
mod shadowsocks2022;
mod sockopt;
mod socks;
mod tun;
mod veepn;
mod vision;
mod vmess;
mod ws;
mod xdrive;
mod xhttp;
mod xhttp_h2;
mod xray_pb;

use ferrox_core::policy::UnsafeOptIn;
use ferrox_core::transport::Support;
use std::io::Read as _;
use std::io::Write as _;
use std::time::Duration;

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  ferrox-app check <vless://...> [--allow-unsafe-fp] [--allow-plaintext-public]   parse + support + header len (no network)");
    eprintln!("  ferrox-app run <vless://...> [--allow-unsafe-fp] [--allow-plaintext-public]     check + TCP reachability (sends nothing)");
    eprintln!("  ferrox-app version                print the serving binary's version");
    eprintln!("  ferrox-app x25519                 print a fresh X25519 keypair");
    eprintln!("  ferrox-app run -c <config.json>   serve inbounds until killed");
    eprintln!("  ferrox-app -config=<file|stdin:> [-format=json|pb]   same, xray's own invocation");
    eprintln!("  ferrox-app mint-foxy-pass -c <config.json> -o <pass.json>");
    eprintln!("                                sign in once, store the proxy pass (0600)");
    eprintln!(
        "  ferrox-app edges [--ping]         list the catalogue's edges as JSON rows; --ping adds a handshake ms (null when silent)"
    );
    std::process::exit(2);
}

/// One share link plus any out-of-band consent flags, in either order.
fn link_and_opt_in<I: Iterator<Item = String>>(args: &mut I) -> (String, UnsafeOptIn) {
    let mut link: Option<String> = None;
    let mut opt = UnsafeOptIn::none();
    for arg in args {
        match arg.as_str() {
            "--allow-unsafe-fp" => opt = opt.allow_unsafe_fingerprint(),
            "--allow-plaintext-public" => opt = opt.allow_plaintext_to_public(),
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
            println!("needs explicit opt-in (policy::UnsafeOptIn, or --allow-unsafe-fp / --allow-plaintext-public): {reason}");
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
            let rest: Vec<String> = args.collect();
            if rest.first().is_some_and(|arg| is_serve_flag(arg)) {
                serve_from_flags(&rest);
            }
            let mut iter = rest.into_iter();
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
            let mut ping = false;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--ping" => ping = true,
                    // A config is accepted and ignored for the spelling the docs already carry: the catalogue needs no lane.
                    "-c" | "-config" => {
                        args.next().unwrap_or_else(|| usage());
                    }
                    _ => usage(),
                }
            }
            proxy::print_foxy_edges(ping);
        }
        "x25519" => {
            if args.next().is_some() {
                usage();
            }
            proxy::print_x25519();
        }
        _ if is_serve_flag(&cmd) => {
            let rest: Vec<String> = std::iter::once(cmd).chain(args).collect();
            serve_from_flags(&rest);
        }
        _ => usage(),
    }
}

/// A flag xray itself takes for a config; `run <link> --allow-unsafe-fp` is link mode.
fn is_serve_flag(arg: &str) -> bool {
    matches!(
        arg.split('=').next().unwrap_or(arg),
        "-c" | "-config" | "-confdir" | "-format" | "-test" | "-dump"
    )
}

/// xray's own invocation (`-config=stdin: -format=pb`) and the `run -c <file>`
/// spelling this tree shipped first; one config per process either way.
fn serve_from_flags(args: &[String]) -> ! {
    let mut configs: Vec<String> = Vec::new();
    let mut format: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) => (flag, Some(value.to_owned())),
            None => (arg.as_str(), None),
        };
        match flag {
            "-c" | "-config" | "-format" => {
                let value = if let Some(value) = inline {
                    value
                } else {
                    i += 1;
                    args.get(i).cloned().unwrap_or_else(|| usage())
                };
                if flag == "-format" {
                    format = Some(value);
                } else {
                    configs.push(value);
                }
            }
            "-confdir" => {
                eprintln!("ferrox-app: -confdir needs README row 127 (multi-file config layering); refused");
                std::process::exit(1);
            }
            "-test" | "-dump" => {
                eprintln!("ferrox-app: {flag} is not carried; this binary serves");
                std::process::exit(1);
            }
            _ => usage(),
        }
        i += 1;
    }
    if configs.len() > 1 {
        eprintln!(
            "ferrox-app: {} -config files need README row 127 (multi-file config layering); refused",
            configs.len()
        );
        std::process::exit(1);
    }
    let Some(source) = configs.pop() else { usage() };
    let format = source_format(format.as_deref(), &source);
    if source == "stdin" || source == "stdin:" {
        let mut bytes = Vec::new();
        if let Err(error) = std::io::stdin().read_to_end(&mut bytes) {
            eprintln!("ferrox-app: cannot read stdin: {error}");
            std::process::exit(1);
        }
        serve_source("stdin:", &bytes, format);
    }
    let bytes = std::fs::read(&source).unwrap_or_else(|error| {
        eprintln!("cannot read {source}: {error}");
        std::process::exit(1);
    });
    serve_source(&source, &bytes, format)
}

#[derive(Clone, Copy)]
enum SourceFormat {
    Json,
    Protobuf,
}

/// xray infers the format from the extension when `-format` is absent; a stream
/// has none, and JSON is this tree's own dialect.
fn source_format(named: Option<&str>, source: &str) -> SourceFormat {
    match named.map(str::to_ascii_lowercase).as_deref() {
        Some("pb" | "protobuf") => SourceFormat::Protobuf,
        Some("json" | "jsonc") => SourceFormat::Json,
        Some("auto") | None => {
            let extension = std::path::Path::new(source)
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or_default();
            if extension.eq_ignore_ascii_case("pb") || extension.eq_ignore_ascii_case("protobuf") {
                SourceFormat::Protobuf
            } else {
                SourceFormat::Json
            }
        }
        Some(other @ ("toml" | "yaml" | "yml")) => {
            eprintln!("ferrox-app: config format `{other}` is not carried; json and protobuf are");
            std::process::exit(1);
        }
        Some(other) => {
            eprintln!("ferrox-app: unknown config format `{other}`");
            std::process::exit(1);
        }
    }
}

fn serve_source(label: &str, bytes: &[u8], format: SourceFormat) -> ! {
    match format {
        SourceFormat::Protobuf => proxy::serve_protobuf(label, bytes),
        SourceFormat::Json => {
            let text = std::str::from_utf8(bytes).unwrap_or_else(|error| {
                eprintln!("bad config {label}: {error}");
                std::process::exit(1);
            });
            proxy::serve_json(label, text)
        }
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

    #[test]
    fn both_out_of_band_consents_parse_in_either_order() {
        let mk = |args: [&str; 3]| {
            let mut it = args.iter().map(|s| (*s).to_owned());
            crate::link_and_opt_in(&mut it)
        };
        // A bare link carries neither consent.
        let (_, opt) = crate::link_and_opt_in(&mut ["vless://x".to_owned()].into_iter());
        assert!(!opt.unsafe_fingerprint() && !opt.plaintext_to_public());
        // Both flags flip their own consent and leave the other off, before or after the link.
        for (a, b) in [
            ("--allow-unsafe-fp", "--allow-plaintext-public"),
            ("--allow-plaintext-public", "--allow-unsafe-fp"),
        ] {
            let (link, opt) = mk(["vless://x", a, b]);
            assert_eq!(link, "vless://x");
            assert!(opt.unsafe_fingerprint() && opt.plaintext_to_public());
        }
    }

    /// The window reaches across the crate boundary: what an app test allocates is counted by core's allocator, so a count taken here measures the app.
    #[test]
    fn a_count_taken_here_sees_what_the_app_allocates() {
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            let buffer = vec![0u8; 64];
            std::hint::black_box(&buffer);
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (1, 64, 1),
            "this test binary is not running on the allocator whose window `measure` opens"
        );
    }
}
