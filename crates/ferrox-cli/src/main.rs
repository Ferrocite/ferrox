#![allow(
    clippy::assigning_clones,
    clippy::borrow_as_ptr,
    clippy::chunks_exact_to_as_chunks,
    clippy::match_same_arms,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

mod args;
mod config;
mod credentials;
mod lane;
mod locations;
mod paths;
mod probe;
mod proxy;

use std::fs::File;
use std::io::{IsTerminal as _, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use args::{Action, Options, Outbound};
use config::{fronts, port_of, FoxyAccount, Ports};
use paths::{read_trim, Paths};

fn main() {
    let mut options = args::parse();
    let mut paths = Paths::new(options.instance.as_deref());
    let code = match options.action {
        Action::Up => up(&mut options, &mut paths, false),
        Action::Serve => up(&mut options, &mut paths, true),
        Action::Down => down(&options, &paths),
        Action::Status => status(&options, &paths),
        Action::Ports => {
            ports(&options, &paths);
            0
        }
        Action::Tun => {
            tun();
            0
        }
        Action::Login => {
            reconcile(&paths);
            credentials::login(&options, &paths).unwrap_or_else(|error| args::die(&error));
            0
        }
        Action::Logout => logout(&paths),
        Action::Locations => {
            locations::list(&paths, &options.loc_filter, options.ping)
                .unwrap_or_else(|error| args::die(&error));
            0
        }
        Action::Location => {
            locations::remember(&paths, &options.loc_country, &options.loc_city)
                .unwrap_or_else(|error| args::die(&error));
            0
        }
        Action::Version => version(&paths),
        Action::Supervise => supervise(&options, &paths),
    };
    exit(code);
}

fn reconcile(paths: &Paths) {
    if paths.proxy_state.exists() && !lane::running(paths) {
        proxy::clear(paths);
    }
}

fn choose_carrier(options: &Options) -> String {
    if options.outbound != Some(Outbound::Foxy)
        || options.carrier_set
        || !std::io::stdin().is_terminal()
    {
        return options.carrier.clone();
    }
    println!("carrier: where the lane sends its flows (name --carrier to skip this):");
    println!("  1) auto  h2, then h1, then h3 — the fastest that answers (default)");
    println!("  2) h2    HTTPS/2 on a session reused across flows");
    println!("  3) h1    one TLS connection per flow");
    println!("  4) h3    QUIC; also carries UDP. Falls back to h2, then h1");
    print!("carrier [auto]: ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    let _ = std::io::stdin().read_line(&mut answer);
    match answer.trim().to_lowercase().as_str() {
        "" | "1" | "auto" => "auto".to_owned(),
        "2" | "h2" => "h2".to_owned(),
        "3" | "h1" => "h1".to_owned(),
        "4" | "h3" => "h3".to_owned(),
        other => {
            println!("carrier: '{other}' is not one of the four; using auto.");
            "auto".to_owned()
        }
    }
}

fn duplicate_fronts(list: &str, ports: Ports) {
    let mut seen: Vec<u16> = Vec::new();
    for front in fronts(list) {
        let port = port_of(&front, ports);
        if seen.contains(&port) {
            args::die(&format!(
                "two fronts cannot share port {port}; nothing was started."
            ));
        }
        seen.push(port);
    }
}

fn prepare(options: &mut Options, paths: &mut Paths) -> (Ports, bool) {
    let user_config = options.outbound == Some(Outbound::Config);
    if user_config {
        if !Path::new(&options.config_file).is_file() {
            args::die(&format!("no such config: {}", options.config_file));
        }
        let list = config::config_fronts(
            &options.config_file,
            options.vpn,
            options.fronts_set,
            &options.fronts,
        )
        .unwrap_or_else(|error| args::die(&error));
        options.fronts = list;
        paths.cfg = PathBuf::from(&options.config_file);
        options.socks_set = false;
        options.http_set = false;
        options.mixed_set = false;
        let ports = config::plan_ports(options, paths, false);
        duplicate_fronts(&options.fronts, ports);
        (ports, true)
    } else {
        let ports = config::plan_ports(options, paths, options.instance.is_some());
        duplicate_fronts(&options.fronts, ports);
        (ports, false)
    }
}

fn foxy_account(options: &mut Options, paths: &Paths) -> FoxyAccount {
    config::load_foxy_location(options, paths);
    credentials::resolve(options, paths).unwrap_or_else(|error| args::die(&error))
}

fn write_lane_config(
    options: &Options,
    paths: &Paths,
    ports: Ports,
    account: Option<&FoxyAccount>,
) {
    if options.outbound == Some(Outbound::Config) {
        return;
    }
    let outbound =
        config::build_outbound(options, paths, account).unwrap_or_else(|error| args::die(&error));
    config::write_config(&paths.cfg, &outbound, &options.fronts, ports)
        .unwrap_or_else(|error| args::die(&error));
    if options.outbound == Some(Outbound::Foxy) {
        config::save_foxy_location(options, paths).unwrap_or_else(|error| args::die(&error));
    }
}

fn up(options: &mut Options, paths: &mut Paths, serve: bool) -> i32 {
    reconcile(paths);
    let (ports, user_config) = prepare(options, paths);
    if options.vpn {
        if let Err(error) = proxy::preflight(&options.fronts, ports) {
            eprintln!("{error}");
            return 1;
        }
    }
    options.carrier = choose_carrier(options);
    let account = if options.outbound == Some(Outbound::Foxy) {
        Some(foxy_account(options, paths))
    } else {
        None
    };
    let bin = lane::require_bin();
    write_lane_config(options, paths, ports, account.as_ref());
    if lane::running(paths) {
        println!(
            "a lane{} is already running (pid {}); stopping it first.",
            options
                .instance
                .as_ref()
                .map_or_else(String::new, |name| format!(" '{name}'")),
            lane::pid(paths).unwrap_or_default()
        );
        lane::stop(paths);
    }
    let pid = lane::start(&bin, paths, options.debug).unwrap_or_else(|error| args::die(&error));
    let interrupted = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&interrupted);
    let watched = paths.clone();
    let _ = ctrlc::set_handler(move || {
        lane::stop(&watched);
        if !user_config {
            let _ = std::fs::remove_file(&watched.cfg);
        }
        proxy::clear(&watched);
        flag.store(true, Ordering::SeqCst);
    });

    if !fronts(&options.fronts).is_empty() && !lane::wait_fronts(&options.fronts, ports, paths) {
        println!(
            "the lane did not open its fronts; last lines of {}:",
            paths.log.display()
        );
        tail(&paths.log, 20);
        stop_and_forget(paths, user_config);
        return 3;
    }
    if interrupted.load(Ordering::SeqCst) {
        return 130;
    }
    println!(
        "lane{} up (pid {pid}), fronts:",
        options
            .instance
            .as_ref()
            .map_or_else(String::new, |name| format!(" '{name}'"))
    );
    port_map(options, ports);
    if options.outbound == Some(Outbound::Foxy) {
        println!("carrier: {}", options.carrier);
    }
    if !fronts(&options.fronts).is_empty() && !verify_flow(options, ports, paths) {
        stop_and_forget(paths, user_config);
        return 3;
    }
    if options.vpn {
        if let Err(error) = proxy::arm(paths, &options.fronts, ports) {
            eprintln!("{error}");
            stop_and_forget(paths, user_config);
            return 1;
        }
        if !serve {
            spawn_supervisor(paths, pid, options.instance.as_deref());
        }
    }
    println!("log:  {}", paths.log.display());
    if serve {
        println!("Ctrl-C stops it.");
        while lane::running(paths) && !interrupted.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(1));
        }
        if interrupted.load(Ordering::SeqCst) {
            stop_and_forget(paths, user_config);
            return 130;
        }
        println!("the lane exited; last lines of {}:", paths.log.display());
        tail(&paths.log, 15);
        stop_and_forget(paths, user_config);
        0
    } else {
        println!("stop: ferrox-cli down");
        0
    }
}

fn spawn_supervisor(paths: &Paths, pid: u32, instance: Option<&str>) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let mut command = std::process::Command::new(exe);
    command
        .arg("__supervise")
        .arg(pid.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some(name) = instance {
        command.arg("--instance").arg(name);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x0800_0000);
    }
    if let Ok(child) = command.spawn() {
        let _ = paths::write_private(&paths.supervisor_pid, &format!("{}\n", child.id()));
    }
}

fn stop_and_forget(paths: &Paths, user_config: bool) {
    lane::stop(paths);
    if !user_config {
        let _ = std::fs::remove_file(&paths.cfg);
    }
    proxy::clear(paths);
    let _ = std::fs::remove_file(&paths.supervisor_file);
    let _ = std::fs::remove_file(&paths.supervisor_pid);
    if user_config {
        println!(
            "the lane was stopped; your config is untouched and the log stays at {}.",
            paths.log.display()
        );
    } else {
        println!(
            "the lane was stopped and its config removed; the log stays at {}.",
            paths.log.display()
        );
    }
}

fn verify_flow(options: &Options, ports: Ports, paths: &Paths) -> bool {
    let front = fronts(&options.fronts)
        .first()
        .cloned()
        .unwrap_or_else(|| "socks".to_owned());
    let port = port_of(&front, ports);
    let answer = probe::probe_front(&front, port, probe::trace_timeout());
    if !probe::carries_trace(&answer) {
        if options.outbound == Some(Outbound::Veepn)
            && probe::probe_plain(&front, port, probe::trace_timeout()).contains("Example Domain")
        {
            println!("exit through {front}: a plain HTTP flow answered.");
            return true;
        }
        println!("NOT CONNECTED: the fronts are up, but no flow got through them.");
        diagnose(options, paths);
        return false;
    }
    println!("exit through {front}: {}", probe::exit_line(&answer));
    let want = options.country.to_uppercase();
    let got = probe::exit_country(&answer);
    if options.outbound == Some(Outbound::Veepn) {
        let pinned = config::effective_region(options);
        if !pinned.is_empty() && got.to_lowercase() != pinned {
            println!(
                "note: the exit reads {}, not the pinned {pinned}; the plane's pool can route elsewhere, so the front is carrying the flow either way.",
                if got.is_empty() { "unreadable" } else { &got }
            );
        }
    }
    if options.outbound == Some(Outbound::Foxy) && want != "REC" && got != want {
        println!(
            "the exit reads {}, not the pinned {want}: that is either another country's edge or this machine's own address, so the lane is not carrying it.",
            if got.is_empty() { "unreadable" } else { &got }
        );
        diagnose(options, paths);
        return false;
    }
    true
}

fn diagnose(options: &Options, paths: &Paths) {
    let log = read_tail(&paths.log, 64 * 1024);
    if log.trim().is_empty() {
        println!(
            "the lane log is empty: it refused the flow without saying why. Re-run with --debug for the dial trace."
        );
        return;
    }
    println!(
        "the lane's own words, last lines of {}:",
        paths.log.display()
    );
    tail(&paths.log, 8);
    if options.outbound == Some(Outbound::Veepn) {
        println!("diagnosis: the plane answered no list this lane can dial; the lines above name the region and the reason.");
    } else if log.contains("handshake with the edge failed") {
        println!("diagnosis: TLS to the edge never completed. That is the network, not the account: chain the dial through a proxy this network does allow:");
        println!("  ferrox-cli up --foxy --upstream socks5://127.0.0.1:PORT");
    } else if log.contains("did not sign in") || log.contains("token was refused") {
        println!("diagnosis: the lane never signed in. Check the account, or pass --code 123456 for two-factor.");
    } else if log.contains("no quota left") || log.contains("answered 429") {
        println!("diagnosis: the plane is refusing this account for quota; wait for the reset, or move the exit with --country.");
    } else {
        println!("diagnosis: none of the known shapes; the lines above are all there is.");
    }
}

fn down(options: &Options, paths: &Paths) -> i32 {
    if options.all {
        let rc = stop_all_lanes(paths);
        proxy::clear(paths);
        let _ = std::fs::remove_file(&paths.lanes_file);
        let _ = std::fs::remove_file(&paths.proxy_owner);
        if rc == 0 {
            println!("every lane is stopped and its config removed. The stored foxy session is kept; 'ferrox-cli logout' forgets it.");
        }
        return rc;
    }
    let rc = stop_lane(paths);
    forget_config(paths);
    if rc != 0 {
        eprintln!(
            "lane stopped, but the system proxy was not cleared; run 'ferrox-cli down' again."
        );
    } else {
        println!("lane{} stopped; the lane config is removed. The stored foxy session is kept; 'ferrox-cli logout' forgets it.",
            options
                .instance
                .as_ref()
                .map_or_else(String::new, |name| format!(" '{name}'")));
    }
    rc
}

fn stop_lane(paths: &Paths) -> i32 {
    lane::stop(paths);
    proxy::clear(paths);
    0
}

fn forget_config(paths: &Paths) {
    let name = paths
        .cfg
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let is_json = paths
        .cfg
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
    if paths.cfg.parent() == Some(paths.conf_dir.as_path()) && name.starts_with("lane") && is_json {
        let _ = std::fs::remove_file(&paths.cfg);
    }
}

fn stop_all_lanes(paths: &Paths) -> i32 {
    let mut rc = 0;
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(text) = read_trim(&paths.lanes_file) {
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            dirs.push(PathBuf::from(line));
        }
    }
    if !dirs.iter().any(|dir| dir == &paths.conf_dir) {
        dirs.push(paths.conf_dir.clone());
    }
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(rest) = name.strip_prefix("lane") else {
                continue;
            };
            let Some(rest) = rest.strip_suffix(".pid") else {
                continue;
            };
            let instance = rest.strip_prefix('-');
            let lane_paths = Paths::with_dirs(dir.clone(), paths.state_dir.clone(), instance);
            if stop_lane(&lane_paths) != 0 {
                rc = 1;
            }
            forget_config(&lane_paths);
        }
    }
    rc
}

fn status(options: &Options, paths: &Paths) -> i32 {
    reconcile(paths);
    if !lane::running(paths) {
        println!(
            "lane{} not running.",
            options
                .instance
                .as_ref()
                .map_or_else(String::new, |name| format!(" '{name}'"))
        );
        if let Some(endpoint) = proxy::armed_endpoint(paths) {
            println!("system proxy points at {endpoint} but no lane owns it; run 'ferrox-cli down' to clear it.");
        }
        for (name, pid) in lane::other_lanes(paths) {
            println!("instance {name} is running (pid {pid}).");
        }
        if paths.token_file.exists() {
            println!(
                "foxy session stored in {}: the next up --foxy resumes it without a sign-in mail.",
                paths.token_file.display()
            );
        }
        return 1;
    }
    println!(
        "lane{} pid {}, fronts:",
        options
            .instance
            .as_ref()
            .map_or_else(String::new, |name| format!(" '{name}'")),
        lane::pid(paths).unwrap_or_default()
    );
    let ports = config::plan_ports(options, paths, false);
    port_map(options, ports);
    if let Some(uptime) = lane::uptime(paths) {
        println!("up for {uptime}");
    }
    let log = read_tail(&paths.log, 64 * 1024);
    if let Some(carrier) = log
        .lines()
        .filter_map(|line| line.strip_prefix("foxy: carrier "))
        .next_back()
    {
        println!("carrier: {carrier}");
    }
    if let Some(quota) = log
        .lines()
        .filter_map(|line| line.strip_prefix("foxy: allowance "))
        .next_back()
    {
        println!("quota left: {quota}");
    } else if lane::foxy_configured(paths) {
        println!("quota: the plane named no allowance for the pass this lane carries: that is silence, not zero.");
    }
    let front = fronts(&options.fronts)
        .first()
        .cloned()
        .unwrap_or_else(|| "socks".to_owned());
    let port = port_of(&front, ports);
    println!("exit through {front} ({port}):");
    let answer = probe::probe_front(&front, port, 30);
    if probe::carries_trace(&answer) {
        println!("{}", probe::exit_line(&answer));
    } else {
        println!("no answer through the front; see {}", paths.log.display());
    }
    0
}

fn ports(options: &Options, paths: &Paths) {
    let ports = config::plan_ports(options, paths, false);
    println!("----------------------------------------------------------------");
    println!("local fronts (127.0.0.1 only):");
    port_map(options, ports);
    if options.instance.is_some() {
        println!("----------------------------------------------------------------");
        if !paths.cfg.exists() {
            println!(
                "instance '{}' has not started: these are the defaults it moves off if they are taken.",
                options.instance.as_deref().unwrap_or_default()
            );
        }
        println!("point the app you want at these fronts: the system proxy is one");
        println!("machine-wide setting, so an instance never arms it (--vpn belongs to the");
        println!("unnamed lane).");
        return;
    }
    println!("----------------------------------------------------------------");
    println!("Windows, Settings > Network & Internet > Proxy > Manual proxy setup:");
    println!("  Use a proxy server: 127.0.0.1:{} (HTTP)", ports.http);
    println!("  SOCKS proxy:        127.0.0.1:{}", ports.socks);
    println!("Leave authentication off (the fronts are unauthenticated and loopback-only).");
    println!();
    println!("One app instead of the whole system:");
    println!(
        "  curl --socks5-hostname 127.0.0.1:{} https://example.com",
        ports.socks
    );
    println!(
        "  curl -x http://127.0.0.1:{} https://example.com",
        ports.http
    );
    println!("  set HTTPS_PROXY=http://127.0.0.1:{}", ports.http);
    println!("  set ALL_PROXY=socks5h://127.0.0.1:{}", ports.socks);
}

fn port_map(options: &Options, ports: Ports) {
    for front in fronts(&options.fronts) {
        match front.as_str() {
            "socks" => println!(
                "  SOCKS5        socks5://127.0.0.1:{}   (curl --socks5-hostname, UDP-aware)",
                ports.socks
            ),
            "http" => println!(
                "  HTTP + HTTPS  http://127.0.0.1:{}     (CONNECT tunnels, plain forwards)",
                ports.http
            ),
            "mixed" => println!(
                "  mixed         http://127.0.0.1:{}     (SOCKS5 and HTTP on one port)",
                ports.mixed
            ),
            _ => {}
        }
    }
}

fn tun() {
    println!("TUN mode is refused by this binary, by name, not by silence.");
    println!();
    println!("What TUN would be: a virtual network device that takes every IP packet,");
    println!("so apps that ignore proxies are captured too, UDP included. That needs a");
    println!("device driver, a userspace IP stack, and administrator rights.");
    println!();
    println!("What this binary has: no tun inbound and no tun2socks engine. A config");
    println!("naming one is refused with that reason, and `--tun` here refuses before");
    println!("anything starts.");
    println!();
    println!("What you get instead:");
    println!("  ferrox-cli up --vpn      the Windows proxy: TCP apps that honour it");
    println!("  ferrox-cli up --fronts socks   UDP for apps that speak SOCKS5");
}

fn version(paths: &Paths) -> i32 {
    let bin = lane::require_bin();
    let dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| paths.conf_dir.clone());
    println!("ferrox-cli at {}", dir.display());
    std::process::Command::new(bin)
        .arg("version")
        .status()
        .map_or(1, |status| status.code().unwrap_or(1))
}

fn logout(paths: &Paths) -> i32 {
    let rc = stop_all_lanes(paths);
    proxy::clear(paths);
    let _ = std::fs::remove_file(&paths.token_file);
    let _ = std::fs::remove_file(&paths.creds);
    forget_config(paths);
    println!("signed out: every lane is stopped, and the stored session, the saved account and the lane configs are gone.");
    println!(
        "the remembered exit stays in {}; 'ferrox-cli login' signs in again.",
        paths.location_file.display()
    );
    rc
}

fn supervise(options: &Options, paths: &Paths) -> i32 {
    let Some(watched) = options.supervise_pid else {
        return 0;
    };
    let _ = paths::write_private(&paths.supervisor_file, &format!("{watched}\n"));
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let pid = watched;
    let watched_paths = paths.clone();
    let _ = ctrlc::set_handler(move || {
        lane::kill(pid);
        proxy::clear(&watched_paths);
        flag.store(true, Ordering::SeqCst);
    });
    while lane::alive(watched) && !stop.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(1));
    }
    let current = lane::pid(paths);
    if current.is_none() || current == Some(watched) {
        proxy::clear(paths);
        let _ = std::fs::remove_file(&paths.pid_file);
    }
    if read_trim(&paths.supervisor_file).as_deref() == Some(watched.to_string().as_str()) {
        let _ = std::fs::remove_file(&paths.supervisor_file);
        let _ = std::fs::remove_file(&paths.supervisor_pid);
    }
    0
}

fn read_tail(path: &Path, max_bytes: u64) -> String {
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let Ok(metadata) = file.metadata() else {
        return String::new();
    };
    let start = metadata.len().saturating_sub(max_bytes);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut bytes = Vec::new();
    if file.take(max_bytes).read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn tail(path: &Path, lines: usize) {
    let text = read_tail(path, 64 * 1024);
    let all: Vec<&str> = text.lines().collect();
    let start = all.len().saturating_sub(lines);
    for line in &all[start..] {
        println!("{line}");
    }
}
