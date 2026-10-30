//! One trace through a front proves a lane carries bytes. The probe is curl on
//! every platform: Windows ships it, and the two proxy spellings are the same.

use std::process::{Command, Stdio};

pub fn trace_timeout() -> u64 {
    20
}

fn curl(binary: &str, args: &[String], timeout: u64) -> String {
    let output = Command::new(binary)
        .args(args)
        .args(["--noproxy", "", "--max-time", &timeout.to_string()])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    output
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}

fn through_proxy(front: &str, port: u16, url: &str, timeout: u64) -> String {
    let mut args = vec!["-s".to_owned()];
    if front == "socks" {
        args.push("--socks5-hostname".to_owned());
        args.push(format!("127.0.0.1:{port}"));
    } else {
        args.push("-x".to_owned());
        args.push(format!("http://127.0.0.1:{port}"));
    }
    args.push(url.to_owned());
    let first = curl("curl.exe", &args, timeout);
    if first.is_empty() {
        curl("curl", &args, timeout)
    } else {
        first
    }
}

pub fn probe_front(front: &str, port: u16, timeout: u64) -> String {
    through_proxy(
        front,
        port,
        "https://www.cloudflare.com/cdn-cgi/trace",
        timeout,
    )
}

pub fn probe_plain(front: &str, port: u16, timeout: u64) -> String {
    through_proxy(front, port, "http://example.com/", timeout)
}

pub fn exit_line(answer: &str) -> String {
    answer
        .lines()
        .filter(|line| line.starts_with("ip=") || line.starts_with("loc="))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn exit_country(answer: &str) -> String {
    answer
        .lines()
        .find_map(|line| line.strip_prefix("loc="))
        .map(str::to_uppercase)
        .unwrap_or_default()
}

pub fn carries_trace(answer: &str) -> bool {
    answer
        .lines()
        .any(|line| line.starts_with("ip=") || line.starts_with("loc="))
}
