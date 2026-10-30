//! One trace through a front proves a lane carries bytes. The probe is curl on
//! every platform: Windows ships it, and the two proxy spellings are the same.

use std::path::PathBuf;
use std::process::{Command, Stdio};

pub fn trace_timeout() -> u64 {
    20
}

fn candidates() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let mut paths = Vec::new();
        if let Some(root) = std::env::var_os("SystemRoot") {
            paths.push(PathBuf::from(root).join("System32").join("curl.exe"));
        }
        paths.push(PathBuf::from(r"C:\Windows\System32\curl.exe"));
        paths.push(PathBuf::from("curl.exe"));
        paths.push(PathBuf::from("curl"));
        paths
    }
    #[cfg(not(windows))]
    {
        vec![
            PathBuf::from("/usr/bin/curl"),
            PathBuf::from("/usr/local/bin/curl"),
            PathBuf::from("curl"),
        ]
    }
}

fn curl(args: &[String], timeout: u64) -> String {
    for binary in candidates() {
        if binary.is_absolute() && !binary.exists() {
            continue;
        }
        let output = Command::new(&binary)
            .args(args)
            .args([
                "--noproxy",
                "",
                "--fail",
                "--max-filesize",
                "65536",
                "--max-time",
                &timeout.to_string(),
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output();
        match output {
            Ok(output) if output.status.success() => {
                return String::from_utf8_lossy(&output.stdout).into_owned();
            }
            Ok(_) => return String::new(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return String::new(),
        }
    }
    String::new()
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
    curl(&args, timeout)
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
