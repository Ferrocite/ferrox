//! One lane is one child process. The pid file is the truth about whether it is
//! alive; a log beside the config is where the engine says what it is doing.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::args::die;
use crate::config::{fronts, port_of, Ports};
use crate::paths::{read_trim, read_trim_checked, secure_dir, write_private, Paths};

pub fn require_bin() -> PathBuf {
    if let Some(path) = std::env::var_os("FERROX_BIN") {
        return PathBuf::from(path);
    }
    let name = if cfg!(windows) {
        "ferrox-app.exe"
    } else {
        "ferrox-app"
    };
    let beside = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join(name)));
    if let Some(path) = beside.filter(|path| path.exists()) {
        return path;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let cargo_target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    let built = cargo_target.join("release").join(if cfg!(windows) {
        "ferrox-app.exe"
    } else {
        "ferrox-app"
    });
    if built.exists() {
        return built;
    }
    #[cfg(debug_assertions)]
    if root.join("Cargo.toml").exists() {
        eprintln!("building ferrox-app (release, one time)...");
        let status = Command::new("cargo")
            .args(["build", "--locked", "--release", "-p", "ferrox-app"])
            .current_dir(&root)
            .status();
        if status.is_ok_and(|status| status.success()) && built.exists() {
            return built;
        }
    }
    die(&format!(
        "no binary at {}: unpack a release package beside this launcher, or build one: cargo build --release -p ferrox-app",
        built.display()
    ))
}

pub fn pid(paths: &Paths) -> Option<u32> {
    read_trim(&paths.pid_file).and_then(|text| text.parse().ok())
}

pub fn alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = i32::try_from(pid) else {
            return false;
        };
        unsafe { libc::kill(pid, 0) == 0 }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }
        let mut code = 0_u32;
        let ok = unsafe { GetExitCodeProcess(handle, &mut code) };
        unsafe { CloseHandle(handle) };
        ok != 0 && code == STILL_ACTIVE as u32
    }
}

pub fn running(paths: &Paths) -> bool {
    pid(paths).is_some_and(alive)
}

fn process_exe(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        (!path.is_empty()).then(|| PathBuf::from(path))
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return None;
        }
        let mut buffer = vec![0_u16; 32_768];
        let mut length = buffer.len() as u32;
        let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut length) };
        unsafe { CloseHandle(handle) };
        if ok == 0 {
            return None;
        }
        Some(PathBuf::from(String::from_utf16_lossy(
            &buffer[..length as usize],
        )))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = pid;
        None
    }
}

fn expected_bin() -> PathBuf {
    if let Some(path) = std::env::var_os("FERROX_BIN") {
        return PathBuf::from(path);
    }
    let name = if cfg!(windows) {
        "ferrox-app.exe"
    } else {
        "ferrox-app"
    };
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join(name)))
        .unwrap_or_default()
}

fn same_exe(actual: &Path, expected: &Path) -> bool {
    let actual = std::fs::canonicalize(actual).unwrap_or_else(|_| actual.to_path_buf());
    let expected = std::fs::canonicalize(expected).unwrap_or_else(|_| expected.to_path_buf());
    #[cfg(windows)]
    {
        actual
            .to_string_lossy()
            .eq_ignore_ascii_case(&expected.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        actual == expected
    }
}

fn is_ferrox(pid: u32) -> bool {
    let Some(actual) = process_exe(pid) else {
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        return true;
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        return false;
    };
    same_exe(&actual, &expected_bin())
}

pub fn kill(pid: u32) {
    if !is_ferrox(pid) {
        eprintln!(
            "ferrox-cli: process {pid} is not ferrox-app; it was not stopped. If the binary was renamed, set FERROX_BIN."
        );
        return;
    }
    #[cfg(unix)]
    {
        let Ok(pid) = i32::try_from(pid) else {
            return;
        };
        unsafe { libc::kill(pid, libc::SIGTERM) };
        std::thread::sleep(Duration::from_secs(1));
        if unsafe { libc::kill(pid, 0) } == 0 {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, TerminateProcess, PROCESS_TERMINATE,
        };
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if !handle.is_null() {
            unsafe {
                TerminateProcess(handle, 1);
                CloseHandle(handle);
            }
        }
    }
}

fn register(paths: &Paths) -> Result<(), String> {
    secure_dir(&paths.state_dir)
        .map_err(|error| format!("cannot create the state dir: {error}"))?;
    let text = match read_trim_checked(&paths.lanes_file) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(format!(
                "cannot read {}: {error}",
                paths.lanes_file.display()
            ));
        }
    };
    let conf = paths.conf_dir.to_string_lossy();
    if text.lines().any(|line| line == conf) {
        return Ok(());
    }
    let current = std::fs::metadata(&paths.lanes_file).map_or(0, |meta| meta.len());
    let addition = conf.len() as u64 + 1;
    if current.saturating_add(addition) > crate::paths::MAX_PRIVATE_BYTES {
        return Err(format!(
            "the lane registry {} would exceed {} bytes; nothing was started.",
            paths.lanes_file.display(),
            crate::paths::MAX_PRIVATE_BYTES
        ));
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.lanes_file)
        .map_err(|error| format!("cannot append to {}: {error}", paths.lanes_file.display()))?;
    writeln!(file, "{conf}")
        .map_err(|error| format!("cannot append to {}: {error}", paths.lanes_file.display()))?;
    if file.metadata().map_or(current, |meta| meta.len()) > crate::paths::MAX_PRIVATE_BYTES {
        let _ = file.set_len(current);
        return Err(format!(
            "the lane registry {} exceeded {} bytes; the entry was rolled back.",
            paths.lanes_file.display(),
            crate::paths::MAX_PRIVATE_BYTES
        ));
    }
    Ok(())
}

pub fn start(bin: &Path, paths: &Paths, debug: bool) -> Result<u32, String> {
    secure_dir(&paths.conf_dir)
        .map_err(|error| format!("cannot create the config dir: {error}"))?;
    secure_dir(&paths.state_dir)
        .map_err(|error| format!("cannot create the state dir: {error}"))?;
    register(paths)?;
    let out = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&paths.log)
        .map_err(|error| format!("cannot open {}: {error}", paths.log.display()))?;
    let err = out
        .try_clone()
        .map_err(|error| format!("cannot open {}: {error}", paths.log.display()))?;
    let mut command = Command::new(bin);
    command
        .arg("run")
        .arg("-c")
        .arg(&paths.cfg)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err);
    if debug {
        command.env("FOXY_DEBUG", "1");
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x0800_0000);
    }
    let child = command
        .spawn()
        .map_err(|error| format!("cannot start {}: {error}", bin.display()))?;
    let pid = child.id();
    write_private(&paths.pid_file, &format!("{pid}\n"))
        .map_err(|error| format!("cannot write the pid file: {error}"))?;
    Ok(pid)
}

pub fn stop(paths: &Paths) {
    if let Some(pid) = pid(paths) {
        if alive(pid) {
            kill(pid);
        }
    }
    let _ = std::fs::remove_file(&paths.pid_file);
}

pub fn port_open(port: u16) -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_ok()
}

pub fn wait_fronts(list: &str, ports: Ports, paths: &Paths) -> bool {
    for front in fronts(list) {
        let port = port_of(&front, ports);
        let mut opened = false;
        for _ in 0..90 {
            if port_open(port) {
                opened = true;
                break;
            }
            if !running(paths) {
                return false;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        if !opened {
            return false;
        }
    }
    true
}

pub fn uptime(paths: &Paths) -> Option<String> {
    let created = std::fs::metadata(&paths.pid_file).ok()?.created().ok()?;
    let elapsed = created.elapsed().ok()?;
    let seconds = elapsed.as_secs();
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;
    Some(if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes}:{seconds:02}")
    })
}

pub fn foxy_configured(paths: &Paths) -> bool {
    read_trim(&paths.cfg)
        .is_some_and(|text| text.contains("\"protocol\"") && text.contains("\"foxy\""))
}

pub fn other_lanes(paths: &Paths) -> Vec<(String, u32)> {
    let mut lanes = Vec::new();
    let Ok(entries) = std::fs::read_dir(&paths.conf_dir) else {
        return lanes;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(rest) = name.strip_prefix("lane-") else {
            continue;
        };
        let Some(instance) = rest.strip_suffix(".pid") else {
            continue;
        };
        if let Some(pid) = read_trim(&entry.path()).and_then(|text| text.parse().ok()) {
            if alive(pid) {
                lanes.push((instance.to_owned(), pid));
            }
        }
    }
    lanes
}
