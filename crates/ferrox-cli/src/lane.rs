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
use crate::paths::{read_trim, secure_dir, write_private, Paths};

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
    let manifest = root.join("Cargo.toml");
    if manifest.exists() {
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
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .is_ok_and(|status| status.success())
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

pub fn kill(pid: u32) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
        std::thread::sleep(Duration::from_secs(1));
        if alive(pid) {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
        }
    }
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn register(paths: &Paths) {
    let _ = secure_dir(&paths.state_dir);
    let text = read_trim(&paths.lanes_file).unwrap_or_default();
    let conf = paths.conf_dir.to_string_lossy();
    if !text.lines().any(|line| line == conf) {
        let _ = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&paths.lanes_file)
            .and_then(|mut file| writeln!(file, "{conf}"));
    }
}

pub fn start(bin: &Path, paths: &Paths, debug: bool) -> Result<u32, String> {
    secure_dir(&paths.conf_dir)
        .map_err(|error| format!("cannot create the config dir: {error}"))?;
    secure_dir(&paths.state_dir)
        .map_err(|error| format!("cannot create the state dir: {error}"))?;
    register(paths);
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
    std::fs::read_to_string(&paths.cfg)
        .is_ok_and(|text| text.contains("\"protocol\"") && text.contains("\"foxy\""))
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
