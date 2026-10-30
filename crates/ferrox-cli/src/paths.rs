//! Where a lane keeps its config, pid, log and proxy transaction. The release
//! package owns no repository, so the paths are the platform's own per-user
//! directories, and `FERROX_CONF_DIR`/`FERROX_STATE_DIR` can move them.

use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Paths {
    pub conf_dir: PathBuf,
    pub state_dir: PathBuf,
    pub cfg: PathBuf,
    pub pid_file: PathBuf,
    pub log: PathBuf,
    pub proxy_ports: PathBuf,
    pub proxy_state: PathBuf,
    pub supervisor_file: PathBuf,
    pub supervisor_pid: PathBuf,
    pub location_file: PathBuf,
    pub locations_file: PathBuf,
    pub lanes_file: PathBuf,
    pub proxy_owner: PathBuf,
    pub creds: PathBuf,
    pub token_file: PathBuf,
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
}

fn conf_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("FERROX_CONF_DIR") {
        return PathBuf::from(dir);
    }
    if cfg!(windows) {
        if let Some(base) = std::env::var_os("APPDATA") {
            return PathBuf::from(base).join("ferrox");
        }
    }
    if let Some(base) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(base).join("ferrox");
    }
    home().join(".config").join("ferrox")
}

fn state_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("FERROX_STATE_DIR") {
        return PathBuf::from(dir);
    }
    if cfg!(windows) {
        if let Some(base) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(base).join("ferrox");
        }
    }
    if let Some(base) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(base).join("ferrox");
    }
    home().join(".local").join("state").join("ferrox")
}

impl Paths {
    pub fn new(instance: Option<&str>) -> Self {
        Self::with_dirs(conf_root(), state_root(), instance)
    }

    pub fn with_dirs(conf_dir: PathBuf, state_dir: PathBuf, instance: Option<&str>) -> Self {
        let suffix = instance.map_or_else(String::new, |name| format!("-{name}"));
        Self {
            cfg: conf_dir.join(format!("lane{suffix}.json")),
            pid_file: conf_dir.join(format!("lane{suffix}.pid")),
            log: conf_dir.join(format!("lane{suffix}.log")),
            proxy_ports: state_dir.join(format!("system-proxy{suffix}.ports")),
            proxy_state: state_dir.join(format!("system-proxy{suffix}.state")),
            supervisor_file: state_dir.join(format!("system-proxy{suffix}.supervisor")),
            supervisor_pid: state_dir.join(format!("system-proxy{suffix}.supervisor.pid")),
            location_file: conf_dir.join(format!("foxy-location{suffix}")),
            locations_file: conf_dir.join("foxy-locations.jsonl"),
            lanes_file: state_dir.join("lanes"),
            proxy_owner: state_dir.join("system-proxy.owner"),
            creds: conf_dir.join("credentials"),
            token_file: conf_dir.join("foxy-token.json"),
            conf_dir,
            state_dir,
        }
    }
}

pub fn secure_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!(
                "{}:(OI)(CI)F",
                std::env::var("USERNAME").unwrap_or_else(|_| "user".to_owned())
            ))
            .output();
    }
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
pub fn secure_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!(
                "{}:F",
                std::env::var("USERNAME").unwrap_or_else(|_| "user".to_owned())
            ))
            .output();
    }
    Ok(())
}

pub fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        secure_dir(parent)?;
    }
    std::fs::write(path, contents)?;
    secure_file(path)
}

pub fn read_trim(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_owned())
}
