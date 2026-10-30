//! Where a lane keeps its config, pid, log and proxy transaction. The release
//! package owns no repository, so the paths are the platform's own per-user
//! directories, and `FERROX_CONF_DIR`/`FERROX_STATE_DIR` can move them.

use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP: AtomicU64 = AtomicU64::new(0);

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

#[cfg(windows)]
fn icacls(path: &Path, grant: &str) -> std::io::Result<()> {
    let output = std::process::Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(grant)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "icacls {} failed: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ))
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
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_owned());
        icacls(path, &format!("{user}:(OI)(CI)F"))?;
    }
    Ok(())
}

#[cfg(windows)]
pub fn secure_file(path: &Path) -> std::io::Result<()> {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_owned());
    icacls(path, &format!("{user}:F"))?;
    Ok(())
}

/// Replace a private file atomically: a reader never sees a half-written
/// credential, and the new inode is owner-only before a byte lands in it.
pub fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    secure_dir(parent)?;
    let name = path
        .file_name()
        .map_or_else(|| "ferrox".into(), |name| name.to_string_lossy());
    for _ in 0..32 {
        let serial = TEMP.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(".{name}.tmp.{}.{serial}", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = match options.open(&temp) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        #[cfg(windows)]
        if let Err(error) = secure_file(&temp) {
            drop(file);
            let _ = std::fs::remove_file(&temp);
            return Err(error);
        }
        let written = file
            .write_all(contents.as_bytes())
            .and_then(|()| file.flush());
        drop(file);
        if let Err(error) = written {
            let _ = std::fs::remove_file(&temp);
            return Err(error);
        }
        match std::fs::rename(&temp, path) {
            Ok(()) => return Ok(()),
            Err(error) => {
                let _ = std::fs::remove_file(&temp);
                return Err(error);
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "cannot create a private temporary file",
    ))
}

/// Read a small private file, capped so a planted multi-gigabyte file cannot
/// turn a startup check into an allocation.
pub fn read_trim(path: &Path) -> Option<String> {
    let mut text = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(8 * 1024 * 1024)
        .read_to_end(&mut text)
        .ok()?;
    Some(String::from_utf8_lossy(&text).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_private_write_replaces_the_file_and_leaves_no_temp() {
        let serial = TEMP.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ferrox-paths-{}-{serial}", std::process::id()));
        let path = dir.join("credentials");
        write_private(&path, "first\n").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let file = std::fs::metadata(&path).expect("file");
            let parent = std::fs::metadata(&dir).expect("dir");
            assert_eq!(file.permissions().mode() & 0o777, 0o600);
            assert_eq!(parent.permissions().mode() & 0o777, 0o700);
        }
        write_private(&path, "second\n").expect("replace");
        assert_eq!(read_trim(&path).as_deref(), Some("second"));
        let names: Vec<String> = std::fs::read_dir(&dir)
            .expect("dir")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["credentials"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
