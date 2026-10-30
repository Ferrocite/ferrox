//! The one machine-wide setting `--vpn` touches. On Windows that is `WinINET`'s
//! Internet Settings: the same proxy Chrome, Edge and most desktop apps read.
//! A snapshot is taken before the first arm and restored on `down`.

use crate::config::{fronts, Ports};
use crate::paths::{read_trim, Paths};

pub struct Routes {
    pub socks: Option<u16>,
    pub http: Option<u16>,
}

pub fn routes(list: &str, ports: Ports) -> Routes {
    let mut socks = None;
    let mut http = None;
    for front in fronts(list) {
        match front.as_str() {
            "socks" => socks = Some(ports.socks),
            "http" => http = Some(ports.http),
            "mixed" => {
                if socks.is_none() {
                    socks = Some(ports.mixed);
                }
                if http.is_none() {
                    http = Some(ports.mixed);
                }
            }
            _ => {}
        }
    }
    Routes { socks, http }
}

pub fn preflight(list: &str, ports: Ports) -> Result<(), String> {
    let routes = routes(list, ports);
    if routes.socks.is_none() && routes.http.is_none() {
        return Err(
            "system proxy: --fronts names no socks, http or mixed front; nothing was started."
                .to_owned(),
        );
    }
    #[cfg(windows)]
    {
        let key = win::open().map_err(|error| {
            format!("system proxy: cannot read the current proxy settings ({error}); nothing was started.")
        })?;
        win::close(key);
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err(format!(
            "ferrox-cli: --vpn sets the Windows system proxy; on {} nothing was started.\n  point the app at the fronts instead: ferrox-cli ports",
            std::env::consts::OS
        ))
    }
}

pub fn arm(paths: &Paths, list: &str, ports: Ports) -> Result<(), String> {
    #[cfg(not(windows))]
    let _ = paths;
    let routes = routes(list, ports);
    if routes.socks.is_none() && routes.http.is_none() {
        return Err("system proxy: the fronts name no proxy; nothing was armed.".to_owned());
    }
    #[cfg(windows)]
    {
        win::arm(paths, routes.socks, routes.http)
    }
    #[cfg(not(windows))]
    {
        Err("system proxy: this launcher only arms the Windows proxy.".to_owned())
    }
}

pub fn clear(paths: &Paths) {
    #[cfg(windows)]
    {
        win::clear(paths);
    }
    #[cfg(not(windows))]
    {
        let _ = std::fs::remove_file(&paths.proxy_ports);
        let _ = std::fs::remove_file(&paths.proxy_state);
        let _ = std::fs::remove_file(&paths.proxy_owner);
    }
}

pub fn armed_endpoint(paths: &Paths) -> Option<String> {
    let ports = read_trim(&paths.proxy_ports)?;
    let mut parts = ports.split_whitespace();
    let socks = parts.next().filter(|value| *value != "-");
    let http = parts.next().filter(|value| *value != "-");
    socks.or(http).map(|port| format!("127.0.0.1:{port}"))
}

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::ptr;

    use serde_json::{json, Value};
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_SZ,
    };

    use crate::paths::{read_trim, write_private, Paths};

    const SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const MAX_VALUE: u32 = 1024 * 1024;
    const NAMES: [&str; 5] = [
        "ProxyEnable",
        "ProxyServer",
        "ProxyOverride",
        "AutoConfigURL",
        "AutoDetect",
    ];

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn close(key: HKEY) {
        unsafe { RegCloseKey(key) };
    }

    pub fn open() -> Result<HKEY, String> {
        let subkey = wide(SETTINGS);
        let mut key: HKEY = ptr::null_mut();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                &mut key,
            )
        };
        if status == ERROR_SUCCESS {
            Ok(key)
        } else {
            Err(format!("RegOpenKeyEx failed with {status}"))
        }
    }

    fn read(key: HKEY, name: &str) -> Result<Option<(u32, Vec<u8>)>, String> {
        let name = wide(name);
        let mut kind = 0_u32;
        let mut size = 0_u32;
        let status = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                ptr::null_mut(),
                &mut size,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(format!("RegQueryValueEx({name:?}) failed with {status}"));
        }
        if size > MAX_VALUE {
            return Err(format!(
                "registry value {name:?} is larger than {MAX_VALUE} bytes"
            ));
        }
        let mut buffer = vec![0_u8; size as usize];
        let status = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                buffer.as_mut_ptr(),
                &mut size,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("RegQueryValueEx({name:?}) failed with {status}"));
        }
        let size = (size as usize).min(buffer.len());
        buffer.truncate(size);
        Ok(Some((kind, buffer)))
    }

    fn text_of(bytes: &[u8]) -> String {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|unit| *unit != 0)
            .collect();
        String::from_utf16_lossy(&units)
    }

    fn write_raw(key: HKEY, name: &str, kind: u32, data: &[u8]) -> bool {
        let name = wide(name);
        unsafe {
            RegSetValueExW(
                key,
                name.as_ptr(),
                0,
                kind,
                data.as_ptr(),
                data.len() as u32,
            ) == ERROR_SUCCESS
        }
    }

    fn write_sz(key: HKEY, name: &str, value: &str) -> bool {
        let bytes: Vec<u8> = value
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect();
        write_raw(key, name, REG_SZ, &bytes)
    }

    fn write_dword(key: HKEY, name: &str, value: u32) -> bool {
        write_raw(key, name, REG_DWORD, &value.to_le_bytes())
    }

    fn delete(key: HKEY, name: &str) {
        let name = wide(name);
        unsafe {
            RegDeleteValueW(key, name.as_ptr());
        }
    }

    fn snapshot(key: HKEY) -> Result<Value, String> {
        let mut object = serde_json::Map::new();
        for name in NAMES {
            if let Some((kind, bytes)) = read(key, name)? {
                object.insert(name.to_owned(), json!({"kind": kind, "bytes": bytes}));
            }
        }
        Ok(Value::Object(object))
    }

    fn restore(key: HKEY, snapshot: &Value) {
        for name in NAMES {
            match snapshot.get(name) {
                Some(Value::Object(value)) => {
                    let kind = value
                        .get("kind")
                        .and_then(Value::as_u64)
                        .and_then(|kind| u32::try_from(kind).ok());
                    let bytes: Option<Vec<u8>> =
                        value.get("bytes").and_then(Value::as_array).map(|rows| {
                            rows.iter()
                                .filter_map(Value::as_u64)
                                .filter_map(|byte| u8::try_from(byte).ok())
                                .collect()
                        });
                    match (kind, bytes) {
                        (Some(kind), Some(bytes)) => {
                            write_raw(key, name, kind, &bytes);
                        }
                        _ => delete(key, name),
                    }
                }
                Some(Value::String(text)) => {
                    write_sz(key, name, text);
                }
                Some(Value::Number(number)) => {
                    if let Some(value) = number.as_u64() {
                        write_dword(key, name, value as u32);
                    }
                }
                _ => delete(key, name),
            }
        }
    }

    fn notify() -> bool {
        unsafe {
            InternetSetOptionW(
                ptr::null(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                ptr::null::<c_void>(),
                0,
            ) != 0
                && InternetSetOptionW(
                    ptr::null(),
                    INTERNET_OPTION_REFRESH,
                    ptr::null::<c_void>(),
                    0,
                ) != 0
        }
    }

    fn server(socks: Option<u16>, http: Option<u16>) -> String {
        let mut parts = Vec::new();
        if let Some(port) = http {
            parts.push(format!("http=127.0.0.1:{port}"));
            parts.push(format!("https=127.0.0.1:{port}"));
        }
        if let Some(port) = socks {
            parts.push(format!("socks=127.0.0.1:{port}"));
        }
        parts.join(";")
    }

    fn bypass(key: HKEY) -> Result<String, String> {
        let prior = match read(key, "ProxyOverride")? {
            Some((kind, bytes)) if kind == REG_SZ => text_of(&bytes),
            Some(_) | None => String::new(),
        };
        let mut entries: Vec<String> = [
            "localhost",
            "127.0.0.1",
            "::1",
            "<local>",
            "*.local",
            "10.*",
            "172.16.*",
            "192.168.*",
        ]
        .iter()
        .map(|entry| (*entry).to_owned())
        .collect();
        let seen: Vec<String> = entries.clone();
        for entry in prior.split(';') {
            let entry = entry.trim();
            if entry.is_empty() || seen.iter().any(|item| item == entry) {
                continue;
            }
            entries.push(entry.to_owned());
        }
        Ok(entries.join(";"))
    }

    pub fn arm(paths: &Paths, socks: Option<u16>, http: Option<u16>) -> Result<(), String> {
        let key = open().map_err(|error| {
            format!("system proxy: cannot read the current settings ({error}).")
        })?;
        let bypass = match bypass(key) {
            Ok(bypass) => bypass,
            Err(error) => {
                close(key);
                return Err(format!(
                    "system proxy: cannot read the current bypass list: {error}"
                ));
            }
        };
        let fresh = !paths.proxy_state.exists();
        if fresh {
            let snapshot = match snapshot(key) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    close(key);
                    return Err(format!("system proxy: cannot record the snapshot: {error}"));
                }
            };
            let text = match serde_json::to_string(&snapshot) {
                Ok(text) => text,
                Err(error) => {
                    close(key);
                    return Err(format!("system proxy: cannot record the snapshot: {error}"));
                }
            };
            if text.len() as u64 > crate::paths::MAX_PRIVATE_BYTES {
                close(key);
                return Err(
                    "system proxy: the current settings are too large to snapshot safely; nothing was armed."
                        .to_owned(),
                );
            }
            if let Err(error) = write_private(&paths.proxy_state, &text) {
                close(key);
                return Err(format!("system proxy: cannot record the snapshot: {error}"));
            }
        }
        let server = server(socks, http);
        let ok = write_dword(key, "ProxyEnable", 1)
            && write_sz(key, "ProxyServer", &server)
            && write_sz(key, "ProxyOverride", &bypass)
            && write_dword(key, "AutoDetect", 0);
        delete(key, "AutoConfigURL");
        unsafe { RegCloseKey(key) };
        if !ok || !notify() {
            clear(paths);
            return Err("system proxy: the arm did not stick; nothing was armed.".to_owned());
        }
        let _ = write_private(
            &paths.proxy_ports,
            &format!(
                "{} {}\n",
                socks.map_or_else(|| "-".to_owned(), |port| port.to_string()),
                http.map_or_else(|| "-".to_owned(), |port| port.to_string())
            ),
        );
        let _ = write_private(&paths.proxy_owner, &paths.conf_dir.to_string_lossy());
        if let Some(port) = socks {
            println!("system proxy on: SOCKS 127.0.0.1:{port}");
        }
        if let Some(port) = http {
            println!("system proxy on: HTTP and HTTPS 127.0.0.1:{port}");
        }
        println!("scope: apps that honour the Windows proxy. Apps that ignore it (and raw UDP) are not captured: ferrox-cli tun says why.");
        Ok(())
    }

    pub fn clear(paths: &Paths) {
        if let Some(text) = read_trim(&paths.proxy_state) {
            if let Ok(snapshot) = serde_json::from_str::<Value>(&text) {
                if let Ok(key) = open() {
                    restore(key, &snapshot);
                    unsafe { RegCloseKey(key) };
                    notify();
                }
            }
        }
        let _ = std::fs::remove_file(&paths.proxy_ports);
        let _ = std::fs::remove_file(&paths.proxy_state);
        let _ = std::fs::remove_file(&paths.proxy_owner);
    }
}
