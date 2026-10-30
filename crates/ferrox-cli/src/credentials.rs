//! The one account a lane holds. The file is the release package's own, written
//! owner-only, and a named flag always beats what was stored.

use std::io::{IsTerminal as _, Write as _};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::args::Options;
use crate::config::FoxyAccount;
use crate::paths::{read_trim, write_private, Paths};

fn unquote(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = raw.chars();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        match ch {
            '\'' => quoted = !quoted,
            '\\' if !quoted => out.push(chars.next()?),
            _ => out.push(ch),
        }
    }
    (!quoted).then_some(out)
}

fn read(path: &Path) -> (String, String) {
    let Some(text) = read_trim(path) else {
        return (String::new(), String::new());
    };
    let mut email = String::new();
    let mut password = String::new();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("FOXY_EMAIL=") {
            email = unquote(value).unwrap_or_default();
        } else if let Some(value) = line.strip_prefix("FOXY_PASS=") {
            password = unquote(value).unwrap_or_default();
        }
    }
    (email, password)
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn stored_email(paths: &Paths) -> String {
    let Some(text) = read_trim(&paths.token_file) else {
        return String::new();
    };
    serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|value| {
            value
                .get("email")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

/// A grant the browser sign-in stored: a token file with an access token that has not lapsed.
fn stored_grant(paths: &Paths) -> bool {
    let Some(text) = read_trim(&paths.token_file) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    if value
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .is_none_or(str::is_empty)
    {
        return false;
    }
    let expires = value
        .get("expires_at")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    expires == 0 || expires > now + 60
}

fn same_account(stored: &str, email: &str) -> bool {
    !stored.is_empty()
        && stored.trim().to_lowercase()
            == email
                .chars()
                .filter(|ch| !ch.is_whitespace())
                .collect::<String>()
                .to_lowercase()
}

pub fn resolve(options: &Options, paths: &Paths) -> Result<FoxyAccount, String> {
    let (file_email, file_password) = read(&paths.creds);
    let mut email = if options.email.is_empty() {
        if file_email.is_empty() {
            self::stored_email(paths)
        } else {
            file_email
        }
    } else {
        options.email.clone()
    };
    let mut password = if options.password.is_empty() {
        file_password
    } else {
        options.password.clone()
    };
    let has_grant = |email: &str| same_account(&stored_email(paths), email) && stored_grant(paths);
    if email.is_empty() || (password.is_empty() && !has_grant(&email)) {
        if !std::io::stdin().is_terminal() {
            return Err(
                "no account: run 'ferrox-cli login --browser' first, or pass --email and --password"
                    .to_owned(),
            );
        }
        println!(
            "Foxy needs a Firefox account — a password, or --browser to sign in through Firefox."
        );
        if email.is_empty() {
            email = prompt("firefox account email: ", false)?;
        }
        if password.is_empty() && !has_grant(&email) {
            password = prompt("password (hidden, not echoed): ", true)?;
        }
        if !password.is_empty() {
            save(&email, &password, paths)?;
        }
    }
    if email.is_empty() {
        return Err("an account is a firefox email".to_owned());
    }
    if password.is_empty() && !has_grant(&email) {
        return Err(
            "the stored browser session expired: run 'ferrox-cli login --browser' again".to_owned(),
        );
    }
    Ok(FoxyAccount { email, password })
}

fn prompt(label: &str, hidden: bool) -> Result<String, String> {
    print!("{label}");
    std::io::stdout()
        .flush()
        .map_err(|error| format!("cannot write the prompt: {error}"))?;
    if hidden {
        let value = rpassword::read_password().map_err(|error| format!("cannot read: {error}"))?;
        println!();
        Ok(value)
    } else {
        let mut value = String::new();
        std::io::stdin()
            .read_line(&mut value)
            .map_err(|error| format!("cannot read: {error}"))?;
        Ok(value.trim().to_owned())
    }
}

fn save(email: &str, password: &str, paths: &Paths) -> Result<(), String> {
    let body = format!(
        "FOXY_EMAIL={}\nFOXY_PASS={}\n",
        quote(email),
        quote(password)
    );
    write_private(&paths.creds, &body)
        .map_err(|error| format!("cannot save the account: {error}"))?;
    let _ = std::fs::remove_file(&paths.token_file);
    println!(
        "account saved to {}: owner-only, outside the repository, read by every future up.",
        paths.creds.display()
    );
    println!(
        "the next up --foxy signs in once and keeps the session in {}.",
        paths.token_file.display()
    );
    Ok(())
}

fn save_email(email: &str, paths: &Paths) -> Result<(), String> {
    let body = format!("FOXY_EMAIL={}\n", quote(email));
    write_private(&paths.creds, &body)
        .map_err(|error| format!("cannot save the account: {error}"))?;
    println!(
        "account saved to {}: the browser grant is in {}.",
        paths.creds.display(),
        paths.token_file.display()
    );
    Ok(())
}

fn browser_login(options: &Options, paths: &Paths) -> Result<(), String> {
    let mut email = options.email.clone();
    if email.is_empty() {
        email = prompt("firefox account email: ", false)?;
    }
    if email.is_empty() {
        return Err("an account is a firefox email".to_owned());
    }
    let status = std::process::Command::new(crate::lane::require_bin())
        .arg("browser-login")
        .arg("--email")
        .arg(&email)
        .arg("--token-file")
        .arg(&paths.token_file)
        .status()
        .map_err(|error| format!("cannot start the browser sign-in: {error}"))?;
    if !status.success() {
        return Err("the browser sign-in did not finish".to_owned());
    }
    save_email(&email, paths)
}

pub fn login(options: &Options, paths: &Paths) -> Result<(), String> {
    if options.browser {
        return browser_login(options, paths);
    }
    let mut email = options.email.clone();
    let mut password = options.password.clone();
    if email.is_empty() {
        email = prompt("firefox account email: ", false)?;
    }
    if password.is_empty() {
        password = prompt("password (hidden, not echoed): ", true)?;
    }
    if email.is_empty() || password.is_empty() {
        return Err("an account is an email and a password".to_owned());
    }
    save(&email, &password, paths)
}

#[cfg(test)]
mod tests {
    use super::{quote, unquote};

    #[test]
    fn the_stored_quoting_round_trips_and_a_broken_line_is_refused() {
        for value in ["plain", "two words", "it's", r"back\slash", r"both ' and \"] {
            assert_eq!(unquote(&quote(value)).as_deref(), Some(value));
        }
        assert_eq!(unquote("'unterminated"), None);
        assert_eq!(unquote(r"trailing\"), None);
    }
}
