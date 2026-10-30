//! The one account a lane holds. The file is the release package's own, written
//! owner-only, and a named flag always beats what was stored.

use std::io::{IsTerminal as _, Write as _};
use std::path::Path;

use crate::args::Options;
use crate::config::FoxyAccount;
use crate::paths::{read_trim, write_private, Paths};

fn unquote(raw: &str) -> String {
    let mut out = String::new();
    let mut chars = raw.chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        match ch {
            '\'' => quoted = !quoted,
            '\\' if !quoted => {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            _ => out.push(ch),
        }
    }
    out
}

fn read(path: &Path) -> (String, String) {
    let Some(text) = read_trim(path) else {
        return (String::new(), String::new());
    };
    let mut email = String::new();
    let mut password = String::new();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("FOXY_EMAIL=") {
            email = unquote(value);
        } else if let Some(value) = line.strip_prefix("FOXY_PASS=") {
            password = unquote(value);
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
    if email.is_empty() || (password.is_empty() && !same_account(&stored_email(paths), &email)) {
        if !std::io::stdin().is_terminal() {
            return Err(
                "no account: run 'ferrox-cli login' first, or pass --email and --password"
                    .to_owned(),
            );
        }
        println!("Foxy needs a Firefox account — an email and a password, no server to name.");
        if email.is_empty() {
            email = prompt("firefox account email: ", false)?;
        }
        if password.is_empty() {
            password = prompt("password (hidden, not echoed): ", true)?;
        }
        save(&email, &password, paths)?;
    }
    if email.is_empty() || password.is_empty() {
        return Err("an account is an email and a password".to_owned());
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

pub fn login(options: &Options, paths: &Paths) -> Result<(), String> {
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
