//! Unauthenticated and fetched once: re-reading the edge list per flow is a round trip per flow, and an edge the catalogue published an hour ago is still an edge.

use crate::foxy_account::Endpoint;
use crate::foxy_challenge::{Agent, Jar};
use crate::json::{self, Json};
use ferrox_core::foxy::Candidate;
use std::io::Write as _;
use std::sync::Mutex;

/// Published by Mozilla unauthenticated, under the same agent every other control-plane call uses.
pub(crate) const CATALOG_URL: &str = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records";

/// The protocol entry the tunnel dials; a server with no `connect` entry is unreachable on this lane.
const CONNECT: &str = "connect";

/// A placeholder row rather than a country, and the one row the reference drops.
const PLACEHOLDER: &str = "catchall anycast";

/// How long a fetched list is trusted: a new country is not an emergency, so minutes and not seconds.
const FRESH: u64 = 300;

/// Fetched once and reused; the clock is the only state, edge selection living in `ferrox_core::foxy::catalog`.
static CACHE: Mutex<(u64, Vec<Candidate>)> = Mutex::new((0, Vec::new()));

/// What the last process wrote down for the next one, so a cold start with no network still has edges to dial.
const CACHE_FILE: &str = "ferrox-foxy-catalogue";

fn epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Whether the cache answers without asking the settings server: a list is trusted for `FRESH` seconds, and never when it is empty.
#[must_use]
fn trusted(known: &(u64, Vec<Candidate>), now: u64) -> bool {
    !known.1.is_empty() && now.saturating_sub(known.0) < FRESH
}

/// One fetch's answer, applied to the list already known: edges fetched now are the list, and are worth writing down; a fetch that failed or read none keeps the list already known at its own age, because an edge that answered yesterday is worth a dial today.
#[must_use]
fn settled(
    known: (u64, Vec<Candidate>),
    now: u64,
    fresh: Option<Vec<Candidate>>,
) -> (u64, Vec<Candidate>, bool) {
    match fresh {
        Some(edges) if !edges.is_empty() => (now, edges, true),
        _ => (known.0, known.1, false),
    }
}

/// Every dialable edge: a fresh list, a fetched one, or the last one known — no edges is a refusal with a reason, never a guess.
pub(crate) fn edges(roots: ferrox_core::tls::Anchors) -> Vec<Candidate> {
    let now = epoch();
    let cached = CACHE.lock().map_or((0, Vec::new()), |cache| cache.clone());
    let known = if cached.1.is_empty() {
        read_at(&cache_path())
    } else {
        cached
    };
    if trusted(&known, now) {
        remember(&known);
        return known.1;
    }
    let (stamp, listed, fetched) = settled(known, now, fetch(roots));
    remember(&(stamp, listed.clone()));
    if fetched {
        write_at(&cache_path(), &listed);
    }
    listed
}

fn remember(listed: &(u64, Vec<Candidate>)) {
    if let Ok(mut cache) = CACHE.lock() {
        *cache = listed.clone();
    }
}

fn cache_path() -> std::path::PathBuf {
    std::env::temp_dir().join(CACHE_FILE)
}

/// One tab-separated line per edge, in the order the catalogue published them.
fn encode(listed: &[Candidate]) -> Vec<u8> {
    let mut text = Vec::new();
    for edge in listed {
        let _ = writeln!(
            text,
            "{}\t{}\t{}\t{}",
            edge.host, edge.port, edge.country, edge.city
        );
    }
    text
}

/// A line that is not four fields is not an edge, so a file cut off mid-write loses its tail and not its meaning.
#[must_use]
fn decode(text: &str) -> Vec<Candidate> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let [host, port, country, city] = fields.as_slice() else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        if host.is_empty() || country.is_empty() {
            continue;
        }
        out.push(Candidate {
            host: std::sync::Arc::from(*host),
            port,
            country: (*country).to_owned(),
            city: (*city).to_owned(),
        });
    }
    out
}

/// The list the last process left, aged by what the filesystem saw; no file, an unreadable file and a file with no whole lines all read as no list.
fn read_at(path: &std::path::Path) -> (u64, Vec<Candidate>) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return (0, Vec::new());
    };
    let listed = decode(&text);
    if listed.is_empty() {
        return (0, listed);
    }
    let stamp = path
        .metadata()
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|when| when.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |since| since.as_secs());
    (stamp, listed)
}

/// Written beside the file it replaces and moved onto it, so a reader sees this whole list or the last one; best-effort, because a catalogue that cannot be cached is still a catalogue that was fetched.
fn write_at(path: &std::path::Path, listed: &[Candidate]) {
    let temp = path.with_extension(format!("{}.tmp", std::process::id()));
    let Ok(mut file) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
    else {
        return;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    if file.write_all(&encode(listed)).is_err() {
        let _ = std::fs::remove_file(&temp);
        return;
    }
    if std::fs::rename(&temp, path).is_err() {
        let _ = std::fs::remove_file(&temp);
    }
}

fn fetch(roots: ferrox_core::tls::Anchors) -> Option<Vec<Candidate>> {
    let endpoint = Endpoint::parse(CATALOG_URL, roots)?;
    let reply = crate::foxy_account::send(
        &endpoint,
        &Mutex::new(Jar::default()),
        Agent::Api,
        "GET",
        "",
        &[],
        b"",
    )
    .ok()?;
    if reply.status / 100 != 2 {
        return None;
    }
    let body = json::parse(&String::from_utf8_lossy(&reply.body)).ok()?;
    Some(edges_of(&body))
}

/// A record is dropped, not dialled, when it has no code or cities, is the anycast placeholder, or is quarantined.
#[must_use]
pub(crate) fn edges_of(body: &Json) -> Vec<Candidate> {
    let mut out = Vec::new();
    for record in body.get("data").and_then(Json::as_arr).unwrap_or(&[]) {
        let country = record.get("country").unwrap_or(record);
        let code = country.get("code").and_then(Json::as_str).unwrap_or("");
        if code.is_empty()
            || country
                .get("name")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_ascii_lowercase()
                == PLACEHOLDER
        {
            continue;
        }
        for city in country.get("cities").and_then(Json::as_arr).unwrap_or(&[]) {
            let city_code = city
                .get("code")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned();
            for server in city.get("servers").and_then(Json::as_arr).unwrap_or(&[]) {
                if matches!(server.get("quarantined"), Some(Json::Bool(true))) {
                    continue;
                }
                let Some((host, port)) = target_of(server) else {
                    continue;
                };
                out.push(Candidate {
                    host: std::sync::Arc::from(host),
                    port,
                    country: code.to_owned(),
                    city: city_code.clone(),
                });
            }
        }
    }
    out
}

/// Its `connect` entry, or itself when it publishes none; a server with entries but no `connect` is dropped.
fn target_of(server: &Json) -> Option<(String, u16)> {
    let hostname = server.get("hostname").and_then(Json::as_str).unwrap_or("");
    let port = server.get("port").and_then(Json::as_port).unwrap_or(0);
    let entries = server
        .get("protocols")
        .and_then(Json::as_arr)
        .unwrap_or(&[]);
    for entry in entries {
        if entry.get("name").and_then(Json::as_str) != Some(CONNECT) {
            continue;
        }
        let host = entry.get("host").and_then(Json::as_str).unwrap_or("");
        let port = entry.get("port").and_then(Json::as_port).unwrap_or(port);
        let host = if host.is_empty() { hostname } else { host };
        return (!host.is_empty() && port != 0).then(|| (host.to_owned(), port));
    }
    (entries.is_empty() && !hostname.is_empty() && port != 0).then(|| (hostname.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = r#"{"data":[
      {"country":{"name":"United States","code":"US","cities":[
        {"name":"San Francisco","code":"SFO","servers":[
          {"hostname":"us-sfo","port":443,"protocols":[{"name":"connect","host":"edge.sfo","port":8443}]},
          {"hostname":"us-sfo-quarantined","port":443,"quarantined":true,"protocols":[{"name":"connect"}]},
          {"hostname":"us-no-connect","port":443,"protocols":[{"name":"wireguard","port":51820}]}]},
        {"name":"New York","code":"NYC","servers":[
          {"hostname":"us-nyc","port":443,"protocols":[{"name":"connect"}]}]}]}},
      {"country":{"name":"Recommended","code":"REC","cities":[
        {"code":"ANY","servers":[{"hostname":"rec","port":443,"protocols":[{"name":"connect"}]}]}]}},
      {"country":{"name":"CatchAll Anycast","code":"AC1","cities":[
        {"code":"ANY","servers":[{"hostname":"ac1","port":443,"protocols":[{"name":"connect"}]}]}]}},
      {"country":{"name":"No Code","code":"","cities":[
        {"code":"X","servers":[{"hostname":"x","port":443,"protocols":[{"name":"connect"}]}]}]}},
      {"name":"Bare Record","code":"DE","cities":[
        {"code":"BER","servers":[{"hostname":"de-ber","port":443}]}]}
    ]}"#;

    fn parsed() -> Json {
        json::parse(BODY).expect("the envelope parses")
    }

    #[test]
    fn every_published_country_becomes_the_edges_it_can_be_dialed_on() {
        let edges = edges_of(&parsed());
        let named: Vec<String> = edges
            .iter()
            .map(|edge| format!("{}:{} {}/{}", edge.host, edge.port, edge.country, edge.city))
            .collect();
        assert_eq!(
            named,
            [
                "edge.sfo:8443 US/SFO",
                "us-nyc:443 US/NYC",
                "rec:443 REC/ANY",
                "de-ber:443 DE/BER",
            ],
            "a quarantined server, a server with no connect entry, a blank code"
        );
    }

    #[test]
    fn the_catalogue_alone_picks_a_country_without_an_account() {
        let edges = edges_of(&parsed());
        assert_eq!(
            ferrox_core::foxy::catalog::tier(&edges, "us", "", 3)
                .iter()
                .map(Candidate::authority)
                .collect::<Vec<_>>(),
            ["edge.sfo:8443", "us-nyc:443"]
        );
        assert_eq!(
            ferrox_core::foxy::catalog::tier(&edges, "FR", "", 3),
            Vec::new()
        );
    }

    #[test]
    fn an_envelope_this_lane_cannot_read_is_no_edges_rather_than_a_guess() {
        for body in [r"{}", r#"{"data":[]}"#, r#"{"data":{}}"#, r"[]"] {
            assert!(
                edges_of(&json::parse(body).expect("parses")).is_empty(),
                "{body}"
            );
        }
    }

    #[test]
    fn a_server_that_names_its_own_edge_is_dialed_there() {
        let server = json::parse(
            r#"{"hostname":"ignored","port":443,"protocols":[{"name":"connect","host":"own","port":2499}]}"#,
        )
        .expect("parses");
        assert_eq!(target_of(&server), Some(("own".to_owned(), 2499)));
        let blank = json::parse(r#"{"hostname":"only","port":8443}"#).expect("parses");
        assert_eq!(target_of(&blank), Some(("only".to_owned(), 8443)));
        let nothing = json::parse(r#"{"hostname":"only","port":0}"#).expect("parses");
        assert_eq!(target_of(&nothing), None);
    }

    #[test]
    fn a_fetch_that_failed_keeps_the_edges_already_known() {
        let listed = edges_of(&parsed());
        let (wrote_at, inside, past) = (1_000u64, 1_000 + FRESH - 1, 1_000 + FRESH);
        let known = (wrote_at, listed.clone());
        assert!(
            trusted(&known, inside),
            "inside the window the cache answers alone"
        );
        assert!(
            !trusted(&known, past),
            "one second past it the fetch is asked"
        );
        assert!(
            !trusted(&(wrote_at, Vec::new()), inside),
            "an empty list is never an answer, at any age"
        );
        let missed: [Option<Vec<Candidate>>; 2] = [None, Some(Vec::new())];
        for fetched in missed {
            let (stamp, kept, wrote) = settled(known.clone(), past, fetched);
            assert_eq!(
                kept, listed,
                "the edges already known are the edges to dial"
            );
            assert_eq!(
                stamp, wrote_at,
                "and they keep their own age, so the next flow asks again"
            );
            assert!(
                !wrote,
                "nothing was fetched, so nothing is worth writing down"
            );
        }
        let (stamp, fresh, wrote) = settled(known, past, Some(listed.clone()));
        assert_eq!(fresh, listed);
        assert_eq!(stamp, past, "a fetched list is aged from now");
        assert!(wrote, "and it is the list the next process should find");
    }

    #[test]
    fn the_cache_file_one_process_writes_is_the_one_the_next_reads() {
        let path = std::env::temp_dir().join(format!(
            "ferrox-foxy-catalogue-{}-round",
            std::process::id()
        ));
        let mut listed = edges_of(&parsed());
        // A published city code can be blank, so the field separator has to keep an empty one.
        listed.push(Candidate {
            host: std::sync::Arc::from("no.city"),
            port: 2499,
            country: "NL".to_owned(),
            city: String::new(),
        });
        write_at(&path, &listed);
        let (stamp, read) = read_at(&path);
        assert_eq!(read, listed, "every field survives the file");
        assert!(
            stamp > 0 && stamp <= epoch(),
            "the file carries its own age"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_cache_file_cut_off_mid_write_keeps_the_lines_that_are_whole() {
        let path = std::env::temp_dir().join(format!(
            "ferrox-foxy-catalogue-{}-truncated",
            std::process::id()
        ));
        std::fs::write(&path, "edge.sfo\t8443\tUS\tSFO\nus-nyc\t443\tUS\ntrunc").expect("writes");
        let (_, read) = read_at(&path);
        assert_eq!(
            read.iter().map(Candidate::authority).collect::<Vec<_>>(),
            ["edge.sfo:8443"],
            "three fields and a torn line are not edges"
        );
        let _ = std::fs::remove_file(&path);
        assert!(
            read_at(&path).1.is_empty(),
            "no file is no list, and never a guess"
        );
    }
}
