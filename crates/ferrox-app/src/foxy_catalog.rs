//! Unauthenticated and fetched once: re-reading the edge list per flow is a round trip per flow.

use crate::foxy_account::Endpoint;
use crate::foxy_challenge::{Agent, Jar};
use crate::json::{self, Json};
use ferrox_core::foxy::Candidate;
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

fn epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Every dialable edge, or an empty list: no edges is a refusal with a reason, never a guess.
pub(crate) fn edges(roots: Vec<Vec<u8>>) -> Vec<Candidate> {
    let now = epoch();
    if let Ok(cache) = CACHE.lock() {
        if !cache.1.is_empty() && now.saturating_sub(cache.0) < FRESH {
            return cache.1.clone();
        }
    }
    let fresh = fetch(roots).unwrap_or_default();
    if let Ok(mut cache) = CACHE.lock() {
        if !fresh.is_empty() {
            *cache = (now, fresh.clone());
        }
    }
    fresh
}

fn fetch(roots: Vec<Vec<u8>>) -> Option<Vec<Candidate>> {
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
                    host,
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
}
