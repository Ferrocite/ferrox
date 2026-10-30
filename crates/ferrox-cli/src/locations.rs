//! The catalogue is public, so the listing is the binary's `edges` call. The
//! last answer is kept so the list still prints when the catalogue is down.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

use crate::args::die;
use crate::config::{remembered_city, remembered_country};
use crate::lane::require_bin;
use crate::paths::{read_trim, secure_dir, write_private, Paths};

fn rows(bin: &Path, ping: bool) -> String {
    let mut command = Command::new(bin);
    command.arg("edges");
    if ping {
        command.arg("--ping");
    }
    command
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}

fn plain(line: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<Value>(line) else {
        return line.to_owned();
    };
    if let Some(object) = value.as_object_mut() {
        object.remove("ms");
    }
    value.to_string()
}

#[allow(clippy::option_option)]
fn ms_of(value: &Value) -> Option<Option<u64>> {
    let object = value.as_object()?;
    if !object.contains_key("ms") {
        return None;
    }
    Some(object.get("ms").and_then(Value::as_u64))
}

pub fn list(paths: &Paths, filter: &str, ping: bool) -> Result<(), String> {
    let bin = require_bin();
    secure_dir(&paths.conf_dir)
        .map_err(|error| format!("cannot create the config dir: {error}"))?;
    let wanted = filter.to_uppercase();
    let mut text = rows(&bin, ping);
    if text.trim().is_empty() {
        let Some(saved) = read_trim(&paths.locations_file) else {
            return Err(
                "the catalogue did not answer and no list is saved yet: check the network, then run 'ferrox-cli locations' again."
                    .to_owned(),
            );
        };
        println!(
            "the catalogue did not answer; showing the last list it gave ({}).",
            paths.locations_file.display()
        );
        text = saved;
    } else {
        let kept: Vec<String> = text.lines().map(plain).collect();
        write_private(&paths.locations_file, &format!("{}\n", kept.join("\n")))
            .map_err(|error| format!("cannot save the catalogue: {error}"))?;
    }

    let mut places: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let mut best: BTreeMap<(String, String), Option<u64>> = BTreeMap::new();
    let mut total = 0;
    let mut measured = false;
    for line in text.lines() {
        let Ok(edge) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let country = edge
            .get("country")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_uppercase();
        if country.is_empty() || (!wanted.is_empty() && country != wanted) {
            continue;
        }
        let city = edge
            .get("city")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_uppercase();
        *places
            .entry(country.clone())
            .or_default()
            .entry(city.clone())
            .or_default() += 1;
        total += 1;
        if let Some(reading) = ms_of(&edge) {
            measured = true;
            let key = (country, city);
            best.entry(key)
                .and_modify(|entry| {
                    *entry = match (*entry, reading) {
                        (Some(current), Some(next)) => Some(current.min(next)),
                        (None, _) => None,
                        (Some(current), None) => Some(current),
                    };
                })
                .or_insert(reading);
        }
    }

    if places.is_empty() {
        if wanted.is_empty() {
            return Err(
                "the catalogue listed no dialable edge just now; the lane would refuse every country."
                    .to_owned(),
            );
        }
        return Err(format!(
            "{wanted} is not in the published catalogue; run 'ferrox-cli locations' for every country it lists."
        ));
    }

    let current_country = remembered_country(paths);
    let current_city = remembered_city(paths);
    println!(
        "exit locations from Mozilla's catalogue: {} countries, {total} edges",
        places.len()
    );
    println!("country and city are the codes --country and --city take; * is what this machine remembers.");
    if ping {
        println!("ms is one TCP handshake from this machine to the edge (1.5 s budget); 'no answer' is an edge that did not take it.");
        if !measured {
            println!("latency not measured: this listing came from the offline copy; run 'locations --ping' again when the catalogue answers.");
        }
    }

    let mut countries: Vec<String> = places.keys().cloned().collect();
    countries.sort();
    if let Some(index) = countries.iter().position(|country| country == "REC") {
        let rec = countries.remove(index);
        countries.insert(0, rec);
    }
    for country in &countries {
        let cities = &places[country];
        let mark = if country == &current_country {
            "*"
        } else {
            " "
        };
        println!(
            " {mark} {country:<4} {:>3} edges{}",
            cities.values().sum::<usize>(),
            readable(country_reading(&best, country), ping)
        );
        let mut city_names: Vec<&String> = cities.keys().collect();
        city_names.sort();
        for city in city_names {
            let star = if country == &current_country && city == &current_city {
                "*"
            } else {
                " "
            };
            let label = if city.is_empty() {
                "any"
            } else {
                city.as_str()
            };
            println!(
                "   {star}   {label:<6} {:>3}{}",
                cities[city],
                readable(
                    best.get(&(country.clone(), city.clone()))
                        .copied()
                        .flatten(),
                    ping
                )
            );
        }
    }
    println!();
    println!("remember one:  ferrox-cli location <CC> [CITY]");
    println!("the list is saved in {}", paths.locations_file.display());
    Ok(())
}

fn readable(reading: Option<u64>, ping: bool) -> String {
    if !ping {
        return String::new();
    }
    reading.map_or_else(
        || format!("{:>12}", "no answer"),
        |ms| format!("{ms:>9} ms"),
    )
}

fn country_reading(best: &BTreeMap<(String, String), Option<u64>>, country: &str) -> Option<u64> {
    let mut found: Option<u64> = None;
    for ((candidate, _city), reading) in best {
        if candidate != country {
            continue;
        }
        let Some(ms) = reading else {
            return None;
        };
        found = Some(found.map_or(*ms, |current: u64| current.min(*ms)));
    }
    found
}

pub fn remember(paths: &Paths, country: &str, city: &str) -> Result<(), String> {
    let country = country.trim().to_uppercase();
    let city = city.trim().to_uppercase();
    if country.is_empty() {
        die("usage: ferrox-cli location <CC> [CITY]   (see 'ferrox-cli locations')");
    }
    if let Some(saved) = read_trim(&paths.locations_file) {
        let needle = format!("\"country\":\"{country}\"");
        if !saved.to_lowercase().contains(&needle.to_lowercase()) {
            die(&format!(
                "'{country}' is not in the saved catalogue list; run 'ferrox-cli locations' to refresh it, or pick a code it prints."
            ));
        }
    }
    secure_dir(&paths.conf_dir)
        .map_err(|error| format!("cannot create the config dir: {error}"))?;
    write_private(&paths.location_file, &format!("{country} {city}\n"))
        .map_err(|error| format!("cannot remember the exit: {error}"))?;
    if city.is_empty() {
        println!("exit remembered: {country} (its catalogue order picks the city). The next 'up --foxy' moves there.");
    } else {
        println!("exit remembered: {country} / {city}. The next 'up --foxy' moves there.");
    }
    Ok(())
}
