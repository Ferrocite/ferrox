//! The top-level `geodata` block: the reference's config build checks every asset and the cron, and
//! a cron schedules a refresh this tree does not carry yet, so the files on disk are what runs.

use crate::json::Json;
use std::path::PathBuf;

/// Validate the `geodata` block as the reference's build does: a robfig standard cron, and an HTTPS
/// URL plus a statable local file for every asset. An unknown field is inert, as the reference's decoder leaves it.
pub(crate) fn parse(root: &Json, dirs: &[PathBuf]) -> Result<(), String> {
    let Some(section) = root.get("geodata") else {
        return Ok(());
    };
    let Json::Obj(pairs) = section else {
        return match section {
            Json::Null => Ok(()),
            _ => Err("`geodata` is not an object".to_owned()),
        };
    };
    let mut cron = None;
    let mut assets: &[Json] = &[];
    for (key, value) in pairs {
        match key.as_str() {
            "cron" => cron = text(value, key)?,
            "outbound" => {
                text(value, key)?;
            }
            "assets" if matches!(value, Json::Null) => {}
            "assets" => {
                assets = value
                    .as_arr()
                    .ok_or_else(|| format!("`geodata.{key}` is not an array"))?;
            }
            _ => {}
        }
    }
    if let Some(cron) = cron {
        parse_standard(cron).map_err(|reason| format!("invalid geodata cron: {reason}"))?;
    }
    for asset in assets {
        check_asset(asset, dirs)?;
    }
    if cron.is_some() {
        eprintln!(
            "geodata: a cron schedule is configured, but asset downloads are not carried here; the files on disk are used"
        );
    }
    Ok(())
}

/// A string field, where the reference's JSON decoder treats `null` as absent.
fn text<'a>(value: &'a Json, field: &str) -> Result<Option<&'a str>, String> {
    match value {
        Json::Null => Ok(None),
        Json::Str(text) => Ok(Some(text)),
        _ => Err(format!("`geodata.{field}` is not a string")),
    }
}

/// One `{url, file}` asset: an HTTPS URL and a local regular file the asset directories can find.
fn check_asset(asset: &Json, dirs: &[PathBuf]) -> Result<(), String> {
    let Json::Obj(pairs) = asset else {
        return Err("`geodata.assets` holds an entry that is not an object".to_owned());
    };
    let mut url = "";
    let mut file = "";
    for (key, value) in pairs {
        match key.as_str() {
            "url" => url = value.as_str().unwrap_or_default(),
            "file" => file = value.as_str().unwrap_or_default(),
            _ => {}
        }
    }
    https_url(url)?;
    if !crate::router::is_local_asset(file) {
        return Err(format!(
            "invalid geodata asset file: {file}: asset path must stay in asset directory"
        ));
    }
    crate::router::resolve_asset_path(file, dirs).ok_or_else(|| {
        format!("invalid geodata asset file: {file}: the file is not a regular file under the asset directories")
    })?;
    Ok(())
}

/// The reference's `validateHTTPS`: the scheme compared without case, as Go's URL parser lowercases it, and a host that is not empty.
fn https_url(url: &str) -> Result<(), String> {
    let refused = |reason: &str| format!("invalid geodata asset url: {url}: {reason}");
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(refused("URL names no scheme"));
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(refused("scheme must be https"));
    }
    crate::conn::HttpUrl::parse(&format!("https://{rest}")).map_err(|error| refused(&error))?;
    Ok(())
}

/// One field's bounds and the names it accepts, in the reference's parser's own ranges.
#[derive(Clone, Copy)]
struct Bounds {
    min: u32,
    max: u32,
    names: &'static [(&'static str, u32)],
}

const MINUTES: Bounds = Bounds {
    min: 0,
    max: 59,
    names: &[],
};
const HOURS: Bounds = Bounds {
    min: 0,
    max: 23,
    names: &[],
};
const DOM: Bounds = Bounds {
    min: 1,
    max: 31,
    names: &[],
};
const MONTH_NAMES: [(&str, u32); 12] = [
    ("jan", 1),
    ("feb", 2),
    ("mar", 3),
    ("apr", 4),
    ("may", 5),
    ("jun", 6),
    ("jul", 7),
    ("aug", 8),
    ("sep", 9),
    ("oct", 10),
    ("nov", 11),
    ("dec", 12),
];
const MONTHS: Bounds = Bounds {
    min: 1,
    max: 12,
    names: &MONTH_NAMES,
};
const DOW_NAMES: [(&str, u32); 7] = [
    ("sun", 0),
    ("mon", 1),
    ("tue", 2),
    ("wed", 3),
    ("thu", 4),
    ("fri", 5),
    ("sat", 6),
];
const DOW: Bounds = Bounds {
    min: 0,
    max: 6,
    names: &DOW_NAMES,
};

/// robfig's standard parser's language — five fields, names, steps, lists, `?` for `*`, the `@`
/// descriptors and a `TZ=`/`CRON_TZ=` zone — so a schedule the reference accepts is not refused.
fn parse_standard(spec: &str) -> Result<(), String> {
    let mut spec = spec;
    for prefix in ["CRON_TZ=", "TZ="] {
        let Some(rest) = spec.strip_prefix(prefix) else {
            continue;
        };
        let (_, tail) = rest.split_once(char::is_whitespace).ok_or_else(|| {
            "provided bad location: the spec names no schedule after the zone".to_owned()
        })?;
        spec = tail.trim();
        break;
    }
    if spec.is_empty() {
        return Err("empty spec string".to_owned());
    }
    if spec.starts_with('@') {
        return parse_descriptor(spec);
    }
    let fields: Vec<&str> = spec.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(format!(
            "expected exactly 5 fields, found {}: {spec}",
            fields.len()
        ));
    }
    for (field, bounds) in fields.iter().zip([MINUTES, HOURS, DOM, MONTHS, DOW]) {
        parse_field(field, bounds)?;
    }
    Ok(())
}

fn parse_descriptor(spec: &str) -> Result<(), String> {
    match spec {
        "@yearly" | "@annually" | "@monthly" | "@weekly" | "@daily" | "@midnight" | "@hourly" => {
            Ok(())
        }
        _ => match spec.strip_prefix("@every ") {
            Some(duration) if parse_duration(duration) => Ok(()),
            Some(duration) => Err(format!("failed to parse duration {duration}")),
            None => Err(format!("unrecognized descriptor: {spec}")),
        },
    }
}

/// A comma-separated list of ranges; an empty piece contributes nothing, as the reference's split does.
fn parse_field(field: &str, bounds: Bounds) -> Result<(), String> {
    for expr in field.split(',').filter(|expr| !expr.is_empty()) {
        parse_range(expr, bounds)?;
    }
    Ok(())
}

fn parse_range(expr: &str, bounds: Bounds) -> Result<(), String> {
    let (range, step) = match expr.split_once('/') {
        Some((range, step)) if !step.contains('/') => (range, Some(parse_uint(step)?)),
        Some(_) => return Err(format!("too many slashes: {expr}")),
        None => (expr, None),
    };
    let mut hyphenated = range.split('-');
    let low = hyphenated.next().unwrap_or_default();
    let high = hyphenated.next();
    if hyphenated.next().is_some() {
        return Err(format!("too many hyphens: {expr}"));
    }
    let (start, end) = if low == "*" || low == "?" {
        (bounds.min, bounds.max)
    } else {
        let start = parse_value(low, bounds)?;
        let end = match high {
            Some(high) => parse_value(high, bounds)?,
            None => start,
        };
        (start, end)
    };
    let end = if high.is_none() && step.is_some() {
        bounds.max
    } else {
        end
    };
    let step = step.unwrap_or(1);
    if start < bounds.min {
        return Err(format!(
            "beginning of range ({start}) below minimum ({}): {expr}",
            bounds.min
        ));
    }
    if end > bounds.max {
        return Err(format!(
            "end of range ({end}) above maximum ({}): {expr}",
            bounds.max
        ));
    }
    if start > end {
        return Err(format!(
            "beginning of range ({start}) beyond end of range ({end}): {expr}"
        ));
    }
    if step == 0 {
        return Err(format!("step of range should be a positive number: {expr}"));
    }
    Ok(())
}

fn parse_value(text: &str, bounds: Bounds) -> Result<u32, String> {
    let lowered = text.to_ascii_lowercase();
    if let Some((_, value)) = bounds.names.iter().find(|(name, _)| *name == lowered) {
        return Ok(*value);
    }
    parse_uint(text)
}

fn parse_uint(text: &str) -> Result<u32, String> {
    let digits = text.strip_prefix('+').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("failed to parse int from {text}"));
    }
    digits
        .parse()
        .map_err(|_| format!("failed to parse int from {text}"))
}

/// Go's `time.ParseDuration` grammar, which an `@every` descriptor carries: unit groups of decimal
/// and optional fractional numbers, with `0` as the one unitless form.
fn parse_duration(text: &str) -> bool {
    let text = text.strip_prefix(['+', '-']).unwrap_or(text);
    if text == "0" {
        return true;
    }
    let bytes = text.as_bytes();
    let mut at = 0;
    let mut groups = 0;
    while at < bytes.len() {
        let mut digits = 0;
        while at < bytes.len() && bytes[at].is_ascii_digit() {
            at += 1;
            digits += 1;
        }
        if at < bytes.len() && bytes[at] == b'.' {
            at += 1;
            while at < bytes.len() && bytes[at].is_ascii_digit() {
                at += 1;
                digits += 1;
            }
        }
        if digits == 0 {
            return false;
        }
        let rest = &bytes[at..];
        let unit = if rest.starts_with(b"ns") || rest.starts_with(b"us") || rest.starts_with(b"ms")
        {
            2
        } else if rest.starts_with(b"\xc2\xb5s") || rest.starts_with(b"\xce\xbcs") {
            3
        } else if rest
            .first()
            .is_some_and(|byte| matches!(byte, b's' | b'm' | b'h'))
        {
            1
        } else {
            return false;
        };
        at += unit;
        groups += 1;
    }
    groups > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ferrox-geodata-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("creates the asset directory");
        std::fs::write(dir.join("geosite.dat"), b"").expect("writes the asset");
        dir
    }

    fn config(geodata: &str) -> Json {
        crate::json::parse(&format!(r#"{{"geodata": {geodata}}}"#)).expect("parses")
    }

    #[test]
    fn a_geodata_asset_url_must_be_https() {
        let root = config(
            r#"{"assets": [{"url": "http://example.test/geosite.dat", "file": "geosite.dat"}]}"#,
        );
        let error = parse(&root, &[asset_dir()]).expect_err("http is refused");
        assert!(
            error.contains("invalid geodata asset url") && error.contains("https"),
            "{error}"
        );
    }

    #[test]
    fn a_geodata_asset_url_scheme_is_read_without_case() {
        let dir = asset_dir();
        for url in [
            "HTTPS://example.test/geosite.dat",
            "Https://example.test/a/b",
        ] {
            let root = config(&format!(
                r#"{{"assets": [{{"url": "{url}", "file": "geosite.dat"}}]}}"#
            ));
            parse(&root, std::slice::from_ref(&dir))
                .expect("Go's URL parser lowercases the scheme, so the reference accepts it");
        }
        let root =
            config(r#"{"assets": [{"url": "https:///geosite.dat", "file": "geosite.dat"}]}"#);
        let error = parse(&root, &[dir]).expect_err("a URL with no host is refused");
        assert!(error.contains("invalid geodata asset url"), "{error}");
    }

    #[test]
    fn a_geodata_asset_file_must_be_statable() {
        let missing = format!("geodata-missing-{}.dat", std::process::id());
        let root = config(&format!(
            r#"{{"assets": [{{"url": "https://example.test/geoip.dat", "file": "{missing}"}}]}}"#
        ));
        let error = parse(&root, &[asset_dir()]).expect_err("a missing file is refused");
        assert!(
            error.contains("invalid geodata asset file") && error.contains(&missing),
            "{error}"
        );
        let root = config(&format!(
            r#"{{"assets": [{{"url": "https://example.test/geoip.dat", "file": "../{missing}"}}]}}"#
        ));
        let error = parse(&root, &[asset_dir()])
            .expect_err("a file outside the asset directory is refused");
        assert!(
            error.contains("asset path must stay in asset directory"),
            "{error}"
        );
    }

    #[test]
    fn the_references_geodata_block_is_accepted() {
        let root = config(
            r#"{"cron": "0 3 * * *", "outbound": "direct", "assets": [{"url": "https://example.test/geosite.dat", "file": "geosite.dat"}]}"#,
        );
        parse(&root, &[asset_dir()]).expect("the reference's example is accepted");
    }

    #[test]
    fn a_geodata_cron_outside_the_standard_grammar_is_refused() {
        let error =
            parse(&config(r#"{"cron": "0 3 * *"}"#), &[]).expect_err("four fields are refused");
        assert!(error.contains("invalid geodata cron"), "{error}");
    }

    #[test]
    fn a_null_geodata_block_is_no_block() {
        parse(
            &crate::json::parse(r#"{"geodata": null}"#).expect("parses"),
            &[],
        )
        .expect("the reference's pointer stays nil, so this config runs");
    }

    #[test]
    fn an_unknown_geodata_field_is_ignored() {
        parse(&config(r#"{"schedule": "0 3 * * *"}"#), &[])
            .expect("the reference's decoder ignores an unknown field, so this config runs");
    }

    #[test]
    fn the_cron_grammar_matches_the_references_standard_parser() {
        for spec in [
            "0 3 * * *",
            "* * * * *",
            "? ? ? ? ?",
            "*/15 0-6,22 1 jan-mar mon-fri",
            "5/10 * * * *",
            "+5 * * * *",
            "TZ=UTC 0 3 * * *",
            "TZ= 0 3 * * *",
            "CRON_TZ=Europe/Berlin @hourly",
            "@yearly",
            "@annually",
            "@monthly",
            "@weekly",
            "@daily",
            "@midnight",
            "@hourly",
            "@every 1h30m",
            "@every .5s",
            "@every 0",
        ] {
            assert!(
                parse_standard(spec).is_ok(),
                "{spec} is accepted by the reference"
            );
        }
        for spec in [
            "",
            "0 3 * *",
            "0 3 * * * *",
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * * 13 *",
            "* * * * 7",
            "5-1 * * * *",
            "*/0 * * * *",
            "1-2-3 * * * *",
            "1/2/3 * * * *",
            "x * * * *",
            "@sometimes",
            "@every 5",
            "@every",
        ] {
            assert!(
                parse_standard(spec).is_err(),
                "{spec} is refused by the reference"
            );
        }
    }
}
