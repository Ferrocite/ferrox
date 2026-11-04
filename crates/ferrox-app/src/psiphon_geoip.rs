//! A `MaxMind` country database consulted before an in-proxy peer carries bytes.

use maxminddb::geoip2;
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug)]
pub(crate) struct GeoIp {
    reader: maxminddb::Reader<Vec<u8>>,
    reject: HashSet<String>,
}

impl GeoIp {
    /// Open `path` when both a database and at least one country code are configured.
    pub(crate) fn open(path: &str, countries: &[String]) -> Result<Option<Self>, String> {
        let reject: HashSet<String> = countries
            .iter()
            .map(|code| code.trim().to_ascii_uppercase())
            .filter(|code| !code.is_empty())
            .collect();
        if path.is_empty() || reject.is_empty() {
            return Ok(None);
        }
        let reader = maxminddb::Reader::open_readfile(path)
            .map_err(|error| format!("psiphon: GeoIP database {path}: {error}"))?;
        Ok(Some(Self { reader, reject }))
    }

    /// True when the database places `address` in a rejected country.
    pub(crate) fn rejects(&self, address: IpAddr) -> bool {
        let Ok(result) = self.reader.lookup(address) else {
            return false;
        };
        let Ok(Some(record)) = result.decode::<geoip2::Country<'_>>() else {
            return false;
        };
        let code = record
            .country
            .iso_code
            .or(record.registered_country.iso_code);
        code.is_some_and(|code| self.reject.contains(code))
    }
}

#[cfg(test)]
mod tests {
    use super::GeoIp;

    #[test]
    fn no_database_or_no_country_is_not_an_error() {
        assert!(matches!(GeoIp::open("", &["IR".to_owned()]), Ok(None)));
        assert!(matches!(GeoIp::open("/nonexistent.mmdb", &[]), Ok(None)));
    }

    #[test]
    fn a_missing_database_names_the_path() {
        let error = GeoIp::open("/nonexistent.mmdb", &["IR".to_owned()]).unwrap_err();
        assert!(error.contains("/nonexistent.mmdb"), "{error}");
    }
}
