//! `Psiphon`: the public bootstrap list, its publisher key, and the region code
//! the native lane validates before it dials.

/// The local SOCKS listener the native lane binds when the config names none.
pub const DEFAULT_BIND: &str = "127.0.0.1:1821";

/// How long the first tunnel is given before the lane says the network answered nothing.
pub const READY_SECS: u64 = 180;

/// The public server list the native lane fetches and verifies with the key below.
pub const SERVER_LIST_URL: &str =
    "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed";

/// The publisher's key for [`SERVER_LIST_URL`].
pub const SERVER_LIST_SIGNATURE_KEY: &str = concat!(
    "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH",
    "5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5",
    "OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42Kcot",
    "LFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6",
    "/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7G",
    "stZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1O",
    "geF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8",
    "u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz",
    "31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xal",
    "KxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=",
);

/// A two-letter egress region, upper-cased, or nothing when the text is not one.
#[must_use]
pub fn region(text: &str) -> Option<String> {
    let text = text.trim();
    (text.len() == 2 && text.bytes().all(|byte| byte.is_ascii_alphabetic()))
        .then(|| text.to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_region_is_two_letters_and_upper_case() {
        assert_eq!(region(" us "), Some("US".to_owned()));
        assert_eq!(region("USA"), None);
        assert_eq!(region("1A"), None);
    }
}
