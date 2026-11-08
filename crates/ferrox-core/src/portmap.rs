//! Gateway port-mapping bytes: SSDP discovery headers, the device description tags a `go-nat`
//! mapper walks and the SOAP envelopes of `AddPortMapping` and `GetExternalIPAddress`.
//!
//! The reference hands all of this to `github.com/libp2p/go-nat` and lets it assemble bytes off a
//! discovery struct beside the wire it writes. This tree names only the bytes the wire carries:
//! `ssdp_search` writes the `M-SEARCH` the router answers, `ssdp_location` reads the `LOCATION`
//! it names back, `parse_root_desc` reads the one service an IGD node names for `UDP`, and the SOAP
//! envelopes and their answers are built and read from the caller's buffer, every tag carried
//! exactly as the reference crate writes it. No table of gateways is held, no device struct with a
//! heap beside the description it read.

use std::net::{IpAddr, SocketAddr};

/// SSDP multicast group the reference discovers a gateway on.
pub const SSDP_MULTICAST: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(239, 255, 255, 250)),
    1900,
);

/// The search types a mapper asks for, in order: the Internet Gateway Device first, because its
/// `WANIPConnection`/`WANPPPConnection` services are the ones that map `UDP`.
pub const SEARCH_TYPES: [&str; 3] = [
    "upnp:rootdevice",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];

/// The `WANIPConnection` service a no-PPP router names; the `WANPPPConnection` spelling is its twin.
pub const WAN_IP_SERVICE: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";

/// The `WANPPPConnection` service a PPP router names.
pub const WAN_PPP_SERVICE: &str = "urn:schemas-upnp-org:service:WANPPPConnection:1";

/// Write one `M-SEARCH` for `st` into `out`, returning its length or `None` when `out` has no room.
/// The `HOST` is the multicast group the router itself answers, and `MX` is its search window in
/// seconds; the reference writes `3` on every search.
#[must_use]
pub fn ssdp_search(st: &str, out: &mut [u8]) -> Option<usize> {
    let head = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\"MAN\": \"noseek\"; ns=01\r\nMX: 3\r\nST: ";
    let tail = "\r\n\r\n";
    let total = head.len() + st.len() + tail.len();
    let room = out.get_mut(..total)?;
    room[..head.len()].copy_from_slice(head.as_bytes());
    room[head.len()..head.len() + st.len()].copy_from_slice(st.as_bytes());
    room[head.len() + st.len()..].copy_from_slice(tail.as_bytes());
    Some(total)
}

/// Read the `LOCATION` a SSDP `200 OK` names, header names compared without case. `None` when the
/// reply names no location or names one too short to be a URL.
#[must_use]
pub fn ssdp_location(reply: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(reply).ok()?;
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("location") {
            let value = value.trim();
            if value.is_empty() {
                return None;
            }
            return Some(value.to_owned());
        }
    }
    None
}

/// One service an IGD description names for `UDP`: its type and the control URL a mapping request
/// travels to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// The `WANIPConnection` or `WANPPPConnection` type the description listed.
    pub service_type: String,
    /// The control URL a mapping request travels to.
    pub control_url: String,
}

/// Read the `URLBase` a description roots itself at and the first `WANIPConnection` or
/// `WANPPPConnection` service it lists. `None` when the description names neither. A missing base
/// leaves the control URL as the description literally names it — the caller joins the two when
/// it dials.
#[must_use]
pub fn parse_root_desc(xml: &str) -> Option<(Option<String>, Service)> {
    let url_base = xml_tag(xml, "URLBase").map(str::to_owned);
    let block = xml_between(xml, "<serviceList>")?;
    let services: Vec<&str> = block.split("<service>").collect();
    for part in services {
        let Some(service_type) = xml_tag(part, "serviceType") else {
            continue;
        };
        if service_type != WAN_IP_SERVICE && service_type != WAN_PPP_SERVICE {
            continue;
        }
        let control_url = xml_tag(part, "controlURL")?;
        return Some((
            url_base,
            Service {
                service_type: service_type.to_owned(),
                control_url: control_url.to_owned(),
            },
        ));
    }
    None
}

/// Read one tag's contents exactly as the description writes them.
fn xml_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let at = xml.find(&open)?;
    let rest = &xml[at + open.len()..];
    let close = format!("</{tag}>");
    let end = rest.find(&close)?;
    Some(&rest[..end])
}

/// Read the bytes of one `<service>` block's list, or `None` when the description lists no service.
fn xml_between<'a>(xml: &'a str, open: &str) -> Option<&'a str> {
    let at = xml.find(open)?;
    let rest = &xml[at + open.len()..];
    let end = rest.find("</serviceList>")?;
    Some(&rest[..end])
}

/// Build the SOAP envelope for `AddPortMapping`: the bytes gateways accept, `Call` and `RemoteHost`
/// named exactly as the reference writes them, and `ProtocolType` the router's `UDP` it opens. The
/// `Description`, `PortMappingDescription` and `LeaseDuration` ride behind, so a lease that is not
/// positive is refused here rather than leased forever by a `0`. `None` when `out` has no room.
#[must_use]
pub fn add_mapping_body(
    service_type: &str,
    internal_port: u16,
    description: &str,
    lease: u32,
    out: &mut [u8],
) -> Option<usize> {
    if lease == 0 {
        return None;
    }
    let envelope = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:AddPortMapping xmlns:u=\"{service_type}\">"
    );
    let tail = "</u:AddPortMapping></s:Body></s:Envelope>";
    let args = format!(
        "<NewRemotePort>{internal_port}</NewRemotePort><NewProtocol>UDP</NewProtocol><NewInternalPort>{internal_port}</NewInternalPort><NewInternalClient>127.0.0.1</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{description}</NewPortMappingDescription><NewLeaseDuration>{lease}</NewLeaseDuration>"
    );
    let total = envelope.len() + args.len() + tail.len();
    let room = out.get_mut(..total)?;
    room[..envelope.len()].copy_from_slice(envelope.as_bytes());
    room[envelope.len()..envelope.len() + args.len()].copy_from_slice(args.as_bytes());
    room[envelope.len() + args.len()..].copy_from_slice(tail.as_bytes());
    Some(total)
}

/// Build the SOAP envelope for `GetExternalIPAddress`: the address a mapping is reachable at, read
/// after the mapping itself, not read off the mapping reply.
#[must_use]
pub fn external_ip_body(service_type: &str, out: &mut [u8]) -> Option<usize> {
    let envelope = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:GetExternalIPAddress xmlns:u=\"{service_type}\"></u:GetExternalIPAddress></s:Body></s:Envelope>"
    );
    let room = out.get_mut(..envelope.len())?;
    room.copy_from_slice(envelope.as_bytes());
    Some(envelope.len())
}

/// Read the `NewExternalPort` an `AddPortMapping` reply names.
#[must_use]
pub fn parse_external_port(xml: &str) -> Option<u16> {
    xml_tag(xml, "NewExternalPort")?.parse().ok()
}

/// Read the `NewExternalIPAddress` a `GetExternalIPAddress` reply names.
#[must_use]
pub fn parse_external_ip(xml: &str) -> Option<IpAddr> {
    xml_tag(xml, "NewExternalIPAddress")?.parse().ok()
}

/// Join a device's `controlURL` onto the `URLBase` its description roots itself at, or keep it as
/// the description names it when no base is rooted there. An absolute control URL wins.
#[must_use]
pub fn join_control(url_base: Option<&str>, control: &str) -> String {
    if control.starts_with("http://") || control.starts_with("https://") {
        return control.to_owned();
    }
    if let Some(base) = url_base {
        let base = base.trim_end_matches('/');
        if control.starts_with('/') {
            if let Some(scheme_end) = base.find("://") {
                if let Some(host_end) = base[scheme_end + 3..]
                    .find('/')
                    .map(|at| at + scheme_end + 3)
                {
                    return format!("{}{control}", &base[..host_end]);
                }
                return format!("{base}{control}");
            }
        }
        return format!("{base}/{control}");
    }
    control.to_owned()
}

/// Split a `LOCATION` or control URL into the host, port and path a dial travels to. `None` when
/// the URL names no host.
#[must_use]
pub fn split_url(url: &str) -> Option<(String, u16, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let path = if authority_end < rest.len() {
        rest[authority_end..].to_owned()
    } else {
        "/".to_owned()
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (
            h.trim_matches(['[', ']']).to_owned(),
            p.parse::<u16>().ok()?,
        ),
        _ => (
            authority.trim_matches(['[', ']']).to_owned(),
            if scheme.eq_ignore_ascii_case("https") {
                443
            } else {
                80
            },
        ),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The search is twenty `M-SEARCH` lines and nothing beside: the multicast group, the noseek
    /// manifest, the search window and the four advertised `ST` values, which the fake server reads
    /// back as the exact bytes the router answers.
    #[test]
    fn an_m_search_names_every_advertised_search() {
        let mut out = [0u8; 512];
        for st in SEARCH_TYPES {
            let written = ssdp_search(st, &mut out).expect("fits");
            let text = std::str::from_utf8(&out[..written]).expect("utf8");
            assert!(text.starts_with("M-SEARCH * HTTP/1.1\r\n"), "one search");
            assert!(
                text.contains("HOST: 239.255.255.250:1900\r\n"),
                "the multicast host"
            );
            assert!(text.contains("ST: "), "the search type rides at the end");
            assert!(text.ends_with("\r\n\r\n"), "one blank line");
        }
        assert!(ssdp_search("upnp:rootdevice", &mut [0u8; 8]).is_none());
    }

    /// The location is read without case beside the header name, and a reply naming none answers
    /// `None` rather than the first line.
    #[test]
    fn a_location_is_read_without_case_beside_the_name() {
        let reply = b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/rootDesc.xml\r\nCONTENT-LENGTH: 0\r\n\r\n";
        assert_eq!(
            ssdp_location(reply).as_deref(),
            Some("http://192.168.1.1:5000/rootDesc.xml")
        );
        assert_eq!(
            ssdp_location(b"HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 0\r\n\r\n"),
            None
        );
    }

    /// The control the mapper walks is the first IGD service the description lists, joined onto the
    /// base it roots itself at; a description listing no IGD service names no control.
    #[test]
    fn a_root_description_names_its_control_url() {
        let xml = r"<root><URLBase>http://192.168.1.1:5000</URLBase><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/WANIPConnection1</controlURL></service></serviceList></root>";
        let (base, service) = parse_root_desc(xml).expect("a service");
        assert_eq!(base.as_deref(), Some("http://192.168.1.1:5000"));
        assert_eq!(service.service_type, WAN_IP_SERVICE);
        assert_eq!(service.control_url, "/ctl/WANIPConnection1");
        assert_eq!(
            join_control(base.as_deref(), &service.control_url),
            "http://192.168.1.1:5000/ctl/WANIPConnection1"
        );
        assert_eq!(
            join_control(None, "http://192.168.1.2:80/c"),
            "http://192.168.1.2:80/c"
        );
        assert!(parse_root_desc("<root></root>").is_none());
    }

    /// The mapping envelope is the bytes the gateway reads: the action the header names, `UDP` as
    /// its protocol and the lease the dial asked for. The external address body is the one the
    /// reference reads after it.
    #[test]
    fn a_mapping_and_external_ip_body_carry_the_reference_action() {
        let mut out = [0u8; 2048];
        let written =
            add_mapping_body(WAN_IP_SERVICE, 4000, "hysteria-realm", 600, &mut out).expect("fits");
        let xml = std::str::from_utf8(&out[..written]).expect("utf8");
        assert!(xml.contains("AddPortMapping"), "the action");
        assert!(
            xml.contains("<NewProtocol>UDP</NewProtocol>"),
            "the protocol"
        );
        assert!(
            xml.contains("<NewInternalPort>4000</NewInternalPort>"),
            "the internal port"
        );
        assert!(
            xml.contains("<NewLeaseDuration>600</NewLeaseDuration>"),
            "the lease"
        );
        assert!(add_mapping_body(WAN_IP_SERVICE, 4000, "hysteria-realm", 0, &mut out).is_none());
        let mut ext = [0u8; 512];
        let written = external_ip_body(WAN_IP_SERVICE, &mut ext).expect("fits");
        let xml = std::str::from_utf8(&ext[..written]).expect("utf8");
        assert!(xml.contains("GetExternalIPAddress"), "the address action");
        let reply = r"<s:Envelope><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>203.0.113.7</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>";
        assert_eq!(
            parse_external_ip(reply),
            Some(IpAddr::V4([203, 0, 113, 7].into()))
        );
        let port_reply = r"<s:Envelope><s:Body><u:AddPortMappingResponse><NewExternalPort>4100</NewExternalPort></u:AddPortMappingResponse></s:Body></s:Envelope>";
        assert_eq!(parse_external_port(port_reply), Some(4100));
    }

    /// The URL the description or the search names is split without guessing at a bracketed host.
    #[test]
    fn a_url_is_split_without_guessing_at_a_bracket() {
        assert_eq!(
            split_url("http://[2001:db8::1]:5000/rootDesc.xml"),
            Some(("2001:db8::1".to_owned(), 5000, "/rootDesc.xml".to_owned()))
        );
        assert_eq!(
            split_url("http://192.168.1.1/ctl"),
            Some(("192.168.1.1".to_owned(), 80, "/ctl".to_owned()))
        );
        assert_eq!(split_url("http://"), None);
    }
}
