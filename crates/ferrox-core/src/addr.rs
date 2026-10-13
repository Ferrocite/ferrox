pub const IPV4: u8 = 0x01;
pub const DOMAIN: u8 = 0x02;
pub const IPV6: u8 = 0x03;

pub const MAX_DOMAIN: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyError {
    Unknown(u8),
    Short,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addr<'a> {
    V4([u8; 4]),
    V6([u8; 16]),
    Name(&'a [u8]),
}

impl<'a> Addr<'a> {
    #[must_use]
    pub fn of(host: &'a str) -> Self {
        if host.contains(':') {
            if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
                return Self::V6(ip.octets());
            }
        } else if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            return Self::V4(ip.octets());
        }
        let bytes = host.as_bytes();
        Self::Name(&bytes[..bytes.len().min(MAX_DOMAIN)])
    }

    #[must_use]
    pub const fn wire_len(&self) -> usize {
        match self {
            Self::V4(_) => 1 + 4,
            Self::V6(_) => 1 + 16,
            Self::Name(bytes) => 1 + 1 + bytes.len(),
        }
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        match self {
            Self::V4(octets) => octets,
            Self::V6(octets) => octets,
            Self::Name(bytes) => bytes,
        }
    }

    #[inline]
    pub fn encode_into(&self, out: &mut [u8]) -> usize {
        assert!(out.len() >= self.wire_len(), "address buffer too short");
        match self {
            Self::V4(octets) => {
                out[0] = IPV4;
                out[1..5].copy_from_slice(octets);
                5
            }
            Self::V6(octets) => {
                out[0] = IPV6;
                out[1..17].copy_from_slice(octets);
                17
            }
            Self::Name(bytes) => {
                out[0] = DOMAIN;
                out[1] = bytes.len() as u8;
                out[2..2 + bytes.len()].copy_from_slice(bytes);
                2 + bytes.len()
            }
        }
    }

    #[inline]
    pub fn take(buf: &'a [u8]) -> Result<(Self, usize), FamilyError> {
        let Some((&family, rest)) = buf.split_first() else {
            return Err(FamilyError::Short);
        };
        let (addr, body) = match family {
            IPV4 => (Self::V4(fixed::<4>(rest).ok_or(FamilyError::Short)?), 4),
            IPV6 => (Self::V6(fixed::<16>(rest).ok_or(FamilyError::Short)?), 16),
            DOMAIN => {
                let (&n, tail) = rest.split_first().ok_or(FamilyError::Short)?;
                let n = usize::from(n);
                (Self::Name(tail.get(..n).ok_or(FamilyError::Short)?), 1 + n)
            }
            other => return Err(FamilyError::Unknown(other)),
        };
        Ok((addr, 1 + body))
    }
}

fn fixed<const N: usize>(b: &[u8]) -> Option<[u8; N]> {
    let head: &[u8; N] = b.get(..N)?.try_into().ok()?;
    Some(*head)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_families_encode_to_the_bytes_the_field_defines() {
        let mut buf = [0u8; 17];

        let v4 = Addr::of("192.0.2.53");
        assert_eq!(v4.wire_len(), 5);
        assert_eq!(v4.encode_into(&mut buf), 5);
        assert_eq!(&buf[..5], &[IPV4, 192, 0, 2, 53]);

        let v6 = Addr::of("2001:db8::1");
        assert_eq!(v6.wire_len(), 17);
        assert_eq!(v6.encode_into(&mut buf), 17);
        assert_eq!(
            &buf[..17],
            &[IPV6, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );

        let name = Addr::of("example.com");
        assert_eq!(name.wire_len(), 13);
        assert_eq!(name.encode_into(&mut buf), 13);
        assert_eq!(&buf[..13], b"\x02\x0bexample.com");
    }

    #[test]
    fn every_host_round_trips_through_its_own_bytes() {
        for host in ["192.0.2.53", "2001:db8::1", "example.com", "a", "x.test"] {
            let addr = Addr::of(host);
            let mut buf = [0u8; 17];
            let n = addr.encode_into(&mut buf);
            assert_eq!(Addr::take(&buf[..n]), Ok((addr, n)), "{host}");
        }
    }

    #[test]
    fn a_domain_longer_than_the_length_byte_is_cut_not_wrapped() {
        let long = "d".repeat(MAX_DOMAIN + 1);
        let addr = Addr::of(&long);
        assert!(matches!(addr, Addr::Name(b) if b.len() == MAX_DOMAIN));
        let mut buf = [0u8; MAX_DOMAIN + 2];
        let n = addr.encode_into(&mut buf);
        assert_eq!(buf[1], u8::try_from(MAX_DOMAIN).expect("255 fits a byte"));
        assert_eq!(Addr::take(&buf[..n]), Ok((addr, n)));
    }

    #[test]
    fn take_tells_a_bad_family_byte_from_a_short_field() {
        assert_eq!(Addr::take(&[]), Err(FamilyError::Short));
        assert_eq!(Addr::take(&[IPV4, 1, 2, 3]), Err(FamilyError::Short));
        assert_eq!(Addr::take(&[IPV6, 0, 0, 0, 0]), Err(FamilyError::Short));
        assert_eq!(Addr::take(&[DOMAIN]), Err(FamilyError::Short));
        assert_eq!(
            Addr::take(&[DOMAIN, 4, b'a', b'b']),
            Err(FamilyError::Short)
        );
        assert_eq!(
            Addr::take(&[0xff, 1, 2, 3, 4]),
            Err(FamilyError::Unknown(0xff))
        );
    }
}
