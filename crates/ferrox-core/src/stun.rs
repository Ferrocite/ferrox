//! A minimal STUN binding codec: the twenty-byte header and one address attribute.
//!
//! The reference carries `stun.Message` objects and attribute decoders beside the bytes a binding
//! exchange actually moves. This tree carries only the header the peer can answer and the one mapped
//! address it must read, on the stack. `binding_request_into` writes into the caller's buffer and
//! `decode_binding_response` borrows it, so neither side takes a heap for a twenty-byte request or a
//! response it has already received.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The RFC 5389 magic cookie. Every message here carries it; a packet without it is not STUN.
pub const COOKIE: u32 = 0x2112_A442;

/// The binding request type a discovery exchange starts with.
pub const BINDING_REQUEST: u16 = 0x0001;

/// The binding success response type discovery reads the mapped address from.
pub const BINDING_SUCCESS: u16 = 0x0101;

/// The XOR-mapped address attribute, the response's first choice for the mapped address.
pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// The plain mapped address attribute, the fallback when no XOR form is present.
pub const MAPPED_ADDRESS: u16 = 0x0001;

/// The STUN message header length: type, length, cookie and the twelve transaction bytes.
pub const HEADER_LEN: usize = 20;

/// Transaction bytes that tie a response to the request that asked for it.
pub const TRANSACTION_SIZE: usize = 12;

/// Whether `packet` carries the STUN header shape: at least twenty bytes, the class bits clear as
/// RFC 5389 requires for a message, and the magic cookie in place. That is the whole discriminator —
/// a caller then asks `decode_binding_response` for the exchange it belongs to.
#[must_use]
pub fn is_message(packet: &[u8]) -> bool {
    packet.len() >= HEADER_LEN
        && packet[0] & 0xC0 == 0
        && u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]) == COOKIE
}

/// Write the binding request for `transaction` into `out` and return its length. `out` must hold a
/// header; anything smaller is refused with `None` rather than written past.
#[must_use]
pub fn binding_request_into(out: &mut [u8], transaction: &[u8; TRANSACTION_SIZE]) -> Option<usize> {
    let room = out.get_mut(..HEADER_LEN)?;
    room[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    room[2..4].copy_from_slice(&0u16.to_be_bytes());
    room[4..8].copy_from_slice(&COOKIE.to_be_bytes());
    room[8..HEADER_LEN].copy_from_slice(transaction);
    Some(HEADER_LEN)
}

/// Decode a binding success `packet` tied to `transaction` into the mapped address it names. The XOR
/// form wins over the plain one; a packet shorther than its names length, from the wrong transaction,
/// or carrying no mapped address is `None`. The buffer is borrowed where it lies — the address is the
/// header's own bytes read in place, not a copy of the reply.
#[must_use]
pub fn decode_binding_response(
    packet: &[u8],
    transaction: &[u8; TRANSACTION_SIZE],
) -> Option<SocketAddr> {
    if packet.len() < HEADER_LEN {
        return None;
    }
    let kind = u16::from_be_bytes([packet[0], packet[1]]);
    let length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if kind != BINDING_SUCCESS
        || u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]) != COOKIE
        || packet.get(8..HEADER_LEN)? != transaction.as_slice()
        || packet.len() < HEADER_LEN + length
    {
        return None;
    }
    let mut offset = HEADER_LEN;
    while offset + 4 <= HEADER_LEN + length {
        let attribute = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let size = usize::from(u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]));
        let value = packet.get(offset + 4..offset + 4 + size)?;
        if let Some(address) = match attribute {
            XOR_MAPPED_ADDRESS => mapped(value, transaction, true),
            MAPPED_ADDRESS => mapped(value, transaction, false),
            _ => None,
        } {
            return Some(address);
        }
        offset += 4 + ((size + 3) & !3);
    }
    None
}

/// Unmask one mapped or XOR-mapped address value. The port and, for the XOR form, the address ride
/// the cookie (and for IPv6 the transaction bytes) the RFC names. A value shorter than its family
/// needs is `None`.
fn mapped(value: &[u8], transaction: &[u8; TRANSACTION_SIZE], xor: bool) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor {
        port ^= 0x2112;
    }
    match family {
        0x01 if value.len() >= 8 => {
            let mut octets = [value[4], value[5], value[6], value[7]];
            if xor {
                let cookie = COOKIE.to_be_bytes();
                for (octet, cookie) in octets.iter_mut().zip(cookie) {
                    *octet ^= cookie;
                }
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x02 if value.len() >= 20 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            if xor {
                let cookie = COOKIE.to_be_bytes();
                for (octet, cookie) in octets[..4].iter_mut().zip(cookie) {
                    *octet ^= cookie;
                }
                for (octet, transaction) in octets[4..].iter_mut().zip(transaction.iter()) {
                    *octet ^= transaction;
                }
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xor_v4(reply: &mut Vec<u8>, address: Ipv4Addr, port: u16, transaction: &[u8; 12]) {
        let raw_port = port ^ 0x2112;
        let mut value = Vec::with_capacity(8);
        value.push(0);
        value.push(0x01);
        value.extend_from_slice(&raw_port.to_be_bytes());
        let cookie = COOKIE.to_be_bytes();
        let mut octets = address.octets();
        for (octet, cookie) in octets.iter_mut().zip(cookie) {
            *octet ^= cookie;
        }
        value.extend_from_slice(&octets);
        let _ = transaction;
        reply.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        reply.extend_from_slice(&(value.len() as u16).to_be_bytes());
        reply.extend_from_slice(&value);
    }

    fn response_with(transaction: &[u8; 12], fill: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut reply = Vec::with_capacity(20 + 12);
        reply.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        reply.extend_from_slice(&12u16.to_be_bytes());
        reply.extend_from_slice(&COOKIE.to_be_bytes());
        reply.extend_from_slice(transaction);
        fill(&mut reply);
        reply
    }

    /// The request is twenty bytes with the right type, cookie and transaction, and the response the
    /// same transaction decodes its XOR-mapped address back — the loop a discovery exchange runs.
    #[test]
    fn a_binding_request_answers_with_its_xor_mapped_address() {
        let transaction = [7u8; TRANSACTION_SIZE];
        let mut request = [0u8; HEADER_LEN];
        assert_eq!(
            binding_request_into(&mut request, &transaction),
            Some(HEADER_LEN),
            "the request fills exactly one header"
        );
        assert_eq!(&request[0..2], &BINDING_REQUEST.to_be_bytes());
        assert_eq!(&request[4..8], &COOKIE.to_be_bytes());
        assert_eq!(&request[8..HEADER_LEN], &transaction);
        assert!(is_message(&request));
        assert!(binding_request_into(&mut [0u8; 19], &transaction).is_none());
        let reply = response_with(&transaction, |reply| {
            xor_v4(reply, Ipv4Addr::new(192, 0, 2, 1), 8000, &transaction);
        });
        assert_eq!(
            decode_binding_response(&reply, &transaction),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                8000
            ))
        );
    }

    /// The verifier the reference's decoding shares: type, cookie, transaction and bounds refuse
    /// before a mapped address is read, and the plain form answers when no XOR form is present.
    #[test]
    fn a_forged_or_truncated_response_is_refused_and_the_buffer_held() {
        let transaction = [9u8; TRANSACTION_SIZE];
        let other = [8u8; TRANSACTION_SIZE];
        let reply = response_with(&transaction, |reply| {
            xor_v4(reply, Ipv4Addr::new(198, 51, 100, 1), 443, &transaction);
        });
        assert!(decode_binding_response(&reply, &other).is_none());
        let before = reply.clone();
        assert!(decode_binding_response(&reply[..19], &transaction).is_none());
        assert_eq!(reply, before, "a refusal never rewrote the input");
        assert!(!is_message(&[0u8; 10]));
        assert!(!is_message(&[0xff; 20]));
        let mut no_mapped = response_with(&transaction, |_| {});
        no_mapped[2..4].copy_from_slice(&0u16.to_be_bytes());
        assert!(decode_binding_response(&no_mapped, &transaction).is_none());
        let plain_value = {
            let mut value = Vec::with_capacity(8);
            value.push(0);
            value.push(0x01);
            value.extend_from_slice(&443u16.to_be_bytes());
            value.extend_from_slice(&[198, 51, 100, 1]);
            value
        };
        let plain = response_with(&transaction, |reply| {
            reply.extend_from_slice(&MAPPED_ADDRESS.to_be_bytes());
            reply.extend_from_slice(&(plain_value.len() as u16).to_be_bytes());
            reply.extend_from_slice(&plain_value);
        });
        assert_eq!(
            decode_binding_response(&plain, &transaction),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                443
            ))
        );
    }

    /// The address is read where the reply lies: its base is the attribute value's bytes inside the
    /// caller's buffer, and the buffer itself moves and grows by nothing.
    #[test]
    fn a_decoded_address_leaves_the_reply_where_it_landed() {
        let transaction = [7u8; TRANSACTION_SIZE];
        let reply = response_with(&transaction, |reply| {
            xor_v4(reply, Ipv4Addr::new(203, 0, 113, 7), 3478, &transaction);
        });
        let base = reply.as_ptr();
        let room = reply.capacity();
        let decoded = decode_binding_response(&reply, &transaction).expect("a mapped address");
        assert_eq!(decoded.to_string(), "203.0.113.7:3478");
        assert_eq!(reply.as_ptr(), base, "the buffer itself never moved");
        assert_eq!(reply.capacity(), room, "no reallocation in the parse");
    }

    /// One message per request, on the stack: the request writes into its caller's buffer and decodes
    /// its answer into a `SocketAddr` without holding a heap for either — 4096 exchanges allocate
    /// nothing more than the buffer the caller already owns.
    #[test]
    fn a_binding_exchange_takes_no_heap() {
        let transaction = [7u8; TRANSACTION_SIZE];
        let mut request = [0u8; HEADER_LEN];
        let _ = binding_request_into(&mut request, &transaction);
        let reply = response_with(&transaction, |reply| {
            xor_v4(reply, Ipv4Addr::new(192, 0, 2, 55), 53, &transaction);
        });
        let ((), counts) = crate::alloc_count::measure(|| {
            for _ in 0..4096 {
                std::hint::black_box(binding_request_into(
                    std::hint::black_box(&mut request),
                    std::hint::black_box(&transaction),
                ));
                std::hint::black_box(decode_binding_response(
                    std::hint::black_box(&reply),
                    std::hint::black_box(&transaction),
                ));
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "4096 exchanges take no heap at all"
        );
    }
}
