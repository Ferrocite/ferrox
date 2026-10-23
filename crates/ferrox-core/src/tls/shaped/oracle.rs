// The shaped client's TLS 1.2 record layer, gated against Go's own wire bytes.
use super::record::{self, Suite};
use super::{rsa, tls12};
use crate::tls::TlsError;

const CLIENT_PAYLOAD: &[u8] = b"ferrox-c2s";
const SERVER_PAYLOAD: &[u8] = b"ferrox-s2c-payload";

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "the golden holds whole bytes");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("the golden is hex"))
        .collect()
}

/// Every record of a captured stream, header included.
fn records(stream: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < stream.len() {
        let header: [u8; 5] = stream[at..at + 5].try_into().expect("a record header");
        let end = at + 5 + usize::from(u16::from_be_bytes([header[3], header[4]]));
        assert!(end <= stream.len(), "the stream holds whole records");
        out.push(&stream[at..end]);
        at = end;
    }
    out
}

/// The records that follow `ChangeCipherSpec`, in order.
fn sealed<'a>(stream: &'a [&'a [u8]]) -> &'a [&'a [u8]] {
    let at = stream
        .iter()
        .position(|record| record[0] == 20)
        .expect("a ChangeCipherSpec");
    &stream[at + 1..]
}

/// The handshake bytes one direction wrote in the clear, before it switched keys.
fn clear(stream: &[&[u8]]) -> Vec<u8> {
    let mut buf = Vec::new();
    for record in stream {
        match record[0] {
            22 => buf.extend_from_slice(&record[5..]),
            20 => break,
            _ => {}
        }
    }
    buf
}

/// Whole handshake messages, four-byte headers included, as the transcript hashes them.
fn messages(body: &[u8]) -> Vec<&[u8]> {
    let mut rest = body;
    let mut out = Vec::new();
    while !rest.is_empty() {
        let len = usize::try_from(u32::from_be_bytes([0, rest[1], rest[2], rest[3]]))
            .expect("a message length")
            + 4;
        assert!(len <= rest.len(), "the transcript holds whole messages");
        out.push(&rest[..len]);
        rest = &rest[len..];
    }
    out
}

fn has_extension(body: &[u8], kind: u16) -> bool {
    let mut rest = body;
    while rest.len() >= 4 + usize::from(u16::from_be_bytes([rest[2], rest[3]])) {
        if u16::from_be_bytes([rest[0], rest[1]]) == kind {
            return true;
        }
        let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        rest = &rest[4 + len..];
    }
    false
}

/// Replay one captured session: expand the key block from the logged master secret, then open and
/// authenticate every record Go encrypted, in the order its sequence numbers run.
fn gate(id: u16, master: &[u8], c2s: &[u8], s2c: &[u8]) {
    let suite = Suite::from_id(id).expect("a suite the shaped client keys");
    let c2s = records(c2s);
    let s2c = records(s2c);
    let wrote = clear(&c2s);
    let heard = clear(&s2c);
    let client_plain = messages(&wrote);
    let server_plain = messages(&heard);

    let mut client_random = [0u8; 32];
    client_random.copy_from_slice(&client_plain[0][6..38]);
    let hello = server_plain[0];
    let mut server_random = [0u8; 32];
    server_random.copy_from_slice(&hello[6..38]);
    let at = 39 + usize::from(hello[38]);
    assert_eq!(
        u16::from_be_bytes(hello[at..at + 2].try_into().unwrap()),
        id,
        "the server hello names the session's suite"
    );
    let len = usize::from(u16::from_be_bytes([hello[at + 3], hello[at + 4]]));
    assert!(
        has_extension(&hello[at + 5..at + 5 + len], 0x0017),
        "the reference negotiates the extended master secret"
    );

    let mut transcript = client_plain[0].to_vec();
    for message in &server_plain {
        transcript.extend_from_slice(message);
    }
    transcript.extend_from_slice(client_plain[1]);

    let mut keys = tls12::directions(suite, master, &client_random, &server_random);
    let mut body = sealed(&c2s)[0][5..].to_vec();
    let (start, len) = record::open12(&mut keys.client, sealed(&c2s)[0][0], &mut body)
        .expect("opens the Finished");
    let finished = body[start..start + len].to_vec();
    let verify = tls12::finished(suite, master, b"client finished", &transcript);
    assert_eq!(
        finished,
        [&[20u8, 0, 0, 12][..], &verify].concat(),
        "Go's client Finished is the one this key block signs"
    );

    transcript.extend_from_slice(&finished);
    let mut body = sealed(&s2c)[0][5..].to_vec();
    let (start, len) = record::open12(&mut keys.server, sealed(&s2c)[0][0], &mut body)
        .expect("opens the Finished");
    let server_finished = body[start..start + len].to_vec();
    let verify = tls12::finished(suite, master, b"server finished", &transcript);
    assert_eq!(
        server_finished,
        [&[20u8, 0, 0, 12][..], &verify].concat(),
        "Go's server Finished is the one this key block signs"
    );

    let mut body = sealed(&c2s)[1][5..].to_vec();
    let (start, len) = record::open12(&mut keys.client, sealed(&c2s)[1][0], &mut body)
        .expect("opens the application record");
    assert_eq!(
        &body[start..start + len],
        CLIENT_PAYLOAD,
        "Go's client record decrypts and authenticates"
    );
    let mut body = sealed(&s2c)[1][5..].to_vec();
    let (start, len) = record::open12(&mut keys.server, sealed(&s2c)[1][0], &mut body)
        .expect("opens the application record");
    assert_eq!(
        &body[start..start + len],
        SERVER_PAYLOAD,
        "Go's server record decrypts and authenticates"
    );

    reseal(
        suite,
        master,
        (&client_random, &server_random),
        sealed(&c2s),
        sealed(&s2c),
        [&finished, &server_finished],
    );
}

/// Re-seal over the session's own sequence numbers. The header carries the record's whole length,
/// so matching Go's pins this suite's MAC length and padding count behind the random explicit IV,
/// and a stream record — which has neither — pins its every byte.
fn reseal(
    suite: Suite,
    master: &[u8],
    randoms: (&[u8; 32], &[u8; 32]),
    c2s: &[&[u8]],
    s2c: &[&[u8]],
    finished: [&[u8]; 2],
) {
    let mut seal = tls12::directions(suite, master, randoms.0, randoms.1);
    let mut mirror = tls12::directions(suite, master, randoms.0, randoms.1);
    for (ours, back, wire, finished, payload) in [
        (
            &mut seal.client,
            &mut mirror.client,
            c2s,
            finished[0],
            CLIENT_PAYLOAD,
        ),
        (
            &mut seal.server,
            &mut mirror.server,
            s2c,
            finished[1],
            SERVER_PAYLOAD,
        ),
    ] {
        for (kind, clear, header) in [(22u8, finished, wire[0]), (23u8, payload, wire[1])] {
            let mut ours_record = Vec::new();
            record::seal12(ours, kind, clear, &mut ours_record).expect("seals");
            assert_eq!(
                &ours_record[..5],
                &header[..5],
                "our record has Go's type, version and length"
            );
            if suite.is_rc4() {
                assert_eq!(
                    &ours_record[..],
                    header,
                    "a stream record carries no IV and no padding, so it is Go's byte for byte"
                );
            }
            let wire_type = ours_record[0];
            let (start, len) =
                record::open12(back, wire_type, &mut ours_record[5..]).expect("our record opens");
            assert_eq!(
                &ours_record[5 + start..5 + start + len],
                clear,
                "and reads back"
            );
        }
    }
}

/// A DER `INTEGER`, minimal: the leading zero appears only when the value's top bit is set.
fn integer(value: &[u8]) -> Vec<u8> {
    let mut value = value;
    while value.len() > 1 && value[0] == 0 && value[1] & 0x80 == 0 {
        value = &value[1..];
    }
    let body = if value[0] & 0x80 != 0 {
        [&[0u8][..], value].concat()
    } else {
        value.to_vec()
    };
    let mut out = vec![0x02];
    out.extend(element_len(&body));
    out
}

/// A DER `SEQUENCE` over the bytes its elements already encoded to.
fn sequence(body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    out.extend(element_len(body));
    out
}

fn element_len(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 3);
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(body);
    out
}

/// The static-RSA key transport, replayed over the vectors Go wrote for 1024- to 4096-bit keys:
/// `MODEXP` is its own hand-built `EM` under four public exponents, and `RSA` is
/// `EncryptPKCS1v15`'s ciphertext for an all-`0x11` padding, which the same key decrypts back.
#[test]
fn rsa_key_transport_matches_go() {
    let golden = include_str!("../../../../../scripts/tls12-oracle/expected.txt");
    let mut encodings = Vec::new();
    let mut exponentiations = Vec::new();
    for line in golden.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 5 {
            continue;
        }
        let row = (
            unhex(fields[1]),
            fields[2].parse().expect("a decimal exponent"),
            unhex(fields[3]),
            unhex(fields[4]),
        );
        match fields[0] {
            "RSA" => encodings.push(row),
            "MODEXP" => exponentiations.push(row),
            _ => {}
        }
    }
    assert_eq!(encodings.len(), 4, "one key of each size");
    assert_eq!(exponentiations.len(), 16, "four exponents per key");

    for (modulus, exponent, em, cipher) in &exponentiations {
        let mut ours = Vec::new();
        rsa::modexp(em, *exponent, modulus, &mut ours).expect("exponentiates");
        assert_eq!(
            &ours, cipher,
            "the modular exponentiation is the reference's own"
        );
    }

    // The eight buffers hold across all sixteen MODEXP vectors, whatever the exponent's bits or the modulus's width.
    for (modulus, exponent, em, cipher) in &exponentiations {
        let mut counted = Vec::new();
        let ((), counts) = crate::alloc_count::measure(|| {
            rsa::modexp(em, *exponent, modulus, &mut counted).expect("exponentiates");
        });
        assert_eq!(&counted, cipher, "the counted walk is the gated one");
        assert_eq!(
            counts.allocs,
            8,
            "a {}-byte modulus under {exponent}: {counts:?}",
            modulus.len()
        );
    }

    for (modulus, exponent, msg, cipher) in &encodings {
        let der = sequence(&[integer(modulus), integer(&exponent.to_be_bytes())].concat());
        let (n, e) = rsa::public_key(&der).expect("walks an RSAPublicKey");
        assert_eq!(
            (n, e),
            (modulus.as_slice(), *exponent),
            "the DER walk names the key"
        );
        let mut ours = Vec::new();
        let mut padding = |buf: &mut [u8]| {
            buf.fill(0x11);
            Ok::<(), TlsError>(())
        };
        rsa::encrypt(n, e, msg, &mut padding, &mut ours).expect("encrypts");
        assert_eq!(
            &ours, cipher,
            "the padding, the separator and the exponentiation are Go's"
        );
    }
}

/// Every TLS 1.2 session Go's own record layer put on the wire, replayed through this client:
/// the CBC suites' MAC, padding and explicit IV, both AEAD families, and the key expansion that
/// feeds them from the logged master secret.
#[test]
fn tls12_sessions_match_go() {
    let golden = include_str!("../../../../../scripts/tls12-oracle/expected.txt");
    let mut sessions = Vec::new();
    let mut streams = Vec::new();
    for line in golden.lines() {
        let mut fields = line.split_whitespace();
        let (Some(tag), Some(id)) = (fields.next(), fields.next()) else {
            continue;
        };
        let value = fields.next().expect("a case carries its bytes");
        match tag {
            "KEY" => sessions.push((id, unhex(value))),
            "C2S" | "S2C" => streams.push((tag, id, value)),
            _ => {}
        }
    }
    let script = include_str!("../../../../../scripts/tls12-oracle/script.txt");
    let cases: Vec<&str> = script
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("0x"))
        .collect();
    assert_eq!(
        cases.len(),
        sessions.len(),
        "script and golden session counts differ"
    );
    for (id, master) in &sessions {
        let stream = |tag: &str| {
            unhex(
                streams
                    .iter()
                    .find(|case| case.0 == tag && case.1 == *id)
                    .expect("both directions of every session")
                    .2,
            )
        };
        gate(
            u16::from_str_radix(id, 16).expect("a hex suite id"),
            master,
            &stream("C2S"),
            &stream("S2C"),
        );
    }
}
