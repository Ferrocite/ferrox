const HOST: &str = "carrier.test";

/// Mints the `TLS` arm's certificate and key into the directory the caller names, because a
/// private key in the tree is a leak surface `check-fixture-safety.sh` refuses.
pub fn run(args: &[String]) -> i32 {
    let Some(dir) = args.first() else {
        eprintln!("make-tls needs one argument: the directory for cert.pem and key.pem");
        return 2;
    };
    if let Err(e) = write_pair(std::path::Path::new(dir)) {
        eprintln!("make-tls: {e}");
        return 1;
    }
    0
}

fn write_pair(dir: &std::path::Path) -> Result<(), String> {
    let minted = mint()?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for (name, pem) in [
        ("cert.pem", minted.cert.pem()),
        ("key.pem", minted.signing_key.serialize_pem()),
    ] {
        let path = dir.join(name);
        std::fs::write(&path, pem.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(())
}

/// `carrier.test` as both the subject and the one DNS alternative name, because a verifier reads
/// the alternative name and never the subject, so a CN-only certificate is refused by all of them.
fn mint() -> Result<rcgen::CertifiedKey<rcgen::KeyPair>, String> {
    let mut params =
        rcgen::CertificateParams::new(vec![HOST.to_owned()]).map_err(|e| e.to_string())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, HOST);
    let key_pair = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
    Ok(rcgen::CertifiedKey {
        cert,
        signing_key: key_pair,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The arm's checker: the pair lands as PEM the references read, and the certificate that
    /// came with it names `carrier.test` as a DNS alternative name.
    #[test]
    fn the_minted_pair_names_the_carrier() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("ferrox-matrix-tls-{}-{stamp}", std::process::id()));
        write_pair(&dir).expect("the pair is minted");
        let cert = std::fs::read_to_string(dir.join("cert.pem")).expect("a certificate");
        let key = std::fs::read_to_string(dir.join("key.pem")).expect("a key");
        std::fs::remove_dir_all(&dir).expect("the fixture is cleaned up");
        assert!(cert.contains("BEGIN CERTIFICATE"), "{cert}");
        assert!(key.contains("PRIVATE KEY"), "{key}");
        let minted = mint().expect("mints");
        let cert = webpki::EndEntityCert::try_from(minted.cert.der()).expect("parses");
        let name = rustls_pki_types::DnsName::try_from(HOST).expect("a dns name");
        cert.verify_is_valid_for_subject_name(&rustls_pki_types::ServerName::DnsName(name))
            .expect("the certificate names the carrier");
    }
}
