// A ClientHello shaped like a real browser's: the pinned uTLS parrots as data, and the handshake that carries them.
mod client;
pub(crate) mod hello;
mod kdf;
mod keys;
mod profiles;
mod record;
mod tls12;

pub use client::Session;

use crate::tls::TlsConfig;
use std::sync::OnceLock;

/// The GREASE sentinel in a profile table: the builder draws a real value for it.
pub(crate) const GREASE: u16 = 0x0a0a;

#[derive(Debug)]
pub(crate) struct Profile {
    pub name: &'static str,
    pub ciphers: &'static [u16],
    pub shuffle: bool,
    pub exts: &'static [Ext],
}

#[derive(Debug)]
pub(crate) struct Ext {
    pub kind: u16,
    pub body: Body,
}

#[derive(Debug)]
pub(crate) enum Body {
    Grease,
    Sni,
    Pad,
    Groups(&'static [u16]),
    Sigalgs(&'static [u16]),
    Alpn(&'static [u8]),
    Versions(&'static [u16]),
    KeyShare {
        groups: &'static [u16],
        reuse: bool,
    },
    Ech {
        suites: &'static [u32],
        payloads: &'static [u16],
    },
    Raw(&'static [u8]),
}

/// A resolved fingerprint: `None` keeps the stock rustls hello, which is what
/// `unsafe` and `hellogolang` mean; a profile shapes every byte uTLS fixes.
#[derive(Clone, Copy, Debug)]
pub struct Fingerprint(Option<&'static Profile>);

impl PartialEq for Fingerprint {
    fn eq(&self, other: &Self) -> bool {
        match (self.0, other.0) {
            (Some(ours), Some(theirs)) => std::ptr::eq(ours, theirs),
            (None, None) => true,
            _ => false,
        }
    }
}

impl Eq for Fingerprint {}

impl Default for Fingerprint {
    fn default() -> Self {
        Self(Some(&profiles::P_CHROME))
    }
}

impl Fingerprint {
    /// The stock hello, by the two names uTLS gives it.
    pub const fn stock() -> Self {
        Self(None)
    }

    /// The xray default: an empty name is Chrome, and an unknown one is refused
    /// here rather than emitted as a hello no browser sends.
    pub fn resolve(name: &str) -> Option<Self> {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || name == "chrome" {
            return Some(Self::default());
        }
        if name == "unsafe" || name == "hellogolang" {
            return Some(Self::stock());
        }
        if name == "random" {
            return Some(Self(Some(random_profile())));
        }
        if name == "randomized" {
            return Some(Self(Some(randomized(Some(true)))));
        }
        if name == "randomizednoalpn" {
            return Some(Self(Some(randomized(Some(false)))));
        }
        if name == "hellorandomized" {
            return Some(Self(Some(randomized(None))));
        }
        if name == "hellorandomizedalpn" {
            return Some(Self(Some(randomized(Some(true)))));
        }
        if name == "hellorandomizednoalpn" {
            return Some(Self(Some(randomized(Some(false)))));
        }
        profiles::profile(&name).map(|profile| Self(Some(profile)))
    }

    pub(crate) fn profile(self) -> Option<&'static Profile> {
        self.0
    }
}

/// The eleven browser shapes xray draws `random` from once per process.
fn random_profile() -> &'static Profile {
    static PICK: OnceLock<&'static Profile> = OnceLock::new();
    PICK.get_or_init(|| {
        const POOL: [&str; 11] = [
            "hellofirefox_120",
            "hellofirefox_148",
            "hellochrome_120",
            "hellochrome_131",
            "hellochrome_133",
            "helloios_13",
            "helloios_14",
            "helloedge_106",
            "hellosafari_26_3",
            "hello360_11_0",
            "helloqq_11_1",
        ];
        let mut seed = [0u8; 8];
        let _ = getrandom::fill(&mut seed);
        let pick = usize::from(u16::from_le_bytes([seed[0], seed[1]])) % POOL.len();
        profiles::profile(POOL[pick]).expect("the pool names pinned profiles")
    })
}

/// A randomized spec is drawn once per process, as xray seeds its preset once:
/// uTLS reseeds per connection, so a spec generated per dial would leak one profile
/// per connection without making the hello any more random than its weights already do.
fn randomized(with_alpn: Option<bool>) -> &'static Profile {
    let generated = match with_alpn {
        Some(true) => &ALPN,
        Some(false) => &NO_ALPN,
        None => &AUTO,
    };
    generated.profile(with_alpn)
}

static ALPN: Generated = Generated::new();
static NO_ALPN: Generated = Generated::new();
static AUTO: Generated = Generated::new();

/// The drawn tables a generated profile borrows, held for the process so its slices are `'static`.
struct Drawn {
    ciphers: Vec<u16>,
    sigalgs: Vec<u16>,
    curves: Vec<u16>,
    shares: Vec<u16>,
    exts: OnceLock<Vec<Ext>>,
}

struct Generated {
    drawn: OnceLock<Drawn>,
    profile: OnceLock<Profile>,
}

impl Generated {
    const fn new() -> Self {
        Self {
            drawn: OnceLock::new(),
            profile: OnceLock::new(),
        }
    }

    fn profile(&'static self, mode: Option<bool>) -> &'static Profile {
        self.profile.get_or_init(|| {
            let with_alpn = mode.unwrap_or_else(|| Spec::new().chance(70));
            let drawn = self.drawn.get_or_init(draw);
            let exts = drawn.exts.get_or_init(|| build_exts(drawn, with_alpn));
            Profile {
                name: "randomized",
                ciphers: drawn.ciphers.as_slice(),
                shuffle: false,
                exts: exts.as_slice(),
            }
        })
    }
}

/// uTLS's randomized generator at the weights xray pins: TLS 1.3 always, X25519's
/// share first, and every optional extension behind its own coin.
fn draw() -> Drawn {
    let mut rng = Spec::new();
    let mut ciphers = vec![0x1301u16, 0x1302, 0x1303];
    rng.shuffle(&mut ciphers);
    let mut legacy = vec![
        0xc02bu16, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
    ];
    rng.shuffle(&mut legacy);
    let total = legacy.len();
    let mut kept = 1;
    for i in 1..total {
        // uTLS removes later ciphers more readily, never the first.
        if !rng.chance(40 * i / total) {
            legacy.swap(kept, i);
            kept += 1;
        }
    }
    legacy.truncate(kept);
    ciphers.extend_from_slice(&legacy);

    let mut sigalgs = vec![0x0403u16, 0x0401, 0x0503, 0x0501, 0x0201, 0x0601];
    if rng.chance(63) {
        sigalgs.push(0x0203);
    }
    if rng.chance(59) {
        sigalgs.push(0x0603);
    }
    sigalgs.push(0x0804);
    if rng.chance(90) {
        sigalgs.push(0x0805);
        sigalgs.push(0x0806);
    }
    rng.shuffle(&mut sigalgs);

    let mut curves = Vec::new();
    if rng.chance(71) {
        curves.push(keys::X25519_MLKEM768);
    }
    curves.extend_from_slice(&[keys::X25519, keys::P256, keys::P384]);

    let mut shares = vec![keys::X25519];
    if rng.chance(50) {
        shares.push(keys::P256);
    }
    if rng.chance(50) {
        shares.insert(0, keys::X25519_MLKEM768);
    }

    Drawn {
        ciphers,
        sigalgs,
        curves,
        shares,
        exts: OnceLock::new(),
    }
}

/// The extension list over a drawn table, its optional coins and shuffle included.
fn build_exts(drawn: &'static Drawn, with_alpn: bool) -> Vec<Ext> {
    let mut rng = Spec::new();
    let mut exts = vec![
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(drawn.sigalgs.as_slice()),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(drawn.curves.as_slice()),
        },
    ];
    if with_alpn {
        exts.push(Ext {
            kind: 0x0010,
            body: Body::Alpn(b"\x00\x0c\x02h2\x08http/1.1"),
        });
    }
    exts.push(Ext {
        kind: 0x0015,
        body: Body::Pad,
    });
    let optional = [
        (0x0005, 74, &[0x01, 0x00, 0x00, 0x00, 0x00][..]),
        (0x0012, 46, &[][..]),
        (0xff01, 75, &[0x00][..]),
        (0x0017, 77, &[][..]),
    ];
    for (kind, weight, body) in optional {
        if rng.chance(weight) {
            exts.push(Ext {
                kind,
                body: Body::Raw(body),
            });
        }
    }
    exts.push(Ext {
        kind: 0x0033,
        body: Body::KeyShare {
            groups: drawn.shares.as_slice(),
            reuse: false,
        },
    });
    exts.push(Ext {
        kind: 0x002d,
        body: Body::Raw(&[0x01, 0x01]),
    });
    let versions: &'static [u16] = if rng.chance(50) {
        &[0x0304, 0x0303, 0x0302, 0x0301]
    } else {
        &[0x0304, 0x0303]
    };
    exts.push(Ext {
        kind: 0x002b,
        body: Body::Versions(versions),
    });
    if with_alpn && rng.chance(33) {
        exts.push(Ext {
            kind: 0x44cd,
            body: Body::Raw(&[0x00, 0x03, 0x02, 0x68, 0x32]),
        });
    }
    rng.shuffle(&mut exts);
    exts
}

/// A SHAKE256 stream over a process seed, the same construction uTLS seeds its
/// spec generator with; the seed is fresh, so only the weights are shared.
struct Spec {
    xof: shake::Shake256Reader,
}

impl Spec {
    fn new() -> Self {
        use shake::{ExtendableOutput as _, Update as _, XofReader as _};
        let mut seed = [0u8; 32];
        let _ = getrandom::fill(&mut seed);
        let mut hash = shake::Shake256::default();
        hash.update(&seed);
        let mut xof = hash.finalize_xof();
        // A draw before the seed's own stretch keeps the stream independent of the first record.
        let mut warm = [0u8; 32];
        xof.read(&mut warm);
        Self { xof }
    }

    fn next(&mut self) -> u64 {
        use shake::XofReader as _;
        let mut bytes = [0u8; 8];
        self.xof.read(&mut bytes);
        u64::from_be_bytes(bytes)
    }

    fn below(&mut self, n: usize) -> usize {
        let bound = u64::try_from(n).expect("an index fits in u64");
        let zone = u64::MAX - (u64::MAX % bound);
        loop {
            let draw = self.next();
            if draw < zone {
                return usize::try_from(draw % bound).expect("a draw below the bound fits");
            }
        }
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }
}

/// The profile a config's fingerprint selects, or `None` for the stock hello.
pub(crate) fn profile_of(cfg: &TlsConfig) -> Option<&'static Profile> {
    cfg.fingerprint.and_then(Fingerprint::profile)
}
