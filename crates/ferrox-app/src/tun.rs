//! The device layer a TUN inbound stands on (`carrier-device`, docs/method-superset.md).
//!
//! A config naming `tun`/`utun`/`wintun`/`tun2socks` asks for a native IP interface. This
//! binary refuses it, and this module is what makes the refusal *true*: it reads the device
//! request out of the config — the interface to carry, the packet limit, whether the host
//! has already opened an interface and passed its descriptor to us — and reports exactly
//! which of the row's two remaining halves is the one that refuses the inbound.
//!
//! The two halves the README names as the whole gap — a privileged open (`/dev/net/tun` +
//! `TUNSETIFF`, `utun`, Wintun) and a userspace IP stack that reads whole packets off the
//! interface and turns each into a dial — are neither here. A `Device` seam with packet I/O
//! would have no production reader until the stack exists, so it would be dead code, and its
//! two kinds (a host descriptor and an in-process queue) differ only by that unwritten I/O.
//! They land with the stack that consumes them (a template in prompts.md), not as an
//! unconsumed abstraction here.

use std::ffi::OsString;

/// The MTU the references default an interface to: an IPv4 jumbo-free datagram fits, and
/// anything larger cannot cross it whole. A config that sets none is reported as unset, not
/// silently given this, so the refusal never claims a bound the config did not choose.
const DEFAULT_MTU: usize = 1500;

/// The protocols that name a device rather than a front, each refused by name until the
/// device layer's two halves land.
pub(crate) fn is_device(protocol: &str) -> bool {
    matches!(protocol, "tun" | "utun" | "wintun" | "tun2socks")
}

/// What a config asks of the device: the interface name it carries, and the largest packet
/// it may. Both come straight from the config, so the refusal can say which it was given.
pub(crate) struct Spec {
    name: String,
    mtu: Option<usize>,
}

impl Spec {
    pub(crate) fn new(name: Option<&str>, mtu: Option<usize>) -> Self {
        Self {
            name: name.filter(|n| !n.is_empty()).unwrap_or("tun").to_owned(),
            mtu: mtu.filter(|m| *m > 0),
        }
    }
}

/// The file descriptor a host process already opened and handed to this one through
/// `FERROX_TUN_FD`, if it passed one: a socket-activated `tun`, an Android `VpnService`
/// tunnel's descriptor. Its presence is reported, not consumed — reading or writing packets
/// over it is the stack's job, which is the half still owed.
fn inherited() -> Option<OsString> {
    std::env::var_os("FERROX_TUN_FD").filter(|fd| !fd.is_empty())
}

/// Why a device inbound is refused, built from the config so the reason is the truth rather
/// than a blanket "unsupported": whether a host handed us an interface, and which of the two
/// missing halves stands in the way even once the other is supplied.
pub(crate) fn refusal_reason(spec: &Spec) -> String {
    let mut missing =
        "the privileged `ioctl`/`utun`/Wintun open is not landed and no userspace IP stack reads packets".to_string();
    if let Some(fd) = inherited() {
        missing = format!(
            "a host-supplied interface descriptor ({}) was handed over, but no userspace IP stack reads packets from it",
            fd.display()
        );
    }
    let mtu = match spec.mtu {
        Some(mtu) => format!("mtu {mtu} B"),
        None => format!("mtu unspecified, {DEFAULT_MTU} B if defaulted"),
    };
    format!("`{}` ({}) cannot be served: {missing}", spec.name, mtu)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every protocol that names a native device is a device, and a front is not: the set a
    /// config can ask for that this binary refuses by name.
    #[test]
    fn the_device_protocols_are_the_named_interfaces() {
        for name in ["tun", "utun", "wintun", "tun2socks"] {
            assert!(is_device(name), "`{name}` names a device");
        }
        for name in ["vless", "trojan", "socks", "http", "mixed"] {
            assert!(!is_device(name), "`{name}` names a front, not a device");
        }
    }

    /// The refusal names the interface and the packet limit it was given, and both of the
    /// halves that still stand between this binary and a served device — the open, and the
    /// stack. It never claims a device it did not open.
    #[test]
    fn the_refusal_names_the_device_and_both_halves_still_owed() {
        let reason = refusal_reason(&Spec::new(Some("utun3"), Some(1400)));
        assert!(reason.contains("utun3"), "the interface is named: {reason}");
        assert!(reason.contains("1400 B"), "the mtu is named: {reason}");
        assert!(
            reason.contains("cannot be served"),
            "the device is refused, not silently served: {reason}"
        );
        assert!(
            reason.contains("userspace IP stack") || reason.contains("ioctl"),
            "a missing half is named: {reason}"
        );
    }

    /// A config that set no MTU is reported as unset rather than defaulted into a bound the
    /// operator never chose — the refusal is what was read, not what was assumed.
    #[test]
    fn an_unset_mtu_is_named_as_unset_not_defaulted_away() {
        let reason = refusal_reason(&Spec::new(None, None));
        assert!(
            reason.contains("mtu unspecified"),
            "an unset mtu says so: {reason}"
        );
        assert!(
            reason.contains("tun"),
            "a nameless interface is still reported: {reason}"
        );
        assert!(
            !reason.contains("with 1500 B"),
            "the default is only offered, never asserted as the config's bound: {reason}"
        );
    }
}
