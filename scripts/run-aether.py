#!/usr/bin/env python3
"""Translate the matrix's Xray-dialect client config into Aether's environment: a MASQUE or WARP dial to its masque identity, or a WireGuard dial to its wg one."""

import json
import os
import pathlib
import sys
import time


def fail(message):
    """Report an adapter error and exit 2."""
    print(f"aether adapter: {message}", file=sys.stderr)
    raise SystemExit(2)


def text(value):
    """Render a config value as text."""
    return str(value)


def endpoint(settings):
    """Return the peer address and port the outbound settings name."""
    address = settings.get("address")
    port = settings.get("port")
    if address and port:
        return f"{address}:{port}"
    for peer in settings.get("peers") or []:
        address = peer.get("endpoint") or peer.get("address")
        port = peer.get("port")
        if address and port:
            return f"{address}:{port}"
        if address and ":" in address:
            return address
    for server in settings.get("servers") or []:
        address = server.get("address")
        port = server.get("port")
        if address and port:
            return f"{address}:{port}"
    server = settings.get("server") or {}
    address = server.get("address")
    port = server.get("port")
    if address and port:
        return f"{address}:{port}"
    fail("the client config has no address and port")


def local_addresses(settings):
    """Return one local IPv4 and one local IPv6 address from the settings."""
    values = []
    for item in settings.get("address") or []:
        values.append(text(item).split("/", 1)[0])
    if not values:
        fail("the client config has no local address")
    v4 = next((item for item in values if ":" not in item), None)
    v6 = next((item for item in values if ":" in item), None)
    if v4 is None or v6 is None:
        fail("the client config needs one address per family")
    return v4, v6


def pem(value):
    """Wrap PEM text in a TOML multiline string."""
    return '"""' + value + '"""'


def base64_key(value):
    """Normalize a WireGuard key to padded standard base64."""
    key = str(value).strip().replace("-", "+").replace("_", "/")
    return key + "=" * (-len(key) % 4)


def identity(path, fields):
    """Write a TOML identity file and return its path."""
    lines = []
    for key, value in fields:
        lines.append(f"{key} = {value}")
    path.write_text("\n".join(lines) + "\n")
    return path


def masque_identity(cfg_path, stream):
    """Build the MASQUE identity TOML from the client TLS settings."""
    tls = stream.get("tlsSettings") or {}
    certificates = tls.get("certificates") or []
    certificate = certificates[0].get("certificateFile") if certificates else None
    if not certificate:
        certificate = tls.get("caCertFile")
    if not certificate:
        fail("the MASQUE client config names no certificate")
    cert_path = pathlib.Path(certificate)
    key_file = certificates[0].get("keyFile") if certificates else None
    key_path = pathlib.Path(key_file) if key_file else cert_path.with_name("key.pem")
    if not cert_path.exists() or not key_path.exists():
        fail(f"the MASQUE client identity is missing at {cert_path}")
    local_v4, local_v6 = "10.13.0.2", "fd13::2"
    identity_path = cfg_path.with_name("aether-identity.toml")
    zeros = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    return identity(identity_path, [
        ("device_id", '"matrix"'),
        ("access_token", '"matrix"'),
        ("cert_pem", pem(cert_path.read_text())),
        ("key_pem", pem(key_path.read_text())),
        ("cert_issued_at", str(int(time.time()))),
        ("ipv4", f'"{local_v4}"'),
        ("ipv6", f'"{local_v6}"'),
        ("wg_private_key", f'"{zeros}"'),
        ("wg_peer_public_key", f'"{zeros}"'),
        ("client_id", '""'),
    ])


def wireguard_identity(cfg_path, settings):
    """Build the WireGuard identity TOML from the client settings."""
    secret = settings.get("secretKey")
    peers = settings.get("peers") or []
    if not secret or not peers:
        fail("the WireGuard client config has no key or peer")
    public = peers[0].get("publicKey")
    if not public:
        fail("the WireGuard client config has no peer public key")
    local_v4, local_v6 = local_addresses(settings)
    identity_path = cfg_path.with_name("aether-identity.toml")
    return identity(identity_path, [
        ("device_id", '"matrix"'),
        ("access_token", '"matrix"'),
        ("cert_pem", '""'),
        ("key_pem", '""'),
        ("cert_issued_at", "0"),
        ("ipv4", f'"{local_v4}"'),
        ("ipv6", f'"{local_v6}"'),
        ("wg_private_key", f'"{base64_key(secret)}"'),
        ("wg_peer_public_key", f'"{base64_key(public)}"'),
        ("client_id", '""'),
    ])


def main():
    """Read the matrix client config and exec the pinned Aether."""
    args = sys.argv[1:]
    if len(args) != 3 or args[0] != "run" or args[1] not in ("-config", "--config"):
        fail("expected `run -config <path>`")
    cfg_path = pathlib.Path(args[2])
    try:
        doc = json.loads(cfg_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {cfg_path}: {error}")
    inbound = next(
        (item for item in doc.get("inbounds") or [] if item.get("protocol") == "socks"),
        None,
    )
    if inbound is None:
        fail("the config has no SOCKS inbound")
    bind = f"{inbound.get('listen', '127.0.0.1')}:{inbound['port']}"
    outbound = next(
        (item for item in doc.get("outbounds") or []
         if item.get("protocol") in ("masque", "wireguard", "warp")),
        None,
    )
    if outbound is None:
        fail("the config has no MASQUE, WireGuard or WARP outbound")
    settings = outbound.get("settings") or {}
    stream = outbound.get("streamSettings") or {}
    real = pathlib.Path(__file__).resolve().with_name("aether-bin")
    if not real.exists():
        fail(f"the pinned Aether binary is missing at {real}")
    env = os.environ.copy()
    env.update({
        "AETHER_LOG_LEVEL": "warn",
        "AETHER_TLS_VERIFY": "0",
        "AETHER_QUIC_V2": "0",
        "AETHER_MASQUE_NO_DATA_CHECK": "1",
        "AETHER_WG_NO_DATA_CHECK": "1",
        "AETHER_NOIZE": "off",
    })
    if outbound.get("protocol") == "warp":
        block = settings.get("masque") or {}
        masque_peer = block.get("address") and f"{block['address']}:{block['port']}"
        if not masque_peer:
            fail("the WARP outbound names no MASQUE address and port")
        tls = stream.get("tlsSettings") or {}
        sni = block.get("serverName") or tls.get("serverName") or "carrier.test"
        config = masque_identity(cfg_path, stream)
        command = [
            str(real), "--protocol", "masque", "--peer", masque_peer,
            "--masque-sni", sni, "--bind", bind,
            "--masque-config", str(config), "--no-data-check",
            "--no-quic-v2", "--log-level", "warn",
        ]
    elif outbound.get("protocol") == "masque":
        tls = stream.get("tlsSettings") or {}
        sni = tls.get("serverName") or "carrier.test"
        peer = endpoint(settings)
        config = masque_identity(cfg_path, stream)
        command = [
            str(real), "--protocol", "masque", "--peer", peer,
            "--masque-sni", sni, "--bind", bind,
            "--masque-config", str(config), "--no-data-check",
            "--no-quic-v2", "--log-level", "warn",
        ]
    else:
        peer = endpoint(settings)
        config = wireguard_identity(cfg_path, settings)
        command = [
            str(real), "--protocol", "wg", "--wg-peer", peer,
            "--bind", bind, "--wg-config", str(config),
            "--no-data-check", "--log-level", "warn",
        ]
    env["AETHER_SOCKS"] = bind
    os.execve(str(real), command, env)


if __name__ == "__main__":
    main()
