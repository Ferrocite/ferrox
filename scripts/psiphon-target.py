#!/usr/bin/env python3
"""Pin the reference client to the server the native lane selected."""
import argparse
import json
import os
import re
import sys


def chosen(log_path):
    try:
        with open(log_path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return set()
    seen = set()
    for found, protocol in re.findall(r"tunnel up via (\S+) (SSH|OSSH)", text):
        host, port = found.rsplit(":", 1)
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        seen.add((host, int(port), protocol))
    return seen


def port(value):
    if not isinstance(value, int) or isinstance(value, bool):
        return 0
    return value if 0 < value <= 65535 else 0


def reference_port(value):
    if value is None:
        return True
    return isinstance(value, int) and not isinstance(value, bool) and -(1 << 63) <= value < (1 << 63)


def entry(state, host, selected_port, protocol):
    path = os.path.join(state, "server_entries.txt")
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        return None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            payload = bytes.fromhex(line).split(b" ", 4)[4]
            server = json.loads(payload)
        except (ValueError, IndexError, json.JSONDecodeError):
            continue
        if server.get("ipAddress") != host:
            continue
        if not reference_port(server.get("sshPort")) or not reference_port(
            server.get("sshObfuscatedPort")
        ):
            continue
        obfuscated = port(server.get("sshObfuscatedPort"))
        plain = port(server.get("sshPort"))
        key = server.get("sshObfuscatedKey")
        if obfuscated > 0 and isinstance(key, str) and key:
            effective = (obfuscated, "OSSH")
        elif plain > 0:
            effective = (plain, "SSH")
        else:
            continue
        if effective == (selected_port, protocol):
            return line, protocol
    return None


def selftest():
    import tempfile

    servers = [
        {
            "ipAddress": "192.0.2.1",
            "sshPort": 22,
            "sshObfuscatedPort": "443",
            "sshObfuscatedKey": "k",
        },
        {
            "ipAddress": "192.0.2.2",
            "sshPort": 22,
            "sshObfuscatedPort": 443.5,
            "sshObfuscatedKey": "k",
        },
        {
            "ipAddress": "192.0.2.3",
            "sshPort": 22,
            "sshObfuscatedPort": 443.0,
            "sshObfuscatedKey": "k",
        },
        {
            "ipAddress": "192.0.2.4",
            "sshPort": 70000,
            "sshObfuscatedPort": 443,
            "sshObfuscatedKey": "k",
        },
        {
            "ipAddress": "192.0.2.5",
            "sshPort": "22",
            "sshObfuscatedPort": 443,
            "sshObfuscatedKey": "k",
        },
        {
            "ipAddress": "192.0.2.6",
            "sshPort": 22,
            "sshObfuscatedPort": 443.5,
            "sshObfuscatedKey": "k",
        },
        {
            "ipAddress": "192.0.2.7",
            "sshPort": None,
            "sshObfuscatedPort": 443.0,
            "sshObfuscatedKey": "k",
        },
    ]
    assert port(443) == 443
    assert port(443.0) == 0
    assert port("443") == 0
    assert port(443.5) == 0
    assert port(True) == 0
    assert port(0) == 0
    assert port(65536) == 0

    with tempfile.TemporaryDirectory() as state:
        with open(os.path.join(state, "server_entries.txt"), "w", encoding="utf-8") as handle:
            for server in servers:
                line = ("0 0 0 0 " + json.dumps(server)).encode().hex()
                handle.write(line + "\n")
        assert entry(state, "192.0.2.1", 22, "SSH") is None
        assert entry(state, "192.0.2.2", 22, "SSH") is None
        assert entry(state, "192.0.2.3", 443, "OSSH") is None
        assert entry(state, "192.0.2.4", 443, "OSSH") is not None
        assert entry(state, "192.0.2.5", 443, "OSSH") is None
        assert entry(state, "192.0.2.6", 22, "SSH") is None
        assert entry(state, "192.0.2.7", 443, "OSSH") is None

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write(
            "psiphon: tunnel up via 192.0.2.1:22 SSH\n"
            "psiphon: tunnel up via [2001:db8::1]:443 OSSH\n"
            "psiphon: tunnel up via 192.0.2.2:22 SSH\n"
        )
        log = handle.name
    try:
        assert chosen(log) == {
            ("192.0.2.1", 22, "SSH"),
            ("2001:db8::1", 443, "OSSH"),
            ("192.0.2.2", 22, "SSH"),
        }
    finally:
        os.unlink(log)
    print("psiphon-target selftest: ok")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    picked = chosen(args.log)
    if not picked:
        print("psiphon-target: the native lane named no tunnel", file=sys.stderr)
        return 1
    if len(picked) > 1:
        named = ", ".join(
            f"{host}:{port} {protocol}" for host, port, protocol in sorted(picked)
        )
        print(
            f"psiphon-target: the native lane used more than one server ({named})",
            file=sys.stderr,
        )
        return 1
    picked = next(iter(picked))
    target = entry(args.state, *picked)
    if target is None:
        print("psiphon-target: the selected server is not in the verified cache", file=sys.stderr)
        return 1
    try:
        with open(args.config, encoding="utf-8") as handle:
            config = json.load(handle)
    except (OSError, json.JSONDecodeError):
        print("psiphon-target: the reference config is unreadable", file=sys.stderr)
        return 1
    config["TargetServerEntry"], protocol = target
    config["LimitTunnelProtocols"] = [protocol]
    with open(args.config, "w", encoding="utf-8") as handle:
        json.dump(config, handle)
    print(f"psiphon-target: pinned the reference to {picked[0]}:{picked[1]} over {protocol}")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        selftest()
    else:
        sys.exit(main())
