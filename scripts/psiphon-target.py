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
        return None
    found = re.findall(r"tunnel up via (\S+)", text)
    if not found:
        return None
    host, port = found[-1].rsplit(":", 1)
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host, int(port)


def entry(state, host, port):
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
        for key, protocol in (("sshObfuscatedPort", "OSSH"), ("sshPort", "SSH")):
            if int(server.get(key) or 0) == port:
                return line, protocol
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    picked = chosen(args.log)
    if picked is None:
        print("psiphon-target: the native lane named no tunnel", file=sys.stderr)
        return 1
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
    sys.exit(main())
