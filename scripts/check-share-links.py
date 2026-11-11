#!/usr/bin/env python3
"""The CLI's share-link converters, driven through the lane it would start.

`--vless` and `--vmess` hand the binary a config, so the converter is the gate:
each link below runs the real CLI with a fake binary that copies the config it
was given, and the copied JSON is checked field by field. A second pass hands
every config to `ferrox-app -test`, which reads the carrier and security blocks
the converter wrote without opening a socket. Fixtures use only TEST-NET and
example.com: a real server, UUID or public key never enters this file.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
CLI = ROOT / "dist" / "ferrox-cli.sh"
APP = os.environ.get("FERROX_APP", "")
ID = "11111111-2222-3333-4444-555555555555"
PKEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def snapshot_binary(state: pathlib.Path) -> pathlib.Path:
    binary = state / "fake-lane"
    binary.write_text(
        '#!/bin/sh\ncp "$3" "${FERROX_CONF_DIR:?}/snapshot.json"\n',
        encoding="utf-8",
    )
    binary.chmod(0o755)
    return binary


def run_cli(state: pathlib.Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["FERROX_CONF_DIR"] = str(state)
    env["FERROX_STATE_DIR"] = str(state)
    env["FERROX_BIN"] = str(snapshot_binary(state))
    return subprocess.run(
        [str(CLI), "up", "--fronts", "socks", "--socks", str(free_port()), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=90,
    )


def outbound(case: dict, root: pathlib.Path) -> dict:
    state = root / case["name"]
    state.mkdir()
    run = run_cli(state, case["args"])
    snapshot = state / "snapshot.json"
    if case.get("fails"):
        if run.returncode == 0:
            raise AssertionError(f"{case['name']}: the CLI accepted a bad link")
        if snapshot.exists():
            raise AssertionError(f"{case['name']}: a refused link still wrote a config")
        return {}
    if not snapshot.exists():
        raise AssertionError(
            f"{case['name']}: no config was written\nstdout:\n{run.stdout}\nstderr:\n{run.stderr}"
        )
    document = json.loads(snapshot.read_text(encoding="utf-8"))
    if APP:
        check = subprocess.run(
            [APP, "-test", "-c", str(snapshot)], capture_output=True, text=True
        )
        if check.returncode != 0:
            raise AssertionError(
                f"{case['name']}: ferrox-app refused the config:\n{check.stdout}{check.stderr}"
            )
    return document["outbounds"][0]


def at(node: object, path: str) -> object:
    for part in path.split("."):
        if isinstance(node, list):
            node = node[int(part)]
        else:
            node = node[part]
    return node


def vmess_link(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return "vmess://" + base64.b64encode(raw).decode()


CASES = [
    {
        "name": "vless ws tls",
        "args": [
            "--vless",
            f"vless://{ID}@example.com:443?type=ws&security=tls&sni=example.com"
            "&host=example.com&path=%2Fws&ed=2048&fp=chrome&alpn=h2%2Chttp%2F1.1"
            "&allowInsecure=1#demo",
        ],
        "want": {
            "protocol": "vless",
            "settings.vnext.0.address": "example.com",
            "settings.vnext.0.port": 443,
            "settings.vnext.0.users.0.encryption": "none",
            "streamSettings.network": "ws",
            "streamSettings.wsSettings.path": "/ws?ed=2048",
            "streamSettings.wsSettings.headers.Host": "example.com",
            "streamSettings.security": "tls",
            "streamSettings.tlsSettings.serverName": "example.com",
            "streamSettings.tlsSettings.allowInsecure": True,
            "streamSettings.tlsSettings.fingerprint": "chrome",
            "streamSettings.tlsSettings.alpn.0": "h2",
            "streamSettings.tlsSettings.alpn.1": "http/1.1",
        },
    },
    {
        "name": "vless reality vision",
        "args": [
            "--vless",
            f"vless://{ID}@192.0.2.10:443?security=reality&encryption=none"
            f"&pbk={PKEY}&sid=a8&fp=chrome&type=raw&flow=xtls-rprx-vision"
            "&sni=example.com&spx=%2F#reality",
        ],
        "want": {
            "protocol": "vless",
            "settings.vnext.0.users.0.flow": "xtls-rprx-vision",
            "streamSettings.network": "tcp",
            "streamSettings.security": "reality",
            "streamSettings.realitySettings.serverName": "example.com",
            "streamSettings.realitySettings.publicKey": PKEY,
            "streamSettings.realitySettings.shortId": "a8",
            "streamSettings.realitySettings.spiderX": "/",
        },
    },
    {
        "name": "vless grpc",
        "args": [
            "--vless",
            f"vless://{ID}@192.0.2.11:443?type=grpc&security=tls&sni=example.com"
            "&serviceName=svc&mode=multi&authority=a.example.com#grpc",
        ],
        "want": {
            "streamSettings.network": "grpc",
            "streamSettings.grpcSettings.serviceName": "svc",
            "streamSettings.grpcSettings.multiMode": True,
            "streamSettings.grpcSettings.authority": "a.example.com",
        },
    },
    {
        "name": "vless httpupgrade",
        "args": [
            "--vless",
            f"vless://{ID}@192.0.2.12:80?type=httpupgrade&security=none"
            "&host=example.com&path=%2Fup#upgrade",
        ],
        "want": {
            "streamSettings.network": "httpupgrade",
            "streamSettings.httpupgradeSettings.path": "/up",
            "streamSettings.httpupgradeSettings.host": "example.com",
            "streamSettings.security": "none",
        },
    },
    {
        "name": "vless xhttp",
        "args": [
            "--vless",
            f"vless://{ID}@192.0.2.13:443?type=xhttp&security=tls&sni=example.com"
            "&host=example.com&path=%2Fx&mode=auto"
            '&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D#xhttp',
        ],
        "want": {
            "streamSettings.network": "xhttp",
            "streamSettings.xhttpSettings.path": "/x",
            "streamSettings.xhttpSettings.host": "example.com",
            "streamSettings.xhttpSettings.mode": "auto",
            "streamSettings.xhttpSettings.extra": '{"xPaddingBytes":"100-1000"}',
        },
    },
    {
        "name": "vless tcp http header",
        "args": [
            "--vless",
            f"vless://{ID}@192.0.2.14:80?type=tcp&headerType=http&security=none"
            "&host=example.com&path=%2Fcamouflage#camouflage",
        ],
        "want": {
            "streamSettings.network": "tcp",
            "streamSettings.tcpSettings.header.type": "http",
            "streamSettings.tcpSettings.header.request.path.0": "/camouflage",
            "streamSettings.tcpSettings.header.request.headers.Host.0": "example.com",
        },
    },
    {
        "name": "vless kcp",
        "args": [
            "--vless",
            f"vless://{ID}@192.0.2.15:80?type=kcp&security=none&headerType=srtp"
            "&seed=seedvalue&mtu=1350&tti=20#kcp",
        ],
        "want": {
            "streamSettings.network": "kcp",
            "streamSettings.kcpSettings.seed": "seedvalue",
            "streamSettings.kcpSettings.header.type": "srtp",
            "streamSettings.kcpSettings.mtu": 1350,
            "streamSettings.kcpSettings.tti": 20,
        },
    },
    {
        "name": "vless quic",
        "args": [
            "--vless",
            f"vless://{ID}@192.0.2.16:443?type=quic&security=tls&sni=example.com"
            "&quicSecurity=aes-128-gcm&key=quickey&headerType=none#quic",
        ],
        "want": {
            "streamSettings.network": "quic",
            "streamSettings.quicSettings.security": "aes-128-gcm",
            "streamSettings.quicSettings.key": "quickey",
            "streamSettings.quicSettings.header.type": "none",
        },
    },
    {
        "name": "vmess json ws tls",
        "args": [
            "--vmess",
            vmess_link(
                {
                    "v": "2",
                    "ps": "demo",
                    "add": "example.com",
                    "port": "443",
                    "id": ID,
                    "aid": "0",
                    "scy": "auto",
                    "net": "ws",
                    "type": "none",
                    "host": "example.com",
                    "path": "/ws",
                    "tls": "tls",
                    "sni": "example.com",
                    "alpn": "h2,http/1.1",
                    "fp": "chrome",
                    "insecure": "1",
                }
            ),
        ],
        "want": {
            "protocol": "vmess",
            "settings.vnext.0.address": "example.com",
            "settings.vnext.0.port": 443,
            "settings.vnext.0.users.0.security": "auto",
            "streamSettings.network": "ws",
            "streamSettings.wsSettings.path": "/ws",
            "streamSettings.wsSettings.headers.Host": "example.com",
            "streamSettings.security": "tls",
            "streamSettings.tlsSettings.allowInsecure": True,
            "streamSettings.tlsSettings.alpn.0": "h2",
        },
    },
    {
        "name": "vmess json grpc",
        "args": [
            "--vmess",
            vmess_link(
                {
                    "v": "2",
                    "add": "192.0.2.17",
                    "port": 443,
                    "id": ID,
                    "scy": "chacha20-poly1305",
                    "net": "grpc",
                    "type": "multi",
                    "host": "a.example.com",
                    "path": "svc",
                    "tls": "tls",
                    "sni": "example.com",
                }
            ),
        ],
        "want": {
            "settings.vnext.0.users.0.security": "chacha20-poly1305",
            "streamSettings.network": "grpc",
            "streamSettings.grpcSettings.serviceName": "svc",
            "streamSettings.grpcSettings.multiMode": True,
            "streamSettings.grpcSettings.authority": "a.example.com",
        },
    },
    {
        "name": "vmess standard uri",
        "args": [
            "--vmess",
            f"vmess://{ID}@example.com:443?type=ws&security=tls&sni=example.com"
            "&host=example.com&path=%2Fv#standard",
        ],
        "want": {
            "protocol": "vmess",
            "settings.vnext.0.users.0.id": ID,
            "streamSettings.network": "ws",
            "streamSettings.wsSettings.path": "/v",
            "streamSettings.security": "tls",
        },
    },
    {
        "name": "vmess host and uuid",
        "args": ["--vmess", "example.com:8443", "--uuid", ID, "--network", "ws"],
        "want": {
            "protocol": "vmess",
            "settings.vnext.0.address": "example.com",
            "settings.vnext.0.port": 8443,
            "settings.vnext.0.users.0.id": ID,
            "streamSettings.network": "ws",
        },
    },
    {
        "name": "vmess refuses undecodable payload",
        "args": ["--vmess", "vmess://not-base64-json"],
        "fails": True,
    },
    {
        "name": "vmess link needs an id",
        "args": [
            "--vmess",
            vmess_link({"v": "2", "add": "example.com", "port": "443"}),
        ],
        "fails": True,
    },
    {
        "name": "vless refuses a non-link",
        "args": ["--vless", "example.com:443"],
        "fails": True,
    },
]


def main() -> int:
    if not CLI.is_file():
        print(f"check-share-links: no CLI at {CLI}", file=sys.stderr)
        return 1
    if APP and not pathlib.Path(APP).is_file():
        print(f"check-share-links: no app at {APP}", file=sys.stderr)
        return 1
    root = pathlib.Path(tempfile.mkdtemp(prefix="ferrox-links-"))
    failed = 0
    try:
        for case in CASES:
            try:
                found = outbound(case, root)
                for path, want in case.get("want", {}).items():
                    got = at(found, path)
                    if got != want:
                        raise AssertionError(f"{path}: expected {want!r}, got {got!r}")
            except Exception as error:
                failed += 1
                print(f"check-share-links: FAIL {case['name']}: {error}", file=sys.stderr)
            else:
                print(f"check-share-links: ok   {case['name']}")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    if failed:
        print(f"check-share-links: {failed} case(s) failed", file=sys.stderr)
        return 1
    print(f"check-share-links: {len(CASES)} case(s) passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
