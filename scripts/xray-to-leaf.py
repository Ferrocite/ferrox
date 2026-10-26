"""Translate one Xray-dialect client outbound document to a leaf client config.

leaf names the same protocols in `protocol`/`settings`, but a TLS or WebSocket
carrier is a separate outbound in a `chain`. The matrix emits only the fields
this converter needs, and it refuses a carrier or protocol leaf lacks.
"""

import argparse
import json
import sys
from pathlib import Path


def _first(items, what):
    if not isinstance(items, list) or not items:
        raise ValueError(f"{what} must be a non-empty array")
    return items[0]


def _settings(source):
    settings = source.get("settings") or {}
    if not isinstance(settings, dict):
        raise ValueError("`settings` must be an object")
    return settings


def _stream(source):
    stream = source.get("streamSettings") or {}
    if not isinstance(stream, dict):
        raise ValueError("`streamSettings` must be an object")
    return stream


def _tls_layer(stream):
    security = stream.get("security", "none")
    if security == "tls":
        settings = stream.get("tlsSettings") or {}
        layer = {
            "protocol": "tls",
            "tag": "tls",
            "settings": {"serverName": settings.get("serverName", "")},
        }
        if settings.get("caCertFile"):
            layer["settings"]["certificate"] = settings["caCertFile"]
        if settings.get("alpn"):
            layer["settings"]["alpn"] = settings["alpn"]
        return layer
    if security == "reality":
        settings = stream.get("realitySettings") or {}
        return {
            "protocol": "reality",
            "tag": "reality",
            "settings": {
                "serverName": settings.get("serverName", ""),
                "publicKey": settings.get("publicKey", ""),
                "shortId": settings.get("shortId", ""),
            },
        }
    if security in ("", "none"):
        return None
    raise ValueError(f"leaf at this pin has no `{security}` security")


def _carrier_layer(stream):
    network = stream.get("network", "tcp")
    if network in ("tcp", ""):
        return None
    if network == "ws":
        settings = stream.get("wsSettings") or {}
        return {
            "protocol": "ws",
            "tag": "ws",
            "settings": {"path": settings.get("path", "/")},
        }
    raise ValueError(f"leaf at this pin has no `{network}` transport")


def _protocol_layer(source):
    protocol = source.get("protocol")
    if not protocol:
        raise ValueError("the client outbound has no `protocol`")
    settings = _settings(source)
    stream = _stream(source)

    if protocol == "vless":
        server = _first(settings.get("vnext"), "`vnext`")
        user = _first(server.get("users"), "`vnext[0].users`")
        if user.get("flow"):
            raise ValueError("leaf at this pin has no VLESS flow")
        layer = {
            "address": server["address"],
            "port": server["port"],
            "uuid": user["id"],
        }
    elif protocol == "vmess":
        server = _first(settings.get("vnext"), "`vnext`")
        user = _first(server.get("users"), "`vnext[0].users`")
        security = user.get("security", "auto")
        if security == "auto":
            security = "aes-128-gcm"
        if security not in ("aes-128-gcm", "chacha20-poly1305"):
            raise ValueError(f"leaf at this pin has no VMess `{security}` cipher")
        layer = {
            "address": server["address"],
            "port": server["port"],
            "uuid": user["id"],
            "security": security,
        }
    elif protocol == "trojan":
        server = _first(settings.get("servers"), "`servers`")
        layer = {
            "address": server["address"],
            "port": server["port"],
            "password": server["password"],
        }
    elif protocol == "shadowsocks":
        server = _first(settings.get("servers"), "`servers`")
        if server.get("method", "").startswith("2022-"):
            raise ValueError("leaf at this pin has no Shadowsocks 2022")
        layer = {
            "address": server["address"],
            "port": server["port"],
            "method": server["method"],
            "password": server["password"],
        }
    else:
        raise ValueError(f"leaf at this pin has no `{protocol}` client here")

    if stream.get("network") not in ("tcp", "", "ws", None):
        raise ValueError(f"leaf at this pin has no `{stream.get('network')}` transport")
    return {"protocol": protocol, "tag": "proxy", "settings": layer}


def convert(document):
    outbounds = document.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds:
        raise ValueError("`outbounds` must be a non-empty array")
    source = outbounds[0]
    stream = _stream(source)
    layers = [
        layer
        for layer in (_tls_layer(stream), _carrier_layer(stream), _protocol_layer(source))
        if layer is not None
    ]
    if len(layers) == 1:
        return {"outbounds": layers}
    return {
        "outbounds": [
            {
                "protocol": "chain",
                "tag": "chain",
                "settings": {"actors": [layer["tag"] for layer in layers]},
            },
            *layers,
        ]
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        document = json.loads(args.input.read_text())
        converted = convert(document)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"xray-to-leaf: {error}", file=sys.stderr)
        return 2
    args.output.write_text(json.dumps(converted, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
