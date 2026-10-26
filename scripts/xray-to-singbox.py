"""Translate one Xray-dialect document to a sing-box client or server config.

The matrix scenarios are written as Xray JSON because xray-core is the reference
and its dialect is the one every server reads. sing-box reads the same protocols
but names them with `type`, `server`/`server_port`, `tls` and `transport`; this
converter carries only the fields the matrix emits and refuses a carrier sing-box
at the pin does not have.
"""

import argparse
import json
import sys
from pathlib import Path


def _first(items, what):
    if not isinstance(items, list) or not items:
        raise ValueError(f"{what} must be a non-empty array")
    return items[0]


def _tls(stream):
    security = stream.get("security", "none")
    if security not in ("tls", "reality"):
        return None
    settings = stream.get("tlsSettings" if security == "tls" else "realitySettings") or {}
    tls = {"enabled": True}
    if "serverName" in settings:
        tls["server_name"] = settings["serverName"]
    if security == "reality":
        tls["utls"] = {
            "enabled": True,
            "fingerprint": settings.get("fingerprint", "chrome"),
        }
        tls["reality"] = {
            "enabled": True,
            "public_key": settings.get("publicKey", ""),
            "short_id": settings.get("shortId", ""),
        }
    else:
        if "caCertFile" in settings:
            tls["certificate_path"] = settings["caCertFile"]
        if "alpn" in settings:
            tls["alpn"] = settings["alpn"]
        if settings.get("allowInsecure"):
            tls["insecure"] = True
    return tls


def _transport(stream):
    network = stream.get("network", "tcp")
    if network in ("tcp", ""):
        return None
    if network == "ws":
        settings = stream.get("wsSettings") or {}
        transport = {"type": "ws"}
        if "path" in settings:
            transport["path"] = settings["path"]
        return transport
    if network == "grpc":
        settings = stream.get("grpcSettings") or {}
        transport = {"type": "grpc"}
        if "serviceName" in settings:
            transport["service_name"] = settings["serviceName"]
        return transport
    if network == "httpupgrade":
        settings = stream.get("httpupgradeSettings") or {}
        transport = {"type": "httpupgrade"}
        for source, target in (("path", "path"), ("host", "host")):
            if source in settings:
                transport[target] = settings[source]
        return transport
    raise ValueError(f"sing-box at this pin has no `{network}` transport")


def convert(document):
    outbounds = document.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds:
        raise ValueError("`outbounds` must be a non-empty array")
    source = outbounds[0]
    protocol = source.get("protocol")
    if not protocol:
        raise ValueError("the client outbound has no `protocol`")
    settings = source.get("settings") or {}
    stream = source.get("streamSettings") or {}
    outbound = {"type": protocol, "tag": source.get("tag", "proxy")}

    if protocol == "vless":
        server = _first(settings.get("vnext"), "`vnext`")
        user = _first(server.get("users"), "`vnext[0].users`")
        outbound["server"] = server["address"]
        outbound["server_port"] = server["port"]
        outbound["uuid"] = user["id"]
        if user.get("flow"):
            outbound["flow"] = user["flow"]
    elif protocol == "vmess":
        server = _first(settings.get("vnext"), "`vnext`")
        user = _first(server.get("users"), "`vnext[0].users`")
        outbound["server"] = server["address"]
        outbound["server_port"] = server["port"]
        outbound["uuid"] = user["id"]
        outbound["security"] = user.get("security", "auto")
        if user.get("alterId"):
            outbound["alter_id"] = user["alterId"]
    elif protocol == "trojan":
        server = _first(settings.get("servers"), "`servers`")
        outbound["server"] = server["address"]
        outbound["server_port"] = server["port"]
        outbound["password"] = server["password"]
    elif protocol == "shadowsocks":
        server = _first(settings.get("servers"), "`servers`")
        outbound["server"] = server["address"]
        outbound["server_port"] = server["port"]
        outbound["method"] = server["method"]
        outbound["password"] = server["password"]
    elif protocol == "hysteria":
        if settings.get("version") != 1:
            raise ValueError("sing-box at this pin carries only Hysteria v1 here")
        server = settings
        if settings.get("servers"):
            server = _first(settings["servers"], "`servers`")
        outbound["type"] = "hysteria"
        outbound["server"] = server["address"]
        outbound["server_port"] = server["port"]
        outbound["auth_str"] = server.get("auth", settings.get("auth", ""))
        outbound["up_mbps"] = 100
        outbound["down_mbps"] = 100
        obfs = (stream.get("tlsSettings") or {}).get("obfs")
        if obfs:
            outbound["obfs"] = obfs
    else:
        raise ValueError(f"sing-box at this pin has no `{protocol}` client here")

    tls = _tls(stream)
    if tls is not None:
        outbound["tls"] = tls
        if protocol == "vmess" and outbound.get("security") == "auto":
            outbound["security"] = "aes-128-gcm"
    if protocol != "hysteria":
        transport = _transport(stream)
        if transport is not None:
            outbound["transport"] = transport
    return {"outbounds": [outbound], "route": {"final": outbound["tag"]}}


def _certificate(settings):
    certificate = _first(settings.get("certificates"), "`tlsSettings.certificates`")
    if "certificateFile" not in certificate or "keyFile" not in certificate:
        raise ValueError("`tlsSettings.certificates[0]` needs a file and a key")
    return certificate["certificateFile"], certificate["keyFile"]


def _server_inbound(inbound):
    protocol = inbound.get("protocol")
    if protocol == "socks":
        return {
            "type": "socks",
            "tag": inbound.get("tag", "socks-in"),
            "listen": inbound.get("listen", "127.0.0.1"),
            "listen_port": inbound["port"],
        }
    if protocol != "hysteria":
        raise ValueError(f"sing-box at this pin has no `{protocol}` server here")
    settings = inbound.get("settings") or {}
    if settings.get("version") != 1:
        raise ValueError("sing-box at this pin carries only Hysteria v1 here")
    stream = inbound.get("streamSettings") or {}
    tls_settings = stream.get("tlsSettings") or {}
    certificate, key = _certificate(tls_settings)
    users = settings.get("users") or settings.get("clients")
    if not isinstance(users, list) or not users:
        raise ValueError("the Hysteria v1 server needs at least one user")
    converted = {
        "type": "hysteria",
        "tag": inbound.get("tag", "hysteria-in"),
        "listen": inbound.get("listen", "127.0.0.1"),
        "listen_port": inbound["port"],
        "up_mbps": 100,
        "down_mbps": 100,
        "users": [
            {"auth_str": user.get("auth", user.get("auth_str", ""))}
            for user in users
        ],
        "tls": {
            "enabled": True,
            "alpn": tls_settings.get("alpn", ["hysteria"]),
            "certificate_path": certificate,
            "key_path": key,
        },
    }
    if tls_settings.get("obfs"):
        converted["obfs"] = tls_settings["obfs"]
    return converted


def convert_server(document):
    inbounds = document.get("inbounds")
    if not isinstance(inbounds, list) or not inbounds:
        raise ValueError("`inbounds` must be a non-empty array")
    return {
        "inbounds": [_server_inbound(inbound) for inbound in inbounds],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--server", action="store_true")
    args = parser.parse_args()
    try:
        document = json.loads(args.input.read_text())
        converted = convert_server(document) if args.server else convert(document)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"xray-to-singbox: {error}", file=sys.stderr)
        return 2
    args.output.write_text(json.dumps(converted, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
