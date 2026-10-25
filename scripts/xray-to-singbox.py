"""Translate one Xray-dialect client outbound document to a sing-box client config.

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
    else:
        raise ValueError(f"sing-box at this pin has no `{protocol}` client here")

    tls = _tls(stream)
    if tls is not None:
        outbound["tls"] = tls
    transport = _transport(stream)
    if transport is not None:
        outbound["transport"] = transport
    return {"outbounds": [outbound], "route": {"final": outbound["tag"]}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        document = json.loads(args.input.read_text())
        converted = convert(document)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"xray-to-singbox: {error}", file=sys.stderr)
        return 2
    args.output.write_text(json.dumps(converted, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
