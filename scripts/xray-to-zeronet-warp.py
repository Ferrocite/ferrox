#!/usr/bin/env python3
"""Translate the matrix's WARP outbound into the account shape ZeroNet reads.

The matrix writes ferrox's WARP identity block; ZeroNet's `warp` outbound takes
the account fields directly and the edge's SPKI as the pin. The certificate the
cell already mints carries that SPKI, so no second key is introduced here.
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cert_spki import spki_base64


def fail(message):
    print(f"xray-to-zeronet-warp: {message}", file=sys.stderr)
    raise SystemExit(2)


def main():
    if len(sys.argv) != 2:
        fail("usage: xray-to-zeronet-warp.py <client.json>")
    try:
        doc = json.load(open(sys.argv[1], encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {sys.argv[1]}: {error}")
    outbound = next(
        (item for item in doc.get("outbounds") or []
         if item.get("protocol") == "warp"),
        None,
    )
    if outbound is None:
        fail("the config has no warp outbound")
    settings = outbound.get("settings") or {}
    identity = settings.get("identity") or {}
    wireguard = identity.get("wireguard") or {}
    masque = identity.get("masque") or {}
    edge = settings.get("masque") or {}
    tls = (outbound.get("streamSettings") or {}).get("tlsSettings") or {}
    certificates = tls.get("certificates") or []
    certificate = certificates[0].get("certificateFile") if certificates else None
    certificate = certificate or tls.get("caCertFile")
    if not certificate:
        fail("the warp outbound names no certificate to pin")
    try:
        server_public_key = spki_base64(certificate)
    except ValueError as error:
        fail(str(error))
    host = edge.get("address")
    port = edge.get("port")
    if not host or not port:
        fail("the warp outbound names no MASQUE address and port")
    addresses = masque.get("address") or wireguard.get("address")
    if not addresses:
        fail("the warp outbound names no tunnel address")
    translated = copy.deepcopy(doc)
    translated["outbounds"] = [{
        "tag": outbound.get("tag", "proxy"),
        "protocol": "warp",
        "settings": {
            "route": "masque-h3",
            "masque": {
                "privateKey": masque.get("privateKey"),
                "serverPublicKey": server_public_key,
                "address": addresses,
                "http3Endpoints": [f"{host}:{port}"],
                "http3Sni": edge.get("serverName") or tls.get("serverName"),
                "authority": edge.get("host") or edge.get("serverName"),
            },
        },
    }]
    json.dump(translated, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
