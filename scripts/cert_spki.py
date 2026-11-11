#!/usr/bin/env python3
"""Print a PEM certificate's SubjectPublicKeyInfo as base64, the pin WARP uses."""
import base64
import sys


def der_next(data, at):
    """One DER TLV: tag, content, and the raw bytes including the header."""
    start = at
    if at + 2 > len(data):
        return None
    tag = data[at]
    at += 1
    first = data[at]
    at += 1
    if first & 0x80:
        width = first & 0x7F
        if width == 0 or at + width > len(data):
            return None
        length = int.from_bytes(data[at:at + width], "big")
        at += width
    else:
        length = first
    end = at + length
    if end > len(data):
        return None
    return tag, data[at:end], data[start:end], end


def spki_of_certificate(der):
    outer = der_next(der, 0)
    if outer is None or outer[0] != 0x30:
        return None
    tbs = der_next(outer[1], 0)
    if tbs is None or tbs[0] != 0x30:
        return None
    first = der_next(tbs[1], 0)
    if first is None:
        return None
    target = (1 if first[0] == 0xA0 else 0) + 5
    index = 0
    at = 0
    while at < len(tbs[1]):
        entry = der_next(tbs[1], at)
        if entry is None:
            return None
        if index == target:
            return entry[2]
        index += 1
        at = entry[3]
    return None


def pem_der(path):
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as error:
        raise ValueError(f"cannot read {path}: {error}") from error
    body = "".join(
        line.strip() for line in text.splitlines()
        if line.strip() and not line.startswith("-----")
    )
    return base64.b64decode(body, validate=True)


def spki_base64(path):
    spki = spki_of_certificate(pem_der(path))
    if spki is None:
        raise ValueError(f"{path} has no subjectPublicKeyInfo")
    return base64.b64encode(spki).decode()


def sec1_private_key(der):
    """The SEC1 ECPrivateKey inside a PKCS #8 or SEC1 key, or None.

    ZeroNet reads an outer key whose version is 1 as SEC1, but PKCS #8 v2
    carries that version too. The field after the version separates them:
    an AlgorithmIdentifier opens PKCS #8, an OCTET STRING opens SEC1.
    """
    outer = der_next(der, 0)
    if outer is None or outer[0] != 0x30:
        return None
    version = der_next(outer[1], 0)
    if version is None or version[0] != 0x02 or version[1] not in (b"\x00", b"\x01"):
        return None
    follows = der_next(outer[1], version[3])
    if follows is None:
        return None
    if follows[0] == 0x04:
        return der
    if follows[0] != 0x30:
        return None
    inner = der_next(outer[1], follows[3])
    if inner is None or inner[0] != 0x04:
        return None
    key = der_next(inner[1], 0)
    if key is None or key[0] != 0x30:
        return None
    return inner[1]


def main():
    if len(sys.argv) != 2:
        print("usage: cert-spki.py <certificate.pem>", file=sys.stderr)
        raise SystemExit(2)
    try:
        print(spki_base64(sys.argv[1]))
    except ValueError as error:
        print(f"cert-spki: {error}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
