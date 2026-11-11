#!/usr/bin/env python3
"""Print a PEM certificate's SubjectPublicKeyInfo as base64, the pin WARP uses."""
import base64
import sys

_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def der(tag, content):
    if len(content) < 0x80:
        header = bytes((tag, len(content)))
    elif len(content) < 0x100:
        header = bytes((tag, 0x81, len(content)))
    else:
        header = bytes((tag, 0x82, len(content) >> 8, len(content) & 0xFF))
    return header + content


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


def _p256_add(one, other):
    if one is None:
        return other
    if other is None:
        return one
    if one[0] == other[0]:
        if (one[1] + other[1]) % _P256_P == 0:
            return None
        slope = (3 * one[0] * one[0] + _P256_A) * pow(2 * one[1], -1, _P256_P)
    else:
        slope = (other[1] - one[1]) * pow(other[0] - one[0], -1, _P256_P)
    slope %= _P256_P
    x = (slope * slope - one[0] - other[0]) % _P256_P
    return x, (slope * (one[0] - x) - one[1]) % _P256_P


def _p256_multiply(scalar, point):
    result = None
    while scalar:
        if scalar & 1:
            result = _p256_add(result, point)
        point = _p256_add(point, point)
        scalar >>= 1
    return result


def p256_public_key(scalar):
    """The uncompressed point of a P-256 private scalar, or None."""
    if len(scalar) > 32:
        return None
    value = int.from_bytes(scalar, "big")
    if not 0 < value < _P256_N:
        return None
    point = _p256_multiply(value, _P256_G)
    if point is None:
        return None
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def sec1_with_public_key(sec1):
    """A SEC1 ECPrivateKey carrying the public point ring derives and checks."""
    outer = der_next(sec1, 0)
    if outer is None or outer[0] != 0x30:
        return None
    version = der_next(outer[1], 0)
    if version is None or version[0] != 0x02 or version[1] != b"\x01":
        return None
    key = der_next(outer[1], version[3])
    if key is None or key[0] != 0x04:
        return None
    point = p256_public_key(key[1])
    if point is None:
        return None
    parameters = der(0xA0, bytes.fromhex("06082a8648ce3d030107"))
    public = der(0xA1, der(0x03, b"\x00" + point))
    return der(0x30, b"\x02\x01\x01" + der(0x04, key[1]) + parameters + public)


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
