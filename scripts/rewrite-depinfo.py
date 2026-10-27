#!/usr/bin/env python3
"""Point a cloned target tree at the worktree that now owns it.

A copy-on-write clone keeps the seed's compiled dependencies, but Cargo's
fingerprint dep-info still names the seed's absolute paths. Rewriting those
paths (and the build-script outputs and text `.d` files beside them) lets the
clone reuse the seed's workspace artefacts when the source is byte-identical,
instead of recompiling every crate because the checkout moved.

Cargo's fingerprint dep-info is a binary record stream: an 11-byte header, then
`u32 length`, path bytes, a NUL and a flag byte per file. The length must move
with the path, so this is not a text substitution.

    scripts/rewrite-depinfo.py <old-root> <new-root> <target-dir>

Prints the number of files rewritten. A record stream this build does not
recognise is left alone: the clone then rebuilds that unit, which is slower but
never stale.
"""

from __future__ import annotations

import glob
import os
import struct
import sys
import tempfile

REFERENCE_MTIME = 1640995200  # 2022-01-01, between the aged sources and today.


def parse(blob: bytes, header: int) -> tuple[list[tuple[bytes, bytes]], bytes] | None:
    """The records of one fingerprint dep-info, or None if the stream is unknown."""
    if len(blob) < header:
        return None
    count = struct.unpack_from("<I", blob, 6)[0] if len(blob) >= 10 else -1
    records: list[tuple[bytes, bytes]] = []
    offset = header
    while offset + 5 <= len(blob):
        length = struct.unpack_from("<I", blob, offset)[0]
        end = offset + 4 + length
        if length == 0 or end + 2 > len(blob):
            break
        path = blob[offset + 4:end]
        tail = blob[end:end + 2]
        if tail[0] != 0 or tail[1] not in (0, 1, 2):
            break
        records.append((path, tail))
        offset = end + 2
    if not records or offset > len(blob) or len(blob) - offset > 4:
        return None
    if count >= 0 and count != len(records):
        return None
    return records, blob[offset:]


def rewrite_fingerprint(path: str, old: bytes, new: bytes) -> bool:
    blob = open(path, "rb").read()
    if old not in blob:
        return False
    for header in (11, 10, 12, 13, 14):
        parsed = parse(blob, header)
        if parsed is None:
            continue
        records, trailer = parsed
        out = bytearray(blob[:header])
        for record, tail in records:
            record = record.replace(old, new)
            out += struct.pack("<I", len(record)) + record + tail
        out += trailer
        with open(path, "wb") as handle:
            handle.write(out)
        os.utime(path, (REFERENCE_MTIME, REFERENCE_MTIME))
        return True
    return False


def rewrite_text(path: str, old: bytes, new: bytes) -> bool:
    blob = open(path, "rb").read()
    if old not in blob:
        return False
    with open(path, "wb") as handle:
        handle.write(blob.replace(old, new))
    return True


def selftest() -> int:
    header = struct.pack("<IHIB", 1, 0x01FF, 2, 0)
    records = [(b"/seed/crates/ferrox-core/src/lib.rs", b"\x00\x01"),
               (b"/seed/crates/ferrox-app/src/main.rs", b"\x00\x00")]
    trailer = b"\x00\x00\x00"
    blob = header + b"".join(
        struct.pack("<I", len(path)) + path + tail for path, tail in records) + trailer
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "dep-test")
        with open(path, "wb") as handle:
            handle.write(blob)
        if not rewrite_fingerprint(path, b"/seed", b"/work"):
            print("selftest: rewrite declined a known stream", file=sys.stderr)
            return 1
        out = open(path, "rb").read()
        parsed = parse(out, 11)
        if parsed is None:
            print("selftest: rewritten stream no longer parses", file=sys.stderr)
            return 1
        paths, tail = parsed
        if [p for p, _ in paths] != [b"/work/crates/ferrox-core/src/lib.rs",
                                     b"/work/crates/ferrox-app/src/main.rs"] or tail != trailer:
            print("selftest: rewritten records differ", file=sys.stderr)
            return 1
        if out[:11] != header:
            print("selftest: header changed", file=sys.stderr)
            return 1
        with open(path, "wb") as handle:
            handle.write(b"not a fingerprint")
        if rewrite_fingerprint(path, b"/seed", b"/work"):
            print("selftest: rewrite accepted an unknown stream", file=sys.stderr)
            return 1
        if open(path, "rb").read() != b"not a fingerprint":
            print("selftest: unknown stream changed", file=sys.stderr)
            return 1
    print("rewrite-depinfo: ok")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--selftest":
        return selftest()
    if len(argv) != 4:
        print("usage: rewrite-depinfo.py <old-root> <new-root> <target-dir>", file=sys.stderr)
        return 2
    old, new, target = (os.fsencode(arg) for arg in argv[1:])
    if old == new:
        return 0
    rewritten = 0
    for path in glob.glob(os.path.join(os.fsdecode(target), "debug", ".fingerprint", "*", "dep-*")):
        rewritten += rewrite_fingerprint(path, old, new)
    text = [os.path.join(os.fsdecode(target), "debug", "*.d")]
    text += glob.glob(os.path.join(os.fsdecode(target), "debug", "deps", "*.d"))
    text += glob.glob(os.path.join(os.fsdecode(target), "debug", "build", "*", "output"))
    text += glob.glob(os.path.join(os.fsdecode(target), "debug", "build", "*", "root-output"))
    for path in text:
        for candidate in glob.glob(path):
            rewritten += rewrite_text(candidate, old, new)
    print(rewritten)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
