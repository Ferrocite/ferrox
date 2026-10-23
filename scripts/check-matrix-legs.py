"""Attribute a slow cell to the leg that lost: client or server.

Every scenario runs against both servers, and every admitted client runs against
each server, so the same corpus already carries the two controls a gap needs:

    xray-core server + xray-core client      the reference
    xray-core server + ferrox client         the client leg
    ferrox server + xray-core client         the server leg

When the client leg is below the reference the client has the hole; when the
server leg is, the server does. A ferrox-vs-xray-core cell that loses while both
controls hold its own comparison is noise, and this check leaves it to the ratio
rows rather than guessing a leg.
"""

import argparse
import json
import statistics
import sys
from pathlib import Path

REFERENCE = "xray-core"
FERRORX = "ferrox"


def load(path):
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"::error::{path}: {exc}", file=sys.stderr)
        return None


def median_throughput(cell, engine):
    """The engine's median over its repeats, or None when it did not run."""
    for entry in cell.get("engines", []):
        if entry.get("name") != engine:
            continue
        samples = [
            run["throughput_mib_s"]
            for run in entry.get("runs", [])
            if isinstance(run.get("throughput_mib_s"), (int, float))
        ]
        return statistics.median(samples) if samples else None
    return None


def cells_by_scenario(cells_dir):
    """(base scenario, server) -> cell document."""
    grouped = {}
    for path in sorted(Path(cells_dir).glob("*/cell.json")):
        cell = load(path)
        if cell is None:
            continue
        scenario = cell.get("scenario", "")
        base, sep, server = scenario.rpartition("--srv-")
        if not sep:
            continue
        grouped[(base, server)] = cell
    return grouped


def attempted(cell, engine):
    """The engine was asked to run this cell, even if it landed no number."""
    for entry in cell.get("engines", []):
        if entry.get("name") != engine:
            continue
        if entry.get("runs"):
            return True
        return any(f.get("engine") == engine for f in cell.get("failures", []))
    return False


def load_baseline(path):
    """(base, leg) -> (ratio, issue) for holes already filed and owned."""
    known = {}
    try:
        lines = Path(path).read_text().splitlines()
    except OSError:
        return known
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) != 4:
            continue
        base, leg, ratio, issue = parts
        try:
            known[(base, leg)] = (float(ratio), issue)
        except ValueError:
            continue
    return known


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cells", required=True, help="cells/ directory")
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.85,
        help="a leg below this fraction of the reference is a hole (default 0.85)",
    )
    parser.add_argument(
        "--baseline",
        default=str(Path(__file__).with_name("leg-gaps.txt")),
        help="holes that are filed already; new or worse holes still fail",
    )
    parser.add_argument(
        "--no-baseline", action="store_true", help="fail on every hole"
    )
    args = parser.parse_args()
    baseline = {} if args.no_baseline else load_baseline(args.baseline)

    grouped = cells_by_scenario(args.cells)
    holes = []
    checked = 0
    for base in sorted({key[0] for key in grouped}):
        if "setup" in base:
            continue
        reference = grouped.get((base, REFERENCE))
        if reference is None:
            continue
        reference_mib_s = median_throughput(reference, REFERENCE)
        if not reference_mib_s:
            continue
        client_leg = median_throughput(reference, FERRORX)
        server_cell = grouped.get((base, FERRORX))
        server_leg = (
            median_throughput(server_cell, REFERENCE) if server_cell is not None else None
        )
        rust_client = median_throughput(reference, "xray-core-rust")
        checked += 1
        if client_leg is None and attempted(reference, FERRORX):
            holes.append({
                "base": base,
                "leg": "client",
                "ratio": 0.0,
                "text": f"{base}: ferrox client landed no number on the xray-core server: the client leg lost",
            })
        elif client_leg is not None and client_leg < reference_mib_s * args.threshold:
            holes.append({
                "base": base,
                "leg": "client",
                "ratio": client_leg / reference_mib_s,
                "text": f"{base}: ferrox client {client_leg:.1f} MiB/s vs "
                        f"{reference_mib_s:.1f} MiB/s (xray-core client) on the xray-core "
                        f"server, {client_leg / reference_mib_s:.2f}x: the client leg lost",
            })
        if server_leg is None and server_cell is not None and attempted(server_cell, REFERENCE):
            holes.append({
                "base": base,
                "leg": "server",
                "ratio": 0.0,
                "text": f"{base}: xray-core client landed no number on the ferrox server: the server leg lost",
            })
        elif server_leg is not None and server_leg < reference_mib_s * args.threshold:
            holes.append({
                "base": base,
                "leg": "server",
                "ratio": server_leg / reference_mib_s,
                "text": f"{base}: ferrox server {server_leg:.1f} MiB/s vs "
                        f"{reference_mib_s:.1f} MiB/s (xray-core server) with the xray-core "
                        f"client, {server_leg / reference_mib_s:.2f}x: the server leg lost",
            })
        if (
            rust_client is not None
            and client_leg is not None
            and client_leg < rust_client * args.threshold
        ):
            holes.append({
                "base": base,
                "leg": "rust",
                "ratio": client_leg / rust_client,
                "text": f"{base}: ferrox client {client_leg:.1f} MiB/s vs "
                        f"{rust_client:.1f} MiB/s (xray-core-rust client) on the "
                        f"xray-core server, {client_leg / rust_client:.2f}x",
            })

    new, known, fixed = [], [], []
    for hole in holes:
        filed = baseline.get((hole["base"], hole["leg"]))
        if filed is None:
            new.append(hole)
        elif hole["ratio"] >= filed[0] - 0.10:
            known.append((hole, filed[1]))
        else:
            new.append(hole)
    seen = {(hole["base"], hole["leg"]) for hole in holes}
    for key, (ratio, issue) in sorted(baseline.items()):
        if key not in seen:
            fixed.append((key, ratio, issue))

    for hole in new:
        print(f"::error::leg gap: {hole['text']}", file=sys.stderr)
    for hole, issue in known:
        print(f"::warning::known leg gap ({issue}): {hole['text']}", file=sys.stderr)
    for (base, leg), ratio, issue in fixed:
        print(f"::warning::{base} {leg} leg no longer gaps (baseline {ratio:.2f}x, {issue}); remove its line from scripts/leg-gaps.txt", file=sys.stderr)
    print(
        f"legs checked: {checked}, holes: {len(holes)} "
        f"(new {len(new)}, known {len(known)}, fixed {len(fixed)}; "
        f"threshold {args.threshold:.2f})",
        file=sys.stderr,
    )
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
