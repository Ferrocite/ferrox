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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cells", required=True, help="cells/ directory")
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.85,
        help="a leg below this fraction of the reference is a hole (default 0.85)",
    )
    args = parser.parse_args()

    grouped = cells_by_scenario(args.cells)
    holes = []
    checked = 0
    for base in sorted({key[0] for key in grouped}):
        reference = grouped.get((base, REFERENCE))
        if reference is None:
            continue
        baseline = median_throughput(reference, REFERENCE)
        if not baseline:
            continue
        client_leg = median_throughput(reference, FERRORX)
        server_cell = grouped.get((base, FERRORX))
        server_leg = (
            median_throughput(server_cell, REFERENCE) if server_cell is not None else None
        )
        rust_client = median_throughput(reference, "xray-core-rust")
        checked += 1
        if client_leg is not None and client_leg < baseline * args.threshold:
            holes.append(
                f"{base}: ferrox client {client_leg:.1f} MiB/s vs "
                f"{baseline:.1f} MiB/s (xray-core client) on the xray-core "
                f"server, {client_leg / baseline:.2f}x: the client leg lost"
            )
        if server_leg is not None and server_leg < baseline * args.threshold:
            holes.append(
                f"{base}: ferrox server {server_leg:.1f} MiB/s vs "
                f"{baseline:.1f} MiB/s (xray-core server) with the xray-core "
                f"client, {server_leg / baseline:.2f}x: the server leg lost"
            )
        if (
            rust_client is not None
            and client_leg is not None
            and client_leg < rust_client * args.threshold
        ):
            holes.append(
                f"{base}: ferrox client {client_leg:.1f} MiB/s vs "
                f"{rust_client:.1f} MiB/s (xray-core-rust client) on the "
                f"xray-core server, {client_leg / rust_client:.2f}x"
            )

    for hole in holes:
        print(f"::error::leg gap: {hole}", file=sys.stderr)
    print(
        f"legs checked: {checked}, holes: {len(holes)} "
        f"(threshold {args.threshold:.2f})",
        file=sys.stderr,
    )
    return 1 if holes else 0


if __name__ == "__main__":
    sys.exit(main())
