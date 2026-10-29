"""Attribute a slow cell to the leg that lost: client or server.

Every scenario runs against both servers, and every admitted client runs against
each server, so the same corpus already carries the two controls a gap needs:

    xray-core server + xray-core client      the reference
    xray-core server + ferrox client         the client leg
    ferrox server + xray-core client         the server leg

When the client leg is below the reference the client has the hole; when the
server leg is, the server does. A ferrox-vs-xray-core cell that loses while both
controls hold its own comparison is noise, and this check leaves it to the ratio
rows rather than guessing a leg. A scenario with no xray-core server cell, such
as standalone Hysteria v1, has no legs to attribute and is skipped.
"""

import argparse
import json
import statistics
import subprocess
import sys
import tempfile
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


def median_metric(cell, engine, metric):
    """The engine's median over its repeats, or None when it did not run."""
    for entry in cell.get("engines", []):
        if entry.get("name") != engine:
            continue
        samples = [
            run[metric]
            for run in entry.get("runs", [])
            if isinstance(run.get(metric), (int, float))
        ]
        return statistics.median(samples) if samples else None
    return None


def median_throughput(cell, engine):
    return median_metric(cell, engine, "throughput_mib_s")


def median_server_metric(cell, engine, metric):
    """The server's median for the runs this client produced, or None."""
    for entry in cell.get("engines", []):
        if entry.get("name") != engine:
            continue
        samples = [
            run["server"][metric]
            for run in entry.get("runs", [])
            if isinstance(run.get("server"), dict)
            and isinstance(run["server"].get(metric), (int, float))
        ]
        return statistics.median(samples) if samples else None
    return None


def median_ceiling(cell):
    """The harness's own loopback ceiling for the cell, MiB/s, or None."""
    if cell is None:
        return None
    samples = [
        value
        for value in cell.get("harness_ceilings_mib_s", [])
        if isinstance(value, (int, float)) and value > 0
    ]
    return statistics.median(samples) if samples else None


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
    """(base, leg) -> (ratio, issue, basis) for holes already filed and owned."""
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
        if len(parts) not in (4, 5):
            continue
        base, leg, ratio, issue = parts[:4]
        basis = parts[4] if len(parts) == 5 else "raw"
        if basis not in ("raw", "ceiling"):
            continue
        try:
            known[(base, leg)] = (float(ratio), issue, basis)
        except ValueError:
            continue
    return known


def filed_basis_ratio(hole, basis):
    """The current ratio on the basis its baseline was filed on, raw when unavailable."""
    raw = hole.get("raw_ratio", hole["ratio"])
    if basis == "ceiling":
        ceiling = hole.get("ceiling_ratio")
        if ceiling is not None:
            return ceiling
    return raw


def within_baseline(leg, ratio, filed):
    """A hole is known while it is no worse than its filed ratio by more than 0.10.

    Throughput legs are fractions where lower is worse; the server cost legs are
    multiples where higher is worse, so the same subtraction cannot read both.
    """
    if leg in ("server-cpu", "server-threads"):
        return ratio <= filed + 0.10
    return ratio >= filed - 0.10


def check_grouped(grouped, threshold, cpu_threshold, threads_threshold):
    """Every leg gap in the matrix, before baseline reconciliation."""
    holes = []
    checked = 0
    measured = set()
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
        # The server leg compares two cells, so a runner that was faster in one
        # of them is not a server loss: each cell's own harness ceiling is the
        # common denominator. The client leg stays raw; both clients share a cell.
        reference_ceiling = median_ceiling(reference)
        server_ceiling = median_ceiling(server_cell)
        raw_ratio = (
            server_leg / reference_mib_s
            if server_leg is not None and reference_mib_s
            else None
        )
        ceiling_ratio = None
        if raw_ratio is not None and reference_ceiling and server_ceiling:
            ceiling_ratio = (server_leg / server_ceiling) / (
                reference_mib_s / reference_ceiling
            )
        server_ratio = ceiling_ratio if ceiling_ratio is not None else raw_ratio
        rust_client = median_throughput(reference, "xray-core-rust")
        checked += 1
        measured.add(base)
        if client_leg is None and attempted(reference, FERRORX):
            holes.append({
                "base": base,
                "leg": "client",
                "ratio": 0.0,
                "text": f"{base}: ferrox client landed no number on the xray-core server: the client leg lost",
            })
        elif client_leg is not None and client_leg < reference_mib_s * threshold:
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
        elif server_ratio is not None and server_ratio < threshold:
            basis = " of the harness ceiling" if reference_ceiling and server_ceiling else ""
            holes.append({
                "base": base,
                "leg": "server",
                "ratio": server_ratio,
                "raw_ratio": raw_ratio,
                "ceiling_ratio": ceiling_ratio,
                "text": f"{base}: ferrox server {server_leg:.1f} MiB/s vs "
                        f"{reference_mib_s:.1f} MiB/s (xray-core server) with the xray-core "
                        f"client, {server_ratio:.2f}x{basis}: the server leg lost",
            })
        if (
            rust_client is not None
            and client_leg is not None
            and client_leg < rust_client * threshold
        ):
            holes.append({
                "base": base,
                "leg": "rust",
                "ratio": client_leg / rust_client,
                "text": f"{base}: ferrox client {client_leg:.1f} MiB/s vs "
                        f"{rust_client:.1f} MiB/s (xray-core-rust client) on the "
                        f"xray-core server, {client_leg / rust_client:.2f}x",
            })
        if server_cell is not None and attempted(server_cell, REFERENCE):
            holes.extend(server_cost_holes(
                base,
                reference,
                server_cell,
                cpu_threshold,
                threads_threshold,
            ))
    return holes, checked, measured


def server_cost_holes(base, reference, server_cell, cpu_threshold, threads_threshold):
    """The server leg's CPU and thread peak, both lower-is-better.

    The xray-core client on each server is the control: the same client moves
    the same bytes, so the only difference is the server process. CPU is already
    per GiB, from the same bytes the throughput panel divides by.
    """
    holes = []
    ref_cpu = median_server_metric(reference, REFERENCE, "cpu_millis_per_gib")
    fer_cpu = median_server_metric(server_cell, REFERENCE, "cpu_millis_per_gib")
    if ref_cpu is None or fer_cpu is None:
        holes.append({
            "base": base,
            "leg": "server-cpu",
            "ratio": 0.0,
            "text": f"{base}: server CPU was not sampled on both legs; "
                    f"the server cost has no measurement, so it cannot be gated",
        })
    elif ref_cpu > 0:
        ratio = fer_cpu / ref_cpu
        if ratio > cpu_threshold:
            holes.append({
                "base": base,
                "leg": "server-cpu",
                "ratio": ratio,
                "text": f"{base}: ferrox server {fer_cpu:.1f} ms/GiB vs "
                        f"{ref_cpu:.1f} ms/GiB (xray-core server), {ratio:.2f}x: "
                        f"the server spent more CPU",
            })
    else:
        holes.append({
            "base": base,
            "leg": "server-cpu",
            "ratio": 0.0,
            "text": f"{base}: xray-core server CPU is below the sampler's "
                    f"resolution ({fer_cpu:.1f} ms/GiB for ferrox): no server "
                    f"CPU ratio, so the leg cannot be gated",
        })
    ref_threads = median_server_metric(reference, REFERENCE, "threads_peak")
    fer_threads = median_server_metric(server_cell, REFERENCE, "threads_peak")
    if ref_threads is None or fer_threads is None:
        holes.append({
            "base": base,
            "leg": "server-threads",
            "ratio": 0.0,
            "text": f"{base}: server threads were not sampled on both legs; "
                    f"the server cost has no measurement, so it cannot be gated",
        })
    elif ref_threads > 0:
        ratio = fer_threads / ref_threads
        if ratio > threads_threshold:
            holes.append({
                "base": base,
                "leg": "server-threads",
                "ratio": ratio,
                "text": f"{base}: ferrox server peaked at {fer_threads:.0f} threads vs "
                        f"{ref_threads:.0f} (xray-core server), {ratio:.2f}x: "
                        f"the server held more threads",
            })
    else:
        holes.append({
            "base": base,
            "leg": "server-threads",
            "ratio": 0.0,
            "text": f"{base}: xray-core server threads are 0 while ferrox reports "
                    f"{fer_threads:.0f}: no ratio, so the leg cannot be gated",
        })
    return holes


def selftest():
    """Prove the server CPU and thread gate fails a losing server and passes a winning one."""
    with tempfile.TemporaryDirectory() as tmp:
        cells = Path(tmp)
        for server, cpu, threads, throughput in (
            ("xray-core", 100.0, 8.0, 1000.0),
            ("ferrox", 150.0, 12.0, 1000.0),
        ):
            write_fixture(cells, server, cpu, threads, throughput)
        proc = run_self(cells)
        if proc.returncode == 0:
            return "a ferrox server with 1.50x CPU and 1.50x threads passed the gate"
        for expect in ("server spent more CPU", "server held more threads"):
            if expect not in proc.stderr:
                return f"the losing-server gate did not report {expect!r}: {proc.stderr}"

        for server, cpu, threads, throughput in (
            ("xray-core", 100.0, 8.0, 1000.0),
            ("ferrox", 80.0, 6.0, 1000.0),
        ):
            write_fixture(cells, server, cpu, threads, throughput)
        proc = run_self(cells)
        if proc.returncode != 0:
            return f"a cheaper ferrox server failed the gate: {proc.stderr}"

        for server, cpu, threads, throughput in (
            ("xray-core", 100.0, 8.0, 1000.0),
            ("ferrox", None, None, 1000.0),
        ):
            write_fixture(cells, server, cpu, threads, throughput)
        proc = run_self(cells)
        if proc.returncode == 0 or "server CPU was not sampled" not in proc.stderr:
            return f"an unsampled ferrox server passed the gate: {proc.stderr}"

        # A slower runner in the ferrox-server cell is not a server loss: the
        # ceiling measured in each cell is the common denominator.
        for server, throughput, ceiling in (
            ("xray-core", 1000.0, 2000.0),
            ("ferrox", 800.0, 1000.0),
        ):
            write_fixture(cells, server, 100.0, 8.0, throughput, ceiling)
        proc = run_self(cells)
        if proc.returncode != 0:
            return f"a server leg at its cell's ceiling share failed the gate: {proc.stderr}"

        # The same raw ratio at the same ceiling on both cells is a real loss.
        for server, throughput, ceiling in (
            ("xray-core", 1000.0, 1000.0),
            ("ferrox", 800.0, 1000.0),
        ):
            write_fixture(cells, server, 100.0, 8.0, throughput, ceiling)
        proc = run_self(cells)
        if proc.returncode == 0:
            return "a server leg below 0.85x at the same ceiling passed the gate"

        # A raw-filed server ratio is compared on its own basis: a raw 0.70 is
        # 0.50 of the ferrox cell's ceiling, and that cell is still the filed gap.
        for server, throughput, ceiling in (
            ("xray-core", 1000.0, 1000.0),
            ("ferrox", 700.0, 1400.0),
        ):
            write_fixture(cells, server, 100.0, 8.0, throughput, ceiling)
        baseline = cells / "leg-gaps.txt"
        baseline.write_text("selftest-vless-raw-down-8|server|0.70|1\n")
        proc = run_self(cells, baseline)
        if proc.returncode != 0:
            return f"a raw baseline was compared against a ceiling ratio: {proc.stderr}"

        # A ceiling-filed entry is compared on the ceiling basis.
        baseline.write_text("selftest-vless-raw-down-8|server|0.50|1|ceiling\n")
        proc = run_self(cells, baseline)
        if proc.returncode != 0:
            return f"a ceiling baseline was not read: {proc.stderr}"

        # The same ceiling basis still fails a ratio worse than what was filed.
        for server, throughput, ceiling in (
            ("xray-core", 1000.0, 1000.0),
            ("ferrox", 700.0, 1750.0),
        ):
            write_fixture(cells, server, 100.0, 8.0, throughput, ceiling)
        baseline.write_text("selftest-vless-raw-down-8|server|0.55|1|ceiling\n")
        proc = run_self(cells, baseline)
        if proc.returncode == 0:
            return "a ceiling ratio worse than its filed baseline passed the gate"

    for leg, ratio, filed, want in (
        ("client", 0.50, 0.56, True),
        ("client", 0.40, 0.56, False),
        ("server-threads", 1.29, 1.54, True),
        ("server-threads", 1.70, 1.54, False),
        ("server-cpu", 0.90, 1.00, True),
        ("server-cpu", 1.20, 1.00, False),
    ):
        if within_baseline(leg, ratio, filed) != want:
            return (
                f"{leg} at {ratio:.2f}x against a filed {filed:.2f}x was "
                f"read as {not want}: the wrong direction is worse"
            )
    print("check-matrix-legs selftest: passed")
    return None


def write_fixture(cells, server, cpu, threads, throughput, ceiling=None):
    """One scenario for both servers; `cpu`/`threads` None omits the measurement."""
    base = "selftest-vless-raw-down-8"
    scenario = f"{base}--srv-{server}"
    runs = []
    for _ in range(3):
        run = {"throughput_mib_s": throughput}
        if cpu is not None:
            run["server"] = {
                "cpu_millis_per_gib": cpu,
                "threads_peak": threads,
            }
        runs.append(run)
    doc = {
        "scenario": scenario,
        "engines": [
            {"name": "xray-core", "runs": runs},
            {"name": "ferrox", "runs": [{"throughput_mib_s": throughput} for _ in range(3)]},
        ],
        "failures": [],
    }
    if ceiling is not None:
        doc["harness_ceilings_mib_s"] = [ceiling] * 3
    path = cells / scenario / "cell.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc))


def run_self(cells, baseline=None):
    command = [sys.executable, __file__, "--cells", str(cells)]
    if baseline is None:
        command.append("--no-baseline")
    else:
        command += ["--baseline", str(baseline)]
    return subprocess.run(command, text=True, capture_output=True)


def main():
    if "--selftest" in sys.argv:
        failure = selftest()
        if failure:
            print(f"::error::check-matrix-legs selftest: {failure}", file=sys.stderr)
            return 1
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cells", required=True, help="cells/ directory")
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.85,
        help="a leg below this fraction of the reference is a hole (default 0.85)",
    )
    parser.add_argument(
        "--server-cpu-threshold",
        type=float,
        default=1.0,
        help="ferrox server CPU above this fraction of xray-core's is a hole (default 1.0)",
    )
    parser.add_argument(
        "--server-threads-threshold",
        type=float,
        default=1.0,
        help="ferrox server threads above this fraction of xray-core's is a hole (default 1.0)",
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
    holes, checked, measured = check_grouped(
        grouped,
        args.threshold,
        args.server_cpu_threshold,
        args.server_threads_threshold,
    )

    new, known, fixed = [], [], []
    for hole in holes:
        filed = baseline.get((hole["base"], hole["leg"]))
        if filed is None:
            new.append(hole)
        elif within_baseline(hole["leg"], filed_basis_ratio(hole, filed[2]), filed[0]):
            known.append((hole, filed[1]))
        else:
            new.append(hole)
    seen = {(hole["base"], hole["leg"]) for hole in holes}
    for key, (ratio, issue, _basis) in sorted(baseline.items()):
        if key[0] in measured and key not in seen:
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
        f"threshold {args.threshold:.2f}, server CPU "
        f"{args.server_cpu_threshold:.2f}, server threads "
        f"{args.server_threads_threshold:.2f})",
        file=sys.stderr,
    )
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
