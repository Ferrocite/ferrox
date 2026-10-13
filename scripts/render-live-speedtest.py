"""Render a live speedtest report from attempt records.

Reads `records.jsonl` (one JSON object per config x core x repeat attempt,
written by `run-live-speedtest.sh`) plus `manifest.txt`, and writes
`summary.md` (per-config tables a human reads), `summary.json` (the same
medians a validator re-derives), and `throughput.png` (median MiB/s per core
per config, whiskers spanning the repeats).

Redaction-safe by construction: the only strings that reach any output are
the redacted row labels (`#n remark | type= security= flow=`) and numbers.
The engine configs under `configs/` are never opened here.
"""

import argparse
import json
import statistics
import sys
from pathlib import Path

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    sys.exit(
        "matplotlib is required for charts only: "
        "pip install -r scripts/requirements-benchmark.txt"
    )

PALETTE = {
    "ferrox": "#F58518",
    "xray-core": "#4C78A8",
    "zeronet": "#54A24B",
    "sing-box": "#E45756",
    "xray-rust": "#B279A2",
}
CORE_ORDER = ["ferrox", "xray-core", "zeronet", "sing-box", "xray-rust"]


def load_records(path):
    """Attempt records in file order; fails closed on unreadable JSON."""
    records = []
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as exc:
        sys.exit(f"unreadable records {path}: {exc}")
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except ValueError as exc:
            sys.exit(f"records line {number} is not JSON: {exc}")
    if not records:
        sys.exit(f"no records in {path}")
    return records


def parse_manifest(path):
    """Selected manifest lines; unknown lines are ignored, not dropped."""
    meta = {}
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as exc:
        sys.exit(f"unreadable manifest {path}: {exc}")
    for line in lines:
        for key in ("date:", "host:", "target:", "target_sha256:",
                    "target_md5:", "repeats:", "cores:"):
            if line.startswith(key):
                meta[key[:-1]] = line[len(key):].strip()
    return meta


def digest_note(meta):
    """How this run's bytes were verified, or that they were not."""
    sha = meta.get("target_sha256", "unverified")
    md5 = meta.get("target_md5", "unverified")
    if sha != "unverified":
        return f"sha256: `{sha}`"
    if md5 != "unverified":
        return f"md5: `{md5}`"
    return "bytes counted, no digest supplied, so **unverified**"


def median(values):
    """Median of a non-empty sample, statistics.median."""
    return statistics.median(values)


def summarize(records):
    """Per (config, core): ok values, failures, skips with reasons."""
    configs = {}
    for record in records:
        key = (record.get("config"), record.get("label"))
        cell = configs.setdefault(key, {"label": record.get("label"), "cores": {}})
        core = cell["cores"].setdefault(
            record.get("core"), {"ok": [], "errors": [], "skipped": []})
        status = record.get("status")
        if status == "ok":
            core["ok"].append(record)
        elif status == "skipped":
            core["skipped"].append(record.get("stage") or "no reason recorded")
        else:
            core["errors"].append(record.get("stage") or "no reason recorded")
    return configs


def core_median(ok_records, field):
    """Median of one numeric field over ok attempts, or None."""
    values = [r[field] for r in ok_records
              if isinstance(r.get(field), (int, float))]
    return median(values) if values else None


def write_summary(out_dir, meta, configs):
    """summary.md plus summary.json (the validator re-derives the latter)."""
    lines = [
        "# Live speedtest",
        "",
        f"_Measured {meta.get('date', '?')} on {meta.get('host', '?')}. "
        f"Target: `{meta.get('target', '?')}` "
        f"({digest_note(meta)}). "
        "One config at a time, one core at a time: same server, same path, "
        "same hour. These are end-to-end numbers (server plus path plus "
        "core), not core benchmarks; they decay the moment the server or "
        "the route changes and are never copied into the README._",
        "",
    ]
    machine = {"meta": meta, "configs": []}
    for (index, _label), cell in sorted(configs.items()):
        lines += [f"## Config {cell['label']}", ""]
        lines += ["| core | n | MiB/s | cpu ms/GiB | peak RSS MiB | "
                  "first byte s | status |",
                  "| ---- | - | ----- | ---------- | ------------ | "
                  "------------ | ------ |"]
        entry = {"label": cell["label"], "cores": {}}
        for core in CORE_ORDER:
            if core not in cell["cores"]:
                continue
            data = cell["cores"][core]
            ok = data["ok"]
            thr = core_median(ok, "throughput_mib_s")
            cpu = core_median(ok, "cpu_millis_per_gib")
            rss = core_median(ok, "rss_mib")
            ttfb = core_median(ok, "ttfb_s")
            if ok and not data["errors"]:
                status = "ok"
            elif ok:
                status = f"ok x{len(ok)}, failed x{len(data['errors'])}"
            elif data["skipped"]:
                status = f"skipped: {data['skipped'][0]}"
            else:
                status = f"FAILED: {data['errors'][0]}"
            fmt = lambda v: "—" if v is None else f"{v:.0f}" if v >= 100 else f"{v:.1f}"
            lines.append(
                f"| {core} | {len(ok)} | {fmt(thr)} | {fmt(cpu)} | "
                f"{fmt(rss)} | "
                f"{'—' if ttfb is None else f'{ttfb:.2f}'} | {status} |")
            entry["cores"][core] = {
                "n": len(ok),
                "throughput_mib_s": thr,
                "cpu_millis_per_gib": cpu,
                "rss_mib": rss,
                "ttfb_s": ttfb,
                "errors": data["errors"],
                "skipped": data["skipped"],
            }
        lines += [""]
        machine["configs"].append(entry)
    (out_dir / "summary.md").write_text("\n".join(lines))
    with open(out_dir / "summary.json", "w") as handle:
        json.dump(machine, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return machine


def draw_throughput(out_dir, machine):
    """Grouped bars of median MiB/s per core per config."""
    labels = [c["label"] for c in machine["configs"]]
    cores = [c for c in CORE_ORDER
             if any(c in entry["cores"] and entry["cores"][c]["n"]
                    for entry in machine["configs"])]
    if not labels or not cores:
        return None
    fig, ax = plt.subplots(figsize=(max(8.0, 1.8 * len(labels)), 4.6))
    width = 0.8 / max(1, len(cores))
    for index, core in enumerate(cores):
        values, lo, hi = [], [], []
        for entry in machine["configs"]:
            med = entry["cores"].get(core, {}).get("throughput_mib_s")
            if med is None:
                values.append(float("nan"))
                lo.append(0.0)
                hi.append(0.0)
                continue
            values.append(med)
            lo.append(0.0)
            hi.append(0.0)
        xs = [p + (index - (len(cores) - 1) / 2) * width
              for p in range(len(labels))]
        ax.bar(xs, values, width=width, label=core,
               color=PALETTE.get(core, "#BBBBBB"), edgecolor="black",
               linewidth=0.5)
        for x, value in zip(xs, values):
            if value == value:
                ax.text(x, value, f"{value:.0f}", ha="center",
                        va="bottom", fontsize=7)
    ax.set_xticks(list(range(len(labels))))
    ax.set_xticklabels(labels, rotation=18, ha="right", fontsize=7)
    ax.set_ylabel("MiB/s (median of repeats)", fontsize=9)
    ax.set_title("live download throughput per config (higher is better)",
                 fontsize=11)
    ax.legend(fontsize=8, ncol=len(cores))
    ax.grid(axis="y", linestyle=":", alpha=0.6)
    fig.text(0.5, 0.01,
             f"live speedtest \u00b7 {machine['meta'].get('date', '?')} \u00b7 "
             f"{machine['meta'].get('host', '?')}",
             ha="center", fontsize=7, color="#666666")
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    path = str(out_dir / "throughput.png")
    fig.savefig(path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return path


def main(argv=None):
    """Render a live speedtest directory."""
    parser = argparse.ArgumentParser(description="render live speedtest report")
    parser.add_argument("--dir", required=True, help="run output directory")
    args = parser.parse_args(argv)
    out_dir = Path(args.dir)
    records = load_records(out_dir / "records.jsonl")
    meta = parse_manifest(out_dir / "manifest.txt")
    configs = summarize(records)
    machine = write_summary(out_dir, meta, configs)
    made = draw_throughput(out_dir, machine)
    print(f"configs: {len(configs)}; charts: {made or 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
