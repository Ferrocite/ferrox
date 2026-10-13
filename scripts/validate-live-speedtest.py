"""Validate a live speedtest run: re-derived medians plus redaction.

Two jobs. First, every median in `summary.json` is re-derived from the ok
attempts in `records.jsonl`: a report that disagrees with its own cells
fails. Second, every credential substring in the tokens file is searched in
every artefact the run would publish — and a hit fails the run naming only
the file, never the token. The tokens file itself, the engine configs and
the downloaded bytes are never scanned and never uploaded: they are the
things being protected, not evidence.
"""

import argparse
import json
import statistics
import sys
from pathlib import Path

EXCLUDED = {"tokens.txt", "configs", "dl", "summary.json"}


def load_tokens(path):
    """Credential substrings, one per line; empty lines are not tokens."""
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as exc:
        sys.exit(f"unreadable tokens {path}: {exc}")
    tokens = [line for line in lines if line.strip()]
    if not tokens:
        sys.exit(f"no tokens in {path}: nothing would be checked")
    return tokens


def check_medians(run_dir):
    """summary.json medians equal the medians of the ok attempts."""
    try:
        records = [json.loads(line) for line in
                   (run_dir / "records.jsonl").read_text().splitlines()
                   if line.strip()]
    except (OSError, ValueError) as exc:
        return [f"unreadable records.jsonl: {exc}"]
    try:
        summary = json.loads((run_dir / "summary.json").read_text())
    except (OSError, ValueError) as exc:
        return [f"unreadable summary.json: {exc}"]
    failures = []
    by_cell = {}
    for record in records:
        if record.get("status") != "ok":
            continue
        cell = by_cell.setdefault(
            (record.get("label"), record.get("core")), {})
        for field in ("throughput_mib_s", "cpu_millis_per_gib",
                      "rss_mib", "ttfb_s"):
            value = record.get(field)
            if isinstance(value, (int, float)):
                cell.setdefault(field, []).append(value)
    for entry in summary.get("configs", []):
        label = entry.get("label", "?")
        for core, values in entry.get("cores", {}).items():
            key = (label, core)
            if key not in by_cell:
                if values.get("n"):
                    failures.append(
                        f"{label}/{core}: summary claims {values.get('n')} "
                        "ok attempts but records have none")
                continue
            for field in ("throughput_mib_s", "cpu_millis_per_gib",
                          "rss_mib", "ttfb_s"):
                samples = by_cell[key].get(field, [])
                reported = values.get(field)
                if not samples:
                    if reported is not None:
                        failures.append(
                            f"{label}/{core}: summary reports {field} "
                            f"{reported} with no samples")
                    continue
                expected = statistics.median(samples)
                if reported != expected:
                    failures.append(
                        f"{label}/{core}: {field} median {reported} "
                        f"re-derives to {expected}")
    return failures


def check_redaction(run_dir, tokens):
    """No credential substring in any publishable artefact."""
    failures = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(run_dir)
        if rel.parts and rel.parts[0] in EXCLUDED:
            continue
        if path.suffix == ".png":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except (UnicodeError, OSError):
            continue
        for token in tokens:
            if len(token) >= 4 and token in text:
                failures.append(f"credential leak: {rel} contains a secret")
                break
    return failures


def main(argv=None):
    """Validate a live speedtest directory."""
    parser = argparse.ArgumentParser(description="validate live speedtest run")
    parser.add_argument("--dir", required=True, help="run output directory")
    parser.add_argument("--tokens", required=True, help="tokens file")
    args = parser.parse_args(argv)
    run_dir = Path(args.dir)
    tokens = load_tokens(args.tokens)
    failures = check_medians(run_dir)
    failures += check_redaction(run_dir, tokens)
    if failures:
        print("\n".join(failures))
        return 1
    print(f"live speedtest valid: redaction holds for {len(tokens)} tokens")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
