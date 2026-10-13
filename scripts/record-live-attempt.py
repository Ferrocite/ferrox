"""Append one live-speedtest attempt record as a JSON line.

Arguments, in order: config label core repeat status stage
throughput_mib_s cpu_millis_per_gib rss_mib ttfb_s bytes http_code hash.
Empty strings become null (absent measurement), never zero: the renderer
reads every row with the same shape and a zero would read as "free".
"""

import json
import sys

KEYS = (
    "config",
    "label",
    "core",
    "repeat",
    "status",
    "stage",
    "throughput_mib_s",
    "cpu_millis_per_gib",
    "rss_mib",
    "ttfb_s",
    "bytes",
    "http_code",
    "hash",
)

NUMERIC = {
    "throughput_mib_s",
    "cpu_millis_per_gib",
    "rss_mib",
    "ttfb_s",
    "bytes",
    "http_code",
}


def main(argv):
    """One JSON object on stdout."""
    values = []
    for key, arg in zip(KEYS, argv):
        if arg == "":
            values.append(None)
        elif key in NUMERIC:
            values.append(float(arg))
        else:
            values.append(arg)
    print(json.dumps(dict(zip(KEYS, values))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
