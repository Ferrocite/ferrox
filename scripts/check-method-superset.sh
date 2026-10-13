#!/usr/bin/env bash
# The method matrix is a claim about a superset, so it gets a checker.
#
# Three rules, and the second and third are the superset:
#   1. a row names a state from a closed vocabulary, a layer, at least one
#      reference path that exists on disk, and a note;
#   2. every method this tree already carries has a row — every
#      `Support::Implemented` method string in `vless.rs` above `#[cfg(test)]`
#      and every page under `docs/function/`;
#   3. every method any of the four pinned trees carries has a row — every
#      directory in their method catalogues is cited by at least one row.
#
# Rule 3 needs the pinned checkouts. A source that `upstream/pins.toml` names
# and that is not on disk fails rather than skipping: a gate that cannot run
# says so, and `CHECK_SUPERSET_UPSTREAM=0` is the one way to say so without a
# red.
set -euo pipefail

root="${FERROX_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$root"

python3 - <<'EOF'
import os
import re
import sys

root = os.getcwd()
matrix = os.path.join(root, "docs/method-superset.md")
vless = os.path.join(root, "crates/ferrox-core/src/vless.rs")
pages = os.path.join(root, "docs/function")
pins = os.path.join(root, "upstream/pins.toml")

STATES = {"implemented", "partial", "planned", "refused", "not-scheduled"}
LAYERS = {
    "protocol", "front", "carrier", "security", "multiplex",
    "obfuscation", "record", "engine", "surface",
}
CATALOGUES = [
    "upstream/xray-core/proxy",
    "upstream/xray-core/transport/internet",
    "upstream/sing-box/protocol",
    "upstream/sing-box/transport",
    "upstream/xray-rust/crates",
    "upstream/zeronet/crates",
]
EXTRAS = [
    "upstream/zeronet/bench/hotpath",
    "upstream/xray-rust/fuzz",
    "upstream/zeronet/fuzz",
]

fails = []
rows = {}
cited = set()


def load_rows():
    with open(matrix, encoding="utf-8") as f:
        text = f.read()
    match = re.search(
        r"<!-- matrix:begin -->(.*?)<!-- matrix:end -->", text, re.S
    )
    if not match:
        fails.append("docs/method-superset.md: no matrix between the markers")
        return
    for number, line in enumerate(match.group(1).splitlines(), 1):
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip().replace("\\|", "|")
                 for c in re.split(r"(?<!\\)\|", line)[1:-1]]
        if len(cells) != 5 or cells[0] in ("row", "") or set(cells[0]) == {"-"}:
            continue
        rows[cells[0]] = {
            "layer": cells[1],
            "state": cells[2],
            "references": cells[3],
            "note": cells[4],
        }
        cited.update(ref.strip() for ref in cells[3].split(",") if ref.strip())
    if not rows:
        fails.append("docs/method-superset.md: the matrix has no rows")


def check_rows():
    for name, row in sorted(rows.items()):
        if row["state"] not in STATES:
            fails.append(f"{name}: state {row['state']!r} is not one of "
                         f"{', '.join(sorted(STATES))}")
        if row["layer"] not in LAYERS:
            fails.append(f"{name}: layer {row['layer']!r} is not one of "
                         f"{', '.join(sorted(LAYERS))}")
        if row["state"] in {"planned", "refused", "not-scheduled"} \
                and not row["note"]:
            fails.append(f"{name}: a {row['state']} row must say why")
        if not row["references"]:
            fails.append(f"{name}: no reference path, so the row proves nothing")
            continue
        for path in row["references"].split(","):
            path = path.strip()
            if not path or path.startswith("#"):
                continue
            if not os.path.exists(os.path.join(root, path)):
                fails.append(f"{name}: reference `{path}` does not exist")


def check_in_flight():
    table = " ".join(
        f"{name} {row['layer']} {row['state']} {row['references']} {row['note']}"
        for name, row in rows.items()
    )
    with open(vless, encoding="utf-8") as f:
        head = f.read().split("#[cfg(test)]", 1)[0]
    for method in sorted(set(re.findall(r'"vless-[a-z0-9-]+"', head))):
        method = method.strip('"')
        if method not in table:
            fails.append(f"`{method}` is an implemented method string in "
                         "vless.rs and no matrix row names it")
    for page in sorted(os.listdir(pages)):
        if not page.endswith(".md"):
            continue
        key = page[:-3]
        if key not in rows:
            fails.append(f"docs/function/{page} is a method page and no "
                         "matrix row is named for it")


def pinned_sources():
    names = []
    if not os.path.isfile(pins):
        fails.append("upstream/pins.toml is missing, so no reference can be "
                     "verified")
        return names
    with open(pins, encoding="utf-8") as f:
        for line in f:
            match = re.match(r"^\[sources\.([A-Za-z0-9_-]+)\]", line)
            if match:
                names.append(match.group(1))
    return names


def covered(path):
    return any(reference == path or reference.startswith(path + "/")
               for reference in cited)


def check_upstream(sources):
    if os.environ.get("CHECK_SUPERSET_UPSTREAM") == "0":
        print("note: CHECK_SUPERSET_UPSTREAM=0, the pinned methods were not "
              "verified")
        return len(CATALOGUES) + len(EXTRAS)
    for catalogue in CATALOGUES:
        full = os.path.join(root, catalogue)
        if not os.path.isdir(full):
            fails.append(f"{catalogue} is not on disk, so its methods are "
                         "unverified")
            continue
        for child in sorted(os.listdir(full)):
            if child.startswith("."):
                continue
            path = f"{catalogue}/{child}"
            if not os.path.isdir(os.path.join(full, child)):
                continue
            if not covered(path):
                fails.append(f"`{path}` is a method directory in a pinned "
                             "tree and no matrix row cites it")
    for extra in EXTRAS:
        if not os.path.isdir(os.path.join(root, extra)):
            fails.append(f"{extra} is not on disk, so its methods are "
                         "unverified")
        elif not covered(extra):
            fails.append(f"`{extra}` is a method directory in a pinned tree "
                         "and no matrix row cites it")
    missing = [name for name in ("xray-core", "sing-box", "xray-rust",
                                "zeronet") if name not in sources]
    if missing:
        fails.append(f"pins.toml does not name {', '.join(missing)}, so the "
                     "matrix is only checked against what is pinned")
    return len(CATALOGUES) + len(EXTRAS)


load_rows()
check_rows()
check_in_flight()
sources = pinned_sources()
catalogues = check_upstream(sources)

checked = 0
for name, row in rows.items():
    for path in row["references"].split(","):
        path = path.strip()
        if path and os.path.exists(os.path.join(root, path)):
            checked += 1

if fails:
    for line in fails:
        print(f"check-method-superset: {line}", file=sys.stderr)
    print(f"check-method-superset: {len(fails)} problem(s), "
          f"{checked} reference(s) agreed", file=sys.stderr)
    sys.exit(1)

print(f"check-method-superset: {len(rows)} row(s) over {catalogues} catalogue(s) "
      f"and 4 pinned source(s), {checked} reference path(s) agreed")
EOF

# A rule that cannot fail is a rule that has not been written, so the gate
# proves it fails on a synthetic root: one catalogue the row stops citing, one
# state outside the vocabulary, and one row renamed away from its page.
selftest="$(mktemp -d)"
trap 'rm -rf "$selftest"' EXIT
mkdir -p "$selftest/docs/function" "$selftest/crates/ferrox-core/src" \
    "$selftest/upstream"
for catalogue in upstream/xray-core/proxy \
    upstream/xray-core/transport/internet \
    upstream/sing-box/protocol \
    upstream/sing-box/transport \
    upstream/xray-rust/crates \
    upstream/zeronet/crates; do
  mkdir -p "$selftest/$catalogue/probe"
done
for extra in upstream/zeronet/bench/hotpath upstream/xray-rust/fuzz \
    upstream/zeronet/fuzz; do
  mkdir -p "$selftest/$extra"
done
printf '[sources.xray-core]\n[sources.sing-box]\n[sources.xray-rust]\n[sources.zeronet]\n' \
    > "$selftest/upstream/pins.toml"
printf 'let support = Support::Implemented { method: "vless-probe" };\n#[cfg(test)]\n' \
    > "$selftest/crates/ferrox-core/src/vless.rs"
printf '# page\n' > "$selftest/docs/function/probe-page.md"
refs="upstream/xray-core/proxy/probe, upstream/xray-core/transport/internet/probe, upstream/sing-box/protocol/probe, upstream/sing-box/transport/probe, upstream/xray-rust/crates/probe, upstream/zeronet/crates/probe, upstream/zeronet/bench/hotpath, upstream/xray-rust/fuzz, upstream/zeronet/fuzz"
matrix="$selftest/docs/method-superset.md"
printf '<!-- matrix:begin -->\n| row | layer | state | references | note |\n| --- | --- | --- | --- | --- |\n| probe-page | surface | implemented | %s | carries `vless-probe` |\n<!-- matrix:end -->\n' \
    "$refs" > "$matrix"

expect() {
  local want="$1" label="$2" out
  out="$(FERROX_ROOT="$selftest" "$0" 2>&1)" && {
    echo "::error::self-test: the $label mutation still passes, so the gate cannot fail"
    exit 1
  }
  if ! grep -q "$want" <<<"$out"; then
    echo "::error::self-test: the $label mutation failed for the wrong reason: $out"
    exit 1
  fi
}

sed -i '' 's#upstream/zeronet/fuzz##' "$matrix"
expect 'upstream/zeronet/fuzz` is a method directory' "uncited catalogue"
sed -i '' 's/| implemented |/| maybe |/' "$matrix"
expect "state 'maybe' is not one of" "unknown state"
sed -i '' 's/| probe-page |/| probe |/' "$matrix"
expect "no matrix row is named for it" "renamed row"
printf '%s\n' 'check-method-superset: self-test passed (three mutations refused)'

