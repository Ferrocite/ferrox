#!/usr/bin/env bash
# Every claim a method doc makes about ops, syscalls or memory copies is a row
# here, and the doc's table must equal the rows here exactly. A number that
# changes in the doc without changing here fails; a row here with no doc fails.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
counts="$root/scripts/method-counts.txt"
docs="$root/docs/function"

python3 - "$counts" "$docs" "$root/README.md" <<'EOF'
import os
import re
import sys

counts_path, docs_dir, readme_path = sys.argv[1:4]
fails = []


def load_counts():
    rows = {}
    with open(counts_path, encoding="utf-8") as f:
        for number, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split(" ", 3)
            if len(parts) != 4 or not all(parts):
                fails.append(f"{os.path.basename(counts_path)}:{number}: "
                             "expected `doc key value checker`")
                continue
            doc, key, value, checker = parts
            if rows.get(doc, {}).get(key, (value, checker)) != (value, checker):
                fails.append(f"{os.path.basename(counts_path)}:{number}: "
                             f"{doc} {key} declared twice")
                continue
            rows.setdefault(doc, {})[key] = (value, checker)
    return rows


def load_doc(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    rows = {}
    match = re.search(r"<!-- counts:begin -->(.*?)<!-- counts:end -->", text, re.S)
    if not match:
        fails.append(f"{os.path.basename(path)}: no counts block between the markers")
        return rows
    for line in match.group(1).splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip("|").split("|")]
        if len(cells) != 3 or cells[0] in ("key", "---", ""):
            continue
        if set(cells[1]) == {"-"} or cells[0].startswith("-"):
            continue
        rows[cells[0]] = (cells[1], cells[2])
    return rows


counts = load_counts()
if not os.path.isdir(docs_dir):
    fails.append("docs/function is missing; every method needs a page")
    docs = []
else:
    docs = sorted(n for n in os.listdir(docs_dir) if n.endswith(".md"))

with open(readme_path, encoding="utf-8") as f:
    readme = f.read()

checked = 0
for name in docs:
    key = name[:-3]
    path = os.path.join(docs_dir, name)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if f"](docs/function/{name})" not in readme:
        fails.append(f"{name}: README.md does not link it")
    if "```mermaid" not in text or not re.search(r"graph\s+TD", text):
        fails.append(f"{name}: needs a ```mermaid graph TD block")
    if "## Time" not in text:
        fails.append(f"{name}: needs a `## Time` section, measured or not")
    declared = counts.get(key, {})
    stated = load_doc(path)
    for name_, (value, checker) in sorted(stated.items()):
        if name_ not in declared:
            fails.append(f"{key}: `{name_}` is claimed in the doc but not in "
                         "scripts/method-counts.txt")
        elif declared[name_] != (value, checker):
            fails.append(f"{key}: `{name_}` is {value!r} by {checker!r} in the doc "
                         f"and {declared[name_][0]!r} by {declared[name_][1]!r} in "
                         "scripts/method-counts.txt")
        else:
            checked += 1
    for name_ in sorted(set(declared) - set(stated)):
        fails.append(f"{key}: `{name_}` is in scripts/method-counts.txt "
                     "but no doc claims it")

for key in sorted(set(counts) - {n[:-3] for n in docs}):
    fails.append(f"scripts/method-counts.txt has rows for `{key}`, "
                 f"which has no page in docs/function")

if fails:
    for line in fails:
        print(f"check-method-docs: {line}", file=sys.stderr)
    print(f"check-method-docs: {len(fails)} problem(s), {checked} count(s) agreed",
          file=sys.stderr)
    sys.exit(1)

print(f"check-method-docs: {len(docs)} method page(s), {checked} count(s) agreed "
      "with scripts/method-counts.txt")
EOF