#!/usr/bin/env python3
"""Plan what CI has to measure from what a change actually touches.

`docs/function/<method>.md` is the registry. Each page declares the source files
that trigger it (`paths`), the items of the shared relay that are its own
(`symbols`), and the work its change owes: matrix scenario ids (`scenarios`),
upstream oracle test names (`oracle`), reference packages (`go`).

A file one page claims is that page's change. A file no page claims is shared,
and shared code owes the whole matrix — **unless** every hunk of the diff in it
sits inside something one page names. `proxy.rs` hosts every method's dial and
serve rungs beside the relay helpers, so a VMess rung edit is a VMess change and
gets the VMess cells, while `read_exact` changing still owes everything: a Rust
hunk is attributed by the item it sits in, matched against each page's
`symbols`. A row of `scripts/method-counts.txt` or `scripts/method-ops.txt`
already carries its page in the first column, so it claims itself. A hunk that
resolves to no name, or to items of two methods where only one is claimed, keeps
the plan wide: attribution is only allowed to narrow on evidence, never to skip
a measurement.

A workflow runs `scope` once to write the plan file, then every expensive job
asks for its own slice of it. With no plan file — locally, or on a scheduled run
that skipped the step — every query answers wide, so nothing narrows by accident.
"""

from __future__ import annotations

import argparse
import fnmatch
import glob
import json
import os
import re
import subprocess
import sys

PLAN = ".ferrox/ci-scope.json"
PAGES = "docs/function"
OPS_ROWS = "scripts/method-ops.txt"
PINS = "upstream/pins.toml"
LIB_MATRIX = "scripts/lib-matrix.sh"
TIERS = ("smoke", "standard", "full")
WIDE_GO = ["./..."]
# A page whose code lives in the shared relay has no file of its own to name; the
# plan then treats its source as shared and runs wide, which is what a relay
# change owes. The page still declares what it owes once anything is in scope.
OWNED_NOWHERE = "-"

# Under crates/, the trees that ship no method code: a change here owes the
# workspace build and its tests, not the comparisons against the references. The
# bench harness measures, the prompt library plans; neither is a thing measured.
TOOL = ("crates/ferrox-prompt/", "crates/ferrox-bench/")

SCOPE_BLOCK = re.compile(r"<!--\s*scope:begin\s*-->(.*?)<!--\s*scope:end\s*-->", re.S)
SCOPE_KEYS = ("paths", "symbols", "engines", "scenarios", "oracle", "go")
LIST_KEYS = ("methods", "scenarios", "go_packages", "suites_skipped", "engines")

# The comparators `scripts/run-benchmark-matrix.sh` builds from `upstream/pins.toml`.
# A page may declare which of these its method's row is gated against; the ones it
# leaves out are engines it has recorded as unable to serve the method, so a cell
# need not build, fetch or probe them. `xray-core` is not optional: the harness
# refuses a comparison without it.
ENGINES = ("xray-core", "sing-box", "zeronet", "xray-core-rust", "xray-rust", "leaf")
REFERENCE = "xray-core"

# The data files whose every row names its own page in the first column: a hunk
# here moves one page's claim, so it is that page's change, not shared code
# moving. `method-ops.txt` rows are `method filter symbol`, `method-counts.txt`
# rows are `doc key value checker`.
PAGE_KEYED = ("scripts/method-counts.txt", "scripts/method-ops.txt")
# A row here is `symbol count`, so the page rides on the symbol: the final path
# segment is the item whose count is blessed, and a page claiming that item name
# claims the row.
SYMBOL_KEYED = ("scripts/expected-ops.txt",)

# The header of a Rust item, as far up as a hunk has to read to know what it
# changed. `impl` is its own case: the name worth claiming is the type.
ITEM_KIND = r"(?:const|static|fn|struct|enum|trait|type|mod)"
ITEM_HEAD = re.compile(rf"^(\s*)(?:pub(?:\([a-z]+\))?\s+)?(?:unsafe\s+)?{ITEM_KIND}\s+([A-Za-z0-9_]+)")
IMPL_HEAD = re.compile(r"^(\s*)(?:pub(?:\([a-z]+\))?\s+)?(?:unsafe\s+)?impl"
                       r"(?:\s*<[^<>]*>)?\s+([A-Za-z0-9_]+)")


def item_at(lines: list[str], number: int) -> str | None:
    """The enclosing item name of one 1-based line, or None if it has none.

    A hunk between two items belongs to neither, so a change at or above the
    header's own indentation is refused instead of blamed on the function above
    it: a diff must not narrow CI by the accident of where a function ends.
    """
    if not lines:
        return None
    at = min(max(number, 1), len(lines)) - 1
    depth = len(lines[at]) - len(lines[at].lstrip())
    for index in range(at, -1, -1):
        head = ITEM_HEAD.match(lines[index]) or IMPL_HEAD.match(lines[index])
        if not head:
            continue
        if depth <= len(head.group(1)) and index != at:
            return None
        return head.group(2)
    return None


def enclosing(blob: str, start: int, count: int) -> list[str]:
    """The item names one hunk reaches: its first changed line's and its last."""
    if not blob:
        return []
    lines = blob.splitlines()
    names: list[str] = []
    for name in (item_at(lines, start), item_at(lines, start + max(count - 1, 0))):
        if name is None:
            return []
        if name not in names:
            names.append(name)
    return names


def row_pages(lines: list[str], scopes: dict) -> list[tuple[str, list[str]]]:
    """A data file's changed rows, each naming its own page in the first column.

    A comment or a blank row names nothing; a row whose key is no page resolves
    to nothing, and the plan stays wide for it.
    """
    found: list[tuple[str, list[str]]] = []
    for line in lines:
        row = line.lstrip("+-").strip()
        if not row or row.startswith("#"):
            continue
        key = row.split()[0]
        if key not in scopes:
            return [(key, [])]
        if not any(key == name for name, _ in found):
            found.append((key, [key]))
    return found


def symbol_pages(lines: list[str], scopes: dict) -> list[tuple[str, list[str]]]:
    """The pages claiming the blessed symbol counts a diff moved.

    A symbol is a path — `ferrox_core::record::fill_exact` — and the item worth
    claiming is its last segment, which is the name a page's `symbols` holds.
    """
    found: list[tuple[str, list[str]]] = []
    for line in lines:
        row = line.lstrip("+-").strip()
        if not row or row.startswith("#"):
            continue
        tail = row.split()[0].split("::")[-1]
        serving = pages_for(tail, scopes)
        if not serving:
            return [(tail, [])]
        if not any(tail == name for name, _ in found):
            found.append((tail, serving))
    return found


def pages_for(name: str, scopes: dict) -> list[str]:
    """The pages whose `symbols` claim one item name."""
    return [page for page, scope in sorted(scopes.items())
            if matches(page, name, scope.get("symbols", []))]


def hunk_pages(root: str, base: str, path: str,
               hunks: list[tuple[int, int, int, int]], lines: list[str],
               scopes: dict) -> list[tuple[str, list[str]]]:
    """What one shared file's change is, name by name, and who claims each.

    A Rust hunk is read from both sides of the diff because a deletion has no new
    lines to look at, and removing a rung is still a change to that rung.
    """
    if path in PAGE_KEYED:
        return row_pages(lines, scopes)
    if path in SYMBOL_KEYED:
        return symbol_pages(lines, scopes)
    found: list[tuple[str, list[str]]] = []
    blobs: dict[str, str] = {}
    for side, rev in (("old", base), ("new", "HEAD")):
        out = subprocess.run(["git", "show", f"{rev}:{path}"],
                             capture_output=True, text=True, cwd=root)
        blobs[side] = out.stdout if out.returncode == 0 else ""
    for old_start, old_count, new_start, new_count in hunks:
        for blob, start, count in ((blobs["old"], old_start, old_count),
                                   (blobs["new"], new_start, new_count)):
            if count == 0:
                continue
            for name in enclosing(blob, start, count):
                if any(name == seen for seen, _ in found):
                    continue
                found.append((name, pages_for(name, scopes)))
    return found


def parse_diff(text: str) -> tuple[dict[str, list], dict[str, list[str]]]:
    """`path -> hunks` and `path -> changed lines` from a `git diff -U0`.

    A hunk is the old and new start and count; the changed lines are the body's
    `+` and `-` rows, which is what a data file's row key is read from.
    """
    hunks: dict[str, list] = {}
    bodies: dict[str, list[str]] = {}
    path = ""
    for line in text.splitlines():
        if line.startswith("+++ "):
            candidate = line[4:].strip()
            if candidate.startswith("b/") and candidate != "b/dev/null":
                path = candidate[2:]
            elif candidate != "/dev/null":
                path = ""
            continue
        if line.startswith("diff --git "):
            path = ""
            continue
        if not path:
            continue
        if line.startswith("@@"):
            match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if match:
                hunks.setdefault(path, []).append(
                    (int(match.group(1)), int(match.group(2) or 1),
                     int(match.group(3)), int(match.group(4) or 1)))
            continue
        if line[:1] in "+-" and not line.startswith(("+++", "---")):
            bodies.setdefault(path, []).append(line)
    return hunks, bodies


def repo_root() -> str:
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


def split_values(text: str) -> list[str]:
    return [part.strip() for part in text.split(",") if part.strip()]


def read_scope(path: str) -> dict[str, list[str]]:
    """The scope block of one page, keyed by SCOPE_KEYS."""
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    match = SCOPE_BLOCK.search(text)
    if match is None:
        return {}
    found: dict[str, list[str]] = {}
    for line in match.group(1).splitlines():
        line = line.strip().lstrip("-").strip()
        key, colon, value = line.partition(":")
        if not colon or key.strip() not in SCOPE_KEYS:
            continue
        found[key.strip()] = split_values(value)
    return found


def pages(root: str) -> dict[str, dict[str, list[str]]]:
    return {os.path.splitext(os.path.basename(path))[0]: read_scope(path)
            for path in sorted(glob.glob(os.path.join(root, PAGES, "*.md")))}


def scenario_ids(root: str) -> list[str]:
    """Every id lib-matrix.sh knows, asked of the script itself rather than copied."""
    script = f'source "{LIB_MATRIX}"; for t in {" ".join(TIERS)}; do scenarios $t; done'
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, cwd=root)
    if out.returncode != 0:
        sys.exit(f"ci-scope: {LIB_MATRIX} would not answer: {out.stderr.strip()}")
    ids: list[str] = []
    for line in out.stdout.splitlines():
        if line.strip() and line.split()[0] not in ids:
            ids.append(line.split()[0])
    return ids


def pins(root: str) -> list[dict[str, str]]:
    """Each [sources.<name>] block, with the fields the plan reads."""
    with open(os.path.join(root, PINS), encoding="utf-8") as handle:
        text = handle.read()
    found: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in text.splitlines():
        header = re.match(r"^\[sources\.([A-Za-z0-9_.-]+)\]\s*$", line)
        if header:
            if current:
                found.append(current)
            current = {"name": header.group(1)}
            continue
        if current is None:
            continue
        string = re.match(r'^([a-z_]+)\s*=\s*"(.*)"\s*$', line)
        if string:
            current[string.group(1)] = string.group(2)
            continue
        flag = re.match(r"^([a-z_]+)\s*=\s*(true|false)\s*$", line)
        if flag:
            current[flag.group(1)] = flag.group(2)
    if current:
        found.append(current)
    return found


def suite_parts(suite: str) -> tuple[str, list[str], list[str]]:
    """A suite command split into the part before `--`, its flags, its test names."""
    if " -- " not in suite:
        return suite, [], []
    head, tail = suite.split(" -- ", 1)
    tokens = tail.split()
    return (head, [t for t in tokens if t.startswith("-")],
            [t for t in tokens if not t.startswith("-")])


def matches(pin: str, name: str, patterns: list[str]) -> bool:
    """A pattern is `text`, or `pin=text` to bind it to one suite. `text` has to
    land on whole `_`-separated segments of the test name: libtest's own substring
    filter is looser, and a loose pattern here reads as scope that is not — `ws`
    is inside `shadowsocks_over_raw_tcp` and inside `…_echo_flows_…`."""
    for pattern in patterns:
        qualified, sep, text = pattern.partition("=")
        if sep:
            if qualified != pin:
                continue
        else:
            text = pattern
        if re.search(rf"(^|_){re.escape(text)}(_|$)", name, re.I):
            return True
    return False


def filter_suite(pin: str, suite: str, patterns: list[str]) -> str:
    """The pin's suite narrowed to the names in scope; empty means run nothing of it.

    A suite with no test-name list cannot be narrowed, so it is reported as it is.
    """
    head, flags, names = suite_parts(suite)
    if not flags:
        return suite
    keep = [name for name in names if matches(pin, name, patterns)]
    if not keep:
        return ""
    return f"{head} -- {' '.join(flags)} " + " ".join(keep)


def classify(changed: list[str], scopes: dict[str, dict[str, list[str]]],
             names: dict[str, list[tuple[str, list[str]]]] | None = None) -> dict:
    """Which methods a diff touches, or why it touches everything.

    `names` maps a changed shared path to the pairs `(thing, pages)` its hunks
    resolve to — an item name in a Rust file, a row key or symbol in a data file;
    without it (a path list from `--changed-file`, or no diff at all) a file no
    page claims stays shared, which is the wide answer.
    """
    methods: set[str] = set()
    unclaimed: set[str] = set()
    attributed: list[str] = []
    tool = False
    rust = False
    # A plan with nothing to look at has no evidence to narrow on, so it runs wide.
    shared = "" if changed else "no changed-path list to plan against"
    for path in changed:
        if path.startswith(TOOL):
            tool = True
            continue
        if path.endswith((".rs", ".toml")) and path.startswith("crates/"):
            rust = True
        elif path in ("Cargo.toml", "Cargo.lock"):
            rust = True
        page = re.match(r"^docs/function/([A-Za-z0-9_.-]+)\.md$", path)
        if page and page.group(1) in scopes:
            methods.add(page.group(1))
            continue
        if is_shared_source(path):
            owners = [name for name, scope in scopes.items()
                      if any(fnmatch.fnmatch(path, g) for g in scope.get("paths", []))]
            if len(owners) == 1:
                methods.add(owners[0])
                continue
            if len(owners) > 1:
                unclaimed.add(path)
                shared = f"{path} is claimed by {' and '.join(sorted(owners))}"
                continue
            found = (names or {}).get(path)
            if found:
                # Every hunk of this shared file belongs to a thing a page claims,
                # so the file is not what this change is; those things are.
                if all(pages for _, pages in found):
                    for name, pages in found:
                        methods.update(pages)
                        attributed.append(f"{path}::{name}")
                    continue
                first = next(name for name, pages in found if not pages)
                shared = shared or f"{path}::{first} is claimed by no method page"
            else:
                shared = shared or (
                    f"{path} is claimed by no method page" if found is None
                    else f"{path} changes rows or items no method page claims")
            unclaimed.add(path)
            continue
        if path.startswith(("scripts/", ".github/", "upstream/", "crates/")) \
                or path in ("Cargo.toml", "Cargo.lock"):
            shared = shared or f"{path} is shared infrastructure"
            continue
    wide = bool(unclaimed) or bool(shared)
    reason = shared or ("" if methods else "nothing a method page owns")
    return {"wide": wide, "reason": reason, "methods": sorted(methods),
            "unclaimed": sorted(unclaimed), "attributed": attributed,
            "planned": bool(changed), "rust": rust or tool}


def is_shared_source(path: str) -> bool:
    """A source or data file whose hunks, not its name, decide the scope."""
    return (path.startswith("crates/") and path.endswith(".rs")) \
        or path in PAGE_KEYED or path in SYMBOL_KEYED


def ops_rows(root: str, selected: list[str] | None) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with open(os.path.join(root, OPS_ROWS), encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 3:
                continue
            if selected is None or parts[0] in selected:
                rows.append({"method": parts[0], "filter": parts[1], "symbol": parts[2]})
    return rows


def measure(root: str, scopes: dict, plan: dict) -> None:
    """Fill in what the touched methods owe; for a wide plan, what everything owes."""
    selected = None if plan["wide"] else plan["methods"]
    patterns: list[str] = []
    wanted: list[str] = []
    packages: list[str] = []
    # An engine list is only ever a *reduction*, and a page that declares no list
    # owes every comparator, so the answer is the pages' union unless one of them
    # has not ruled any engine out — then the tier's own default stands.
    engines: list[str] = []
    every_declared = selected is not None and bool(selected)
    for name in sorted(scopes) if selected is None else selected:
        scope = scopes[name]
        patterns += scope.get("oracle", [])
        wanted += scope.get("scenarios", [])
        packages += scope.get("go", [])
        declared = scope.get("engines", [])
        if selected is not None:
            if not declared:
                every_declared = False
            for engine in declared:
                if engine not in engines:
                    engines.append(engine)
    plan["engines"] = sorted(engines, key=ENGINES.index) if every_declared else []
    plan["scenarios"] = [] if selected is None else [
        i for i in scenario_ids(root) if any(w in i for w in wanted)]
    plan["go_packages"] = sorted(set(packages)) if selected is not None else list(WIDE_GO)
    plan["rows"] = ops_rows(root, None if selected is None else set(selected))
    suites: dict[str, str] = {}
    skipped: list[str] = []
    for pin in pins(root):
        if pin.get("test_enabled") != "true" or not pin.get("suite"):
            continue
        suite = pin["suite"] if selected is None else filter_suite(
            pin["name"], pin["suite"], patterns)
        if suite:
            suites[pin["name"]] = suite
        else:
            skipped.append(pin["name"])
    plan["suites"] = suites
    plan["suites_skipped"] = skipped
    plan["ops_all"] = len(ops_rows(root, None))


def shared_paths(changed: list[str], scopes: dict) -> list[str]:
    """Changed files no single page claims: the ones worth attributing by hunk."""
    out: list[str] = []
    for path in changed:
        if not is_shared_source(path) or path.startswith(TOOL):
            continue
        owners = [name for name, scope in scopes.items()
                  if any(fnmatch.fnmatch(path, g) for g in scope.get("paths", []))]
        if len(owners) != 1:
            out.append(path)
    return out


def build_plan(root: str, changed: list[str], hunks: dict | None = None,
               bodies: dict | None = None, base: str = "") -> dict:
    scopes = pages(root)
    attributed = None
    if base and hunks is not None:
        attributed = {path: hunk_pages(root, base, path, hunks.get(path, []),
                                       (bodies or {}).get(path, []), scopes)
                      for path in shared_paths(changed, scopes)}
    plan = classify(changed, scopes, attributed)
    measure(root, scopes, plan)
    return plan


def changed_from(root: str, base: str) -> tuple[list[str], dict, dict]:
    out = subprocess.run(["git", "diff", "--name-only", f"{base}...HEAD"],
                         capture_output=True, text=True, cwd=root)
    if out.returncode != 0:
        sys.exit(f"ci-scope: git diff against {base} failed: {out.stderr.strip()}")
    paths = [line for line in out.stdout.splitlines() if line.strip()]
    detail = subprocess.run(["git", "diff", "-U0", "--no-color", f"{base}...HEAD"],
                            capture_output=True, text=True, cwd=root)
    if detail.returncode != 0:
        sys.exit(f"ci-scope: git diff -U0 against {base} failed: "
                 f"{detail.stderr.strip()}")
    return paths, *parse_diff(detail.stdout)


def output_flags(plan: dict) -> dict[str, str]:
    """The job-level `if:` answers. `rust` is what the compiler reads, not whether
    the plan is wide: a workflow or a script change cannot move a test's outcome,
    while a plan with no diff to look at (--wide, a schedule) owes the tests."""
    return {
        "wide": "true" if plan["wide"] else "false",
        "rust": "true" if plan["rust"] or not plan["planned"] else "false",
        "methods": ",".join(plan["methods"]),
        "cells": ",".join(plan["scenarios"]),
        "engines": ",".join(plan["engines"]),
        "matrix": "true" if plan["wide"] or plan["scenarios"] else "false",
        "suites": "true" if plan["wide"] or plan["suites"] else "false",
        "go": "true" if plan["go_packages"] else "false",
        "ops": "true" if plan["wide"] or plan["rows"] else "false",
        "ops_rows": str(len(plan["rows"])),
        "reason": plan["reason"] or "the touched methods are the scope",
    }


def write_summary(plan: dict, path: str) -> None:
    """The plan as one block on the run page, so a reader sees what was skipped
    and why without opening a log. Every workflow gets it from this one call."""
    suites = ", ".join(f"{name}: {len(suite_parts(command)[2])} test(s)"
                       for name, command in sorted(plan["suites"].items()))
    cells = (f"{len(plan['scenarios'])} cell(s): " + ", ".join(plan["scenarios"])
             if not plan["wide"] else "every cell of the tier")
    rows = [(key, value) for key, value in [
        ("plan", "wide" if plan["wide"] else "narrow"),
        ("why", plan["reason"] or "the touched methods are the scope"),
        ("methods in scope", ", ".join(plan["methods"]) or "none"),
        ("shared items attributed", ", ".join(plan["attributed"]) or "none"),
        ("matrix", cells),
        ("comparators", ",".join(plan["engines"])
         or "the tier's own default set"),
        ("ops rows", f"{len(plan['rows'])} of {plan['ops_all']}"),
        ("oracle suites", suites or "none"),
        ("reference packages", " ".join(plan["go_packages"])),
    ]]
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("### CI scope\n\n")
        handle.write("\n".join(f"- **{key}**: {value}" for key, value in rows))
        handle.write("\n\n")


def emit_outputs(plan: dict, github_output: str) -> None:
    keys = output_flags(plan)
    lines = [f"{key}={value}" for key, value in keys.items()]
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    print(f"plan: {'wide' if plan['wide'] else 'narrow'} -- {plan['reason']}")
    print(f"methods: {','.join(plan['methods']) or 'none'}")
    print(f"cells: {len(plan['scenarios'])} ops rows: {len(plan['rows'])}"
          f" of {plan['ops_all']} suites: {','.join(plan['suites']) or 'none'}"
          f" go: {' '.join(plan['go_packages'])}")
    print("\n".join(lines))


def cmd_scope(args: argparse.Namespace) -> int:
    root = repo_root()
    hunks: dict = {}
    bodies: dict = {}
    if args.wide:
        changed: list[str] = []
    elif args.changed_file:
        changed = [line.strip() for line in open(args.changed_file, encoding="utf-8")
                   if line.strip()]
    else:
        if not args.base:
            sys.exit("ci-scope: scope wants --base, --changed-file or --wide")
        changed, hunks, bodies = changed_from(root, args.base)
    plan = build_plan(root, changed, hunks, bodies, args.base or "")
    path = os.path.join(root, PLAN)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(plan, handle, indent=1, sort_keys=True)
        handle.write("\n")
    emit_outputs(plan, args.github_output)
    summary = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if summary:
        write_summary(plan, summary)
    return 0


def query_plan(root: str) -> dict:
    path = os.path.join(root, PLAN)
    if not os.path.exists(path):
        return build_plan(root, [])
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def cmd_rows(args: argparse.Namespace) -> int:
    plan = query_plan(repo_root())
    grouped: dict[str, list[str]] = {}
    order: list[str] = []
    for row in plan["rows"]:
        key = f"{row['method']} {row['filter']}"
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(row["symbol"])
    for key in order:
        print(f"{key} " + " ".join(grouped[key]))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    plan = query_plan(repo_root())
    for item in plan[args.key]:
        print(item)
    return 0


def cmd_suite(args: argparse.Namespace) -> int:
    print(query_plan(repo_root())["suites"].get(args.pin, ""))
    return 0


def shared_names(root: str, scopes: dict) -> dict[str, list[str]]:
    """Item names in the files no single page claims, per file.

    This is what a `symbols:` pattern is checked against: an attribution that
    names nothing is a claim that narrows CI for a code path that does not exist.
    A blessed symbol count is a name of the same kind, so it is read too.
    """
    found: dict[str, list[str]] = {}
    for path in sorted(glob.glob(os.path.join(root, "crates", "*", "src", "**", "*.rs"),
                                 recursive=True)):
        relative = os.path.relpath(path, root)
        if relative.startswith(TOOL):
            continue
        owners = [name for name, scope in scopes.items()
                  if any(fnmatch.fnmatch(relative, g) for g in scope.get("paths", []))]
        if len(owners) == 1:
            continue
        with open(path, encoding="utf-8") as handle:
            names = [head.group(2) for line in handle.read().splitlines()
                     for head in [ITEM_HEAD.match(line) or IMPL_HEAD.match(line)]
                     if head]
        found[relative] = names
    for relative in SYMBOL_KEYED:
        full = os.path.join(root, relative)
        if not os.path.exists(full):
            continue
        with open(full, encoding="utf-8") as handle:
            found[relative] = [row.split()[0].split("::")[-1] for line in handle
                               for row in [line.strip()]
                               if row and not row.startswith("#")]
    return found


def validate(root: str) -> tuple[list[str], list[str]]:
    scopes = pages(root)
    pinned = {pin["name"]: pin for pin in pins(root)}
    fails: list[str] = []
    notes: list[str] = []
    claimed: dict[str, str] = {}
    items = shared_names(root, scopes)
    every_item = sorted({name for names in items.values() for name in names})
    seen: dict[str, str] = {}
    for name, scope in sorted(scopes.items()):
        if not scope:
            fails.append(f"{name}.md: no <!-- scope:begin --> block")
            continue
        if not scope.get("paths"):
            fails.append(f"{name}.md: scope declares no paths: line")
        for pattern in scope.get("symbols", []):
            if "=" in pattern:
                fails.append(f"{name}.md: symbols {pattern} is pin-qualified; an item "
                             "name belongs to every suite")
                continue
            if pattern in seen:
                fails.append(f"{name}.md: symbols {pattern} is already declared by "
                             f"{seen[pattern]}, so a hunk cannot pick between them")
                continue
            seen[pattern] = name
            if not any(matches(name, item, [pattern]) for item in every_item):
                fails.append(f"{name}.md: symbols {pattern} names no item in the shared "
                             "files, so it attributes nothing")
        declared = scope.get("engines", [])
        for engine in declared:
            if engine not in ENGINES:
                fails.append(f"{name}.md: engine {engine} is not one the matrix builds "
                             f"({', '.join(ENGINES)})")
        if declared and REFERENCE not in declared:
            fails.append(f"{name}.md: engines drops {REFERENCE}, and a comparison "
                         "without the reference is not a comparison")
        for engine in declared:
            pin = pinned.get(engine)
            if pin is None or not pin.get("rev"):
                fails.append(f"{name}.md: engine {engine} has no pinned rev to build")
            if engine != REFERENCE and not scope.get("scenarios"):
                fails.append(f"{name}.md: engines {engine} is ruled in or out of a cell "
                             "this page never measures")
        for value in scope.get("paths", []):
            if value == OWNED_NOWHERE:
                if scope.get("symbols"):
                    notes.append(f"{name}.md: no file of its own; its hunks are "
                                 "attributed by the items they sit in")
                else:
                    notes.append(f"{name}.md: no file of its own, so its source "
                                 "changes plan a wide run")
                continue
            hits = glob.glob(os.path.join(root, value))
            if not hits:
                fails.append(f"{name}.md: scope path {value} matches no file")
            for path in hits:
                relative = os.path.relpath(path, root)
                if relative in claimed:
                    fails.append(f"{relative}: claimed by {claimed[relative]} and {name}")
                claimed[relative] = name
    rows = {row["method"] for row in ops_rows(root, None)}
    for label in sorted(rows):
        if label not in scopes:
            fails.append(f"{OPS_ROWS}: method {label} has no page under {PAGES}")
    check_oracle(root, scopes, fails, notes)
    check_scenarios(scopes, scenario_ids(root), fails)
    check_go(root, scopes, fails, notes)
    unowned = [path for path in items if path not in claimed]
    if unowned:
        every = [(path, item) for path in unowned for item in items[path]]
        notes.append(
            f"{len(unowned)} shared file(s) hold {len(every)} item(s): a hunk there "
            "narrows only inside an item a page claims by name, so "
            f"{sum(1 for _, item in every if pages_for(item, scopes))} of them can; "
            "the rest plan a wide run")
    return fails, notes


def check_oracle(root: str, scopes: dict, fails: list, notes: list) -> None:
    listed: dict[str, list[str]] = {}
    for pin in pins(root):
        if pin.get("test_enabled") == "true" and pin.get("suite"):
            _, flags, names = suite_parts(pin["suite"])
            if flags:
                listed[pin["name"]] = names
    if not listed:
        notes.append(f"{PINS} has no enabled suite with a test-name list; "
                     "oracle patterns not verified")
        return
    for name, scope in sorted(scopes.items()):
        for pattern in scope.get("oracle", []):
            qualified, sep, _ = pattern.partition("=")
            if sep and qualified not in listed:
                fails.append(f"{name}.md: oracle pattern {pattern} names {qualified}, "
                             "which has no enabled test list")
                continue
            serving = [pin for pin, names in listed.items()
                       if any(matches(pin, name, [pattern]) for name in names)]
            if not serving:
                fails.append(f"{name}.md: oracle pattern {pattern} matches no test in "
                             "any enabled suite")
            elif len(serving) < len(listed) and not sep:
                notes.append(f"{name}.md: {pattern} is measured only by "
                             f"{', '.join(serving)}")


def check_scenarios(scopes: dict, ids: list[str], fails: list) -> None:
    for name, scope in sorted(scopes.items()):
        for pattern in scope.get("scenarios", []):
            if not any(pattern in i for i in ids):
                fails.append(f"{name}.md: scenario pattern {pattern} matches no id in "
                             f"{LIB_MATRIX}")


def check_go(root: str, scopes: dict, fails: list, notes: list) -> None:
    tree = os.path.join(root, "upstream", "xray-core")
    if not os.path.isdir(tree):
        notes.append("upstream/xray-core is not checked out here; go packages not verified")
        return
    for name, scope in sorted(scopes.items()):
        for pattern in scope.get("go", []):
            directory = pattern.rstrip("/").removesuffix("/...")
            if not os.path.isdir(os.path.join(tree, directory)):
                fails.append(f"{name}.md: go package {pattern} is not a directory of "
                             "the pinned xray-core")


def cmd_check(args: argparse.Namespace) -> int:
    root = repo_root()
    fails, notes = validate(root)
    for note in notes:
        print(f"check-ci-scope: note: {note}")
    if fails:
        for line in fails:
            print(f"check-ci-scope: {line}", file=sys.stderr)
        print(f"check-ci-scope: {len(fails)} problem(s)", file=sys.stderr)
        return 1
    print(f"check-ci-scope: {len(pages(root))} scope block(s) agree with the tree, "
          f"{len(ops_rows(root, None))} row(s) in the wide plan")
    return 0


FIXTURES = [
    ("a method's own file", ["crates/ferrox-app/src/vmess.rs"], False, ["vmess"]),
    ("its page too", ["crates/ferrox-app/src/vmess.rs", "docs/function/vmess.md"],
     False, ["vmess"]),
    ("nothing a page owns", ["crates/ferrox-app/src/proxy.rs"], True, None),
    ("shared infrastructure", ["scripts/count-ops.sh"], True, None),
    ("a dependency move", ["Cargo.lock"], True, None),
    ("the prompt tool", ["crates/ferrox-prompt/src/check.rs"], False, []),
    ("the bench harness", ["crates/ferrox-bench/src/methods.rs"], False, []),
    ("an empty change list", [], True, None),
    ("prose only", ["README.md"], False, []),
    ("two carriers", ["crates/ferrox-app/src/ws.rs", "crates/ferrox-app/src/grpc.rs"],
     False, ["carrier-grpc", "carrier-websocket"]),
]

# The same paths with their hunks attributed: what a shared file owes is the item
# its hunk sits in, not the file.
ATTRIBUTED = [
    ("a shared file, hunks in one method's rung",
     ["crates/ferrox-app/src/proxy.rs"],
     {"crates/ferrox-app/src/proxy.rs": [("dial_vmess_rung", ["vmess"])]},
     False, ["vmess"]),
    ("a shared file, hunks in a relay helper no page claims",
     ["crates/ferrox-app/src/proxy.rs"],
     {"crates/ferrox-app/src/proxy.rs": [("read_exact", [])]},
     True, None),
    ("a shared file, rungs of two methods",
     ["crates/ferrox-app/src/proxy.rs"],
     {"crates/ferrox-app/src/proxy.rs": [("dial_vmess_rung", ["vmess"]),
                                         ("dial_trojan_rung", ["trojan"])]},
     False, ["trojan", "vmess"]),
    ("a shared file, one rung and one helper",
     ["crates/ferrox-app/src/proxy.rs"],
     {"crates/ferrox-app/src/proxy.rs": [("dial_vmess_rung", ["vmess"]),
                                         ("relay", [])]},
     True, None),
    ("a method file plus its counts row and its rung",
     ["crates/ferrox-app/src/vmess.rs", "docs/function/vmess.md",
      "scripts/method-counts.txt", "crates/ferrox-app/src/proxy.rs"],
     {"crates/ferrox-app/src/proxy.rs": [("dial_vmess_rung", ["vmess"])],
      "scripts/method-counts.txt": [("vmess", ["vmess"])]},
     False, ["vmess"]),
    ("a counts row whose key is no page",
     ["scripts/method-counts.txt"],
     {"scripts/method-counts.txt": [("vmesss", [])]},
     True, None),
    ("a page edit and a shared item of another method",
     ["docs/function/vless.md", "crates/ferrox-app/src/config.rs"],
     {"crates/ferrox-app/src/config.rs": [("resolve_xhttp", ["carrier-xhttp"])]},
     False, ["carrier-xhttp", "vless"]),
    ("a blessed symbol no page claims",
     ["scripts/expected-ops.txt"],
     {"scripts/expected-ops.txt": [("der_to_pem", [])]},
     True, None),
    ("a blessed symbol a page claims",
     ["scripts/expected-ops.txt"],
     {"scripts/expected-ops.txt": [("fill_exact", ["record-layer"])]},
     False, ["record-layer"]),
]

RUST_SIDES = """
pub(crate) fn read_exact(stream: &mut dyn Read, buf: &mut [u8]) {}

mod tests {
    fn dial_vmess_rung() {
        let pump = 1;
        assert_eq!(pump, 1);
    }
}
"""


def cmd_selftest(args: argparse.Namespace) -> int:
    root = repo_root()
    scopes = pages(root)
    failed = 0
    for label, changed, want_wide, want_methods in FIXTURES:
        plan = classify(changed, scopes)
        ok = plan["wide"] == want_wide and (want_methods is None
                                            or plan["methods"] == want_methods)
        failed += 0 if ok else 1
        print(f"selftest: {'ok  ' if ok else 'FAIL'} {label} -> "
              f"wide={plan['wide']} methods={plan['methods']}")
    for label, changed, names, want_wide, want_methods in ATTRIBUTED:
        plan = classify(changed, scopes, names)
        ok = plan["wide"] == want_wide and (want_methods is None
                                            or plan["methods"] == want_methods)
        failed += 0 if ok else 1
        print(f"selftest: {'ok  ' if ok else 'FAIL'} {label} -> "
              f"wide={plan['wide']} methods={plan['methods']} "
              f"attributed={plan['attributed']}")
    sides = RUST_SIDES.splitlines()
    for label, number, want in [
        ("a hunk on a signature names that item", 2, "read_exact"),
        ("a hunk in a body names its item", 6, "dial_vmess_rung"),
        ("a hunk between two items names nothing", 3, None),
        ("a hunk on a mod line names the mod", 4, "tests"),
    ]:
        got = item_at(sides, number)
        ok = got == want
        failed += 0 if ok else 1
        print(f"selftest: {'ok  ' if ok else 'FAIL'} {label} -> {got}")
    diff = """diff --git a/scripts/method-counts.txt b/scripts/method-counts.txt
--- a/scripts/method-counts.txt
+++ b/scripts/method-counts.txt
@@ -65 +65,2 @@
-vmess ops-retired-instructions UNBLESSED scripts/count-ops.sh
+vmess ops-retired-instructions 790 scripts/count-ops.sh
+vmess frames-per-write-syscall 4 ferrox-app-vmess::tests::a_batch_on_the_wire
"""
    hunks, bodies = parse_diff(diff)
    rows = row_pages(bodies["scripts/method-counts.txt"], scopes)
    ok = len(hunks["scripts/method-counts.txt"]) == 1 and rows == [("vmess", ["vmess"])]
    failed += 0 if ok else 1
    print(f"selftest: {'ok  ' if ok else 'FAIL'} a counts hunk is read as its row key "
          f"({hunks} {rows})")
    # The declarations have to name what is really in the tree, or the narrowing is
    # a claim about a function that does not exist.
    for label, name, want in [
        ("a rung of the relay is claimed by its page", "dial_vmess_rung", ["vmess"]),
        ("a relay helper is claimed by nobody", "read_exact", []),
        ("the request decoder is claimed by nobody", "decode_request", []),
    ]:
        got = pages_for(name, scopes)
        ok = got == want
        failed += 0 if ok else 1
        print(f"selftest: {'ok  ' if ok else 'FAIL'} {label} "
              f"({name} -> {got or 'no page'})")
    suite = ("cargo test -p p --test t -- --ignored --test-threads=1 "
             "vmess_over_raw_tcp trojan_over_raw_tcp")
    for label, got, want in [
        ("a suite narrows to the names in scope",
         filter_suite("zeronet", suite, ["vmess"]),
         "cargo test -p p --test t -- --ignored --test-threads=1 vmess_over_raw_tcp"),
        ("a pin with no name in scope is skipped", filter_suite("zeronet", suite, ["kcp"]), ""),
        ("a pin-qualified pattern stays with its pin",
         "yes" if matches("xray-rust", "rust_socks_vless_reality",
                          ["xray-rust-hysteria=auth"]) else "no", "no"),
        ("a qualified pattern serves its own pin",
         "yes" if matches("xray-rust-hysteria", "pinned_reference_rejects_wrong_auth",
                          ["xray-rust-hysteria=auth"]) else "no", "yes"),
    ]:
        ok = got == want
        failed += 0 if ok else 1
        print(f"selftest: {'ok  ' if ok else 'FAIL'} {label}")
    plan = build_plan(root, ["crates/ferrox-app/src/vmess.rs"])
    ok = plan["scenarios"] == ["vmess-raw-down-8", "vmess-tls-ws-down-8"] and len(plan["rows"]) == 2 \
        and "vmess_over_raw_tcp_matches_the_oracle" in plan["suites"].get("zeronet", "") \
        and "vmess" not in plan["suites"].get("xray-rust", "") \
        and "rust_" not in plan["suites"].get("xray-rust", "") \
        and plan["suites_skipped"] == ["xray-rust", "xray-rust-hysteria"]
    failed += 0 if ok else 1
    print(f"selftest: {'ok  ' if ok else 'FAIL'} a vmess plan carries vmess and nothing "
          f"else ({len(plan['scenarios'])} cell(s), {len(plan['rows'])} row(s), "
          f"suites {sorted(plan['suites'])})")
    shared = build_plan(root, ["crates/ferrox-core/src/record.rs"])
    ok = len(shared["rows"]) == 4 and len(shared["scenarios"]) == 10 \
        and "trojan_over_raw_tcp_matches_the_oracle" in shared["suites"]["zeronet"] \
        and shared["go_packages"] == ["./common/crypto/..."]
    failed += 0 if ok else 1
    print(f"selftest: {'ok  ' if ok else 'FAIL'} the record layer owes every method "
          f"that frames with it ({len(shared['scenarios'])} cell(s), "
          f"{len(shared['rows'])} row(s))")
    wide = build_plan(root, ["crates/ferrox-app/src/proxy.rs"])
    untouched = [pin["name"] for pin in pins(root)
                 if pin.get("test_enabled") == "true" and pin.get("suite")]
    flags = output_flags(wide)
    ok = wide["scenarios"] == [] and wide["go_packages"] == WIDE_GO \
        and len(wide["rows"]) == wide["ops_all"] \
        and sorted(wide["suites"]) == sorted(untouched) \
        and all(wide["suites"][pin["name"]] == pin["suite"]
                for pin in pins(root) if pin["name"] in wide["suites"]) \
        and all(v == "true" for k, v in flags.items()
                if k in ("rust", "matrix", "suites", "go", "ops"))
    failed += 0 if ok else 1
    print(f"selftest: {'ok  ' if ok else 'FAIL'} a wide plan is the whole list "
          f"({len(wide['rows'])} row(s), suites {sorted(wide['suites'])})")
    # A job gated on `rust` must still run for the scheduled `--wide` plan, which
    # has an empty change list and so never sees a .rs path at all.
    scheduled = output_flags(build_plan(root, []))
    ok = scheduled["wide"] == "true" and scheduled["rust"] == "true"
    failed += 0 if ok else 1
    print(f"selftest: {'ok  ' if ok else 'FAIL'} --wide still owes the build "
          f"and its tests (rust={scheduled['rust']})")
    # The other half of that rule: a plan read off a real diff that moves no Rust
    # cannot move a test's outcome either, so three compilers are not owed.
    infra = output_flags(build_plan(root, [".github/workflows/ci.yml",
                                            "scripts/check-ci-scope.sh"]))
    ok = infra["wide"] == "true" and infra["rust"] == "false" \
        and infra["matrix"] == "true" and infra["ops"] == "true"
    failed += 0 if ok else 1
    print(f"selftest: {'ok  ' if ok else 'FAIL'} a wide plan that moves no Rust "
          f"does not owe the test matrix (rust={infra['rust']}, "
          f"matrix={infra['matrix']})")
    prose = output_flags(build_plan(root, ["docs/function/vmess.md"]))
    ok = prose["rust"] == "false" and prose["matrix"] == "true" \
        and prose["ops_rows"] == "2" and prose["go"] == "true"
    failed += 0 if ok else 1
    print(f"selftest: {'ok  ' if ok else 'FAIL'} a page edit owes the comparisons "
          f"but not the compiler (rust={prose['rust']}, cells={prose['cells']})")
    # An engine a page rules out is an engine the cell never builds, fetches or
    # probes; a page that says nothing keeps the tier's whole set.
    for label, changed, want in [
        ("a page's own plan carries only its proven comparators",
         ["crates/ferrox-app/src/vmess.rs"], ["xray-core", "zeronet"]),
        ("a page that declares nothing keeps every comparator",
         ["crates/ferrox-app/src/ws.rs"], []),
        ("a plan of both keeps every comparator",
         ["crates/ferrox-app/src/ws.rs", "crates/ferrox-app/src/vmess.rs"], []),
        ("a wide plan keeps every comparator", ["crates/ferrox-app/src/proxy.rs"], []),
    ]:
        got = build_plan(root, changed)["engines"]
        ok = got == want
        failed += 0 if ok else 1
        print(f"selftest: {'ok  ' if ok else 'FAIL'} {label} (engines={','.join(got)})")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="ci-scope",
                                     description="What CI has to measure for a change")
    sub = parser.add_subparsers(dest="command", required=True)
    scope = sub.add_parser("scope", help="plan from a diff and write " + PLAN)
    scope.add_argument("--base", help="diff this ref...HEAD")
    scope.add_argument("--changed-file", help="newline list of changed paths")
    scope.add_argument("--wide", action="store_true",
                       help="plan the whole set: a scheduled or manual run")
    scope.add_argument("--github-output", default=os.environ.get("GITHUB_OUTPUT", ""))
    scope.set_defaults(func=cmd_scope)
    sub.add_parser("rows", help="method-ops rows in scope, one filter per line"
                   ).set_defaults(func=cmd_rows)
    for key in LIST_KEYS:
        sub.add_parser(key.replace("_", "-"),
                       help=f"the plan's {key}").set_defaults(func=cmd_list, key=key)
    sub.add_parser("check", help="refuse a scope declaration that has drifted"
                   ).set_defaults(func=cmd_check)
    sub.add_parser("selftest", help="the planner's own fixtures").set_defaults(
        func=cmd_selftest)
    pin = sub.add_parser("suite", help="one pin's suite command, as scoped")
    pin.add_argument("pin")
    pin.set_defaults(func=cmd_suite)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
