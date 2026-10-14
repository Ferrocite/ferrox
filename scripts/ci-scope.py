#!/usr/bin/env python3
"""Plan what CI has to measure from what a change actually touches.

`docs/function/<method>.md` is the registry. Each page declares the source files
that trigger it (`paths`) and the work its change owes: matrix scenario ids
(`scenarios`), upstream oracle test names (`oracle`), reference packages (`go`).
A changed file no page owns is shared code, and shared code owes the whole
matrix, so the plan is wide and every job runs exactly as it did before.

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
SCOPE_KEYS = ("paths", "scenarios", "oracle", "go")
LIST_KEYS = ("methods", "scenarios", "go_packages", "suites_skipped")


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


def classify(changed: list[str], scopes: dict[str, dict[str, list[str]]]) -> dict:
    """Which methods a diff touches, or why it touches everything."""
    methods: set[str] = set()
    unclaimed: set[str] = set()
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
        if path.startswith("crates/") and path.endswith(".rs"):
            owners = [name for name, scope in scopes.items()
                      if any(fnmatch.fnmatch(path, g) for g in scope.get("paths", []))]
            if len(owners) == 1:
                methods.add(owners[0])
                continue
            unclaimed.add(path)
            if len(owners) > 1:
                shared = f"{path} is claimed by {' and '.join(sorted(owners))}"
            elif not shared:
                shared = f"{path} is claimed by no method page"
            continue
        if path.startswith(("scripts/", ".github/", "upstream/", "crates/")) \
                or path in ("Cargo.toml", "Cargo.lock"):
            shared = shared or f"{path} is shared infrastructure"
            continue
    wide = bool(unclaimed) or bool(shared)
    reason = shared or ("" if methods else "nothing a method page owns")
    return {"wide": wide, "reason": reason, "methods": sorted(methods),
            "unclaimed": sorted(unclaimed), "rust": rust or tool}


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
    for name in sorted(scopes) if selected is None else selected:
        scope = scopes[name]
        patterns += scope.get("oracle", [])
        wanted += scope.get("scenarios", [])
        packages += scope.get("go", [])
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


def build_plan(root: str, changed: list[str]) -> dict:
    scopes = pages(root)
    plan = classify(changed, scopes)
    measure(root, scopes, plan)
    return plan


def changed_from(root: str, base: str) -> list[str]:
    out = subprocess.run(["git", "diff", "--name-only", f"{base}...HEAD"],
                         capture_output=True, text=True, cwd=root)
    if out.returncode != 0:
        sys.exit(f"ci-scope: git diff against {base} failed: {out.stderr.strip()}")
    return [line for line in out.stdout.splitlines() if line.strip()]


def output_flags(plan: dict) -> dict[str, str]:
    """The job-level `if:` answers. A wide plan is true for every one of them,
    including `rust`: a scheduled or manual run has no diff to narrow on, so it
    owes the build and the tests like any shared change does."""
    return {
        "wide": "true" if plan["wide"] else "false",
        "rust": "true" if plan["wide"] or plan["rust"] else "false",
        "methods": ",".join(plan["methods"]),
        "cells": ",".join(plan["scenarios"]),
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
        ("matrix", cells),
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
    if args.wide:
        changed: list[str] = []
    elif args.changed_file:
        changed = [line.strip() for line in open(args.changed_file, encoding="utf-8")
                   if line.strip()]
    else:
        if not args.base:
            sys.exit("ci-scope: scope wants --base, --changed-file or --wide")
        changed = changed_from(root, args.base)
    plan = build_plan(root, changed)
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


def validate(root: str) -> tuple[list[str], list[str]]:
    scopes = pages(root)
    fails: list[str] = []
    notes: list[str] = []
    claimed: dict[str, str] = {}
    for name, scope in sorted(scopes.items()):
        if not scope:
            fails.append(f"{name}.md: no <!-- scope:begin --> block")
            continue
        if not scope.get("paths"):
            fails.append(f"{name}.md: scope declares no paths: line")
        for value in scope.get("paths", []):
            if value == OWNED_NOWHERE:
                notes.append(f"{name}.md: no file of its own, so its source changes "
                             "plan a wide run")
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
    unowned = [os.path.relpath(path, root)
               for path in glob.glob(os.path.join(root, "crates", "*", "src", "**",
                                                  "*.rs"), recursive=True)
               if os.path.relpath(path, root) not in claimed
               and not os.path.relpath(path, root).startswith(TOOL)]
    if unowned:
        notes.append(f"{len(unowned)} source file(s) no page owns, so their changes "
                     f"plan a wide run: {', '.join(sorted(unowned))}")
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
          f"{len(query_plan(root)['rows'])} row(s) in the wide plan")
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
    ok = plan["scenarios"] == ["vmess-raw-down-8"] and len(plan["rows"]) == 2 \
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
    prose = output_flags(build_plan(root, ["docs/function/vmess.md"]))
    ok = prose["rust"] == "false" and prose["matrix"] == "true" \
        and prose["ops_rows"] == "2" and prose["go"] == "true"
    failed += 0 if ok else 1
    print(f"selftest: {'ok  ' if ok else 'FAIL'} a page edit owes the comparisons "
          f"but not the compiler (rust={prose['rust']}, cells={prose['cells']})")
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
