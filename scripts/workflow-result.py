#!/usr/bin/env python3
"""Publish one workflow run as a human- and machine-readable result.

Every workflow ends with a `result` job that passes its `needs` context here.
The script writes `result.md` and `result.json`, appends the markdown to the
job summary, and the composite action uploads the two files as a small
artifact. A reader gets a status table; an LLM gets the same facts as JSON.
"""

import argparse
import json
import os
from pathlib import Path

SCHEMA = "ferrox.workflow-result.v1"


def load_jobs(raw):
    try:
        needs = json.loads(raw or "{}")
    except ValueError:
        needs = {}
    if not isinstance(needs, dict):
        return []
    jobs = []
    for name in sorted(needs):
        value = needs[name]
        if isinstance(value, dict):
            jobs.append(
                {
                    "job": name,
                    "result": value.get("result", "unknown"),
                    "outputs": value.get("outputs", {}),
                }
            )
        else:
            jobs.append({"job": name, "result": str(value), "outputs": {}})
    return jobs


def verdict(jobs, explicit):
    if explicit:
        return explicit
    results = {job["result"] for job in jobs}
    for state in ("failure", "cancelled", "timed_out", "action_required"):
        if state in results:
            return "failure" if state != "cancelled" else "cancelled"
    if results and all(result == "skipped" for result in results):
        return "skipped"
    if "success" in results:
        return "success"
    return "unknown"


def env(name, default=""):
    return os.environ.get(name, default)


def build(args):
    jobs = load_jobs(args.needs)
    status = verdict(jobs, args.status)
    run_id = env("GITHUB_RUN_ID", "?")
    server = env("GITHUB_SERVER_URL", "https://github.com")
    repo = env("GITHUB_REPOSITORY", "?")
    run_url = f"{server}/{repo}/actions/runs/{run_id}"
    artifacts = [name.strip() for name in args.artifacts.split(",") if name.strip()]
    summary = Path(args.summary).read_text() if args.summary and Path(args.summary).is_file() else ""
    data = None
    if args.data and Path(args.data).is_file():
        try:
            data = json.loads(Path(args.data).read_text())
        except ValueError:
            data = None
    document = {
        "schema": SCHEMA,
        "workflow": args.title or env("GITHUB_WORKFLOW", "?"),
        "status": status,
        "run": {
            "id": run_id,
            "attempt": env("GITHUB_RUN_ATTEMPT", "1"),
            "url": run_url,
        },
        "event": env("GITHUB_EVENT_NAME", "?"),
        "ref": env("GITHUB_REF", "?"),
        "sha": env("GITHUB_SHA", "?"),
        "repository": repo,
        "jobs": jobs,
        "artifacts": artifacts,
        "summary_markdown": summary,
        "data": data,
    }
    return document


def markdown(document):
    lines = [
        f"## Result — {document['workflow']}",
        "",
        f"**{document['status']}** · [run {document['run']['id']}]({document['run']['url']}) · "
        f"`{document['event']}` on `{document['ref']}` (`{document['sha'][:12]}`)",
        "",
    ]
    if document["jobs"]:
        lines += ["| job | result |", "| --- | --- |"]
        lines += [f"| `{job['job']}` | {job['result']} |" for job in document["jobs"]]
        lines.append("")
    if document["artifacts"]:
        lines += ["Artifacts: " + ", ".join(f"`{name}`" for name in document["artifacts"]), ""]
    if document["summary_markdown"]:
        lines += [document["summary_markdown"].rstrip(), ""]
    machine = {
        "schema": document["schema"],
        "workflow": document["workflow"],
        "status": document["status"],
        "run": document["run"],
        "event": document["event"],
        "ref": document["ref"],
        "sha": document["sha"],
        "jobs": document["jobs"],
        "artifacts": document["artifacts"],
    }
    lines += [
        "<details><summary>Machine-readable result</summary>",
        "",
        "```json",
        json.dumps(machine, indent=2, sort_keys=True),
        "```",
        "",
        "</details>",
        "",
    ]
    return "\n".join(lines)


def selftest():
    jobs = load_jobs('{"plan":{"result":"success"},"test":{"result":"skipped"}}')
    assert verdict(jobs, "") == "success"
    assert verdict(load_jobs('{"test":{"result":"failure"}}'), "") == "failure"
    assert verdict(load_jobs('{"test":{"result":"cancelled"}}'), "") == "cancelled"
    assert verdict([], "") == "unknown"
    document = {
        "schema": SCHEMA,
        "workflow": "selftest",
        "status": "success",
        "run": {"id": "1", "attempt": "1", "url": "https://example.invalid/1"},
        "event": "workflow_dispatch",
        "ref": "refs/heads/main",
        "sha": "0" * 40,
        "repository": "example/ferrox",
        "jobs": jobs,
        "artifacts": ["table"],
        "summary_markdown": "one line",
        "data": None,
    }
    text = markdown(document)
    assert "**success**" in text and "`test`" in text and "`table`" in text
    assert '"schema": "ferrox.workflow-result.v1"' in text
    print("workflow-result: selftest ok")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true", help="check the result rules")
    parser.add_argument("--title", default="", help="workflow name shown in the heading")
    parser.add_argument("--needs", default="", help="toJSON(needs) from the result job")
    parser.add_argument("--status", default="", help="override the status derived from jobs")
    parser.add_argument("--summary", default="", help="markdown file to include before the JSON")
    parser.add_argument("--data", default="", help="JSON file to include in result.json")
    parser.add_argument("--artifacts", default="", help="comma-separated artifact names to name")
    parser.add_argument("--out", default="result", help="output directory (default: result)")
    parser.add_argument("--no-summary", action="store_true", help="do not append to the job summary")
    args = parser.parse_args(argv)
    if args.selftest:
        return selftest()

    document = build(args)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    text = markdown(document)
    (out / "result.md").write_text(text)
    (out / "result.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    if not args.no_summary:
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a") as handle:
                handle.write(text + "\n")
    print(f"result: {document['status']} ({', '.join(job['job'] for job in document['jobs'])})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
