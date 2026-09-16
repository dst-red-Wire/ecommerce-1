#!/usr/bin/env python3
"""Low-cost GitHub PR watcher that wakes Codex only for meaningful deltas."""

from __future__ import annotations
import argparse, json, os, shlex, subprocess, sys, time
from pathlib import Path
from typing import Any
import urllib.error, urllib.request

GRAPHQL_QUERY = """query PRMonitor($owner:String!,$repo:String!,$number:Int!){repository(owner:$owner,name:$repo){pullRequest(number:$number){state merged mergeable reviewDecision updatedAt headRefOid reviews(last:100){nodes{id state submittedAt author{login}}} reviewThreads(first:100){nodes{id isResolved comments(last:1){nodes{id updatedAt path author{login}}}}} commits(last:1){nodes{commit{statusCheckRollup{contexts(first:100){nodes{... on CheckRun{id name status conclusion} ... on StatusContext{id context state}}}}}}}}}}"""


def github_request(url: str, token: str, *, body: bytes | None = None, etag: str = "") -> tuple[int, Any, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "ecommerce-pr-monitor/1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if etag:
        headers["If-None-Match"] = etag
    request = urllib.request.Request(url, data=body, headers=headers, method="POST" if body else "GET")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.loads(response.read()), response.headers.get("ETag", etag)
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return 304, None, etag
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"GitHub returned HTTP {exc.code}: {detail}") from exc


def snapshot(pr: dict[str, Any], *, etag: str, timestamp: int) -> dict[str, Any]:
    nodes = (pr.get("commits") or {}).get("nodes") or []
    rollup = ((nodes[-1].get("commit") or {}).get("statusCheckRollup") or {}) if nodes else {}
    checks = {}
    for check in (rollup.get("contexts") or {}).get("nodes") or []:
        key = str(check.get("id") or check.get("name") or check.get("context"))
        checks[key] = str(check.get("conclusion") or check.get("status") or check.get("state") or "UNKNOWN")
    reviews = {
        str(r["id"]): {
            "state": r.get("state"),
            "submitted_at": r.get("submittedAt"),
            "author": (r.get("author") or {}).get("login"),
        }
        for r in ((pr.get("reviews") or {}).get("nodes") or [])
    }
    findings = {}
    for thread in (pr.get("reviewThreads") or {}).get("nodes") or []:
        if thread.get("isResolved"):
            continue
        comments = (thread.get("comments") or {}).get("nodes") or [{}]
        comment = comments[-1]
        findings[str(thread["id"])] = {
            "comment_id": comment.get("id"),
            "updated_at": comment.get("updatedAt"),
            "path": comment.get("path"),
            "author": (comment.get("author") or {}).get("login"),
        }
    return {
        "head_sha": pr.get("headRefOid"),
        "checks": checks,
        "review_decision": pr.get("reviewDecision"),
        "reviews": reviews,
        "open_findings_count": len(findings),
        "open_findings": findings,
        "mergeable": pr.get("mergeable"),
        "state": pr.get("state"),
        "merged": bool(pr.get("merged")),
        "github_updated_at": pr.get("updatedAt"),
        "polled_at": timestamp,
        "etag": etag,
    }


MEANINGFUL = (
    "head_sha",
    "checks",
    "review_decision",
    "reviews",
    "open_findings_count",
    "open_findings",
    "mergeable",
    "state",
    "merged",
)


def meaningful(state):
    return {key: state.get(key) for key in MEANINGFUL}


def delta(previous, current):
    return {
        key: {"before": previous.get(key), "after": value}
        for key, value in meaningful(current).items()
        if previous.get(key) != value
    }


def changed_files(owner, repo, old, new, token):
    if not old or not new or old == new:
        return []
    _, payload, _ = github_request(f"https://api.github.com/repos/{owner}/{repo}/compare/{old}...{new}", token)
    return [item["filename"] for item in payload.get("files", []) if item.get("filename")]


def codex_prompt(number, previous, current, changes, files):
    instruction = "Incremental PR review only. Do not reload PR history or repeat the full audit. Reuse the previous validated verdict and findings. Read only changed_files and run only related validations. Return exactly five lines: PR #<number>; HEAD : <old> → <new or unchanged>; CHANGEMENT : <delta>; VERDICT : READY | BLOCKED | WAITING; ACTION : <one next action>.\n"
    return instruction + json.dumps(
        {
            "pr": number,
            "previous_validated": meaningful(previous),
            "delta": changes,
            "current_head": current.get("head_sha"),
            "changed_files": files,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def invoke_codex(command, prompt):
    if not command:
        print("CHANGE_DETECTED", flush=True)
        return
    subprocess.run(command, input=prompt, text=True, check=True)


def next_interval(unchanged, minimum, maximum):
    if unchanged >= 8:
        return min(3600, maximum)
    if unchanged >= 4:
        return min(1800, maximum)
    return min(minimum, maximum)


def poll_once(args, state_path, token):
    previous = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    body = json.dumps(
        {"query": GRAPHQL_QUERY, "variables": {"owner": args.owner, "repo": args.repo, "number": args.pr}}
    ).encode()
    status, payload, etag = github_request(
        "https://api.github.com/graphql", token, body=body, etag=previous.get("etag", "")
    )
    if status == 304:
        unchanged = int(previous.get("unchanged_polls", 0)) + 1
        previous["unchanged_polls"] = unchanged
        previous["polled_at"] = int(time.time())
        state_path.write_text(json.dumps(previous, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("NO_CHANGE", flush=True)
        return False, unchanged
    if payload.get("errors"):
        raise RuntimeError(f"GitHub GraphQL error: {payload['errors']}")
    pr = payload["data"]["repository"]["pullRequest"]
    if pr is None:
        raise RuntimeError(f"pull request #{args.pr} not found")
    current = snapshot(pr, etag=etag, timestamp=int(time.time()))
    changes = delta(previous, current) if previous else {}
    unchanged = 0 if changes else int(previous.get("unchanged_polls", 0)) + 1
    current["unchanged_polls"] = unchanged
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if previous and changes:
        files = changed_files(args.owner, args.repo, previous.get("head_sha", ""), current.get("head_sha", ""), token)
        invoke_codex(args.codex_command, codex_prompt(args.pr, previous, current, changes, files))
    else:
        print("NO_CHANGE", flush=True)
    return current["merged"] or current["state"] != "OPEN" or args.abandoned, unchanged


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--interval", type=int, default=900)
    parser.add_argument("--max-interval", type=int, default=3600)
    parser.add_argument("--state")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--abandoned", action="store_true")
    parser.add_argument("--codex-command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.interval < 1 or args.max_interval < args.interval:
        parser.error("intervals must satisfy 1 <= --interval <= --max-interval")
    if args.codex_command is None:
        args.codex_command = shlex.split(os.environ.get("PR_MONITOR_CODEX_COMMAND", ""))
    return args


def main():
    args = parse_args()
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("GITHUB_TOKEN is required", file=sys.stderr)
        return 2
    state_path = Path(args.state or f".context/pr-monitor/pr-{args.pr}.json")
    while True:
        terminal, unchanged = poll_once(args, state_path, token)
        if terminal or args.once:
            return 0
        time.sleep(next_interval(unchanged, args.interval, args.max_interval))


if __name__ == "__main__":
    raise SystemExit(main())
