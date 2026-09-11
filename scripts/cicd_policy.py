#!/usr/bin/env python3
import argparse, hashlib, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"^[a-z0-9./:_-]+@sha256:[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def components():
    import yaml

    d = yaml.safe_load((ROOT / "config/contracts/dependency-map.yaml").read_text())
    found = set()

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k in {"component", "name", "id"} and isinstance(v, str):
                    found.add(v)
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk(d)
    found.update({"storefront", "admin", "product"})
    return found


def component(value):
    if value not in components():
        raise ValueError(f"unknown component: {value}")


def context(value):
    p = Path(value)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError("unsafe build context")
    resolved = (ROOT / p).resolve()
    if ROOT not in resolved.parents and resolved != ROOT:
        raise ValueError("context escapes repository")


def digest(value):
    if not DIGEST.fullmatch(value):
        raise ValueError("immutable repository@sha256 digest required")


def sha(value):
    if not SHA.fullmatch(value):
        raise ValueError("full immutable Git SHA required")


def build(args):
    component(args.component)
    context(args.context)
    sha(args.sha)
    for value in (args.candidates, args.cache):
        if value.endswith(":latest") or "@sha256:" in value:
            raise ValueError("repository (not mutable tag or digest) required")
    if args.affected and args.component not in args.affected.split(","):
        raise ValueError("component is not affected")
    print(
        json.dumps(
            {
                "candidate": f"{args.candidates}/{args.component}:{args.sha}",
                "cache_import": f"{args.cache}/{args.component}",
                "cache_export": args.trusted_cache == "true",
                "deploy": False,
            },
            sort_keys=True,
        )
    )


def supply(args):
    component(args.component)
    sha(args.sha)
    digest(args.image)
    digest(args.runner)
    if args.scan != "pass":
        raise ValueError("blocking scan")
    if args.signature != "valid":
        raise ValueError("invalid signature")
    proof = json.loads(Path(args.provenance).read_text())
    required = {"git_sha", "repository", "component", "runner_digest", "build_inputs", "output_digest", "tool_versions"}
    if not required <= proof.keys():
        raise ValueError("incomplete provenance")
    if proof["git_sha"] != args.sha or proof["component"] != args.component or proof["output_digest"] != args.image:
        raise ValueError("provenance identity mismatch")
    print(
        json.dumps(
            {"qualified": True, "git_sha": args.sha, "component": args.component, "image": args.image}, sort_keys=True
        )
    )


def promote(args):
    import yaml

    component(args.component)
    sha(args.sha)
    digest(args.image)
    contract = yaml.safe_load((ROOT / "config/contracts/gitops-promotion.yaml").read_text())
    if args.environment not in contract["environments"]:
        raise ValueError("unknown environment")
    proof = json.loads(Path(args.proof).read_text())
    if (
        not proof.get("qualified")
        or proof.get("git_sha") != args.sha
        or proof.get("component") != args.component
        or proof.get("image") != args.image
    ):
        raise ValueError("unqualified or mismatched proof")
    allowed = contract["allowed_paths"][args.environment]
    if args.changed_path and args.changed_path != allowed:
        raise ValueError("GitOps modification outside promotion scope")
    print(json.dumps({"allowed_path": allowed, "image": args.image, "deploy": False, "merge": False}, sort_keys=True))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)
    b = sub.add_parser("buildkit-validate")
    for n in ["component", "context", "sha", "candidates", "cache"]:
        b.add_argument("--" + n, required=True)
    b.add_argument("--affected", default="")
    b.add_argument("--trusted-cache", choices=["true", "false"], default="false")
    b.set_defaults(run=build)
    q = sub.add_parser("supply-validate")
    for n in ["component", "sha", "image", "runner", "provenance"]:
        q.add_argument("--" + n, required=True)
    q.add_argument("--scan", choices=["pass", "fail"], required=True)
    q.add_argument("--signature", choices=["valid", "invalid"], required=True)
    q.set_defaults(run=supply)
    g = sub.add_parser("promote-validate")
    for n in ["component", "environment", "sha", "image", "proof"]:
        g.add_argument("--" + n, required=True)
    g.add_argument("--changed-path", default="")
    g.set_defaults(run=promote)
    a = p.parse_args()
    try:
        a.run(a)
    except ValueError as e:
        print(f"FAIL {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
