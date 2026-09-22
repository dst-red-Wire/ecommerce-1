#!/usr/bin/env python3
"""Bounded functional assertions for the six-node local RKE2 HA cluster."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import tempfile
from pathlib import Path

KUBECTL = "/var/lib/rancher/rke2/bin/kubectl"
KUBECONFIG = "/etc/rancher/rke2/rke2.yaml"


def output(
    *args: str,
    input_text: str | None = None,
    timeout: int = 90,
    env: dict[str, str] | None = None,
) -> str:
    return subprocess.run(
        args,
        check=True,
        capture_output=True,
        text=True,
        input=input_text,
        timeout=timeout,
        env=env,
    ).stdout.strip()


def kubectl(kubeconfig: str, *args: str, input_text: str | None = None) -> str:
    return output(KUBECTL, "--kubeconfig", kubeconfig, *args, input_text=input_text)


def ha_kubeconfig(endpoint: str, api_port: int) -> str:
    source = Path(KUBECONFIG).read_text(encoding="utf-8")
    replaced, count = re.subn(
        r"(?m)^\s*server:\s*https://[^:]+:[0-9]+\s*$",
        f"    server: https://{endpoint}:{api_port}",
        source,
        count=1,
    )
    if count != 1:
        raise RuntimeError("could not rewrite RKE2 kubeconfig server endpoint")
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
    try:
        handle.write(replaced)
        handle.flush()
    finally:
        handle.close()
    Path(handle.name).chmod(0o600)
    return handle.name


def tcp_probe(address: str, port: int) -> None:
    sock = socket.create_connection((address, port), timeout=5)
    sock.close()


def ready_nodes(kubeconfig: str) -> tuple[list[str], dict[str, bool]]:
    nodes = json.loads(kubectl(kubeconfig, "get", "nodes", "-o", "json"))["items"]
    readiness: dict[str, bool] = {}
    for node in nodes:
        conditions = {
            item["type"]: item["status"]
            for item in node.get("status", {}).get("conditions", [])
        }
        readiness[node["metadata"]["name"]] = conditions.get("Ready") == "True"
    return sorted(readiness), readiness


def cilium_status(kubeconfig: str) -> tuple[int, int]:
    data = json.loads(
        kubectl(
            kubeconfig,
            "get",
            "daemonset",
            "cilium",
            "-n",
            "kube-system",
            "-o",
            "json",
        )
    )
    status = data.get("status", {})
    return int(status.get("desiredNumberScheduled", 0)), int(status.get("numberReady", 0))


def etcd_pods(kubeconfig: str) -> list[str]:
    pods = json.loads(
        kubectl(
            kubeconfig,
            "get",
            "pods",
            "-n",
            "kube-system",
            "-l",
            "component=etcd",
            "-o",
            "json",
        )
    )["items"]
    running = [
        item["metadata"]["name"]
        for item in pods
        if item.get("status", {}).get("phase") == "Running"
    ]
    return sorted(running)


def active_etcdctl() -> str:
    candidates: set[Path] = set()
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if (proc / "comm").read_text(encoding="utf-8").strip() != "etcd":
                continue
            executable = Path(os.readlink(proc / "exe"))
        except (FileNotFoundError, OSError, PermissionError):
            continue
        candidate = executable.with_name("etcdctl")
        if candidate.is_file() and os.access(candidate, os.X_OK):
            candidates.add(candidate)
    if len(candidates) != 1:
        raise RuntimeError(
            f"expected one etcdctl beside the active etcd binary, found {len(candidates)}"
        )
    return str(next(iter(candidates)))


def _json_output(raw: str, operation: str) -> object:
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"etcdctl {operation} did not return JSON") from exc


def local_etcd_status(expected_members: int) -> dict:
    etcdctl = active_etcdctl()
    common = (
        etcdctl,
        "--endpoints=https://127.0.0.1:2379",
        "--cacert=/var/lib/rancher/rke2/server/tls/etcd/server-ca.crt",
        "--cert=/var/lib/rancher/rke2/server/tls/etcd/server-client.crt",
        "--key=/var/lib/rancher/rke2/server/tls/etcd/server-client.key",
    )
    environment = dict(os.environ, ETCDCTL_API="3")
    members_payload = _json_output(
        output(*common, "member", "list", "--write-out=json", env=environment),
        "member list",
    )
    if not isinstance(members_payload, dict):
        raise RuntimeError("etcdctl member list JSON must be an object")
    members = members_payload.get("members", [])
    if not isinstance(members, list) or len(members) != expected_members:
        count = len(members) if isinstance(members, list) else "invalid"
        raise RuntimeError(f"etcd member count mismatch: {count} != {expected_members}")

    health_payload = _json_output(
        output(*common, "endpoint", "health", "--write-out=json", env=environment),
        "endpoint health",
    )
    health = health_payload if isinstance(health_payload, list) else [health_payload]
    if not health or not all(
        isinstance(item, dict) and item.get("health") is True for item in health
    ):
        raise RuntimeError("local etcd endpoint is not healthy")

    alarms_payload = _json_output(
        output(*common, "alarm", "list", "--write-out=json", env=environment),
        "alarm list",
    )
    if isinstance(alarms_payload, dict):
        alarms = alarms_payload.get("alarms", [])
    elif isinstance(alarms_payload, list):
        alarms = alarms_payload
    else:
        raise RuntimeError("etcdctl alarm list JSON has an invalid shape")
    if not isinstance(alarms, list):
        raise RuntimeError("etcdctl alarm list must contain an alarms list")
    if alarms:
        raise RuntimeError(f"blocking etcd alarms present: {len(alarms)}")

    return {
        "member_count": len(members),
        "member_ids": sorted(str(member.get("ID", "")) for member in members),
        "local_endpoint_healthy": True,
        "alarms": [],
    }


def write_quorum_proof(kubeconfig: str, head_sha: str) -> dict:
    name = "rke2-ha-quorum-proof"
    manifest = kubectl(
        kubeconfig,
        "create",
        "configmap",
        name,
        "--from-literal",
        f"head_sha={head_sha}",
        "--from-literal",
        "quorum=survived-one-control-plane-loss",
        "--dry-run=client",
        "-o",
        "json",
    )
    kubectl(kubeconfig, "apply", "-f", "-", input_text=manifest)
    payload = json.loads(kubectl(kubeconfig, "get", "configmap", name, "-o", "json"))
    data = payload.get("data", {})
    if data.get("head_sha") != head_sha or data.get("quorum") != "survived-one-control-plane-loss":
        raise RuntimeError("HA endpoint write/read quorum proof failed")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("baseline", "degraded", "recovered"))
    parser.add_argument("--ha-endpoint")
    parser.add_argument("--registration-port", type=int)
    parser.add_argument("--api-port", type=int)
    parser.add_argument("--head-sha")
    parser.add_argument("--expected-node", action="append", default=[])
    parser.add_argument("--expected-ready-count", type=int)
    parser.add_argument("--expected-etcd-pods", type=int)
    parser.add_argument("--write-proof", action="store_true")
    parser.add_argument("--etcd-local-only", action="store_true")
    parser.add_argument("--expected-etcd-members", type=int, default=3)
    args = parser.parse_args()

    if args.etcd_local_only:
        print(json.dumps(local_etcd_status(args.expected_etcd_members), sort_keys=True))
        return 0
    if (
        args.phase is None
        or args.ha_endpoint is None
        or args.head_sha is None
        or args.registration_port is None
        or args.api_port is None
        or args.expected_ready_count is None
        or args.expected_etcd_pods is None
    ):
        parser.error("cluster mode requires phase, endpoint, SHA, ready count, and etcd pods")
    if not re.fullmatch(r"[0-9a-f]{40}", args.head_sha):
        raise SystemExit("invalid exact head SHA")
    tcp_probe(args.ha_endpoint, args.registration_port)
    tcp_probe(args.ha_endpoint, args.api_port)
    config = ha_kubeconfig(args.ha_endpoint, args.api_port)
    try:
        readyz = kubectl(config, "get", "--raw=/readyz")
        if readyz.strip() != "ok":
            raise RuntimeError("Kubernetes HA endpoint is not ready")
        nodes, readiness = ready_nodes(config)
        ready_count = sum(1 for value in readiness.values() if value)
        if ready_count < args.expected_ready_count:
            raise RuntimeError(
                f"ready nodes below expectation: {ready_count} < {args.expected_ready_count}"
            )
        missing = sorted(set(args.expected_node) - set(nodes))
        if missing:
            raise RuntimeError("expected nodes missing: " + ",".join(missing))
        desired, cilium_ready = cilium_status(config)
        if args.phase != "degraded":
            if desired != len(args.expected_node) or cilium_ready != len(args.expected_node):
                raise RuntimeError(
                    f"Cilium not ready on all nodes: desired={desired} ready={cilium_ready}"
                )
        etcd = etcd_pods(config)
        if args.phase != "degraded" and len(etcd) != args.expected_etcd_pods:
            raise RuntimeError(
                f"running etcd pod count mismatch: {len(etcd)} != {args.expected_etcd_pods}"
            )
        proof = write_quorum_proof(config, args.head_sha) if args.write_proof else None
        print(
            json.dumps(
                {
                    "phase": args.phase,
                    "ha_endpoint": args.ha_endpoint,
                    "registration_port": args.registration_port,
                    "api_port": args.api_port,
                    "api_ready": True,
                    "nodes": nodes,
                    "ready_nodes": sorted(name for name, ready in readiness.items() if ready),
                    "ready_count": ready_count,
                    "cilium_desired": desired,
                    "cilium_ready": cilium_ready,
                    "etcd_running_pods": etcd,
                    "quorum_write": proof,
                },
                sort_keys=True,
            )
        )
    finally:
        Path(config).unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
