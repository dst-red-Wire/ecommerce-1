#!/usr/bin/env python3
"""Bounded functional assertions for the six-node local RKE2 HA cluster."""

from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import tempfile
from pathlib import Path

KUBECTL = "/var/lib/rancher/rke2/bin/kubectl"
KUBECONFIG = "/etc/rancher/rke2/rke2.yaml"


def output(*args: str, input_text: str | None = None, timeout: int = 90) -> str:
    return subprocess.run(
        args,
        check=True,
        capture_output=True,
        text=True,
        input=input_text,
        timeout=timeout,
    ).stdout.strip()


def kubectl(kubeconfig: str, *args: str, input_text: str | None = None) -> str:
    return output(KUBECTL, "--kubeconfig", kubeconfig, *args, input_text=input_text)


def ha_kubeconfig(endpoint: str) -> str:
    source = Path(KUBECONFIG).read_text(encoding="utf-8")
    replaced, count = re.subn(
        r"(?m)^\s*server:\s*https://[^:]+:6443\s*$",
        f"    server: https://{endpoint}:6443",
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
    parser.add_argument("--phase", required=True, choices=("baseline", "degraded", "recovered"))
    parser.add_argument("--ha-endpoint", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--expected-node", action="append", default=[])
    parser.add_argument("--expected-ready-count", type=int, required=True)
    parser.add_argument("--expected-etcd-pods", type=int, required=True)
    parser.add_argument("--write-proof", action="store_true")
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9a-f]{40}", args.head_sha):
        raise SystemExit("invalid exact head SHA")
    tcp_probe(args.ha_endpoint, 9345)
    tcp_probe(args.ha_endpoint, 6443)
    config = ha_kubeconfig(args.ha_endpoint)
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
