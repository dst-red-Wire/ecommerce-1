#!/usr/bin/env python3
"""Assert a functional single-node RKE2 server and emit bounded JSON evidence."""

import json
import socket
import subprocess

KUBECTL = "/var/lib/rancher/rke2/bin/kubectl"
KUBECONFIG = "/etc/rancher/rke2/rke2.yaml"


def output(*arguments: str) -> str:
    return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=60).stdout.strip()


def kubectl(*arguments: str) -> dict:
    return json.loads(output(KUBECTL, "--kubeconfig", KUBECONFIG, *arguments, "-o", "json"))


def main() -> None:
    nodes = kubectl("get", "nodes")["items"]
    if len(nodes) != 1:
        raise SystemExit("single-node fixture must expose exactly one node")
    conditions = {item["type"]: item["status"] for item in nodes[0]["status"]["conditions"]}
    if conditions.get("Ready") != "True":
        raise SystemExit("RKE2 node is not Ready")
    daemonsets = kubectl("get", "daemonsets", "--all-namespaces")["items"]
    cilium = [item for item in daemonsets if item["metadata"]["name"] == "cilium"]
    if len(cilium) != 1:
        raise SystemExit("canonical Cilium daemonset missing")
    status = cilium[0]["status"]
    if status.get("desiredNumberScheduled") != 1 or status.get("numberReady") != 1:
        raise SystemExit("Cilium daemonset is not Ready")
    deployments = kubectl("get", "deployments", "--all-namespaces")["items"]
    coredns = [item for item in deployments if item["metadata"]["name"] == "rke2-coredns-rke2-coredns"]
    if len(coredns) != 1 or coredns[0].get("status", {}).get("availableReplicas", 0) < 1:
        raise SystemExit("CoreDNS deployment is not Available")
    unavailable = [
        f"{item['metadata']['namespace']}/{item['metadata']['name']}"
        for item in deployments
        if item.get("spec", {}).get("replicas", 0) > 0
        and item.get("status", {}).get("availableReplicas", 0) < 1
    ]
    if unavailable:
        raise SystemExit("deployment has no available replica: " + ",".join(sorted(unavailable)))
    pods = kubectl("get", "pods", "--all-namespaces")["items"]
    failing = []
    pending = []
    for pod in pods:
        phase = pod.get("status", {}).get("phase")
        if phase == "Pending":
            pending.append(f"{pod['metadata']['namespace']}/{pod['metadata']['name']}")
        elif phase not in {"Running", "Succeeded"}:
            failing.append(f"{pod['metadata']['namespace']}/{pod['metadata']['name']}:{phase}")
    if failing:
        raise SystemExit("non-running pods: " + ",".join(sorted(failing)))
    public_error = None
    public_denied = False
    probe = socket.socket()
    probe.settimeout(2)
    try:
        probe.connect(("1.1.1.1", 443))
    except OSError as error:
        public_denied = True
        public_error = error.errno if error.errno is not None else type(error).__name__
    finally:
        probe.close()
    if not public_denied:
        raise SystemExit("public egress was not denied")
    print(json.dumps({
        "cilium_ready": status["numberReady"],
        "node": nodes[0]["metadata"]["name"],
        "node_ready": True,
        "pending_pods": sorted(pending),
        "pod_count": len(pods),
        "public_connect_error": public_error,
        "rke2_version": output("/usr/local/bin/rke2", "--version").splitlines()[0],
        "selinux": output("getenforce"),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
