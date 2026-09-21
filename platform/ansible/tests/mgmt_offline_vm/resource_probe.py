#!/usr/bin/env python3
"""Report resources from the isolated Rocky guest after a VM restart."""

import json
import os
import subprocess
from pathlib import Path


def main() -> None:
    enforcing = subprocess.check_output(["getenforce"], text=True).strip()
    if enforcing != "Enforcing":
        raise SystemExit(f"SELinux must be Enforcing, got {enforcing!r}")
    memory_kib = int(Path("/proc/meminfo").read_text(encoding="utf-8").splitlines()[0].split()[1])
    print(
        json.dumps(
            {
                "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip(),
                "memory_kib": memory_kib,
                "online_cpus": os.cpu_count(),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
