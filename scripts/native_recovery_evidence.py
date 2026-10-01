"""Derive native host recovery proof from protected runner observations only."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

try:
    from . import m25_runtime_evidence as m25, rocky_box_catalog
except ImportError:
    import m25_runtime_evidence as m25
    import rocky_box_catalog

OUTPUT = Path(".context/evidence/native-recovery/current.json")
PRODUCER = "scripts/native_recovery_evidence.py:validate"
SHADOW_ROOT = m25.SHADOW_ROOT
WINDOWS_ROOT = m25.SHADOW_WINDOWS_ROOT
CAMPAIGN = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}")
SHA = re.compile(r"[0-9a-f]{40}")
GUID = r"\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}"
TASK_NAMES = (
    "Ecommerce-Network-Smoke-Native-Resume",
    "Ecommerce-Network-Smoke-Native-Watchdog",
    "Ecommerce-Network-Smoke-Native-S4U-Probe",
)
MAX_JSON = 16 * 1024 * 1024
MAX_AGE = 86400


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError("native recovery: " + reason)


def _unique(pairs):
    value = {}
    for name, item in pairs:
        _require(name not in value, "duplicate JSON key")
        value[name] = item
    return value


def _nonfinite(_value):
    raise ValueError("native recovery: nonfinite JSON value")


def _json(data: bytes) -> dict:
    value = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique,
                       parse_constant=_nonfinite)
    _require(isinstance(value, dict), "observation is not an object")
    return value


def _epoch(value) -> float:
    _require(isinstance(value, str) and len(value) <= 40, "timestamp missing")
    instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _require(instant.tzinfo is not None and instant.utcoffset().total_seconds() == 0,
             "timestamp is not UTC")
    return instant.timestamp()


def _identity(info) -> tuple:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _ProtectedFiles:
    """Read regular single-link files and rehash the same inodes after validation."""

    def __init__(self, shadow: Path):
        self.shadow = shadow
        self.files: dict[str, tuple[str, tuple]] = {}

    def path(self, relative: str) -> Path:
        _require(isinstance(relative, str) and
                 re.fullmatch(r"[A-Za-z0-9._/-]+", relative) is not None and
                 not relative.startswith("/") and
                 all(part not in {"", ".", ".."} for part in relative.split("/")),
                 "protected relative path is invalid")
        _require(SHADOW_ROOT.is_dir() and not SHADOW_ROOT.is_symlink(),
                 "protected root absent or redirected")
        current = SHADOW_ROOT
        for part in (self.shadow.name, *relative.split("/")):
            current /= part
            info = current.lstat()
            _require(not stat.S_ISLNK(info.st_mode), "protected path is a symlink")
        _require(current.resolve(strict=True).is_relative_to(
            SHADOW_ROOT.resolve(strict=True)), "protected path escapes its root")
        return current

    def read(self, relative: str, *, binary: bool = False) -> bytes | str:
        path = self.path(relative)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(descriptor)
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                     "protected file is not regular or has multiple links")
            maximum = 64 * 1024 ** 3 if relative == "box/source.box" else MAX_JSON
            _require(0 < before.st_size <= maximum, "observation exceeds size bound")
            deadline = time.monotonic() + (1800 if relative == "box/source.box" else 60)
            total = 0
            digest = hashlib.sha256()
            chunks = [] if not binary else None
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    total += len(chunk)
                    _require(total <= before.st_size and time.monotonic() <= deadline,
                             "file grew or read exceeded its bound")
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
            after = os.fstat(descriptor)
            _require(_identity(before) == _identity(after), "file changed while reading")
        finally:
            os.close(descriptor)
        item = (digest.hexdigest(), _identity(after))
        _require(relative not in self.files or self.files[relative] == item,
                 "file changed during validation")
        self.files[relative] = item
        return item[0] if binary else b"".join(chunks)

    def json(self, relative: str) -> dict:
        return _json(self.read(relative))

    def verify_unchanged(self) -> None:
        for relative in list(self.files):
            self.read(relative, binary=True)

    def refs(self) -> dict:
        return {name: value[0] for name, value in sorted(self.files.items())}


# This observer reads filesystem metadata only. It never elevates or touches BCD,
# tasks, VM configuration, credentials, or the contents of a private key.
_BOUNDARY_SCRIPT = r"""
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$env:PSModulePath='C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
$requested=@(ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd()))
$root='C:\Program Files\EcommerceNativeSmoke'
$admins=@('S-1-5-18','S-1-5-32-544')
$danger=[int][Security.AccessControl.FileSystemRights]::WriteData -bor
 [int][Security.AccessControl.FileSystemRights]::AppendData -bor
 [int][Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
 [int][Security.AccessControl.FileSystemRights]::WriteAttributes -bor
 [int][Security.AccessControl.FileSystemRights]::Delete -bor
 [int][Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
 [int][Security.AccessControl.FileSystemRights]::ChangePermissions -bor
 [int][Security.AccessControl.FileSystemRights]::TakeOwnership
$paths=@{}
foreach($file in $requested) {
 $path=[IO.Path]::GetFullPath([string]$file)
 if(-not $path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){
  throw 'Recovery file escapes protected root'
 }
 while($path.Length -ge $root.Length){
  $paths[$path]=$true
  if($path -ieq $root){break}
  $path=Split-Path -Parent $path
 }
}
foreach($parent in @('C:\','C:\Program Files')){
 $item=Get-Item -LiteralPath $parent -Force
 if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
  throw 'Protected ancestor is redirected'
 }
 $acl=Get-Acl -LiteralPath $parent
 $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
 if($owner -notin $admins -and $owner -notmatch '^S-1-5-80-'){
  throw 'Protected ancestor has an unprivileged owner'
 }
 $parentDanger=[int][Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
  [int][Security.AccessControl.FileSystemRights]::Delete -bor
  [int][Security.AccessControl.FileSystemRights]::ChangePermissions -bor
  [int][Security.AccessControl.FileSystemRights]::TakeOwnership
 if($parent -eq 'C:\Program Files'){$parentDanger=$danger}
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  if($rule.AccessControlType -eq 'Allow' -and
     ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
     [string]$rule.IdentityReference -notin $admins -and
     [string]$rule.IdentityReference -notmatch '^S-1-5-80-' -and
     ([int]$rule.FileSystemRights -band $parentDanger) -ne 0){
   throw 'Protected ancestor permits unprivileged deletion'
  }
 }
}
$result=@()
foreach($path in @($paths.Keys|Sort-Object)){
 $item=Get-Item -LiteralPath $path -Force
 if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
  throw 'Protected path is redirected'
 }
 $acl=Get-Acl -LiteralPath $path
 $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
 if($owner -notin $admins -or -not $acl.AreAccessRulesProtected){
  throw 'Protected ownership or inheritance differs'
 }
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  if($rule.AccessControlType -eq 'Allow' -and
     [string]$rule.IdentityReference -notin $admins -and
     ([int]$rule.FileSystemRights -band $danger) -ne 0){
   throw 'Protected path permits unprivileged mutation'
  }
 }
 $result+=@{path=$path;owner=$owner;sddl=$acl.Sddl;attributes=[int]$item.Attributes}
}
ConvertTo-Json -InputObject @($result) -Depth 5 -Compress
"""


def _protected_boundary(files: _ProtectedFiles) -> list:
    _require(bool(files.files), "protected file inventory is empty")
    paths = [str(WINDOWS_ROOT / files.shadow.name / PureWindowsPath(relative))
             for relative in sorted(files.files)]
    encoded = base64.b64encode(_BOUNDARY_SCRIPT.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        ["/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
         "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        input=json.dumps(paths), text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=60,
        check=False,
    )
    _require(result.returncode == 0, "protected ACL or redirection check failed")
    value = json.loads(result.stdout, object_pairs_hook=_unique, parse_constant=_nonfinite)
    _require(isinstance(value, list) and len(value) >= len(paths),
             "protected boundary observer returned incomplete data")
    observed = {item.get("path") for item in value if isinstance(item, dict)}
    _require(set(paths) <= observed and len(observed) == len(value),
             "protected boundary observer path set differs")
    return value


def _normalized_bcd_output(text: str) -> str:
    """Ignore line endings and trailing spaces without changing entry contents."""
    return "\n".join(
        line.rstrip() for line in text.replace("\r\n", "\n").splitlines()
    ).strip("\n")


def _bcd_observation(snapshot: dict, normal: str, native: str, *, restored: bool) -> dict:
    bcd = snapshot.get("bcd")
    _require(isinstance(bcd, dict) and set(bcd) ==
             {"current_stdout", "bootmgr_stdout", "all_stdout"}, "BCD observations missing")
    for raw in bcd.values():
        _require(isinstance(raw, str) and 0 < len(raw) <= 1024 * 1024,
                 "BCD raw output missing or oversized")
    identifier = r"(?im)^[ \t]*(?:identifier|identificateur)[ \t]+(" + GUID + r")[ \t]*\r?$"
    loader_path = r"(?im)^[ \t]*(?:path|chemin)[ \t]+[^\r\n]*\\winload\.(?:efi|exe)[ \t]*\r?$"
    current = re.findall(identifier, bcd["current_stdout"])
    manager_id = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}"
    manager = re.findall(identifier, bcd["bootmgr_stdout"])
    defaults = re.findall(
        r"(?im)^[ \t]*(?:default|d[eé]faut|par d[eé]faut)[ \t]+(" + GUID + r")[ \t]*\r?$",
        bcd["bootmgr_stdout"],
    )
    sequence_matches = list(re.finditer(
        r"(?im)^[ \t]*(?:bootsequence|s[eé]quence de d[eé]marrage)[ \t]+([^\r\n]+)\r?$",
        bcd["bootmgr_stdout"],
    ))
    _require([item.lower() for item in current] == [normal] and
             [item.lower() for item in manager] == [manager_id] and
             [item.lower() for item in defaults] == [normal] and
             re.search(loader_path, bcd["current_stdout"]) is not None,
             "normal loader or default differs")
    _require(len(sequence_matches) <= 1, "one-shot boot sequence is ambiguous")
    sequence = ""
    if sequence_matches:
        match = sequence_matches[0]
        sequence = match.group(1).strip().lower()
        following = bcd["bootmgr_stdout"][match.end():]
        _require(sequence in {normal, native} and
                 re.match(r"^\r?\n[ \t]+\S", following) is None,
                 "one-shot boot sequence is ambiguous or has a continuation")
    inventory = {}
    owned = []
    for block in re.split(r"(?:\r?\n){2,}", bcd["all_stdout"].strip()):
        if not block.strip():
            continue
        ids = re.findall(identifier, block)
        _require(len(ids) == 1 and ids[0].lower() not in inventory,
                 "complete unambiguous BCD inventory is required")
        entry_id = ids[0].lower()
        inventory[entry_id] = block
        description = re.search(
            r"(?im)^[ \t]*description[ \t]+Windows - Ecommerce Network Smoke Native VT-x[ \t]*\r?$",
            block,
        )
        if entry_id == native or description:
            _require(entry_id == native and description is not None and
                     re.search(loader_path, block) is not None,
                     "owned loader identity is ambiguous")
            owned.append(entry_id)
    _require(normal in inventory and manager_id in inventory and
             re.search(loader_path, inventory[normal]) is not None,
             "BCD inventory lacks normal loader or boot manager")
    _require(
        _normalized_bcd_output(inventory[normal]) ==
        _normalized_bcd_output(bcd["current_stdout"]) and
        _normalized_bcd_output(inventory[manager_id]) ==
        _normalized_bcd_output(bcd["bootmgr_stdout"]),
        "BCD inventory contradicts dedicated loader or boot manager observations",
    )
    if restored:
        _require(not sequence and not owned, "BCD restoration not observed")
    return {"sequence": sequence, "entries": owned}


def _snapshot(snapshot, *, vm_id, vm_name, normal, native, restored) -> dict:
    _require(isinstance(snapshot, dict), "host observation missing")
    started = _epoch(snapshot.get("observed_at"))
    ended = _epoch(snapshot.get("completed_at"))
    _require(started <= ended and ended - started <= 300, "host observation bounds invalid")
    bcd = _bcd_observation(snapshot, normal, native, restored=restored)
    raw = snapshot.get("vbox_stdout")
    _require(isinstance(raw, str) and len(raw) <= 1024 * 1024, "VM observation missing")
    fields = {}
    for name in ("UUID", "name", "VMState"):
        values = re.findall(r"(?m)^" + name + r'="([^"\r\n]+)"\r?$', raw)
        _require(len(values) == 1, "VM observation is ambiguous")
        fields[name] = values[0]
    _require(fields == {"UUID": vm_id, "name": vm_name, "VMState": "poweroff"},
             "retained VM identity or power state differs")
    tasks = snapshot.get("native_tasks")
    _require(isinstance(tasks, list) and
             all(isinstance(name, str) and name in TASK_NAMES for name in tasks) and
             len(tasks) == len(set(tasks)),
             "task observation is invalid")
    key = snapshot.get("private_key_present")
    _require(type(key) is bool, "private identity observation missing")
    if restored:
        _require(tasks == [] and key is False, "tasks or private identity remain")
    return {"started": started, "ended": ended, "tasks": tasks, "key": key, **bcd}


def _inspect(root: Path, head: str, tree: str, campaign: str, vm_id: str,
             *, historical: bool = False) -> tuple[dict, dict]:
    _require(SHA.fullmatch(head or "") is not None and SHA.fullmatch(tree or "") is not None,
             "exact HEAD and tree are required")
    _require(CAMPAIGN.fullmatch(campaign or "") is not None and
             m25.UUID.fullmatch(vm_id or "") is not None, "campaign or VM UUID invalid")
    shadow = SHADOW_ROOT / f"{campaign}-{head}"
    _require(shadow.is_dir() and not shadow.is_symlink(),
             "exact-head protected shadow and prospective recovery observations are missing")
    files = _ProtectedFiles(shadow)
    boot = files.json("native-boot.json")
    capture = files.json("recovery/capture.json")
    restore = files.json("recovery/restore.json")
    verification = files.json("recovery/verification.json")
    expected_shadow = str(WINDOWS_ROOT / shadow.name)
    vm_name = boot.get("vm_name")
    _require(isinstance(vm_name, str) and
             re.fullmatch(r"ecommerce-rocky-10-2-smoke-[0-9a-f]{12}", vm_name),
             "retained VM name invalid")
    _require(boot.get("source_sha") == head and boot.get("source_tree_sha") == tree and
             boot.get("campaign_id") == campaign and boot.get("vm_id") == vm_id and
             boot.get("expected_vm_id") == vm_id and boot.get("shadow_root") == expected_shadow,
             "protected state identity differs")
    _require("recovery_evidence_error" not in boot,
             "the protected recovery observer reported a failure")
    _require(boot.get("mode") == "NETWORK_SMOKE_NATIVE" and
             boot.get("phase") == "RECOVERED" and boot.get("run_status") == "PASS" and
             type(boot.get("boot_attempts")) is int and boot["boot_attempts"] == 1,
             "a completed real native run and RECOVERED phase are required")
    for phase, observation in (("capture", capture), ("restore", restore),
                               ("restore_verification", verification)):
        _require(type(observation.get("schema_version")) is int and
                 observation["schema_version"] == 1 and observation.get("phase") == phase,
                 f"{phase} producer observation missing")
        for name in ("campaign_id", "source_sha", "source_tree_sha", "vm_id", "vm_name",
                     "box_sha256", "runner_manifest_sha256", "shadow_root"):
            _require(observation.get(name) == boot.get(name),
                     f"{phase} {name} differs from protected state")
        _require("recovery" not in observation and "status" not in observation,
                 "declared recovery status cannot replace observations")
    normal, native = boot.get("normal_boot_id"), boot.get("native_boot_id")
    _require(isinstance(normal, str) and isinstance(native, str) and
             re.fullmatch(GUID, normal) and re.fullmatch(GUID, native) and
             normal == normal.lower() and native == native.lower() and normal != native,
             "loader identities invalid")
    baseline = _snapshot(capture.get("observation"), vm_id=vm_id, vm_name=vm_name,
                         normal=normal, native=native, restored=True)
    before = _snapshot(restore.get("observation"), vm_id=vm_id, vm_name=vm_name,
                       normal=normal, native=native, restored=False)
    after = _snapshot(verification.get("observation"), vm_id=vm_id, vm_name=vm_name,
                      normal=normal, native=native, restored=True)
    initialized = _epoch(capture.get("shadow_initialization_started_at"))
    sealed = _epoch(capture.get("sealed_at"))
    mutation = _epoch(boot.get("mutation_started_at"))
    prepared = _epoch(boot.get("prepared_at"))
    restore_started = _epoch(restore.get("started_at"))
    restore_completed = _epoch(restore.get("completed_at"))
    recovered = _epoch(boot.get("recovered_at"))
    _require(boot.get("shadow_initialization_started_at") ==
             capture.get("shadow_initialization_started_at") and
             baseline["ended"] <= initialized <= sealed <= mutation <= prepared <=
             restore_started <= before["started"] <= before["ended"] <=
             restore_completed <= recovered <= after["started"] <= after["ended"],
             "capture, mutation, restoration and independent readback order invalid")
    _require(verification.get("observed_at") == verification["observation"]["observed_at"],
             "verification observation timestamp differs")
    _require(restore_completed - restore_started <= 1800,
             "restoration exceeds its bounded transaction")
    created = after["ended"]
    now = datetime.now(timezone.utc).timestamp()
    _require(created <= now and (historical or now - created <= MAX_AGE),
             "recovery observation is stale or from the future")
    _require(before["entries"] == [native] and before["key"] is True and
             set(TASK_NAMES[:2]) <= set(before["tasks"]),
             "actual owned resources before restoration were not observed")
    operations = restore.get("operations")
    expected_operations = {
        "bootsequence_removed": bool(before["sequence"]),
        "native_loader_removed": True,
        "tasks_removed": sorted(before["tasks"]),
        "private_key_removed": True,
    }
    _require(isinstance(operations, dict) and operations == expected_operations and
             all(type(operations[name]) is bool for name in
                 ("bootsequence_removed", "native_loader_removed", "private_key_removed")),
             "restoration receipts differ from observed owned resources")
    # Readback compares actual BCD output, including the unchanged normal loader,
    # rather than accepting a mutator's declared status.
    for name in ("current_stdout", "bootmgr_stdout", "all_stdout"):
        _require(_normalized_bcd_output(capture["observation"]["bcd"][name]) ==
                 _normalized_bcd_output(verification["observation"]["bcd"][name]),
                 "BCD readback differs from the captured baseline")
    refs = files.refs()
    capture_hash = refs["recovery/capture.json"]
    restore_hash = refs["recovery/restore.json"]
    _require(boot.get("recovery_capture_sha256") == capture_hash and
             restore.get("capture_sha256") == capture_hash and
             verification.get("capture_sha256") == capture_hash and
             verification.get("restore_sha256") == restore_hash and
             verification.get("native_boot_sha256") == refs["native-boot.json"],
             "protected recovery digest chain differs")
    backup = capture.get("bcd_backup")
    _require(isinstance(backup, dict) and set(backup) == {"path", "sha256"},
             "captured BCD backup missing")
    backup_path = PureWindowsPath(str(backup.get("path", "")))
    try:
        backup_relative = backup_path.relative_to(PureWindowsPath(expected_shadow)).as_posix()
    except ValueError as exc:
        raise ValueError("native recovery: BCD backup escapes exact shadow") from exc
    _require(re.fullmatch(r"bcd/before-" + re.escape(campaign + "-" + head) +
                          r"-[0-9]{8}T[0-9]{9}Z\.bak", backup_relative) is not None,
             "BCD backup path differs from canonical capture")
    _require(boot.get("bcd_backup") == backup["path"] and
             boot.get("bcd_backup_sha256") == backup["sha256"] ==
             files.read(backup_relative, binary=True) and
             files.path(backup_relative).stat().st_size >= 1024,
             "captured BCD export bytes differ")
    runner_relative = f"runner-{head}/runner.json"
    runner = files.json(runner_relative)
    _require(runner.get("source_sha") == head and runner.get("source_tree_sha") == tree and
             runner.get("campaign_id") == campaign and
             files.refs()[runner_relative] == boot.get("runner_manifest_sha256"),
             "exact runner manifest differs")
    digests = runner.get("runner_files")
    _require(isinstance(digests, dict) and set(digests) == set(m25.NETWORK_RUNNER_FILES),
             "protected runner inventory differs")
    for name in m25.NETWORK_RUNNER_FILES:
        relative = f"runner-{head}/scripts/windows/{name}"
        _require(files.read(relative, binary=True) == digests[name] ==
                 m25._digest(root / "scripts/windows" / name),
                 "protected runner bytes differ from exact source: " + name)
    for relative, source, expected in (
        (f"{campaign}/smoke-run/Vagrantfile",
         "platform/vagrant/rocky-image-smoke/Vagrantfile", runner.get("vagrantfile_sha256")),
        (f"{campaign}/config/artifacts/rocky-10.2-base-packages.lock.json",
         "config/artifacts/rocky-10.2-base-packages.lock.json", runner.get("package_lock_sha256")),
    ):
        _require(files.read(relative, binary=True) == expected == m25._digest(root / source),
                 "protected source input differs")
    id_relative = f"{campaign}/smoke-run/.vagrant/machines/default/virtualbox/id"
    _require(files.read(id_relative).decode("ascii").strip().strip("{}") == vm_id,
             "retained Vagrant VM UUID differs")
    result_relative = f"evidence/network-smoke/{campaign}/result.json"
    smoke = files.json(result_relative)
    result_hash = files.refs()[result_relative]
    _require(result_hash == boot.get("result_sha256"), "native result digest differs")
    log = (smoke.get("image_qualification") or {}).get("virtualbox_log_relative")
    _require(isinstance(log, str) and
             re.fullmatch(r"logs/ssh-resume-[0-9]{8}T[0-9]{6}Z/VBox\.log", log),
             "native backend log reference invalid")
    files.read(f"{campaign}/{log}")
    protected_manifest = files.json("box/manifest.json")
    files.read("box/packer.log", binary=True)
    files.read("box/source.box", binary=True)
    boundary_before = _protected_boundary(files)
    # The established image catalog and M2.5 smoke producer remain authoritative
    # for native execution, approved image inputs, guest checks and no NEM.
    box = rocky_box_catalog.find_matching_box(head)
    manifest = rocky_box_catalog.verify(box, head)
    _require(protected_manifest == manifest and
             boot.get("box_sha256") == files.refs()["box/source.box"] == manifest["box_sha256"] and
             files.refs()["box/packer.log"] == manifest["packer_log_sha256"],
             "protected box or Packer provenance differs")
    m25.validate_current_smoke(root, smoke, head, manifest)
    m25.validate_protected_smoke(root, smoke, result_hash, head, tree, manifest)
    files.verify_unchanged()
    _require(_protected_boundary(files) == boundary_before,
             "protected filesystem boundary changed during validation")
    payload = {
        "schema_version": 1, "proof_type": "native-host-recovery", "status": "PASS",
        "outcome": "PASS", "milestone": "M2.5", "environment": "host",
        "runtime_execution": True, "exact_commit_evidence": True,
        "head_sha": head, "head_tree_sha": tree, "source_sha": head,
        "created_at_epoch": created, "campaign_id": campaign,
        "runtime_identity": {"kind": "virtualbox-vm", "id": vm_id},
        "vm_name": vm_name, "shadow_root": expected_shadow,
        "box_sha256": manifest["box_sha256"], "source_evidence": files.refs(),
        "deployment_state": "NOT_DEPLOYED", "paid_resources_created": 0,
    }
    verdict = {
        "status": "PASS", "environment": "host", "runtime_identity": payload["runtime_identity"],
        "recovery": {phase: "PASS" for phase in ("capture", "restore", "restore_verification")},
    }
    return payload, verdict


def validate(root: Path, evidence: dict, head: str, tree: str, *, historical=False) -> dict:
    """Return recovery verdict only after independently validating protected bytes."""
    _require(isinstance(evidence, dict) and "recovery" not in evidence,
             "self-declared recovery cannot replace producer observations")
    _require(type(evidence.get("schema_version")) is int and
             type(evidence.get("paid_resources_created")) is int and
             evidence.get("runtime_execution") is True and
             evidence.get("exact_commit_evidence") is True,
             "proof types or execution identity invalid")
    identity = evidence.get("runtime_identity")
    _require(isinstance(identity, dict) and identity.get("kind") == "virtualbox-vm",
             "runtime identity missing")
    expected, verdict = _inspect(
        Path(root), head, tree, evidence.get("campaign_id"), identity.get("id"),
        historical=historical,
    )
    _require(evidence == expected, "proof metadata or referenced digests differ from observations")
    return verdict


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True,
                            timeout=30, check=True)
    return result.stdout.strip()


def create(root: Path, campaign_id: str, vm_id: str, *, check_only=False) -> dict:
    root = root.resolve(strict=True)
    _require(_git(root, "status", "--porcelain=v1", "--untracked-files=all") == "",
             "proof generation requires a clean source checkout")
    head, tree = _git(root, "rev-parse", "HEAD"), _git(root, "rev-parse", "HEAD^{tree}")
    proof, _verdict = _inspect(root, head, tree, campaign_id, vm_id)
    _require(_git(root, "rev-parse", "HEAD") == head and
             _git(root, "status", "--porcelain=v1", "--untracked-files=all") == "",
             "source changed during proof generation")
    if not check_only:
        destination = root / OUTPUT
        current = root
        for part in OUTPUT.parts:
            current /= part
            _require(not current.is_symlink(), "proof output path is redirected")
        destination.parent.mkdir(parents=True, exist_ok=True)
        _require(not destination.exists() or destination.is_file(), "invalid proof output")
        data = (json.dumps(proof, sort_keys=True, separators=(",", ":")) + "\n").encode()
        temporary = destination.with_suffix(".pending")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()
    return {"status": "PASS", "producer": PRODUCER, "head_sha": head,
            "head_tree_sha": tree, "evidence_path": OUTPUT.as_posix(),
            "written": not check_only}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--vm-id", required=True)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    try:
        result = create(Path(__file__).resolve().parents[1], args.campaign_id,
                        args.vm_id, check_only=args.check_only)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "BLOCKED_RUNTIME", "reason": str(exc)}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
