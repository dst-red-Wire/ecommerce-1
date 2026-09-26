"""Fail-closed lifecycle for the repository automation signing key.

The lock is the policy authority; the ignored state file is only a local journal.
No private material or authentication credential is exported or printed.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone, timedelta
import json
import math
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import urllib.request

import yaml

from native_workspace import workspace_error


ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / ".context/signing-rotation"
STATE = STATE_DIR / "state.json"
FPR = re.compile(r"[A-F0-9]{40}\Z")
PUBLIC = b"-----BEGIN PGP PUBLIC KEY BLOCK-----"


def run(*args: str, input_text: str | None = None) -> str:
    result = subprocess.run(args, cwd=ROOT, input=input_text, text=True,
                            capture_output=True, check=False)
    if result.returncode:
        raise ValueError(f"command failed: {args[0]} {args[1] if len(args) > 1 else ''}")
    return result.stdout.strip()


def policy() -> dict:
    if workspace_error(ROOT):
        raise ValueError(workspace_error(ROOT))
    signing = yaml.safe_load((ROOT / "architecture.lock.yaml").read_text())["repository_governance"]["automation_signing"]
    rotation = signing["rotation"]
    expected = {"enabled": True, "validity_days": 90, "info_days_before_expiry": 30,
                "warning_days_before_expiry": 14, "delivery_block_days_before_expiry": 7,
                "expired_key_use": "forbidden", "overlapping_keys_allowed": True,
                "overlap_max_days": 7, "remote_verification_required_before_activation": True,
                "revocation_certificate_required": True,
                "old_key_retirement_requires_replacement_proven": True}
    if any(rotation.get(k) != v for k, v in expected.items()):
        raise ValueError("rotation policy drift")
    active = signing["automation_key"]["fingerprint"]
    personal = signing["personal_signing"]["fingerprint"]
    if not FPR.fullmatch(active) or not FPR.fullmatch(personal) or active == personal:
        raise ValueError("invalid signing fingerprints")
    return signing


def key(fingerprint: str) -> dict:
    rows = [line.split(":") for line in run("gpg", "--batch", "--with-colons", "--with-keygrip", "--list-secret-keys", fingerprint).splitlines()]
    sec = next((r for r in rows if r[0] == "sec"), None)
    actual = next((r[9] for r in rows if r[0] == "fpr"), None)
    if not sec or actual != fingerprint or sec[1] in {"r", "e", "d"} or "s" not in sec[11].lower():
        raise ValueError("local signing key unavailable or invalid")
    grip = next((r[9] for r in rows if r[0] == "grp"), None)
    if not grip:
        raise ValueError("signing key grip missing")
    info = next((line.split() for line in run("gpg-connect-agent", f"KEYINFO {grip}", "/bye").splitlines()
                 if line.startswith("S KEYINFO ")), None)
    if not info or info[7] != "C":
        raise ValueError("automation key passphrase protection is not disabled")
    return {"created": int(sec[5]), "expires": int(sec[6]), "uid": [r[9] for r in rows if r[0] == "uid"]}


def read_state() -> dict | None:
    if not STATE.exists():
        return None
    if STATE.is_symlink() or STATE.stat().st_uid != os.getuid() or STATE.stat().st_mode & 0o077:
        raise ValueError("rotation state has unsafe ownership or permissions")
    data = json.loads(STATE.read_text())
    if not isinstance(data, dict) or not FPR.fullmatch(str(data.get("new_fingerprint", ""))):
        raise ValueError("rotation state malformed")
    return data


def save_state(data: dict) -> None:
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if STATE_DIR.is_symlink() or STATE_DIR.stat().st_mode & 0o077:
        raise ValueError("rotation directory permissions too broad")
    temp = STATE.with_suffix(".tmp")
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(data, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, STATE)
    finally:
        temp.unlink(missing_ok=True)


def certificate(fingerprint: str) -> Path:
    home = Path(run("gpgconf", "--list-dirs", "homedir"))
    path = home / "openpgp-revocs.d" / f"{fingerprint}.rev"
    if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
        raise ValueError("revocation certificate missing or permissions unsafe")
    if path.parent.stat().st_mode & 0o077:
        raise ValueError("revocation directory permissions unsafe")
    return path


def ensure_public_export(fingerprint: str, expected_path: str | Path) -> Path:
    path = Path(expected_path)
    if path.is_symlink() or (path.exists() and (not path.is_file() or path.stat().st_uid != os.getuid()
                                                or path.stat().st_mode & 0o077)):
        raise ValueError("public export path unsafe")
    content = run("gpg", "--batch", "--armor", "--export", fingerprint).encode("ascii") + b"\n"
    if PUBLIC not in content or b"PRIVATE KEY" in content or b"SECRET KEY" in content:
        raise ValueError("GPG public export invalid")
    if path.exists():
        if path.read_bytes() != content:
            raise ValueError("public export path drift")
        return path
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    return path


def validate_pending(signing: dict, data: dict) -> dict:
    old, new = data["old_fingerprint"], data["new_fingerprint"]
    if old == signing["personal_signing"]["fingerprint"] or new == old or new == signing["personal_signing"]["fingerprint"]:
        raise ValueError("rotation fingerprint conflicts with protected key")
    if data.get("activated"):
        if signing["automation_key"]["fingerprint"] != new:
            raise ValueError("activated fingerprint differs from lock")
    elif signing["automation_key"]["fingerprint"] != old:
        raise ValueError("pending rotation old fingerprint differs from lock")
    if signing["automation_key"].get("pending_fingerprint") != new:
        raise ValueError("pending fingerprint differs from lock")
    details = key(new)
    if details["expires"] <= datetime.now(timezone.utc).timestamp():
        raise ValueError("replacement key expired")
    if details["expires"] - details["created"] > signing["rotation"]["validity_days"] * 86400:
        raise ValueError("replacement validity exceeds policy")
    if datetime.fromisoformat(str(signing["automation_key"].get("pending_expires_at"))).timestamp() != details["expires"]:
        raise ValueError("pending expiration differs from GnuPG")
    identity = signing["automation_key"]["forge_identity"]
    expected_uid = f"{identity['git_name']} <{identity['git_email']}>"
    if expected_uid not in details["uid"]:
        raise ValueError("replacement UID mismatch")
    if str(certificate(new)) != data.get("revocation_certificate_path"):
        raise ValueError("revocation certificate path mismatch")
    public_path = ensure_public_export(new, data["public_key_path"])
    content = public_path.read_bytes()
    records = run("gpg", "--batch", "--with-colons", "--show-keys", str(public_path))
    if f"fpr:::::::::{new}:" not in records:
        raise ValueError("public export fingerprint mismatch")
    return details


def classify(days: float, verified: bool, rotation: dict) -> str:
    if days <= 0:
        return "EXPIRED"
    if days <= rotation["delivery_block_days_before_expiry"] and not verified:
        return "BLOCK"
    if days <= rotation["warning_days_before_expiry"]:
        return "WARN"
    if days <= rotation["info_days_before_expiry"]:
        return "INFO"
    return "OK"


def status() -> dict:
    signing = policy()
    active = signing["automation_key"]["fingerprint"]
    details = key(active)
    data = read_state()
    if data:
        validate_pending(signing, data)
    verified = bool(data and not data.get("activated") and data.get("remote_github_verified") is True
                    and data.get("remote_gitea_verified") is True)
    now = datetime.now(timezone.utc).timestamp()
    days = (details["expires"] - now) / 86400
    if verified and days <= signing["rotation"]["delivery_block_days_before_expiry"]:
        try:
            verified = remote_registration(data) == (True, True)
        except (OSError, ValueError, KeyError):
            verified = False
    return {"status": classify(days, verified, signing["rotation"]), "fingerprint": active,
            "expires_at": datetime.fromtimestamp(details["expires"], timezone.utc).isoformat(),
            "days_remaining": max(0, math.ceil(days)), "replacement_prepared": bool(data and not data.get("activated")),
            "replacement_verified": verified}


def check() -> None:
    result = status()
    print(json.dumps(result, sort_keys=True))
    if result["status"] in {"BLOCK", "EXPIRED"}:
        raise ValueError("automation delivery blocked by signing rotation policy")


def export_public(fingerprint: str) -> Path:
    path = Path(f"/tmp/ecommerce-1-automation-signing-{fingerprint}.asc")
    return ensure_public_export(fingerprint, path)


def write_pending_lock(old: str, new: str, expires: int) -> None:
    lock = ROOT / "architecture.lock.yaml"
    source = lock.read_text()
    old_line = f"      fingerprint: {old}\n"
    if source.count(old_line) != 1:
        raise ValueError("canonical lock is not in pending rotation state")
    status = re.search(r"^      rotation_status: (.+)$", source, re.MULTILINE)
    if not status or status.group(1) not in {"pending_remote_verification", "retired"}:
        raise ValueError("canonical lock rotation status disallows preparation")
    allow_replacement = status.group(1) == "retired"
    pending = f"      pending_fingerprint: {new}\n"
    expiry = f"      pending_expires_at: \"{datetime.fromtimestamp(expires, timezone.utc):%Y-%m-%dT%H:%M:%SZ}\"\n"
    for field, desired in (("pending_fingerprint", pending), ("pending_expires_at", expiry)):
        match = re.search(rf"^      {field}: .*\n", source, re.MULTILINE)
        if not match:
            raise ValueError(f"canonical lock missing {field}")
        current = match.group()
        if current != desired and current.split(":", 1)[1].strip() != "null" and not allow_replacement:
            raise ValueError(f"canonical {field} already points to another rotation")
        source = source.replace(current, desired, 1)
    source = source.replace("      rotation_status: retired", "      rotation_status: pending_remote_verification", 1)
    lock.write_text(source)


def rotate() -> None:
    signing = policy()
    existing = read_state()
    if existing:
        validate_pending(signing, existing)
        if existing.get("retired_old"):
            archive = STATE_DIR / f"{existing['rotation_id']}.json"
            if archive.exists():
                raise ValueError("rotation archive already exists")
            os.replace(STATE, archive)
            existing = None
    if existing:
        print("PASS existing pending rotation reused" if not existing.get("activated") else "PASS existing activated rotation reused")
        print(f"fingerprint={existing['new_fingerprint']} public_key_path={existing['public_key_path']}")
        return
    old = signing["automation_key"]["fingerprint"]
    if run("git", "config", "--local", "--get", "user.signingkey") != old:
        raise ValueError("local signer differs from canonical active fingerprint")
    key(old)
    identity = signing["automation_key"]["forge_identity"]
    uid = f"{identity['git_name']} <{identity['git_email']}>"
    all_fprs = {r[9] for r in (line.split(":") for line in run("gpg", "--batch", "--with-colons", "--list-secret-keys").splitlines()) if r[0] == "fpr"}
    candidates = []
    for candidate in all_fprs - {old, signing["personal_signing"]["fingerprint"]}:
        details = key(candidate)
        if (uid in details["uid"] and details["created"] >= key(old)["created"]
                and details["expires"] > datetime.now(timezone.utc).timestamp()
                and details["expires"] - details["created"] <= signing["rotation"]["validity_days"] * 86400):
            certificate(candidate)
            ensure_public_export(candidate, f"/tmp/ecommerce-1-automation-signing-{candidate}.asc")
            candidates.append(candidate)
    if len(candidates) > 1:
        raise ValueError("multiple replacement candidates; manual recovery required")
    if candidates:
        new = candidates[0]
    else:
        parameters = ("%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\nKey-Usage: sign\n"
                      f"Name-Real: {identity['git_name']}\nName-Email: {identity['git_email']}\n"
                      "Expire-Date: 90d\n%commit\n")
        run("gpg", "--batch", "--pinentry-mode", "loopback", "--generate-key", input_text=parameters)
        after = {r[9] for r in (line.split(":") for line in run("gpg", "--batch", "--with-colons", "--list-secret-keys").splitlines()) if r[0] == "fpr"}
        created = after - all_fprs
        if len(created) != 1:
            raise ValueError("new key fingerprint ambiguous; inspect GnuPG before retry")
        new = created.pop()
    if new == signing["personal_signing"]["fingerprint"]:
        raise ValueError("replacement conflicts with personal key")
    details = key(new)
    cert = certificate(new)
    public_path = export_public(new)
    write_pending_lock(old, new, details["expires"])
    data = {"rotation_id": f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{new[:12]}",
            "old_fingerprint": old, "new_fingerprint": new,
            "created_at": datetime.fromtimestamp(details["created"], timezone.utc).isoformat(),
            "expires_at": datetime.fromtimestamp(details["expires"], timezone.utc).isoformat(),
            "public_key_path": str(public_path), "revocation_certificate_path": str(cert),
            "remote_github_verified": False, "remote_gitea_verified": False,
            "activated": False, "retired_old": False, "old_key_status": "active"}
    save_state(data)
    print(f"PASS pending rotation prepared fingerprint={new} public_key_path={public_path}")
    print("WAITING_FOR_REMOTE_KEY_REGISTRATION")


def _json_url(url: str, *, token: str | None = None, cafile: Path | None = None) -> object:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "token " + token
    request = urllib.request.Request(url, headers=headers)
    context = ssl.create_default_context(cafile=str(cafile)) if cafile else None
    with urllib.request.urlopen(request, context=context, timeout=15) as response:
        return json.load(response)


def public_fingerprint(armor: str) -> str:
    if "PRIVATE KEY" in armor or "SECRET KEY" in armor:
        raise ValueError("forge public key armor invalid")
    payload = armor.encode() if "BEGIN PGP PUBLIC KEY BLOCK" in armor else base64.b64decode(armor, validate=True)
    result = subprocess.run(["gpg", "--batch", "--with-colons", "--show-keys"], input=payload,
                            cwd=ROOT, capture_output=True, check=False)
    if result.returncode:
        raise ValueError("forge public key packet invalid")
    records = result.stdout.decode()
    primaries = []
    kind = None
    for row in (line.split(":") for line in records.splitlines()):
        if row[0] == "pub":
            kind = "pub"
        elif row[0] == "sub":
            kind = "sub"
        elif row[0] == "fpr" and kind == "pub":
            primaries.append(row[9])
            kind = "pub-fpr"
    if len(primaries) != 1 or not FPR.fullmatch(primaries[0]):
        raise ValueError("forge public key fingerprint ambiguous")
    return primaries[0]


def remote_registration(data: dict) -> tuple[bool, bool]:
    account = "dst-red-Wire"
    github = _json_url(f"https://api.github.com/users/{account}/gpg_keys?per_page=100")
    gh_ok = isinstance(github, list) and any(
        public_fingerprint(item["raw_key"]) == data["new_fingerprint"]
        and any(email.get("email") == "141283735+dst-red-Wire@users.noreply.github.com"
                and email.get("verified") is True for email in item.get("emails", []))
        for item in github if isinstance(item, dict) and item.get("raw_key")
    )
    token, ca = _gitea_identity()
    gitea = "https://gitea.ecommerce.local/api/v1"
    user = _json_url(gitea + "/user", token=token, cafile=ca)
    if user.get("login") != account:
        raise ValueError("Gitea token identity mismatch")
    keys = _json_url(gitea + "/user/gpg_keys", token=token, cafile=ca)
    gt_ok = isinstance(keys, list) and any(
        public_fingerprint(item["public_key"]) == data["new_fingerprint"]
        and item.get("can_sign") is True
        and any(email.get("email") == "141283735+dst-red-Wire@users.noreply.github.com"
                and email.get("verified") is True for email in item.get("emails", []))
        for item in keys if isinstance(item, dict) and item.get("public_key"))
    return gh_ok, gt_ok


def _gitea_identity() -> tuple[str, Path]:
    state = ROOT / ".context/local-services"
    credentials = state / "credentials.json"
    if credentials.is_symlink() or credentials.stat().st_mode & 0o077:
        raise ValueError("Gitea credential file unsafe")
    token = json.loads(credentials.read_text())["gitea_account_token"]
    return token, state / "tls/ca.crt"


def remote_commit_proof(fingerprint: str) -> str:
    sha = run("git", "rev-parse", "HEAD")
    if not re.fullmatch(r"[a-f0-9]{40}", sha):
        raise ValueError("invalid exact head SHA")
    signed = subprocess.run(["git", "verify-commit", "--raw", sha], cwd=ROOT,
                            capture_output=True, text=True, check=False)
    if signed.returncode or f"[GNUPG:] VALIDSIG {fingerprint}" not in signed.stdout + signed.stderr:
        raise ValueError("exact head does not carry the replacement signature")
    branch = run("git", "branch", "--show-current")
    if not branch or branch in {"main", "master"}:
        raise ValueError("replacement delivery requires a feature branch")
    for remote in ("origin", "gitea"):
        advertised = run("git", "ls-remote", remote, f"refs/heads/{branch}").split()
        if not advertised or advertised[0] != sha:
            raise ValueError(f"{remote} exact head is not published")
    import repoctl
    if not repoctl._valid_exact_evidence("origin/main", sha):
        raise ValueError("new exact-SHA CI PASS evidence missing")
    if not repoctl._valid_performance_audit("origin/main", sha):
        raise ValueError("new qualification proof missing")
    github = _json_url(f"https://api.github.com/repos/dst-red-Wire/ecommerce-1/commits/{sha}")
    verification = github.get("commit", {}).get("verification", {})
    if (verification.get("verified") is not True or verification.get("reason") != "valid"
            or github.get("author", {}).get("login") != "dst-red-Wire"
            or github.get("committer", {}).get("login") != "dst-red-Wire"):
        raise ValueError("GitHub exact commit verification failed")
    token, ca = _gitea_identity()
    gitea = _json_url(f"https://gitea.ecommerce.local/api/v1/repos/dst-red-Wire/ecommerce-1/git/commits/{sha}",
                       token=token, cafile=ca)
    proof = gitea.get("verification", {})
    if proof.get("verified") is not True:
        raise ValueError("Gitea exact commit verification failed")
    return sha


def verify_remote() -> None:
    signing = policy()
    data = read_state()
    if not data:
        raise ValueError("no prepared rotation")
    validate_pending(signing, data)
    github, gitea = remote_registration(data)
    data["remote_github_verified"] = github
    data["remote_gitea_verified"] = gitea
    save_state(data)
    print(f"github_registered={str(github).lower()} gitea_registered={str(gitea).lower()}")
    if not (github and gitea):
        raise ValueError("WAITING_FOR_REMOTE_KEY_REGISTRATION")


def signed_probe(fingerprint: str) -> str:
    tree = run("git", "rev-parse", "HEAD^{tree}")
    parent = run("git", "rev-parse", "HEAD")
    commit = run("git", "-c", f"user.signingkey={fingerprint}", "commit-tree", tree, "-p", parent,
                 f"-S{fingerprint}", input_text="automation signing rotation probe\n")
    verified = subprocess.run(["git", "verify-commit", "--raw", commit], cwd=ROOT,
                              capture_output=True, text=True, check=False)
    if verified.returncode or f"[GNUPG:] VALIDSIG {fingerprint}" not in verified.stdout + verified.stderr:
        raise ValueError("local signed probe fingerprint mismatch")
    return commit


def activate() -> None:
    signing = policy()
    data = read_state()
    if not data:
        raise ValueError("no prepared rotation")
    transition = data.get("activation")
    if transition and transition.get("transition") == "activating":
        old, new = transition["old_signer"], transition["new_signer"]
        lock = ROOT / "architecture.lock.yaml"
        lock_text = lock.read_text()
        signer = run("git", "config", "--local", "--get", "user.signingkey")
        converged = signer == new and f"      fingerprint: {new}\n" in lock_text
        if converged:
            data["activated"] = True
            data["activated_at"] = datetime.now(timezone.utc).isoformat()
            data["old_key_status"] = "overlap"
            data.pop("activation", None)
            save_state(data)
            print(f"PASS activation recovered signer={new}")
            return
        run("git", "config", "--local", "user.signingkey", old)
        data["activation"] = {**transition, "transition": "activation_failed_recovered"}
        save_state(data)
    validate_pending(signing, data)
    if data.get("activated"):
        raise ValueError("double activation forbidden")
    github, gitea = remote_registration(data)
    if not (github and gitea):
        raise ValueError("WAITING_FOR_REMOTE_KEY_REGISTRATION")
    data["remote_github_verified"], data["remote_gitea_verified"] = True, True
    save_state(data)
    old, new = data["old_fingerprint"], data["new_fingerprint"]
    if run("git", "config", "--local", "--get", "user.signingkey") != old:
        raise ValueError("local signer drift before activation")
    signed_probe(new)
    run("gpgconf", "--kill", "gpg-agent")
    signed_probe(new)
    lock = ROOT / "architecture.lock.yaml"
    source = lock.read_text()
    old_line = f"      fingerprint: {old}\n"
    if source.count(old_line) != 1:
        run("git", "config", "--local", "user.signingkey", old)
        raise ValueError("canonical active fingerprint drift")
    previous = re.search(r"^      previous_fingerprint: .*\n", source, re.MULTILINE)
    if not previous:
        raise ValueError("canonical previous fingerprint missing")
    source = source.replace(old_line, f"      fingerprint: {new}\n", 1)
    source = source[:previous.start()] + f"      previous_fingerprint: {old}\n" + source[previous.end():]
    source = source.replace("      rotation_status: pending_remote_verification", "      rotation_status: active_overlap", 1)
    source = source.replace(f"      uid: {signing['automation_key']['uid']}",
                            f"      uid: {signing['automation_key']['forge_identity']['git_name']} <{signing['automation_key']['forge_identity']['git_email']}>", 1)
    source = source.replace(f"  automation_signing_fingerprint: {old}", f"  automation_signing_fingerprint: {new}", 1)
    expected = {"transition": "activating", "old_signer": old, "new_signer": new,
                "expected_lock_before": old, "expected_lock_after": new}
    data["activation"] = expected
    save_state(data)
    original = lock.read_text()
    try:
        run("git", "config", "--local", "user.signingkey", new)
        lock.write_text(source)
        data["activated"] = True
        data["activated_at"] = datetime.now(timezone.utc).isoformat()
        data["old_key_status"] = "overlap"
        data.pop("activation", None)
        save_state(data)
    except Exception:
        lock.write_text(original)
        run("git", "config", "--local", "user.signingkey", old)
        data["activation"] = {**expected, "transition": "activation_failed_recovered"}
        save_state(data)
        raise
    print(f"PASS activation local signer={new}; fresh-agent proof PASS")
    print("BLOCKED_REMOTE_VERIFICATION pending signed commit verification on both forges")


def retire_old() -> None:
    signing = policy()
    data = read_state()
    if not data or not data.get("activated"):
        raise ValueError("retirement before activation forbidden")
    validate_pending(signing, data)
    if data.get("retired_old"):
        print("PASS old key already retired")
        return
    proof = ROOT / ".context/reboot-proof/result.json"
    if not proof.is_file():
        raise ValueError("replacement reboot proof missing")
    reboot = json.loads(proof.read_text())
    if (reboot.get("status") != "PASS" or reboot.get("observed_fingerprint") != data["new_fingerprint"]
            or reboot.get("passphrase_prompt") != "none"
            or reboot.get("observed_windows_boot_utc", "") <= reboot.get("baseline_windows_boot_utc", "")):
        raise ValueError("replacement reboot proof invalid")
    signed = reboot.get("signed_commit", "")
    if not re.fullmatch(r"[a-f0-9]{40}", signed):
        raise ValueError("reboot proof commit missing")
    verified = subprocess.run(["git", "verify-commit", "--raw", signed], cwd=ROOT,
                              capture_output=True, text=True, check=False)
    if verified.returncode or f"[GNUPG:] VALIDSIG {data['new_fingerprint']}" not in verified.stdout + verified.stderr:
        raise ValueError("reboot proof signature mismatch")
    exact_sha = remote_commit_proof(data["new_fingerprint"])
    if datetime.now(timezone.utc) - datetime.fromisoformat(data["activated_at"]) > timedelta(days=signing["rotation"]["overlap_max_days"]):
        raise ValueError("overlap deadline exceeded; manual recovery required")
    # Remote deletion requires a separate explicit operator decision; preserve historical verification.
    data["retired_old"] = True
    data["old_key_status"] = "retired_locally_registration_preserved"
    data["retirement_proof_sha"] = exact_sha
    lock = ROOT / "architecture.lock.yaml"
    source = lock.read_text()
    if source.count("      rotation_status: active_overlap") != 1:
        raise ValueError("canonical rotation status drift")
    lock.write_text(source.replace("      rotation_status: active_overlap", "      rotation_status: retired", 1))
    save_state(data)
    print("PASS old key retired from automation; remote historical registration preserved")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("rotation-check", "rotation-status", "rotate", "verify-remote", "activate", "retire-old"))
    action = parser.parse_args().action
    {"rotation-check": check, "rotation-status": lambda: print(json.dumps(status(), sort_keys=True)),
     "rotate": rotate, "verify-remote": verify_remote, "activate": activate,
     "retire-old": retire_old}[action]()


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, ValueError, TypeError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(f"BLOCKED signing rotation: {error}", file=sys.stderr)
        sys.exit(1)
