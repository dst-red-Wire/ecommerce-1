"""Fail-closed workstation check for repository-local Git signing.

Run with ``python3 scripts/check_automation_signing.py`` before automated commits.
The only policy authority is architecture.lock.yaml.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import os
import re
import subprocess
import sys

import yaml

from native_workspace import workspace_error


ROOT = Path(__file__).resolve().parents[1]
FINGERPRINT = re.compile(r"[A-F0-9]{40}")
PRIVATE_ARMOR = tuple(b"BEGIN PGP " + kind + b" KEY BLOCK" for kind in (b"PRIVATE", b"SECRET"))


def command(*args: str, input_text: str | None = None) -> str:
    result = subprocess.run(args, input=input_text, text=True, capture_output=True, check=False)
    if result.returncode:
        raise ValueError(f"command failed: {args[0]} {args[1] if len(args) > 1 else ''}")
    return result.stdout.strip()


def config(scope: str, name: str) -> str:
    return command("git", "config", scope, "--get", name)


def key_records(fingerprint: str) -> tuple[list[str], str, str]:
    records = [line.split(":") for line in command(
        "gpg", "--batch", "--with-colons", "--with-keygrip", "--list-secret-keys", fingerprint
    ).splitlines()]
    primary = next((row for row in records if row[0] == "sec"), None)
    actual = next((row[9] for row in records if row[0] == "fpr"), None)
    grip = next((row[9] for row in records if row[0] == "grp"), None)
    uid = next((row[9] for row in records if row[0] == "uid"), None)
    if not primary or not actual or not grip or not uid or actual != fingerprint:
        raise ValueError("dedicated private signing key is unavailable")
    return primary, grip, uid


def check() -> None:
    workspace_failure = workspace_error(ROOT)
    if workspace_failure:
        raise ValueError(workspace_failure)
    policy = yaml.safe_load((ROOT / "architecture.lock.yaml").read_text(encoding="utf-8"))[
        "repository_governance"
    ]["automation_signing"]
    personal = policy["personal_signing"]["fingerprint"]
    automation = policy["automation_key"]["fingerprint"]
    key_policy = policy["automation_key"]
    if (policy["version"] != 1 or policy["kind"] != "AutomationSigningPolicy"
            or policy["status"] != "enforced" or policy["repository"] != "ecommerce-1"):
        raise ValueError("automation signing policy is not enforced for ecommerce-1")
    if (policy["personal_signing"]["passphrase_required"] is not True
            or policy["personal_signing"]["automation_use"] != "forbidden"
            or key_policy["algorithm"] != "ed25519"
            or key_policy["signing_required"] is not True
            or key_policy["passphrase"] != "forbidden"
            or key_policy["expiration_days_max"] != 90
            or key_policy["warning_days_before_expiration"] != 14
            or key_policy["local_git_config_only"] is not True
            or key_policy["revocation_certificate_required"] is not True
            or key_policy["private_key_in_repository"] != "forbidden"
            or key_policy["private_key_export"] != "forbidden"
            or key_policy["global_git_configuration"] != "forbidden"):
        raise ValueError("automation signing policy weakened")
    if not FINGERPRINT.fullmatch(personal) or not FINGERPRINT.fullmatch(automation) or personal == automation:
        raise ValueError("personal and automation fingerprints must be distinct and complete")
    if Path(command("git", "rev-parse", "--show-toplevel")).resolve() != ROOT:
        raise ValueError("automation signing check must run inside ecommerce-1")
    if ROOT.name != policy["repository"]:
        raise ValueError("repository name differs from signing policy")
    if config("--global", "user.signingkey") != personal:
        raise ValueError("global personal signing fingerprint changed")
    if config("--local", "user.signingkey") != automation:
        raise ValueError("local automation signing fingerprint mismatch")
    if config("--local", "commit.gpgsign").lower() != "true":
        raise ValueError("local signed commits are disabled")
    if config("--local", "gpg.program") != "gpg":
        raise ValueError("local GPG program mismatch")
    primary, grip, uid = key_records(automation)
    if uid != key_policy["uid"]:
        raise ValueError("automation key UID mismatch")
    if primary[1] in ("r", "e", "d") or "s" not in primary[11].lower():
        raise ValueError("automation key is invalid or cannot sign")
    created, expires = int(primary[5]), int(primary[6])
    if expires <= created or expires - created > key_policy["expiration_days_max"] * 24 * 3600:
        raise ValueError("automation key validity exceeds 90 days")
    now = datetime.now(timezone.utc).timestamp()
    if expires <= now:
        raise ValueError("automation key expired; signing blocked")
    agent = command("gpg-connect-agent", f"KEYINFO {grip}", "/bye").splitlines()
    info = next((line.split() for line in agent if line.startswith("S KEYINFO ")), None)
    if not info or info[7] != "C":
        raise ValueError("automation key is passphrase protected or protection is unknown")
    personal_primary, personal_grip, _ = key_records(personal)
    if personal_primary[1] in ("r", "e", "d"):
        raise ValueError("personal key is invalid")
    personal_agent = command("gpg-connect-agent", f"KEYINFO {personal_grip}", "/bye").splitlines()
    personal_info = next((line.split() for line in personal_agent if line.startswith("S KEYINFO ")), None)
    if not personal_info or personal_info[7] != "P":
        raise ValueError("personal key passphrase protection cannot be confirmed")
    gpg_home = Path(command("gpgconf", "--list-dirs", "homedir"))
    certificate = gpg_home / "revocation" / f"{automation}.rev"
    if not certificate.is_file():
        certificate = gpg_home / "openpgp-revocs.d" / f"{automation}.rev"
    if not certificate.is_file() or certificate.stat().st_mode & 0o077:
        raise ValueError("revocation certificate missing or permissions too broad")
    if certificate.parent.stat().st_mode & 0o077:
        raise ValueError("revocation directory permissions too broad")
    public_file = Path(f"/tmp/ecommerce-1-automation-signing-{automation}.asc")
    if not public_file.exists():
        public_export = command("gpg", "--batch", "--armor", "--export", automation)
        descriptor = os.open(public_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write((public_export + "\n").encode("ascii"))
    if public_file.is_symlink() or public_file.stat().st_uid != os.getuid():
        raise ValueError("public export has an unsafe owner or path")
    if public_file.stat().st_mode & 0o077:
        raise ValueError("public export permissions too broad")
    public_data = public_file.read_bytes()
    if b"BEGIN PGP PUBLIC KEY BLOCK" not in public_data or any(x in public_data for x in PRIVATE_ARMOR):
        raise ValueError("public export missing or contains private key armor")
    public_records = command("gpg", "--batch", "--with-colons", "--show-keys", str(public_file))
    if f"fpr:::::::::{automation}:" not in public_records:
        raise ValueError("public export fingerprint mismatch")
    files = command("git", "ls-files", "--cached", "--others", "--exclude-standard", "-z").split("\0")
    for relative in filter(None, files):
        path = ROOT / relative
        if not path.is_file():
            continue
        if path.suffix.lower() in {".rev", ".key", ".p12", ".pfx"} or "private-keys-v1.d" in path.parts:
            raise ValueError(f"private key or revocation artifact in repository: {relative}")
        with path.open("rb") as source:
            previous = b""
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                data = previous + chunk
                if any(marker in data for marker in PRIVATE_ARMOR):
                    raise ValueError(f"private key armor in repository: {relative}")
                previous = data[-max(map(len, PRIVATE_ARMOR)):]
    warning = expires - key_policy["warning_days_before_expiration"] * 86400
    if now >= warning:
        print("WARN automation signing key rotation required")
    print(f"PASS automation signing {automation}; expires {datetime.fromtimestamp(expires, timezone.utc).date()}")


if __name__ == "__main__":
    try:
        check()
    except (OSError, KeyError, ValueError, yaml.YAMLError) as error:
        print(f"FAIL automation signing: {error}", file=sys.stderr)
        sys.exit(1)
