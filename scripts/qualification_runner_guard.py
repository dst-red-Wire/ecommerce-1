"""Trusted-controller runner admission; never execute a candidate copy as authority."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess

# Controller policy: the current campaign base and the historical audited M1 base.
# Only an independently reviewed controller revision may extend this authority.
TRUSTED_BASE_REVISIONS = frozenset(
    {
        "91c636997a3d62595c65f815319c1342c93ea956",
        "45433013f97a94a8acf94c51a913ff071e6f74b2",
    }
)

RUNNER_SCOPES = (
    "platform/ansible/qualification-runner.yml",
    "platform/ansible/qualification-egress.yml",
    "platform/ansible/roles/qualification_runner_host",
    "platform/ansible/roles/qualification_proxy_client",
    "platform/ansible/roles/qualification_gateway",
    "platform/ansible/ansible.cfg",
    "platform/ansible/requirements.yml",
    "platform/ansible/inventories",
    "docs/project/M1_LINUX_QUALIFICATION_RUNNER.md",
    "platform/terraform/environments/qualification",
    "platform/terraform/modules/hcloud-qualification",
    "tests/test_m1_qualification_runner.py",
)

# Exact base -> result pairs for PR86 lint fixes and the owning PR103 runner fixes.
# This controller policy requires independent review before use. No arbitrary edits
# or Git mode transitions are admitted.
APPROVED_RUNNER_CORRECTIONS = {
    # Canonical locked collection closure from integration 623f0bd via qualified PR94.
    "platform/ansible/requirements.yml": [
        (
            "59b0c0805444b127408bcda2e3ca8e0c2d44e4464e561ba569bdcadea681f7bd",
            "4ea0fac4f26e5120a2cc2a22bd368df19488766af4902c2b7abe497250744dc5",
        ),
    ],
    "platform/ansible/qualification-runner.yml": [
        (
            "a774d2cf9c69a145e0020b9168e3e86b808e167beb2aa074dc03477d5790a16f",
            "bf9d0b99872464c135809bc02df001357ff107e6cc84d9c21e543cdda4b10857",
        ),
        (None, "bf9d0b99872464c135809bc02df001357ff107e6cc84d9c21e543cdda4b10857"),
        (
            "f892477c58e6f4eab1f196a0a0a29a6be4196fa55f1b2ccc63c33efdf708b2f8",
            "bf9d0b99872464c135809bc02df001357ff107e6cc84d9c21e543cdda4b10857",
        ),
        (
            "bf9d0b99872464c135809bc02df001357ff107e6cc84d9c21e543cdda4b10857",
            "bf9d0b99872464c135809bc02df001357ff107e6cc84d9c21e543cdda4b10857",
        ),
    ],
    "platform/ansible/roles/qualification_runner_host/handlers/main.yml": [
        (
            "53db449af078130814f9d2d4535172c959cf96c22b47da9561b82b3517e7306e",
            "5b1f36eb524e1a06a95717c89ebce3546dcacfe55ea598e4c6e2edd0429fab3b",
        ),
        (None, "5b1f36eb524e1a06a95717c89ebce3546dcacfe55ea598e4c6e2edd0429fab3b"),
        (
            "bffac11b59505c56485adf3f930009f52eb9bc823c74b19f0f74b57fdb208474",
            "5b1f36eb524e1a06a95717c89ebce3546dcacfe55ea598e4c6e2edd0429fab3b",
        ),
    ],
    "platform/ansible/roles/qualification_runner_host/tasks/main.yml": [
        (
            "be23a7e8eaa5bf831d308f0d347eb6d0b074b7221bbc5283d7a8e4d98a821928",
            "23e41a18759b2ed0d218ee3a998e9c789c7c7db613de598dbf161f7d06a64cfc",
        ),
        (None, "23e41a18759b2ed0d218ee3a998e9c789c7c7db613de598dbf161f7d06a64cfc"),
        (
            "64423e2fc4f1ca72d930b04143afd31c966c1884167df40d112d85c4b24412c3",
            "23e41a18759b2ed0d218ee3a998e9c789c7c7db613de598dbf161f7d06a64cfc",
        ),
    ],
    "platform/ansible/roles/qualification_proxy_client/handlers/main.yml": [
        (None, "2557b9cd491e79b89ddf4919e54ab2547962ed16098c827855b11ca2e9c2dcc1"),
        (
            "2557b9cd491e79b89ddf4919e54ab2547962ed16098c827855b11ca2e9c2dcc1",
            "2557b9cd491e79b89ddf4919e54ab2547962ed16098c827855b11ca2e9c2dcc1",
        ),
    ],
    "platform/ansible/roles/qualification_proxy_client/tasks/main.yml": [
        (
            "0aff96b9a791e7d9bd9be1f177d0827df027829af1143be5c3f8a482dd10b1fe",
            "b2898a4b81f821fe049dc6685755e6a695befa76166a8ce56613c1f4ef611635",
        ),
        (None, "b2898a4b81f821fe049dc6685755e6a695befa76166a8ce56613c1f4ef611635"),
        (
            "b2898a4b81f821fe049dc6685755e6a695befa76166a8ce56613c1f4ef611635",
            "b2898a4b81f821fe049dc6685755e6a695befa76166a8ce56613c1f4ef611635",
        ),
    ],
    "docs/project/M1_LINUX_QUALIFICATION_RUNNER.md": [
        (
            "501f901a8c4cafa4a3c3b76b278cb541614ad4cf3b2c3a3039db2a799c66aeed",
            "94e8d667b7b12fbb41ee3ebef17d6165428297ba706e45a3d4998dc396d28669",
        ),
        (None, "94e8d667b7b12fbb41ee3ebef17d6165428297ba706e45a3d4998dc396d28669"),
        (
            "349021f9ca8bcb416ac787931e8fca76d3db9e1e4ae88fc64d2dac0201ae3f86",
            "94e8d667b7b12fbb41ee3ebef17d6165428297ba706e45a3d4998dc396d28669",
        ),
        (
            "94c0c79304ee7edbdc193b5089f6de83e42757c0cc6c5cd8f8ff6b08a0609e30",
            "94e8d667b7b12fbb41ee3ebef17d6165428297ba706e45a3d4998dc396d28669",
        ),
        (
            "a836d47a92e90a50eb7bc48b8de51deef07da2711f495288ed91fc0821d313b1",
            "94e8d667b7b12fbb41ee3ebef17d6165428297ba706e45a3d4998dc396d28669",
        ),
    ],
    "platform/ansible/roles/qualification_runner_host/defaults/main.yml": [
        (
            "9792929d5e51a0aa643fa9dfe79cf39f4dd660280607eba7f2de30490915963e",
            "790b38a52afda8e29978b6cbeb437a72258b9754d11204a98a4b3119a69d1dbc",
        ),
        (None, "790b38a52afda8e29978b6cbeb437a72258b9754d11204a98a4b3119a69d1dbc"),
        (
            "32e619002923f76754b721baf692d08ef023f244b368ec3fe5fd38abe9c3838c",
            "790b38a52afda8e29978b6cbeb437a72258b9754d11204a98a4b3119a69d1dbc",
        ),
    ],
    "platform/terraform/environments/qualification/README.md": [
        (
            "982a2e529d8ba7ca9c763b889f7b2fa7a6bd1703372a6b77a2471a52c72666c9",
            "cf0017b53677d9151894c33a2ca1c226c191b448644acc3caa6c397357a64e51",
        ),
        (None, "cf0017b53677d9151894c33a2ca1c226c191b448644acc3caa6c397357a64e51"),
        (
            "271392b42e7c7397f0dc18aa4f727f962a4391beae15139204c233d0838ec959",
            "cf0017b53677d9151894c33a2ca1c226c191b448644acc3caa6c397357a64e51",
        ),
        (
            "83631bf0d5f13865f071e705e5380792ec05da30b33fa3582d09dd4c552e4096",
            "cf0017b53677d9151894c33a2ca1c226c191b448644acc3caa6c397357a64e51",
        ),
        (
            "cf0017b53677d9151894c33a2ca1c226c191b448644acc3caa6c397357a64e51",
            "cf0017b53677d9151894c33a2ca1c226c191b448644acc3caa6c397357a64e51",
        ),
    ],
    "tests/test_m1_qualification_runner.py": [
        (
            "80bd9a9a87cfd0bbdfcc94e340fd8a949e8ae69adadb0c51c42fb39677a7c0cd",
            "91d70b5824af58ed65abd32857f019a5a1221ae61f591aa055457a3e5deedea3",
        ),
        (None, "91d70b5824af58ed65abd32857f019a5a1221ae61f591aa055457a3e5deedea3"),
        (
            "d6e97151939aaf0131e42460c1f582d3233063c5fcef96e0f051e54676572985",
            "91d70b5824af58ed65abd32857f019a5a1221ae61f591aa055457a3e5deedea3",
        ),
        (
            "1c7eabbfff8d2c759ff32777c5014ace4ae747cd6a6f55bcbc745a013e5ef6de",
            "91d70b5824af58ed65abd32857f019a5a1221ae61f591aa055457a3e5deedea3",
        ),
    ],
    "platform/terraform/environments/qualification/main.tf": [
        (
            "4888ab6014aafa5a161b0ba41ff118b1a8ee98e5ae836012e5687290f293ad01",
            "8c9b00b4b30c4e12bea1efa4a34860ec2d6d19eece906d26e49a549ad22e9237",
        ),
        (None, "8c9b00b4b30c4e12bea1efa4a34860ec2d6d19eece906d26e49a549ad22e9237"),
        (
            "8c9b00b4b30c4e12bea1efa4a34860ec2d6d19eece906d26e49a549ad22e9237",
            "8c9b00b4b30c4e12bea1efa4a34860ec2d6d19eece906d26e49a549ad22e9237",
        ),
    ],
    "platform/terraform/modules/hcloud-qualification/main.tf": [
        (
            "222441ee7c7d7a521a5eff4ce11281686387ad7691fb4c48cd70e49e262c7068",
            "11f36ebbebf24bbb407a728c1dffcf66abfc6ee62df4d7de3daaed7815f2f1c2",
        ),
        (None, "11f36ebbebf24bbb407a728c1dffcf66abfc6ee62df4d7de3daaed7815f2f1c2"),
        (
            "11f36ebbebf24bbb407a728c1dffcf66abfc6ee62df4d7de3daaed7815f2f1c2",
            "11f36ebbebf24bbb407a728c1dffcf66abfc6ee62df4d7de3daaed7815f2f1c2",
        ),
    ],
}


def validate_runner_index(entries: str) -> None:
    for entry in filter(None, entries.split("\0")):
        metadata, path = entry.split("\t", 1)
        mode, _object_id, stage = metadata.split()
        if mode not in {"100644", "100755"} or stage != "0":
            raise AssertionError("unapproved runner index entry")


def validate_runner_changes(before: dict[str, bytes | None], after: dict[str, bytes | None]) -> None:
    for path in before.keys() | after.keys():
        old, new = before.get(path), after.get(path)
        if old == new:
            continue
        pair = (
            hashlib.sha256(old).hexdigest() if old is not None else None,
            hashlib.sha256(new).hexdigest() if new is not None else None,
        )
        if pair not in APPROVED_RUNNER_CORRECTIONS.get(path, ()):
            raise AssertionError("unapproved base-relative runner change")


def git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    # Resolve before entering candidate cwd. Relative PATH entries and aliases
    # into candidate-controlled directories cannot supply the controller's Git.
    candidate = root.resolve()
    trusted_paths = []
    for entry in os.environ.get("PATH", os.defpath).split(os.pathsep):
        directory = Path(entry)
        if not directory.is_absolute():
            continue
        directory = directory.resolve()
        if directory.is_relative_to(candidate):
            continue
        trusted_paths.append(str(directory))
    env["PATH"] = os.pathsep.join(trusted_paths)
    executable = shutil.which("git", path=env["PATH"])
    if not executable or Path(executable).resolve().is_relative_to(candidate):
        raise AssertionError("trusted Git executable unavailable outside candidate")
    executable = str(Path(executable).resolve(strict=True))
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_NO_REPLACE_OBJECTS="1")
    return subprocess.run(
        [executable, "--no-replace-objects", *args], cwd=root, env=env, capture_output=True, check=check
    )


def validate_repository(root: Path, base: str, head: str | None = None) -> None:
    if git(root, "for-each-ref", "--format=%(refname)", "refs/replace/").stdout.strip():
        raise AssertionError("Git replacement refs are forbidden for runner admission")
    if not re.fullmatch(r"[0-9a-f]{40}", base):
        raise AssertionError("runner admission requires an immutable base SHA")
    git(root, "cat-file", "-e", f"{base}^{{commit}}")
    if head is not None:
        if not re.fullmatch(r"[0-9a-f]{40}", head):
            raise AssertionError("runner admission requires an immutable head SHA")
        if git(root, "rev-parse", "HEAD").stdout.decode().strip() != head:
            raise AssertionError("runner admission head differs from selected SHA")
        if git(root, "status", "--porcelain=v1", "--untracked-files=all").stdout:
            raise AssertionError("runner admission requires a clean checkout")
    entries = git(root, "ls-files", "--stage", "-z").stdout.decode(errors="surrogateescape")
    for entry in filter(None, entries.split("\0")):
        _metadata, path = entry.split("\t", 1)
        if any(scope.startswith(path + "/") for scope in RUNNER_SCOPES):
            raise AssertionError("unapproved runner ancestor index entry")
        if any(path == scope or path.startswith(scope + "/") for scope in RUNNER_SCOPES):
            validate_runner_index(entry)

    changed = git(
        root, "diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z", base, "--", *RUNNER_SCOPES
    ).stdout
    untracked = git(root, "ls-files", "--others", "--exclude-standard", "-z", "--", *RUNNER_SCOPES).stdout
    before, after = {}, {}
    for raw in set(filter(None, (changed + untracked).split(b"\0"))):
        path = os.fsdecode(raw)
        original = git(root, "show", f"{base}:{path}", check=False)
        before[path] = original.stdout if original.returncode == 0 else None
        parent = root
        for component in Path(path).parts[:-1]:
            parent = parent / component
            if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
                raise AssertionError("unapproved runner path ancestor")
        current = root / path
        if current.is_symlink() or (current.exists() and not current.is_file()):
            raise AssertionError("unapproved runner file type")
        tree_entry = git(root, "ls-tree", "-z", base, "--", f":(literal){path}").stdout
        old_mode = tree_entry.split(b" ", 1)[0].decode() if tree_entry else None
        new_mode = ("100755" if current.stat().st_mode & 0o100 else "100644") if current.is_file() else None
        if old_mode != new_mode and (old_mode, new_mode) != (None, "100644"):
            raise AssertionError("unapproved runner mode change")
        after[path] = current.read_bytes() if current.is_file() else None
    validate_runner_changes(before, after)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    try:
        if args.base not in TRUSTED_BASE_REVISIONS:
            raise AssertionError("base revision is not admitted by trusted controller policy")
        validate_repository(args.repo, args.base, args.head)
    except (AssertionError, OSError, subprocess.CalledProcessError) as error:
        reason = str(error) if isinstance(error, AssertionError) else "repository inspection failed"
        print(f"FAIL trusted runner admission: {reason}")
        return 1
    print(f"PASS trusted runner admission base={args.base} head={args.head}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
