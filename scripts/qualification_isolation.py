"""Credential-free mount and process boundary for PR-head qualification.

This launcher is used only by a verified exact-base controller. It grants the
qualification child a read-only target checkout, fresh writable evidence area,
and read-only public tool inputs, without the owner's home, process table or network.
An unavailable or unpinned sandbox stops qualification before child execution.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import stat
import subprocess
import tempfile
import time
from pathlib import Path

_BWRAP_PATH_ENV = "ECOMMERCE_QUALIFICATION_BWRAP_PATH"
_BWRAP_DIGEST_ENV = "ECOMMERCE_QUALIFICATION_BWRAP_SHA256"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SYSTEM_DIRS = ("/usr", "/bin", "/lib", "/lib64")
_ETC_PUBLIC_FILES = (
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/hosts",
)
_PRIVATE_HOME = "/tmp/qualification-home"
_CHILD_BOOTSTRAP = (
    "import os,sys;"
    "marker,token,*command=sys.argv[1:];"
    "fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);"
    "os.write(fd,token.encode('ascii'));os.fsync(fd);os.close(fd);"
    "os.execvpe(command[0],command,dict(os.environ))"
)
_CHILD_TIMEOUT_SECONDS = 7200
_FORBIDDEN_BIND_ROOTS = {
    "/dev",
    "/etc",
    "/mnt",
    "/proc",
    "/run",
    "/sys",
    "/usr",
    "/bin",
    "/lib",
    "/lib64",
}


class QualificationIsolationError(RuntimeError):
    """The credential isolation boundary cannot be established."""


def _canonical_directory(value: str | Path, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path == Path("/"):
        raise QualificationIsolationError(f"{label} must be an absolute directory")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise QualificationIsolationError(f"{label} is unavailable") from exc
    if resolved != path or not path.is_dir():
        raise QualificationIsolationError(f"{label} is redirected or unavailable")
    if "/" + path.parts[1] in _FORBIDDEN_BIND_ROOTS:
        raise QualificationIsolationError(
            f"{label} is outside permitted checkout paths"
        )
    return path


def _verified_bwrap_descriptor() -> tuple[int, Path]:
    raw_path = os.environ.get(_BWRAP_PATH_ENV, "")
    digest = os.environ.get(_BWRAP_DIGEST_ENV, "")
    path = Path(raw_path)
    if not raw_path or not path.is_absolute() or _DIGEST.fullmatch(digest) is None:
        raise QualificationIsolationError(
            "pinned qualification sandbox is not configured"
        )
    try:
        for component in (path, *path.parents):
            metadata = os.lstat(component)
            if (
                stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_mode & 0o022
            ):
                raise QualificationIsolationError(
                    "qualification sandbox path is not root-owned and immutable"
                )
    except OSError as exc:
        raise QualificationIsolationError(
            "pinned qualification sandbox is unavailable"
        ) from exc
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or metadata.st_nlink < 1
            or not os.access(path, os.X_OK)
        ):
            raise QualificationIsolationError(
                "qualification sandbox executable is unsafe"
            )
        with os.fdopen(os.dup(descriptor), "rb") as source:
            actual_digest = hashlib.file_digest(source, "sha256").hexdigest()
        if actual_digest != digest:
            raise QualificationIsolationError("qualification sandbox digest differs")
        return descriptor, path
    except OSError as exc:
        raise QualificationIsolationError(
            "pinned qualification sandbox is unavailable"
        ) from exc
    finally:
        if descriptor >= 0 and (
            "actual_digest" not in locals() or actual_digest != digest
        ):
            os.close(descriptor)


def _trusted_checkout(
    target_root: Path, base_sha: str, head_sha: str
) -> tuple[Path | None, dict[str, str]]:
    names = (
        "REPOCTL_TRUSTED_WRAPPER",
        "REPOCTL_TRUSTED_CONTROLLER",
        "REPOCTL_TRUSTED_POLICY_ROOT",
        "REPOCTL_TRUSTED_PR_NUMBER",
    )
    values = {name: os.environ.get(name, "").strip() for name in names}
    if not any(values.values()):
        return None, {}
    if not all(values.values()) or not values["REPOCTL_TRUSTED_PR_NUMBER"].isdigit():
        raise QualificationIsolationError("trusted qualification binding is incomplete")
    if int(values["REPOCTL_TRUSTED_PR_NUMBER"]) < 1:
        raise QualificationIsolationError("trusted qualification PR number is invalid")
    trusted_root = _canonical_directory(
        values["REPOCTL_TRUSTED_POLICY_ROOT"], "trusted checkout"
    )
    if trusted_root == target_root or target_root.is_relative_to(trusted_root):
        raise QualificationIsolationError("trusted checkout overlaps target checkout")
    wrapper = trusted_root / "scripts/repository_delivery.py"
    controller = trusted_root / "scripts/repoctl.py"
    if (
        Path(values["REPOCTL_TRUSTED_WRAPPER"]) != wrapper
        or Path(values["REPOCTL_TRUSTED_CONTROLLER"]) != controller
        or not wrapper.is_file()
        or wrapper.is_symlink()
        or not controller.is_file()
        or controller.is_symlink()
    ):
        raise QualificationIsolationError("trusted controller paths are invalid")
    return trusted_root, {
        "REPOCTL_TRUSTED_WRAPPER": str(wrapper),
        "REPOCTL_TRUSTED_CONTROLLER": str(controller),
        "REPOCTL_TRUSTED_POLICY_ROOT": str(trusted_root),
        "REPOCTL_TRUSTED_BASE_SHA": base_sha,
        "REPOCTL_TRUSTED_TARGET_ROOT": str(target_root),
        "REPOCTL_TRUSTED_HEAD_SHA": head_sha,
        "REPOCTL_TRUSTED_PR_NUMBER": values["REPOCTL_TRUSTED_PR_NUMBER"],
    }


def _trusted_validator_available(trusted_root: Path) -> bool:
    # This is only an early availability check. Authority comes from executing
    # the exact-base controller in the second isolated pass and requiring rc=0.
    controller = trusted_root / "scripts/repoctl.py"
    try:
        metadata = controller.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 5_000_000:
            return False
        return b"qualification-proof-validate-only" in controller.read_bytes()
    except OSError:
        return False


def _private_environment(
    base_sha: str, head_sha: str, force_full: bool, trusted: dict[str, str]
) -> dict[str, str]:
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": _PRIVATE_HOME,
        "XDG_CONFIG_HOME": f"{_PRIVATE_HOME}/config",
        "XDG_CACHE_HOME": f"{_PRIVATE_HOME}/cache",
        "XDG_DATA_HOME": f"{_PRIVATE_HOME}/data",
        "GH_CONFIG_DIR": f"{_PRIVATE_HOME}/config/gh",
        "GNUPGHOME": f"{_PRIVATE_HOME}/gnupg",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TMPDIR": "/tmp",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GH_PROMPT_DISABLED": "1",
        "ECOMMERCE_QUALIFICATION_SANDBOX": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "BASE": base_sha,
        "HEAD": head_sha,
        **trusted,
    }
    if force_full:
        environment["ECOMMERCE_FORCE_FULL_QUALIFICATION"] = "1"
    return environment


def _mount_parents(paths: list[Path]) -> list[str]:
    fixed = {"/", "/usr", "/bin", "/lib", "/lib64", "/etc", "/dev", "/proc", "/tmp"}
    parents = {
        ancestor
        for path in paths
        for ancestor in path.parents
        if str(ancestor) not in fixed
    }
    return [
        argument
        for parent in sorted(parents, key=lambda item: (len(item.parts), str(item)))
        for argument in ("--dir", str(parent))
    ]


def _isolated_git_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "XDG_CONFIG_HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _git_shadow_command(
    root: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    output_file: object | None = None,
) -> bytes:
    command = [
        "/usr/bin/git",
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "diff.external=",
        "-C",
        str(root),
        *arguments,
    ]
    try:
        result = subprocess.run(
            command,
            env=_isolated_git_environment(),
            stdin=subprocess.DEVNULL if input_bytes is None else None,
            input=input_bytes,
            stdout=output_file if output_file is not None else subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise QualificationIsolationError(
            "clean qualification Git view could not be built"
        ) from exc
    if result.returncode != 0:
        raise QualificationIsolationError(
            "clean qualification Git view could not be built"
        )
    return result.stdout if output_file is None else b""


def _verified_system_interpreter(command: list[str], target: Path) -> str:
    raw = command[0]
    path = Path(raw)
    if not path.is_absolute() or path.is_relative_to(target):
        raise QualificationIsolationError(
            "qualification interpreter must be outside target checkout"
        )
    try:
        for component in (path, *path.parents):
            metadata = os.lstat(component)
            if metadata.st_uid != 0 or (
                not stat.S_ISLNK(metadata.st_mode) and metadata.st_mode & 0o022
            ):
                raise QualificationIsolationError(
                    "qualification interpreter path is not system-owned"
                )
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise QualificationIsolationError(
            "qualification interpreter is unavailable"
        ) from exc
    if (
        not resolved.is_relative_to("/usr") and not resolved.is_relative_to("/bin")
    ) or (
        not raw.startswith(
            ("/usr/bin/python3", "/usr/local/bin/python3", "/bin/python3")
        )
        or not resolved.name.startswith("python3")
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or not os.access(path, os.X_OK)
    ):
        raise QualificationIsolationError(
            "qualification interpreter is not a trusted system Python"
        )
    return raw


def _safe_tracked_path(raw: bytes) -> Path:
    try:
        path = os.fsdecode(raw)
    except UnicodeError as exc:
        raise QualificationIsolationError(
            "tracked qualification path is invalid"
        ) from exc
    parts = path.split("/")
    if (
        not path
        or path.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
        or parts[0] in {".git", ".context", ".venv"}
    ):
        raise QualificationIsolationError(
            "tracked qualification path collides with sandbox metadata"
        )
    return Path(*parts)


def _prepare_clean_shadow(
    source: Path,
    *,
    base_sha: str,
    head_sha: str,
    destination: Path,
) -> None:
    """Rebuild a checkout solely from verified committed blobs and reachable objects."""
    if (
        _git_shadow_command(source, "rev-parse", "--verify", "HEAD").strip()
        != head_sha.encode()
    ):
        raise QualificationIsolationError("qualification source HEAD is not pinned")
    if _git_shadow_command(source, "cat-file", "-t", base_sha).strip() != b"commit":
        raise QualificationIsolationError("qualification base commit is missing")
    tree = _git_shadow_command(source, "ls-tree", "-r", "-l", "-z", head_sha)
    if len(tree) > 10_000_000:
        raise QualificationIsolationError("qualification tree inventory is too large")
    entries: list[tuple[Path, str, int, int]] = []
    names: set[Path] = set()
    total_size = 0
    for record in tree.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, kind, raw_oid, raw_size = metadata.split()
            oid = raw_oid.decode("ascii")
            size = int(raw_size)
        except (ValueError, UnicodeError) as exc:
            raise QualificationIsolationError(
                "qualification tree entry is invalid"
            ) from exc
        name = _safe_tracked_path(raw_path)
        if (
            mode not in {b"100644", b"100755"}
            or kind != b"blob"
            or _SHA.fullmatch(oid) is None
            or size < 0
            or size > 50_000_000
            or name in names
        ):
            raise QualificationIsolationError(
                "qualification tree contains an unsupported entry"
            )
        names.add(name)
        total_size += size
        if total_size > 256_000_000 or len(names) > 100_000:
            raise QualificationIsolationError(
                "qualification tracked tree exceeds sandbox limits"
            )
        entries.append((name, oid, size, 0o755 if mode == b"100755" else 0o644))

    destination.mkdir(mode=0o700)
    for name, oid, size, file_mode in entries:
        payload = _git_shadow_command(source, "cat-file", "blob", oid)
        if (
            len(payload) != size
            or hashlib.sha1(
                b"blob " + str(size).encode("ascii") + b"\0" + payload,
                usedforsecurity=False,
            ).hexdigest()
            != oid
        ):
            raise QualificationIsolationError(
                "qualification tracked blob digest differs"
            )
        output = destination / name
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            with output.open("xb") as file:
                file.write(payload)
            output.chmod(file_mode)
        except OSError as exc:
            raise QualificationIsolationError(
                "qualification tracked tree could not be staged"
            ) from exc

    (destination / ".context").mkdir(mode=0o700)
    git_dir = destination / ".git"
    (git_dir / "objects/pack").mkdir(parents=True)
    (git_dir / "refs/heads").mkdir(parents=True)
    (git_dir / "refs/tags").mkdir(parents=True)
    (git_dir / "HEAD").write_text(head_sha + "\n", encoding="ascii")
    (git_dir / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n"
        "\tbare = false\n\tfilemode = true\n\tlogallrefupdates = false\n",
        encoding="ascii",
    )
    usage = _git_shadow_command(
        source, "rev-list", "--objects", "--disk-usage", base_sha, head_sha
    ).strip()
    if not usage.isdigit() or int(usage) > 512_000_000:
        raise QualificationIsolationError(
            "qualification history exceeds sandbox limits"
        )
    pack_path = destination.parent / f"{destination.name}.pack"
    try:
        with pack_path.open("wb") as pack:
            _git_shadow_command(
                source,
                "pack-objects",
                "--stdout",
                "--revs",
                input_bytes=f"{base_sha}\n{head_sha}\n".encode("ascii"),
                output_file=pack,
            )
        if pack_path.stat().st_size > 512_000_000:
            raise QualificationIsolationError(
                "qualification object pack exceeds sandbox limits"
            )
        with pack_path.open("rb") as pack:
            result = subprocess.run(
                [
                    "/usr/bin/git",
                    "-C",
                    str(destination),
                    "index-pack",
                    "--stdin",
                ],
                stdin=pack,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=_isolated_git_environment(),
                check=False,
                timeout=120,
            )
        if result.returncode != 0:
            raise QualificationIsolationError("qualification object pack is invalid")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise QualificationIsolationError(
            "qualification object pack could not be staged"
        ) from exc
    finally:
        pack_path.unlink(missing_ok=True)
    _git_shadow_command(destination, "read-tree", "HEAD")
    if _git_shadow_command(
        destination, "status", "--porcelain", "--untracked-files=all"
    ).strip():
        raise QualificationIsolationError("qualification tracked shadow is not clean")


def _sandbox_command(
    command: list[str],
    target_root: Path,
    trusted_root: Path | None,
    target_shadow: Path,
    trusted_shadow: Path | None,
    child_env: dict[str, str],
    bwrap_path: Path,
    info_fd: int,
    stage: Path,
) -> list[str]:
    mounted = [target_root]
    if trusted_root is not None:
        mounted.append(trusted_root)
    args = [
        str(bwrap_path),
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-net",
        "--disable-userns",
        "--cap-drop",
        "ALL",
        "--new-session",
        "--die-with-parent",
        "--info-fd",
        str(info_fd),
        "--clearenv",
    ]
    for directory in _SYSTEM_DIRS:
        if Path(directory).is_dir():
            args.extend(("--ro-bind", directory, directory))
    args.extend(("--dir", "/etc"))
    for public_file in _ETC_PUBLIC_FILES:
        candidate = Path(public_file)
        if candidate.is_file() and not candidate.is_symlink():
            args.extend(("--ro-bind", public_file, public_file))
    args.extend(("--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"))
    args.extend(_mount_parents(mounted))
    # Both sources are rebuilt from committed Git blobs. The live checkout,
    # including its ignored files and local Git metadata, is never mounted.
    args.extend(("--ro-bind", str(target_shadow), str(target_root)))
    args.extend(("--bind", str(stage), str(target_root / ".context")))
    if trusted_root is not None:
        if trusted_shadow is None:
            raise QualificationIsolationError("trusted checkout shadow is missing")
        args.extend(("--ro-bind", str(trusted_shadow), str(trusted_root)))
    for directory in (
        _PRIVATE_HOME,
        f"{_PRIVATE_HOME}/config",
        f"{_PRIVATE_HOME}/config/gh",
        f"{_PRIVATE_HOME}/cache",
        f"{_PRIVATE_HOME}/data",
        f"{_PRIVATE_HOME}/gnupg",
    ):
        args.extend(("--dir", directory))
    for name, value in child_env.items():
        args.extend(("--setenv", name, value))
    args.extend(("--chdir", str(target_root), "--", *command))
    return args


def _proof_directory(stage: Path) -> tuple[Path, int]:
    proof = stage / "qualification-isolation"
    if proof.is_symlink():
        raise QualificationIsolationError(
            "qualification start witness directory is redirected"
        )
    try:
        proof.mkdir(mode=0o700)
    except OSError as exc:
        raise QualificationIsolationError(
            "qualification start witness directory is unavailable"
        ) from exc
    if not proof.is_dir() or proof.is_symlink():
        raise QualificationIsolationError(
            "qualification start witness directory is invalid"
        )
    try:
        descriptor = os.open(proof, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise QualificationIsolationError(
            "qualification start witness directory is unavailable"
        ) from exc
    return proof, descriptor


def _child_started(proof_fd: int, name: str, token: str) -> bool:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=proof_fd)
    except OSError:
        return False
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return False
        return os.read(descriptor, 65) == token.encode("ascii")
    finally:
        os.close(descriptor)


def _prepare_target_metadata(target: Path) -> None:
    context = target / ".context"
    for candidate in (
        context,
        target / ".codex",
        target / ".git",
        target / ".git/config",
        target / ".git/logs",
        target / ".git/hooks",
        target / ".git/info",
        target / ".git/FETCH_HEAD",
    ):
        if candidate.is_symlink():
            raise QualificationIsolationError(
                "target qualification metadata is redirected"
            )
    try:
        context.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        raise QualificationIsolationError(
            "target qualification context is unavailable"
        ) from exc
    if not context.is_dir() or context.is_symlink():
        raise QualificationIsolationError("target qualification context is invalid")


def _unique_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate JSON property")
        value[name] = item
    return value


def _staged_document(
    stage: Path, directory: str, head_sha: str, limit: int
) -> bytes | None:
    root_fd = -1
    directory_fd = -1
    file_fd = -1
    try:
        root_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            directory_fd = os.open(
                directory,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=root_fd,
            )
        except FileNotFoundError:
            return None
        try:
            file_fd = os.open(
                f"{head_sha}.json",
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return None
        metadata = os.fstat(file_fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size < 1
            or metadata.st_size > limit
        ):
            raise QualificationIsolationError(
                "staged qualification proof file is invalid"
            )
        raw = os.read(file_fd, limit + 1)
        if len(raw) != metadata.st_size:
            raise QualificationIsolationError("staged qualification proof size changed")
        return raw
    except OSError as exc:
        raise QualificationIsolationError(
            "staged qualification proof is unavailable"
        ) from exc
    finally:
        for descriptor in (file_fd, directory_fd, root_fd):
            if descriptor >= 0:
                os.close(descriptor)


def _publish_document(context: Path, directory: str, name: str, raw: bytes) -> None:
    context_fd = -1
    directory_fd = -1
    temp_name = f".{name}.{secrets.token_hex(12)}.tmp"
    temp_created = False
    try:
        context_fd = os.open(context, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.mkdir(directory, mode=0o700, dir_fd=context_fd)
        except FileExistsError:
            pass
        directory_fd = os.open(
            directory,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=context_fd,
        )
        descriptor = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        temp_created = True
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(raw)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(
            temp_name,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temp_created = False
        os.fsync(directory_fd)
    except OSError as exc:
        raise QualificationIsolationError(
            "qualification proof publication failed"
        ) from exc
    finally:
        if temp_created and directory_fd >= 0:
            try:
                os.unlink(temp_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        if directory_fd >= 0:
            os.close(directory_fd)
        if context_fd >= 0:
            os.close(context_fd)


def _git_exact_metadata(
    target: Path, base_sha: str, head_sha: str
) -> tuple[str, list[str]]:
    # These Git commands read object metadata only. They run with no owner
    # credentials, no global config, no pager, hooks or external diff drivers.
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "XDG_CONFIG_HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    prefix = [
        "/usr/bin/git",
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.ext.allow=never",
        "-C",
        str(target),
    ]

    def query(*arguments: str) -> str:
        try:
            result = subprocess.run(
                [*prefix, *arguments],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise QualificationIsolationError(
                "exact qualification Git metadata is unavailable"
            ) from exc
        if result.returncode != 0 or len(result.stdout) > 1_000_000:
            raise QualificationIsolationError(
                "exact qualification Git metadata is unavailable"
            )
        return result.stdout.strip()

    if query("rev-parse", "--verify", "HEAD") != head_sha:
        raise QualificationIsolationError("qualification checkout HEAD changed")
    commit = query("cat-file", "-p", head_sha)
    first = commit.split("\n", 1)[0]
    if not first.startswith("tree ") or _SHA.fullmatch(first[5:]) is None:
        raise QualificationIsolationError("qualification commit tree is invalid")
    paths = query(
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--name-only",
        "--diff-filter=ACDMRTUXB",
        base_sha,
        head_sha,
        "--",
    )
    return first[5:], sorted(set(filter(None, paths.splitlines())))


def _valid_timestamp(value: object, earliest: float) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        parsed = float(value)
    except (ValueError, OverflowError):
        return False
    now = time.time()
    return (
        math.isfinite(parsed) and max(now - 86400, earliest - 60) <= parsed <= now + 60
    )


def _valid_duration(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        duration = float(value)
    except (ValueError, OverflowError):
        return False
    return math.isfinite(duration) and duration >= 0


def _validate_promotion_pair(
    evidence: object,
    audit: object,
    *,
    base_sha: str,
    head_sha: str,
    tree_sha: str,
    changed_paths: list[str],
    started_epoch: float,
    force_full: bool,
) -> None:
    if type(evidence) is not dict or type(audit) is not dict:
        raise QualificationIsolationError("staged qualification proof is invalid")
    verification = evidence.get("verification")
    records = evidence.get("gates")
    components = evidence.get("affected_components")
    metrics = evidence.get("metrics")
    if (
        evidence.get("schema_version") != 5
        or evidence.get("evidence_kind") != "exact_commit"
        or evidence.get("exact_commit_evidence") is not True
        or evidence.get("status") != "PASS"
        or evidence.get("base_sha") != base_sha
        or evidence.get("head_sha") != head_sha
        or evidence.get("head_tree_sha") != tree_sha
        or evidence.get("changed_paths") != changed_paths
        or not isinstance(evidence.get("base_ref"), str)
        or not evidence["base_ref"]
        or not isinstance(evidence.get("head_ref"), str)
        or not evidence["head_ref"]
        or _DIGEST.fullmatch(str(evidence.get("qualification_identity", ""))) is None
        or not _valid_timestamp(evidence.get("created_at_epoch"), started_epoch)
        or not isinstance(components, list)
        or any(not isinstance(item, str) or not item for item in components)
        or not isinstance(metrics, dict)
        or not isinstance(verification, dict)
        or verification.get("execution_profile") != "full"
        or verification.get("runtime_scope") != []
        or verification.get("mode") not in {"full", "incremental", "promoted-worktree"}
        or (force_full and verification.get("mode") != "full")
        or not isinstance(records, list)
        or not records
    ):
        raise QualificationIsolationError("staged qualification evidence is invalid")

    plan = verification.get("execution_plan")
    if not isinstance(plan, list) or len(plan) != len(records):
        raise QualificationIsolationError("staged qualification gate plan is invalid")
    plan_by_name: dict[str, dict] = {}
    for entry in plan:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("gate"), str)
            or not entry["gate"]
            or entry["gate"] in plan_by_name
            or entry.get("scope") not in {"global", "component"}
            or entry.get("action") not in {"run", "fresh", "reuse", "skip"}
        ):
            raise QualificationIsolationError(
                "staged qualification gate plan is invalid"
            )
        plan_by_name[entry["gate"]] = entry

    names: set[str] = set()
    executed = reused = skipped = 0
    for record in records:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("gate"), str)
            or not record["gate"]
            or record["gate"] in names
            or record["gate"] not in plan_by_name
            or record.get("scope") != plan_by_name[record["gate"]]["scope"]
            or record.get("status") not in {"PASS", "SKIP"}
            or not _valid_duration(record.get("duration_seconds"))
            or not isinstance(record.get("execution"), str)
            or not record["execution"]
        ):
            raise QualificationIsolationError(
                "staged qualification gate record is invalid"
            )
        names.add(record["gate"])
        if (
            record["status"] == "PASS"
            and plan_by_name[record["gate"]]["action"] == "skip"
        ):
            raise QualificationIsolationError(
                "staged qualification gate contradicts its plan"
            )
        if record["status"] == "SKIP":
            if (
                plan_by_name[record["gate"]]["action"] != "skip"
                or record["execution"] != "skipped"
                or not isinstance(record.get("reason"), str)
                or not record["reason"]
            ):
                raise QualificationIsolationError(
                    "staged qualification gate skip is invalid"
                )
            skipped += 1
            continue
        if type(record.get("exit_code")) is not int or record["exit_code"] != 0:
            raise QualificationIsolationError(
                "staged qualification gate exit is invalid"
            )
        if record["execution"] in {"parent-evidence", "reused"}:
            reused += 1
        else:
            if (
                not isinstance(record.get("command"), list)
                or not record["command"]
                or any(not isinstance(part, str) for part in record["command"])
                or not isinstance(record.get("log"), str)
                or not record["log"]
            ):
                raise QualificationIsolationError(
                    "staged qualification gate execution is incomplete"
                )
            executed += 1
    if names != set(plan_by_name):
        raise QualificationIsolationError("staged qualification gate inventory differs")
    if force_full and reused:
        raise QualificationIsolationError("forced full qualification reused a gate")

    inventory = audit.get("inventory")
    safety = audit.get("safety")
    actual_executions: dict[str, int] = {}
    for record in records:
        mode = "skipped" if record["status"] == "SKIP" else record["execution"]
        actual_executions[mode] = actual_executions.get(mode, 0) + 1
    if (
        type(audit.get("schema_version")) is not int
        or audit["schema_version"] != 1
        or audit.get("evidence_status") != "PASS"
        or audit.get("base_sha") != base_sha
        or audit.get("head_sha") != head_sha
        or audit.get("verification_mode") != verification["mode"]
        or not isinstance(inventory, dict)
        or type(inventory.get("failed_gates")) is not int
        or inventory["failed_gates"] != 0
        or any(
            type(inventory.get(key)) is not int or inventory[key] != count
            for key, count in (
                ("executed_gates", executed),
                ("reused_gates", reused),
                ("skipped_gates", skipped),
            )
        )
        or sum((executed, reused, skipped)) != len(records)
        or not isinstance(inventory.get("execution_counts"), dict)
        or inventory["execution_counts"] != actual_executions
        or not isinstance(safety, dict)
        or safety.get("content_cache_authorizes_pass_reuse") is not False
        or safety.get("verdict_reuse_policy") != "exact-direct-parent-only"
        or safety.get("unknown_impact_behavior") != "fail-closed/full-execution"
        or safety.get("tekton_remains_ci_authority") is not True
        or not isinstance(audit.get("critical_path"), dict)
        or not isinstance(audit.get("amdahl_priorities"), list)
        or not isinstance(audit.get("cache_layers"), list)
        or not isinstance(audit.get("recommendations"), list)
    ):
        raise QualificationIsolationError("staged qualification audit is invalid")
    for key, count in (
        ("executed_gates", executed),
        ("reused_gates", reused),
        ("skipped_gates", skipped),
    ):
        if type(metrics.get(key)) is not int or metrics[key] != count:
            raise QualificationIsolationError(
                "staged qualification metrics are inconsistent"
            )


def _promote_proofs(
    stage: Path,
    target: Path,
    trusted_root: Path | None,
    base_sha: str,
    head_sha: str,
    started_epoch: float,
    force_full: bool,
    expected_digests: tuple[str, str],
) -> dict[str, str] | None:
    raw_evidence = _staged_document(stage, "evidence", head_sha, 10_000_000)
    raw_audit = _staged_document(stage, "performance", head_sha, 2_000_000)
    if raw_evidence is None and raw_audit is None:
        return None
    if trusted_root is None:
        raise QualificationIsolationError(
            "unbound local qualification cannot promote authoritative proofs"
        )
    if raw_evidence is None or raw_audit is None:
        raise QualificationIsolationError(
            "qualification proof and audit must be published together"
        )
    if (
        hashlib.sha256(raw_evidence).hexdigest(),
        hashlib.sha256(raw_audit).hexdigest(),
    ) != expected_digests:
        raise QualificationIsolationError(
            "staged qualification proof changed during trusted validation"
        )
    try:
        evidence = json.loads(raw_evidence, object_pairs_hook=_unique_object_pairs)
        audit = json.loads(raw_audit, object_pairs_hook=_unique_object_pairs)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise QualificationIsolationError(
            "staged qualification proof is malformed"
        ) from exc
    # Structural checks reject minimal synthetic PASS documents. The separate
    # exact-base controller still verifies policy-derived complete gate inventory.
    if type(evidence) is not dict or type(audit) is not dict:
        raise QualificationIsolationError("staged qualification proof is invalid")
    if (
        evidence.get("base_sha") != base_sha
        or evidence.get("head_sha") != head_sha
        or audit.get("base_sha") != base_sha
        or audit.get("head_sha") != head_sha
    ):
        raise QualificationIsolationError(
            "staged qualification proof binding is invalid"
        )
    tree_sha, changed_paths = _git_exact_metadata(target, base_sha, head_sha)
    _validate_promotion_pair(
        evidence,
        audit,
        base_sha=base_sha,
        head_sha=head_sha,
        tree_sha=tree_sha,
        changed_paths=changed_paths,
        started_epoch=started_epoch,
        force_full=force_full,
    )
    context = target / ".context"
    _publish_document(context, "evidence", f"{head_sha}.json", raw_evidence)
    _publish_document(context, "performance", f"{head_sha}.json", raw_audit)
    return {
        "head_tree_sha": tree_sha,
        "evidence_sha256": hashlib.sha256(raw_evidence).hexdigest(),
        "audit_sha256": hashlib.sha256(raw_audit).hexdigest(),
    }


def _run_sandbox_pass(
    command: list[str],
    *,
    target: Path,
    trusted_root: Path | None,
    child_env: dict[str, str],
    descriptor: int,
    bwrap_path: Path,
    stage: Path,
    target_shadow: Path,
    trusted_shadow: Path | None,
    proof_fd: int,
    capture: bool,
) -> tuple[subprocess.CompletedProcess[str], dict[str, int]]:
    token = secrets.token_hex(24)
    marker_name = f"{token}.ready"
    marker = target / ".context/qualification-isolation" / marker_name
    bootstrap_command = [
        "/usr/bin/python3",
        "-I",
        "-c",
        _CHILD_BOOTSTRAP,
        str(marker),
        token,
        *command,
    ]
    info_read = -1
    info_write = -1
    try:
        info_read, info_write = os.pipe()
        sandbox = _sandbox_command(
            bootstrap_command,
            target,
            trusted_root,
            target_shadow,
            trusted_shadow,
            child_env,
            bwrap_path,
            info_write,
            stage,
        )
        completed = subprocess.run(
            sandbox,
            executable=f"/proc/self/fd/{descriptor}",
            pass_fds=(descriptor, info_write),
            close_fds=True,
            cwd=target,
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            text=True,
            check=False,
            timeout=_CHILD_TIMEOUT_SECONDS,
        )
        os.close(info_write)
        info_write = -1
        with os.fdopen(info_read, "rb") as witness:
            info_read = -1
            raw = witness.read(8193)
        try:
            report = json.loads(raw)
        except (UnicodeError, ValueError, TypeError) as exc:
            raise QualificationIsolationError(
                "qualification sandbox did not establish its namespaces"
            ) from exc
        expected = (
            "child-pid",
            "ipc-namespace",
            "mnt-namespace",
            "net-namespace",
            "pid-namespace",
            "uts-namespace",
        )
        if (
            len(raw) > 8192
            or type(report) is not dict
            or any(
                type(report.get(name)) is not int or report[name] < 1
                for name in expected
            )
            or not _child_started(proof_fd, marker_name, token)
        ):
            raise QualificationIsolationError(
                "qualification sandbox did not start its isolated child"
            )
        return completed, report
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise QualificationIsolationError(
            "qualification sandbox could not complete"
        ) from exc
    finally:
        if info_write >= 0:
            os.close(info_write)
        if info_read >= 0:
            os.close(info_read)
        try:
            os.unlink(marker_name, dir_fd=proof_fd)
        except FileNotFoundError:
            pass


def run_isolated_qualification(
    command: list[str],
    *,
    target_root: Path,
    base_sha: str,
    head_sha: str,
    force_full: bool,
    capture: bool,
) -> subprocess.CompletedProcess[str]:
    """Run exact-SHA qualification and trusted validation in separate sandboxes.

    Proofs remain in an isolated staging directory until an exact-base
    controller validates them after the qualification namespace has exited.
    """
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(part, str) or "\0" in part for part in command)
        or _SHA.fullmatch(base_sha) is None
        or _SHA.fullmatch(head_sha) is None
        or type(force_full) is not bool
        or type(capture) is not bool
    ):
        raise QualificationIsolationError("qualification command or SHA is invalid")
    started_epoch = time.time()
    target = _canonical_directory(target_root, "target checkout")
    _prepare_target_metadata(target)
    trusted_root, trusted_env = _trusted_checkout(target, base_sha, head_sha)
    if trusted_root is not None and not _trusted_validator_available(trusted_root):
        raise QualificationIsolationError(
            "trusted base controller lacks validate-only capability"
        )
    child_env = _private_environment(base_sha, head_sha, force_full, trusted_env)
    descriptor, bwrap_path = _verified_bwrap_descriptor()
    try:
        interpreter = _verified_system_interpreter(command, target)
        with tempfile.TemporaryDirectory(
            prefix="ecommerce-qualification-context-"
        ) as temporary:
            temporary_root = Path(temporary)
            stage = temporary_root / "context"
            stage.mkdir(mode=0o700)
            target_shadow = temporary_root / "target-view"
            _prepare_clean_shadow(
                target,
                base_sha=base_sha,
                head_sha=head_sha,
                destination=target_shadow,
            )
            trusted_shadow = None
            if trusted_root is not None:
                trusted_shadow = temporary_root / "trusted-view"
                _prepare_clean_shadow(
                    trusted_root,
                    base_sha=base_sha,
                    head_sha=base_sha,
                    destination=trusted_shadow,
                )
            _, proof_fd = _proof_directory(stage)
            try:
                first, first_report = _run_sandbox_pass(
                    command,
                    target=target,
                    trusted_root=trusted_root,
                    child_env=child_env,
                    descriptor=descriptor,
                    bwrap_path=bwrap_path,
                    stage=stage,
                    target_shadow=target_shadow,
                    trusted_shadow=trusted_shadow,
                    proof_fd=proof_fd,
                    capture=capture,
                )
                if first.returncode != 0:
                    return first
                raw_evidence = _staged_document(stage, "evidence", head_sha, 10_000_000)
                raw_audit = _staged_document(stage, "performance", head_sha, 2_000_000)
                if raw_evidence is None and raw_audit is None:
                    return first
                if trusted_root is None:
                    raise QualificationIsolationError(
                        "unbound local qualification cannot promote authoritative proofs"
                    )
                if raw_evidence is None or raw_audit is None:
                    raise QualificationIsolationError(
                        "qualification proof and audit must be published together"
                    )
                expected_digests = (
                    hashlib.sha256(raw_evidence).hexdigest(),
                    hashlib.sha256(raw_audit).hexdigest(),
                )
                validator = [
                    interpreter,
                    "-I",
                    str(trusted_root / "scripts/repoctl.py"),
                    "qualification-proof-validate-only",
                    "--base",
                    base_sha,
                ]
                second, second_report = _run_sandbox_pass(
                    validator,
                    target=target,
                    trusted_root=trusted_root,
                    child_env=child_env,
                    descriptor=descriptor,
                    bwrap_path=bwrap_path,
                    stage=stage,
                    target_shadow=target_shadow,
                    trusted_shadow=trusted_shadow,
                    proof_fd=proof_fd,
                    capture=True,
                )
                if second.returncode != 0:
                    raise QualificationIsolationError(
                        "trusted qualification proof validation failed"
                    )
                promoted = _promote_proofs(
                    stage,
                    target,
                    trusted_root,
                    base_sha,
                    head_sha,
                    started_epoch,
                    force_full,
                    expected_digests,
                )
                if promoted is None:
                    raise QualificationIsolationError(
                        "trusted qualification proof disappeared"
                    )
                first.qualification_isolation_receipt = {
                    "schema_version": 1,
                    "base_sha": base_sha,
                    "head_sha": head_sha,
                    **promoted,
                    "bwrap_sha256": os.environ[_BWRAP_DIGEST_ENV],
                    "child_pid": first_report["child-pid"],
                    "namespace_witness": True,
                    "validator_child_pid": second_report["child-pid"],
                    "validator_namespace_witness": True,
                    "trusted_controller": str(trusted_root / "scripts/repoctl.py"),
                    "validation": "trusted-base-validate-only-v1",
                }
                return first
            finally:
                os.close(proof_fd)
    except OSError as exc:
        raise QualificationIsolationError(
            "qualification context staging failed"
        ) from exc
    finally:
        os.close(descriptor)
