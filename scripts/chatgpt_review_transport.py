#!/usr/bin/env python3
"""Explicit, pinned command transport for non-authoritative ChatGPT reviews.

The configured executable owns remote submission and must deduplicate submit
by idempotency_key even if the caller dies before saving the submission ID.
It receives one JSON object on stdin and returns one JSON object on stdout.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_MAX_REQUEST_BYTES = 65_536
_MAX_REPLY_BYTES = 16_384
_MAX_HANDOFF_BYTES = 8_192
_MAX_RESULT_BYTES = 8_192
_TIMEOUT_SECONDS = 30


class ReviewTransportError(RuntimeError):
    """The configured transport is unavailable or returned an invalid reply."""


@dataclass(frozen=True, slots=True)
class TransportResolution:
    state: str
    backend: str
    transport: CommandReviewTransport | None
    reason: str


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


class CommandReviewTransport:
    """Invoke one explicitly configured and SHA-256 pinned executable."""

    def __init__(self, command: Path, sha256: str) -> None:
        self.command = Path(command)
        self.sha256 = sha256
        self._verify_command()

    def _open_verified_command(self) -> int:
        path = self.command
        if (
            not path.is_absolute()
            or any(component.is_symlink() for component in (path, *path.parents))
            or _DIGEST.fullmatch(self.sha256) is None
        ):
            raise ReviewTransportError(
                "review transport command configuration is invalid"
            )
        descriptor = -1
        verified = False
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or not os.access(path, os.X_OK)
                or metadata.st_mode & 0o022
            ):
                raise ReviewTransportError("review transport command is unsafe")
            with os.fdopen(os.dup(descriptor), "rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            os.lseek(descriptor, 0, os.SEEK_SET)
            if digest != self.sha256:
                raise ReviewTransportError("review transport command digest differs")
            verified = True
            return descriptor
        except OSError as exc:
            raise ReviewTransportError(
                "review transport command is unavailable"
            ) from exc
        finally:
            if descriptor >= 0 and not verified:
                os.close(descriptor)

    def _verify_command(self) -> None:
        descriptor = self._open_verified_command()
        os.close(descriptor)

    def _invoke(self, operation: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            message = (
                json.dumps(
                    {"schema_version": 1, "operation": operation, **payload},
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ).encode("ascii")
                + b"\n"
            )
            if len(message) > _MAX_REQUEST_BYTES:
                raise ReviewTransportError(
                    "review transport request exceeds byte limit"
                )
        except (UnicodeError, ValueError, TypeError) as exc:
            raise ReviewTransportError("review transport request is malformed") from exc
        descriptor = self._open_verified_command()
        try:
            completed = self._run_bounded(descriptor, message)
        finally:
            os.close(descriptor)
        try:
            reply = json.loads(
                completed.decode("utf-8", errors="strict"),
                object_pairs_hook=_object_pairs,
            )
        except (UnicodeError, ValueError, TypeError) as exc:
            raise ReviewTransportError("review transport reply is malformed") from exc
        if type(reply) is not dict:
            raise ReviewTransportError("review transport reply is not an object")
        return reply

    def _run_bounded(self, descriptor: int, message: bytes) -> bytes:
        process: subprocess.Popen[bytes] | None = None
        selector = selectors.DefaultSelector()
        output = bytearray()
        deadline = time.monotonic() + _TIMEOUT_SECONDS
        try:
            process = subprocess.Popen(
                [str(self.command)],
                executable=f"/proc/self/fd/{descriptor}",
                pass_fds=(descriptor,),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
            )
            assert process.stdin is not None and process.stdout is not None
            in_fd = process.stdin.fileno()
            out_fd = process.stdout.fileno()
            os.set_blocking(in_fd, False)
            os.set_blocking(out_fd, False)
            selector.register(in_fd, selectors.EVENT_WRITE)
            selector.register(out_fd, selectors.EVENT_READ)
            sent = 0
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ReviewTransportError("review transport command timed out")
                ready = selector.select(remaining)
                if not ready:
                    raise ReviewTransportError("review transport command timed out")
                for key, _ in ready:
                    if key.fd == in_fd:
                        try:
                            sent += os.write(in_fd, message[sent:])
                        except BrokenPipeError:
                            sent = len(message)
                        if sent == len(message):
                            selector.unregister(in_fd)
                            process.stdin.close()
                    else:
                        chunk = os.read(out_fd, 4096)
                        if chunk:
                            output.extend(chunk)
                            if len(output) > _MAX_REPLY_BYTES:
                                raise ReviewTransportError(
                                    "review transport reply exceeds byte limit"
                                )
                        else:
                            selector.unregister(out_fd)
                            process.stdout.close()
            remaining = max(0, deadline - time.monotonic())
            if process.wait(timeout=remaining) != 0:
                raise ReviewTransportError("review transport command failed")
            if not output:
                raise ReviewTransportError("review transport reply is empty")
            return bytes(output)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReviewTransportError("review transport invocation failed") from exc
        finally:
            selector.close()
            if process is not None:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
                if process.stdout is not None and not process.stdout.closed:
                    process.stdout.close()

    def submit(
        self, request: Mapping[str, Any], *, idempotency_key: str
    ) -> Mapping[str, Any]:
        if (
            type(idempotency_key) is not str
            or _DIGEST.fullmatch(idempotency_key) is None
        ):
            raise ReviewTransportError("review transport identity is invalid")
        handoff = request.get("handoff")
        if type(handoff) is not str:
            raise ReviewTransportError("review transport handoff is invalid")
        try:
            handoff_bytes = handoff.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ReviewTransportError("review transport handoff is invalid") from exc
        if not 0 < len(handoff_bytes) <= _MAX_HANDOFF_BYTES:
            raise ReviewTransportError("review transport handoff exceeds byte limit")
        reply = self._invoke(
            "submit", {"idempotency_key": idempotency_key, "request": dict(request)}
        )
        if (
            set(reply) != {"submission_id"}
            or type(reply["submission_id"]) is not str
            or not 0 < len(reply["submission_id"]) <= 200
            or "\x00" in reply["submission_id"]
        ):
            raise ReviewTransportError("review transport submission is malformed")
        return reply

    def status(self, submission_id: str) -> Mapping[str, Any]:
        self._validate_submission_id(submission_id)
        reply = self._invoke("status", {"submission_id": submission_id})
        if (
            set(reply) != {"submission_id", "state"}
            or reply["submission_id"] != submission_id
            or type(reply["state"]) is not str
            or reply["state"] not in {"QUEUED", "RUNNING", "COMPLETED", "FAILED"}
        ):
            raise ReviewTransportError("review transport status is malformed")
        return reply

    def fetch_result(self, submission_id: str) -> Mapping[str, Any]:
        self._validate_submission_id(submission_id)
        reply = self._invoke("fetch_result", {"submission_id": submission_id})
        if (
            set(reply)
            != {
                "submission_id",
                "identity",
                "provider",
                "repository",
                "kind",
                "pr",
                "head_sha",
                "status",
                "blocking_findings",
                "output",
            }
            or reply["submission_id"] != submission_id
            or type(reply["identity"]) is not str
            or _DIGEST.fullmatch(reply["identity"]) is None
            or reply["provider"] != "ChatGPT"
            or type(reply["repository"]) is not str
            or _REPOSITORY.fullmatch(reply["repository"]) is None
            or type(reply["kind"]) is not str
            or reply["kind"] not in {"code", "security"}
            or type(reply["pr"]) is not int
            or reply["pr"] <= 0
            or type(reply["head_sha"]) is not str
            or _SHA.fullmatch(reply["head_sha"]) is None
            or type(reply["status"]) is not str
            or type(reply["blocking_findings"]) is not int
            or not (
                (reply["status"] == "PASS" and reply["blocking_findings"] == 0)
                or (reply["status"] == "FAIL" and reply["blocking_findings"] > 0)
            )
            or type(reply["output"]) is not str
            or not reply["output"]
        ):
            raise ReviewTransportError("review transport result is malformed")
        try:
            encoded = reply["output"].encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ReviewTransportError("review transport result is malformed") from exc
        if len(encoded) > _MAX_RESULT_BYTES:
            raise ReviewTransportError("review transport result exceeds byte limit")
        return reply

    @staticmethod
    def _validate_submission_id(submission_id: str) -> None:
        if (
            type(submission_id) is not str
            or not 0 < len(submission_id) <= 200
            or "\x00" in submission_id
        ):
            raise ReviewTransportError("review transport submission ID is invalid")


def resolve_review_transport(
    env: Mapping[str, str] | None = None,
) -> TransportResolution:
    """Resolve availability with no default backend or silent fallback."""
    config = os.environ if env is None else env
    backend = config.get("CHATGPT_REVIEW_TRANSPORT", "")
    if backend == "disabled":
        return TransportResolution(
            "DISABLED", "none", None, "DISABLED_BY_CONFIGURATION"
        )
    if not backend:
        return TransportResolution("UNAVAILABLE", "none", None, "NOT_CONFIGURED")
    if backend != "command-v1":
        return TransportResolution(
            "UNAVAILABLE", "unsupported", None, "UNSUPPORTED_BACKEND"
        )
    command = config.get("CHATGPT_REVIEW_TRANSPORT_COMMAND", "")
    digest = config.get("CHATGPT_REVIEW_TRANSPORT_SHA256", "")
    if not command or not digest:
        return TransportResolution(
            "UNAVAILABLE", backend, None, "COMMAND_CONFIGURATION_INCOMPLETE"
        )
    try:
        transport = CommandReviewTransport(Path(command), digest)
    except ReviewTransportError:
        return TransportResolution("UNAVAILABLE", backend, None, "COMMAND_UNAVAILABLE")
    return TransportResolution("CONFIGURED", backend, transport, "READY")
