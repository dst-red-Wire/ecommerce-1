#!/usr/bin/env python3
"""Exercise the Git proposal step against isolated local bare repositories."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
TASK = ROOT / "gitops/infrastructure/tekton-ci/tasks/gitops-propose-promotion.yaml"
SERVICE = "catalog"
ENVIRONMENT = "integration"
REPOSITORY = f"ghcr.io/dst-red-wire/ecommerce-1/{SERVICE}"
DIGEST = "sha256:" + "d" * 64
SOURCE_COMMIT = "a" * 40
IDEMPOTENCE_KEY = "sha256:" + "b" * 64
PROOF_SHA = "c" * 64
TARGET = f"gitops/apps/{SERVICE}/overlays/{ENVIRONMENT}/kustomization.yaml"
BRANCH = f"promotion/{ENVIRONMENT}/{SERVICE}/{DIGEST.removeprefix('sha256:')[:12]}"


def run(command: list[str], cwd: Path, *, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        check=check,
        text=True,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def git(cwd: Path, *args: str, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run(["git", *args], cwd, check=check, input_text=input_text)


def message(source_commit: str = SOURCE_COMMIT, proof_sha: str = PROOF_SHA) -> str:
    return "\n".join(
        [
            f"chore(gitops): propose {REPOSITORY}@{DIGEST}",
            "",
            f"Source-Commit: {source_commit}",
            f"Promotion-Idempotence-Key: {IDEMPOTENCE_KEY}",
            f"Promotion-Proof-SHA256: {proof_sha}",
            f"Promotion-Environment: {ENVIRONMENT}",
            f"Promotion-Service: {SERVICE}",
            f"Image-Repository: {REPOSITORY}",
            f"Image-Digest: {DIGEST}",
            "",
        ]
    )


class Repository:
    def __init__(self, root: Path, *, already_promoted: bool = False) -> None:
        self.root = root
        self.remote = root / "remote.git"
        self.work = root / "work"
        self.results = root / "results"
        self.auth = root / "auth"
        git(root, "init", "--bare", str(self.remote))
        git(root, "clone", str(self.remote), str(self.work))
        git(self.work, "config", "user.name", "fixture")
        git(self.work, "config", "user.email", "fixture@example.invalid")
        target = self.work / TARGET
        target.parent.mkdir(parents=True)
        old_digest = DIGEST if already_promoted else "sha256:" + "0" * 64
        target.write_text(
            "apiVersion: kustomize.config.k8s.io/v1beta1\n"
            "kind: Kustomization\n"
            "images:\n"
            f"  - name: {REPOSITORY}\n"
            f"    newName: {REPOSITORY}\n"
            f"    digest: {old_digest}\n",
            encoding="utf-8",
        )
        git(self.work, "add", ".")
        git(self.work, "commit", "-m", "initial main")
        git(self.work, "branch", "-M", "main")
        git(self.work, "push", "origin", "main")
        self.base = git(self.work, "rev-parse", "HEAD").stdout.strip()
        git(self.work, "checkout", "-b", BRANCH, self.base)
        if not already_promoted:
            text = target.read_text(encoding="utf-8").replace("sha256:" + "0" * 64, DIGEST)
            target.write_text(text, encoding="utf-8")
        self.results.mkdir()
        self.auth.mkdir()
        (self.results / "updated").write_text(TARGET, encoding="utf-8")
        (self.results / "branch").write_text(BRANCH, encoding="utf-8")
        (self.auth / ".git-credentials").write_text("https://unused.invalid\n", encoding="utf-8")

    def advance_main(self) -> None:
        admin = self.root / "admin"
        git(self.root, "clone", str(self.remote), str(admin))
        git(admin, "checkout", "main")
        git(admin, "config", "user.name", "fixture")
        git(admin, "config", "user.email", "fixture@example.invalid")
        (admin / "main-advanced.txt").write_text("advanced\n", encoding="utf-8")
        git(admin, "add", ".")
        git(admin, "commit", "-m", "advance main")
        git(admin, "push", "origin", "main")

    def precreate_branch(
        self,
        *,
        wrong_parent: bool = False,
        source_commit: str = SOURCE_COMMIT,
        proof_sha: str = PROOF_SHA,
    ) -> None:
        tree = git(self.work, "write-tree").stdout.strip()
        parent = self.base
        if wrong_parent:
            wrong_tree = git(self.work, "rev-parse", f"{self.base}^{{tree}}").stdout.strip()
            parent = git(self.work, "commit-tree", wrong_tree, "-p", self.base, input_text="wrong base\n").stdout.strip()
        candidate = git(
            self.work,
            "commit-tree",
            tree,
            "-p",
            parent,
            input_text=message(source_commit, proof_sha),
        ).stdout.strip()
        git(self.work, "push", "origin", f"{candidate}:refs/heads/{BRANCH}")


def extracted_script(directory: Path) -> Path:
    task = yaml.safe_load(TASK.read_text(encoding="utf-8"))
    step = next(step for step in task["spec"]["steps"] if step["name"] == "commit-and-push-proposal")
    script = step["script"]
    replacements = {
        "$(workspaces.git-auth.path)": str(directory / "auth"),
        "$(results.UPDATED_FILE.path)": str(directory / "results/updated"),
        "$(results.PROPOSAL_BRANCH.path)": str(directory / "results/branch"),
        "$(results.PROPOSAL_COMMIT.path)": str(directory / "results/commit"),
    }
    for original, replacement in replacements.items():
        script = script.replace(original, replacement)
    path = directory / "proposal-step.sh"
    path.write_text(script, encoding="utf-8")
    path.chmod(0o700)
    return path


def execute(repository: Repository) -> bool:
    script = extracted_script(repository.root)
    environment = os.environ.copy()
    environment.update(
        {
            "EXPECTED_BASE_SHA": repository.base,
            "GIT_AUTHOR_NAME_VALUE": "ecommerce-promotion-bot",
            "GIT_AUTHOR_EMAIL_VALUE": "ecommerce-promotion-bot@users.noreply.github.com",
            "IMAGE_REPOSITORY": REPOSITORY,
            "IMAGE_DIGEST": DIGEST,
            "SOURCE_COMMIT": SOURCE_COMMIT,
            "IDEMPOTENCE_KEY": IDEMPOTENCE_KEY,
            "PROMOTION_PROOF_SHA256": PROOF_SHA,
            "TARGET_ENVIRONMENT": ENVIRONMENT,
            "SERVICE": SERVICE,
        }
    )
    completed = subprocess.run(
        ["/bin/sh", str(script)],
        cwd=repository.work,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return completed.returncode == 0


def case(root: Path, name: str, *, already_promoted: bool = False) -> Repository:
    directory = root / name
    directory.mkdir()
    return Repository(directory, already_promoted=already_promoted)


def assert_static_guards() -> None:
    text = TASK.read_text(encoding="utf-8")
    required = [
        "^[a-z0-9][a-z0-9-]*$",
        "integration|preproduction|production",
        "Promotion-Proof-SHA256",
        "proposal must have exactly expected main as its parent",
        "git diff-tree --no-commit-id --name-only",
        "refresh_and_validate_main",
    ]
    for token in required:
        if token not in text:
            raise AssertionError(f"Git promotion guard missing: {token}")
    if "--force" in text or "--force-with-lease" in text:
        raise AssertionError("force push appears in Git promotion Task")


def main() -> int:
    assert_static_guards()
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)

        nominal = case(root, "nominal")
        if not execute(nominal):
            raise AssertionError("nominal new proposal branch failed")

        concurrent = case(root, "concurrent")
        if not execute(concurrent):
            raise AssertionError("first concurrent proposal failed")
        second_root = root / "concurrent-second"
        second_root.mkdir()
        second = Repository(second_root)
        shutil.rmtree(second.remote)
        shutil.rmtree(second.work)
        second.remote = concurrent.remote
        git(second.root, "clone", str(concurrent.remote), str(second.work))
        git(second.work, "checkout", "main")
        git(second.work, "config", "user.name", "fixture")
        git(second.work, "config", "user.email", "fixture@example.invalid")
        git(second.work, "remote", "set-url", "origin", str(concurrent.remote))
        second.base = concurrent.base
        git(second.work, "checkout", "-b", BRANCH, second.base)
        target = second.work / TARGET
        target.write_text(
            target.read_text(encoding="utf-8").replace("sha256:" + "0" * 64, DIGEST),
            encoding="utf-8",
        )
        if not execute(second):
            raise AssertionError("identical concurrent proposal was not idempotent")

        advanced = case(root, "main-advanced")
        advanced.advance_main()
        if execute(advanced):
            raise AssertionError("proposal succeeded after main advanced")

        wrong_parent = case(root, "wrong-parent")
        wrong_parent.precreate_branch(wrong_parent=True)
        if execute(wrong_parent):
            raise AssertionError("existing same-tree branch with wrong parent was accepted")

        wrong_trailer = case(root, "wrong-trailer")
        wrong_trailer.precreate_branch(source_commit="f" * 40)
        if execute(wrong_trailer):
            raise AssertionError("existing branch with wrong Source-Commit was accepted")

        wrong_proof = case(root, "wrong-proof-trailer")
        wrong_proof.precreate_branch(proof_sha="e" * 64)
        if execute(wrong_proof):
            raise AssertionError("existing branch with wrong PromotionProof hash was accepted")

        no_op = case(root, "no-op", already_promoted=True)
        if execute(no_op):
            raise AssertionError("no-op promotion was reported as a proposal")

        extra = case(root, "extra-path")
        (extra.work / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
        if execute(extra):
            raise AssertionError("promotion changing an additional path was accepted")

    print("Git promotion adversarial tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
