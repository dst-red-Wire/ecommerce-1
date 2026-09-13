from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_qualification_role_pins_and_verifies_host_capabilities():
    defaults = (
        ROOT / "platform/ansible/roles/qualification_runner_host/defaults/main.yml"
    ).read_text()
    tasks = (
        ROOT / "platform/ansible/roles/qualification_runner_host/tasks/main.yml"
    ).read_text()
    for package in ("docker.io", "git", "make", "python3"):
        assert f'- "{package}=' in defaults
    assert "net.ipv4.ip_forward=1" in tasks
    assert "argv: [docker, version]" in tasks
    assert "argv: [docker, info]" in tasks
    assert "become_user" in tasks
    assert "systemd_service" in tasks


def test_qualification_scope_excludes_m4_resources():
    playbook = (
        ROOT / "platform/ansible/qualification-runner.yml"
    ).read_text().lower()
    assert "qualification_runner_host" in playbook
    for future_platform in ("tekton", "harbor", "buildkit", "cosign"):
        assert future_platform not in playbook
