import os
import re
import subprocess
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / "platform/terraform/environments/qualification"
MODULE = ROOT / "platform/terraform/modules/hcloud-qualification"
ANSIBLE = ROOT / "platform/ansible"
RUNNER_PATHS = (
    ROOT / "platform/ansible/qualification-runner.yml",
    ROOT / "platform/ansible/roles/qualification_runner_host",
    ROOT / "docs/project/M1_LINUX_QUALIFICATION_RUNNER.md",
    ROOT / "tests/test_m1_qualification_runner.py",
)


def terraform_output_block(source: str, name: str) -> str:
    match = re.search(
        rf'^output "{re.escape(name)}"\s*\{{.*?(?=^output "|\Z)',
        source,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing Terraform output block: {name}")
    return match.group(0)


def resolve_base(value: str) -> str | None:
    if not value:
        return None
    if re.fullmatch(r"[0-9a-f]{40}", value):
        candidate = value
    else:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", f"{value}^{{commit}}"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        if result.returncode:
            raise AssertionError(f"BASE is not a resolvable local Git ref: {value}")
        candidate = result.stdout.strip()
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{candidate}^{{commit}}"], cwd=ROOT
    )
    if exists.returncode:
        raise AssertionError("the immutable BASE commit must exist")
    return candidate


def validate_contract(files: dict[str, str]) -> None:
    combined = "\n".join(files.values())
    main = files["module/main.tf"]
    gateway_bootstrap = files["module/gateway-cloud-init.yaml.tftpl"]
    gateway_tasks = files["ansible/gateway_tasks"]
    proxy_tasks = files["ansible/proxy_tasks"]
    squid_policy = files["ansible/squid_policy"]
    outputs = files["environment/outputs.tf"]
    required = (
        'version = "= 1.68.0"',
        'resource "hcloud_network" "qualification"',
        'resource "hcloud_network_subnet" "qualification"',
        'resource "hcloud_server" "runner"',
        'resource "hcloud_server" "gateway"',
        'network_zone = data.hcloud_location.qualification.network_zone',
        'subnet_cidr        = var.network_cidr',
        'gateway_private_ip = cidrhost(var.network_cidr, 2)',
        'runner_private_ip  = cidrhost(var.network_cidr, 3)',
        'source_ips = ["${local.gateway_private_ip}/32"]',
        'destination_ips = ["${local.gateway_private_ip}/32"]',
        'ipv4_enabled = false',
        'ipv4_enabled = true',
        'qualification_gateway_user',
        'ProxyCommand=\\"ssh',
        'KnownHostsCommand=none',
        'StrictHostKeyChecking=yes',
        'ForwardAgent=no',
        'ClearAllForwardings=yes',
        '!endswith(cidr, "/0")',
    )
    for marker in required:
        if marker not in combined:
            raise AssertionError(f"missing qualification boundary: {marker}")

    if len(re.findall(r'resource\s+"hcloud_server"\s+"', main)) != 2:
        raise AssertionError("qualification module must define exactly two servers")
    if "runcmd:" in gateway_bootstrap or "squid" in gateway_bootstrap.lower():
        raise AssertionError("gateway cloud-init must own only account and SSH bootstrap")
    for marker in (
        'qualification_squid_package: "squid={{ qualification_squid_version }}"',
        "ansible.builtin.dpkg_selections",
        "validate: /usr/sbin/squid -k parse -f %s",
        "enabled: true",
        "qualification_installed_squid.stdout != qualification_squid_version",
    ):
        if marker not in combined:
            raise AssertionError(f"Ansible does not durably own Squid: {marker}")
    for marker in (
        "Acquire::http::Proxy",
        "Acquire::https::Proxy",
        "/etc/gitconfig",
        "/etc/environment",
        "/etc/systemd/system/docker.service.d/10-ecommerce-qualification-proxy.conf",
        "daemon_reload: true",
    ):
        if marker not in proxy_tasks:
            raise AssertionError(f"runner proxy client is incomplete: {marker}")
    required_domains = (
        "snapshot.ubuntu.com", "github.com", "api.github.com",
        "objects.githubusercontent.com", "release-assets.githubusercontent.com",
        "pypi.org", "files.pythonhosted.org", "proxy.golang.org", "sum.golang.org",
        "go.dev", "dl.google.com", "storage.googleapis.com", "nodejs.org",
        "registry.npmjs.org", "get.helm.sh", "releases.hashicorp.com", "dl.k8s.io",
        "registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com",
        "docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com",
    )
    for domain in required_domains:
        if f"- {domain}" not in files["ansible/gateway_defaults"]:
            raise AssertionError(f"fresh bootstrap endpoint not allowlisted: {domain}")
    if "http_access deny all" not in squid_policy:
        raise AssertionError("Squid must default deny")
    if not re.search(r"^acl allowed_domains dstdomain -n(?:\s|{)", squid_policy, re.MULTILINE):
        raise AssertionError("Squid destination-domain ACL must disable reverse DNS with -n")
    if "http_access allow all" in squid_policy or re.search(
        r"http_access allow (?:CONNECT|runner CONNECT)", squid_policy
    ):
        raise AssertionError("Squid CONNECT must remain hostname allowlisted")
    if "ssh_authorized_keys:" not in gateway_bootstrap or "${jsonencode(gateway_user)}" not in gateway_bootstrap:
        raise AssertionError("explicit gateway user must own the provider key")
    inventory_output = outputs.split('output "qualification_inventory_host_line"', 1)[1].split(
        'output "qualification_gateway_inventory_host_line"', 1
    )[0]
    gateway_proxy = (
        '-o ProxyCommand=\\"ssh '
        '-o UserKnownHostsFile=$${QUALIFICATION_KNOWN_HOSTS} '
        '-o GlobalKnownHostsFile=/dev/null '
        '-o KnownHostsCommand=none '
        '-o StrictHostKeyChecking=yes '
        '-o HostKeyAlias=${module.hcloud_qualification.gateway_ipv4} '
        '-o ForwardAgent=no -o ClearAllForwardings=yes '
        '-l ${module.hcloud_qualification.gateway_user} -W %h:%p '
        '${module.hcloud_qualification.gateway_ipv4}\\"'
    )
    if gateway_proxy not in inventory_output:
        raise AssertionError("inventory gateway hop is not bound to its dedicated trust policy")
    runner_trust = (
        '-o UserKnownHostsFile=$${QUALIFICATION_KNOWN_HOSTS} '
        '-o GlobalKnownHostsFile=/dev/null '
        '-o KnownHostsCommand=none '
        '-o StrictHostKeyChecking=yes '
        '-o HostKeyAlias=${module.hcloud_qualification.runner_private_ip} '
        '-o ForwardAgent=no -o ClearAllForwardings=yes'
    )
    if runner_trust not in inventory_output:
        raise AssertionError("inventory runner hop is not bound to its dedicated trust policy")
    gateway_inventory_output = outputs.split(
        'output "qualification_gateway_inventory_host_line"', 1
    )[1].split('output "qualification_proxyjump"', 1)[0]
    gateway_trust = (
        '-o UserKnownHostsFile=$${QUALIFICATION_KNOWN_HOSTS} '
        '-o GlobalKnownHostsFile=/dev/null '
        '-o KnownHostsCommand=none '
        '-o StrictHostKeyChecking=yes '
        '-o HostKeyAlias=${module.hcloud_qualification.gateway_ipv4} '
        '-o ForwardAgent=no -o ClearAllForwardings=yes'
    )
    if gateway_trust not in gateway_inventory_output:
        raise AssertionError("inventory gateway connection permits alternate SSH trust")
    ansible_ssh_args_output = terraform_output_block(
        outputs, "qualification_ansible_ssh_args"
    )
    if runner_trust not in ansible_ssh_args_output:
        raise AssertionError("standalone Ansible runner hop permits alternate SSH trust")
    if gateway_proxy not in ansible_ssh_args_output:
        raise AssertionError("standalone Ansible gateway hop permits alternate SSH trust")
    runbook = files["runbook"]
    for trust_marker in (
        "QUALIFICATION_GATEWAY_FINGERPRINT=SHA256:",
        "QUALIFICATION_RUNNER_FINGERPRINT=SHA256:",
        'test "$(ssh-keygen -lf "$gateway_key" -E sha256 | awk \'{print $2}\')" = "$QUALIFICATION_GATEWAY_FINGERPRINT"',
        'test "$(ssh-keygen -lf "$runner_key" -E sha256 | awk \'{print $2}\')" = "$QUALIFICATION_RUNNER_FINGERPRINT"',
    ):
        if trust_marker not in runbook:
            raise AssertionError(f"two-hop trust procedure is incomplete: {trust_marker}")
    enrollment_gateway_trust = (
        'ssh -o UserKnownHostsFile="$staged_known_hosts" '
        '-o GlobalKnownHostsFile=/dev/null \\\n'
        '  -o KnownHostsCommand=none \\\n'
        '  -o StrictHostKeyChecking=yes \\\n'
        '  -o HostKeyAlias="$QUALIFICATION_GATEWAY_HOST" \\\n'
        '  -o ForwardAgent=no -o ClearAllForwardings=yes'
    )
    if enrollment_gateway_trust not in runbook:
        raise AssertionError("gateway enrollment is not isolated from global SSH trust")
    if (
        'ANSIBLE_SSH_ARGS="-o UserKnownHostsFile=$QUALIFICATION_KNOWN_HOSTS '
        '-o GlobalKnownHostsFile=/dev/null -o KnownHostsCommand=none -o StrictHostKeyChecking=yes '
        '-o ForwardAgent=no -o ClearAllForwardings=yes"'
    ) not in runbook:
        raise AssertionError("qualification Ansible SSH args permit global trust fallback")
    final_proof_start = runbook.find('ssh \\\n  -o UserKnownHostsFile="$QUALIFICATION_KNOWN_HOSTS"')
    final_proof_end = runbook.find("\nQUALIFICATION_RUNNER", final_proof_start)
    if final_proof_start < 0 or final_proof_end < 0:
        raise AssertionError("final qualification proof lacks an exact SSH invocation")
    final_proof = runbook[final_proof_start:final_proof_end]
    gateway_proxy = (
        '-o ProxyCommand="ssh -o UserKnownHostsFile=$QUALIFICATION_KNOWN_HOSTS '
        '-o GlobalKnownHostsFile=/dev/null '
        '-o KnownHostsCommand=none '
        '-o StrictHostKeyChecking=yes -o HostKeyAlias=$GATEWAY_HOST '
        '-o ForwardAgent=no -o ClearAllForwardings=yes '
        '-l $GATEWAY_USER -W %h:%p $GATEWAY_HOST"'
    )
    runner_trust = (
        '-o UserKnownHostsFile="$QUALIFICATION_KNOWN_HOSTS" \\\n'
        '  -o GlobalKnownHostsFile=/dev/null \\\n'
        '  -o KnownHostsCommand=none \\\n'
        '  -o StrictHostKeyChecking=yes \\\n'
        '  -o HostKeyAlias="$RUNNER_PRIVATE_HOST" \\\n'
        '  -o ForwardAgent=no \\\n'
        '  -o ClearAllForwardings=yes'
    )
    for marker in (
        runner_trust,
        gateway_proxy,
        '"${QUALIFICATION_USER}@${RUNNER_PRIVATE_HOST}"',
        "whoami", "hostname", "uname -a", "docker version", "docker info",
        "sysctl -n net.ipv4.ip_forward", "git checkout --detach 58e10fdb7122f9f3302e3fc5534b07021f7cc37f",
        "make seed", "make bootstrap", "make env-check", "git status --porcelain=v1",
        "$HOME/.local/bin/go test -race -tags=integration ./internal/infrastructure/postgres -count=1",
        "BASE=45433013f97a94a8acf94c51a913ff071e6f74b2 make ci",
    ):
        if marker not in final_proof:
            raise AssertionError(f"final private-runner proof is incomplete: {marker}")
    if 'variable "qualification_subnet_cidr"' in combined or "var.subnet_cidr" in main:
        raise AssertionError("redundant topology inputs are forbidden")
    if 'network_zone = "eu-central"' in main:
        raise AssertionError("network zone must follow provider location metadata")
    if "ipv4_enabled = false" not in main:
        raise AssertionError("runner public IPv4 must remain disabled")
    for name in ("environment/variables.tf", "module/main.tf"):
        if '!endswith(cidr, "/0")' not in files[name]:
            raise AssertionError(f"normalized zero-prefix CIDRs must be rejected in {name}")
    for marker in (
        'provisioner "local-exec"',
        'provisioner "remote-exec"',
        "null_resource",
        'resource "terraform_data"',
    ):
        if marker in combined:
            raise AssertionError(f"Terraform orchestration is forbidden: {marker}")


class QualificationTerraformContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = {}
        for prefix, directory in (("environment", ENV), ("module", MODULE)):
            for path in directory.iterdir():
                if path.is_file() and path.name != ".terraform.lock.hcl":
                    cls.files[f"{prefix}/{path.name}"] = path.read_text(encoding="utf-8")
        cls.files.update(
            {
                "ansible/egress": (ANSIBLE / "qualification-egress.yml").read_text(),
                "ansible/gateway_defaults": (ANSIBLE / "roles/qualification_gateway/defaults/main.yml").read_text(),
                "ansible/gateway_tasks": (ANSIBLE / "roles/qualification_gateway/tasks/main.yml").read_text(),
                "ansible/squid_policy": (ANSIBLE / "roles/qualification_gateway/templates/squid.conf.j2").read_text(),
                "ansible/proxy_tasks": (ANSIBLE / "roles/qualification_proxy_client/tasks/main.yml").read_text(),
                "runbook": (ENV / "README.md").read_text(),
            }
        )

    def test_complete_contract(self):
        validate_contract(self.files)

    def assert_mutation_rejected(self, name, old, new):
        self.assertIn(old, self.files[name], f"mutation fixture missing: {old}")
        mutated = dict(self.files)
        mutated[name] = mutated[name].replace(old, new, 1)
        with self.assertRaises(AssertionError):
            validate_contract(mutated)

    def test_security_and_runtime_mutations_are_rejected(self):
        mutations = (
            (
                "environment/outputs.tf",
                "-l ${module.hcloud_qualification.gateway_user}",
                "-l other-user",
            ),
            ("module/gateway-cloud-init.yaml.tftpl", "#cloud-config", "#cloud-config\nruncmd: [apt-get install squid]"),
            ("ansible/proxy_tasks", "Acquire::http::Proxy", "Removed::http::Proxy"),
            (
                "ansible/proxy_tasks",
                "/etc/systemd/system/docker.service.d/10-ecommerce-qualification-proxy.conf",
                "/tmp/proxy.conf",
            ),
            ("ansible/gateway_defaults", "- nodejs.org", "- removed.invalid"),
            (
                "ansible/gateway_defaults",
                "- docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com",
                "- removed.invalid",
            ),
            ("ansible/squid_policy", "http_access deny all", "http_access allow all"),
            ("ansible/squid_policy", "acl allowed_domains dstdomain -n", "acl allowed_domains dstdomain"),
            ("ansible/squid_policy", "http_access allow runner allowed_domains", "http_access allow CONNECT"),
            ("module/main.tf", "ipv4_enabled = false", "ipv4_enabled = true"),
            (
                "module/main.tf",
                "network_zone = data.hcloud_location.qualification.network_zone",
                'network_zone = "eu-central"',
            ),
            ("module/main.tf", "subnet_cidr        = var.network_cidr", 'subnet_cidr = "10.248.1.0/24"'),
            (
                "module/main.tf",
                "runner_private_ip  = cidrhost(var.network_cidr, 3)",
                'runner_private_ip = "10.249.0.3"',
            ),
            (
                "module/main.tf",
                "runner_private_ip  = cidrhost(var.network_cidr, 3)",
                "runner_private_ip = cidrhost(var.network_cidr, 2)",
            ),
            ("environment/outputs.tf", "StrictHostKeyChecking=yes", "StrictHostKeyChecking=no"),
            (
                "environment/outputs.tf",
                '-o UserKnownHostsFile=$${QUALIFICATION_KNOWN_HOSTS} -o GlobalKnownHostsFile=/dev/null -o KnownHostsCommand=none -o StrictHostKeyChecking=yes -o HostKeyAlias=${module.hcloud_qualification.runner_private_ip}',
                '-o UserKnownHostsFile=$${QUALIFICATION_KNOWN_HOSTS} -o StrictHostKeyChecking=yes -o HostKeyAlias=${module.hcloud_qualification.runner_private_ip}',
            ),
            (
                "environment/outputs.tf",
                '-o ProxyCommand=\\"ssh -o UserKnownHostsFile=$${QUALIFICATION_KNOWN_HOSTS} -o GlobalKnownHostsFile=/dev/null',
                '-o ProxyCommand=\\"ssh -o UserKnownHostsFile=$${QUALIFICATION_KNOWN_HOSTS}',
            ),
            ("runbook", 'QUALIFICATION_GATEWAY_FINGERPRINT=SHA256:', "GATEWAY_SCAN_IS_TRUSTED="),
            ("runbook", 'QUALIFICATION_RUNNER_FINGERPRINT=SHA256:', "RUNNER_SCAN_IS_TRUSTED="),
            ("runbook", '-o ProxyCommand="ssh ', '-o ProxyCommand="false '),
            (
                "runbook",
                'ssh -o UserKnownHostsFile="$staged_known_hosts" -o GlobalKnownHostsFile=/dev/null',
                'ssh -o UserKnownHostsFile="$staged_known_hosts"',
            ),
            (
                "runbook",
                '-o ProxyCommand="ssh -o UserKnownHostsFile=$QUALIFICATION_KNOWN_HOSTS',
                '-o ProxyCommand="ssh',
            ),
            (
                "runbook",
                '-o ProxyCommand="ssh -o UserKnownHostsFile=$QUALIFICATION_KNOWN_HOSTS -o GlobalKnownHostsFile=/dev/null',
                '-o ProxyCommand="ssh -o UserKnownHostsFile=$QUALIFICATION_KNOWN_HOSTS',
            ),
            (
                "runbook",
                '-o StrictHostKeyChecking=yes -o HostKeyAlias=$GATEWAY_HOST',
                '-o StrictHostKeyChecking=yes',
            ),
            (
                "runbook",
                '-o HostKeyAlias=$GATEWAY_HOST -o ForwardAgent=no',
                '-o HostKeyAlias=$GATEWAY_HOST -o ForwardAgent=yes',
            ),
            (
                "runbook",
                '  -o UserKnownHostsFile="$QUALIFICATION_KNOWN_HOSTS" \\'
                + "\n  -o GlobalKnownHostsFile=/dev/null \\"
                + "\n  -o KnownHostsCommand=none \\"
                + "\n  -o StrictHostKeyChecking=yes \\"
                + '\n  -o HostKeyAlias="$RUNNER_PRIVATE_HOST"',
                '  -o UserKnownHostsFile="$QUALIFICATION_KNOWN_HOSTS" \\'
                + "\n  -o GlobalKnownHostsFile=/dev/null \\"
                + "\n  -o KnownHostsCommand=none \\"
                + "\n  -o StrictHostKeyChecking=no \\"
                + '\n  -o HostKeyAlias="$RUNNER_PRIVATE_HOST"',
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_mutation_rejected(*mutation)

    def test_standalone_ansible_ssh_args_trust_mutations_are_rejected(self):
        outputs = self.files["environment/outputs.tf"]
        block = terraform_output_block(outputs, "qualification_ansible_ssh_args")
        proxy_boundary = '-o ProxyCommand=\\"ssh '
        runner_hop, gateway_hop = block.split(proxy_boundary, 1)
        for hop, marker in (
            ("runner", "GlobalKnownHostsFile=/dev/null"),
            ("runner", "KnownHostsCommand=none"),
            ("runner", "StrictHostKeyChecking=yes"),
            ("gateway", "GlobalKnownHostsFile=/dev/null"),
            ("gateway", "KnownHostsCommand=none"),
            ("gateway", "StrictHostKeyChecking=yes"),
        ):
            with self.subTest(hop=hop, marker=marker):
                segment = runner_hop if hop == "runner" else gateway_hop
                self.assertEqual(
                    segment.count(marker), 1, f"{hop} mutation fixture must be exact"
                )
                mutated_segment = segment.replace(marker, "", 1)
                if hop == "runner":
                    mutated_block = mutated_segment + proxy_boundary + gateway_hop
                else:
                    mutated_block = runner_hop + proxy_boundary + mutated_segment
                mutated = dict(self.files)
                mutated["environment/outputs.tf"] = outputs.replace(
                    block, mutated_block, 1
                )
                with self.assertRaises(AssertionError):
                    validate_contract(mutated)

    def test_zero_prefix_and_provisioner_mutations_are_rejected(self):
        for name in ("environment/variables.tf", "module/main.tf"):
            self.assert_mutation_rejected(name, '!endswith(cidr, "/0")', "true")
        for cidr in ("0.0.0.0/0", "192.0.2.1/0", "203.0.113.255/0", "::/0", "2001:db8::1/0"):
            self.assertTrue(cidr.endswith("/0"))

    def test_base_resolution_modes(self):
        expected = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        developer_ref = "refs/heads/test-m1-base-ref"
        developer_ref_before = subprocess.run(
            ["git", "rev-parse", "--verify", developer_ref],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        test_ref = f"refs/m1-tests/base-{uuid.uuid4().hex}"
        self.assertTrue(test_ref.startswith("refs/m1-tests/base-"))
        self.assertFalse(test_ref.startswith("refs/heads/"))
        self.assertNotEqual(developer_ref, test_ref)
        try:
            subprocess.run(["git", "update-ref", test_ref, expected], cwd=ROOT, check=True)
            self.assertIsNone(resolve_base(""))
            self.assertEqual(expected, resolve_base(test_ref))
            self.assertEqual(expected, resolve_base(expected))
            with self.assertRaises(AssertionError):
                resolve_base("not-a-real-base-ref")
        finally:
            subprocess.run(["git", "update-ref", "-d", test_ref], cwd=ROOT, check=True)
        self.assertNotEqual(0, subprocess.run(
            ["git", "show-ref", "--verify", "--quiet", test_ref], cwd=ROOT
        ).returncode)
        developer_ref_after = subprocess.run(
            ["git", "rev-parse", "--verify", developer_ref],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(developer_ref_before.returncode, developer_ref_after.returncode)
        self.assertEqual(developer_ref_before.stdout, developer_ref_after.stdout)

    def test_canonical_runner_is_unchanged_from_base(self):
        base = resolve_base(os.environ.get("BASE", ""))
        if base is None:
            self.skipTest("BASE absent: only the base-relative #78 comparison is skipped")
        for path in RUNNER_PATHS:
            rel = path.relative_to(ROOT)
            result = subprocess.run(["git", "diff", "--quiet", base, "--", str(rel)], cwd=ROOT)
            self.assertEqual(0, result.returncode, f"canonical #78 path changed: {rel}")


if __name__ == "__main__":
    unittest.main()
