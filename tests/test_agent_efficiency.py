import json
import pathlib
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class AgentEfficiencyContractTest(unittest.TestCase):
    def test_delivery_consumes_exact_evidence_not_hardcoded_pass_claims(self):
        text = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn("exact_commit_evidence", text)
        self.assertIn(".context/evidence/", text)
        self.assertNotIn("- governance: PASS", text)

    def test_frontend_uses_single_go_module_without_node_runtime(self):
        module = (ROOT / "frontend/go.mod").read_text(encoding="utf-8")
        workspace = (ROOT / "go.work").read_text(encoding="utf-8")
        self.assertIn("module github.com/dst-red-Wire/ecommerce-1/frontend", module)
        self.assertIn("github.com/a-h/templ", module)
        self.assertIn("./frontend", workspace)
        self.assertFalse((ROOT / "frontend/package.json").exists())

    def test_bazel_and_nx_are_not_tekton_replacements(self):
        topology = (ROOT / "config/contracts/ci-topology.yaml").read_text(encoding="utf-8")
        self.assertIn("ci: tekton", topology)
        self.assertIn("role: local-verification-entrypoint", topology)
        self.assertIn("role: derived-contract-graph-visualization", topology)
        self.assertIn("role: frontend-task-scheduling-and-local-cache", topology)

    def test_node_and_corepack_are_reconciled_by_ansible(self):
        versions = json.loads(
            (ROOT / "config/contracts/toolchain-lock.json").read_text(encoding="utf-8")
        )["versions"]
        self.assertEqual(
            "2f2c0da162318f0de47665410c7c8c2ed3d36c8f3105de4bbc61176c70a7cbf2",
            versions["NODE_SHA256_LINUX_X64"],
        )
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Download pinned Node archive", tasks)
        self.assertIn("Link Node and Corepack commands", tasks)

    def test_prepush_reuses_evidence_only_after_canonical_exact_validation(self):
        text = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        start = text.index("def prepush()")
        end = text.index("\ndef tekton_trigger_readiness_command", start)
        prepush = text[start:end]
        self.assertIn('_valid_exact_evidence("origin/main", head)', prepush)
        self.assertIn('return verify_change("origin/main", head)', prepush)
        self.assertNotIn('data.get("base_sha")', prepush)

    def test_ansible_first_replaces_shell_automation(self):
        self.assertFalse(list((ROOT / "scripts").glob("*.sh")))
        self.assertTrue((ROOT / "platform/ansible/developer.yml").is_file())
        controller = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn("Stateful workstation and", controller)

    def test_oasdiff_checksum_matches_downloaded_tarball_asset(self):
        versions = json.loads(
            (ROOT / "config/contracts/toolchain-lock.json").read_text(encoding="utf-8")
        )["versions"]
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text(encoding="utf-8")
        self.assertEqual("1.28.0", versions["OASDIFF_VERSION"])
        self.assertEqual(
            "e0ef076f2cf953d922addc04be9c3851cf3ec18f7678d2b94d44cea23dca51b5",
            versions["OASDIFF_SHA256_LINUX_AMD64_TARGZ"],
        )
        self.assertIn("oasdiff_{{ oasdiff_version }}_linux_amd64.tar.gz", tasks)
        self.assertIn('checksum: "sha256:{{ oasdiff_sha256 }}"', tasks)

    def test_isolated_nx_has_exact_fail_closed_build_approval(self):
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Write fail-closed PNPM build policy for isolated Nx", tasks)
        self.assertIn("strictDepBuilds: true", tasks)
        self.assertIn('"nx@{{ nx_version }}": true', tasks)
        self.assertIn("nx_pnpm_policy.changed", tasks)
        self.assertIn("Validate exact isolated Nx local version", tasks)
        self.assertNotIn("pnpm approve-builds", tasks)
        self.assertNotIn("dangerouslyAllowAllBuilds", tasks)


    def test_codex_context_budgets_are_enforced_and_agents_is_small(self):
        budget = json.loads(
            (ROOT / "config/contracts/codex-token-budget.json").read_text(encoding="utf-8")
        )
        self.assertEqual("enforced", budget["status"])
        self.assertEqual({"L0": 4096, "L1": 8192, "L2": 12288}, budget["context_level_max_bytes"])
        self.assertLessEqual(
            len((ROOT / "AGENTS.md").read_bytes()),
            budget["project_doc_max_bytes"],
        )
        router = (ROOT / "config/context/router.yaml").read_text(encoding="utf-8")
        for value in (4096, 8192, 12288):
            self.assertIn(f"max_bytes: {value}", router)
        canonical = router.split("canonical:", 1)[1].split("\n\n# Section-level", 1)[0]
        self.assertNotIn("AGENTS.md", canonical)
        self.assertIn("^archive/legacy-prompts/", router)

    def test_project_codex_hook_is_bounded(self):
        budget = json.loads(
            (ROOT / "config/contracts/codex-token-budget.json").read_text(encoding="utf-8")
        )
        config = tomllib.loads((ROOT / ".codex/config.toml").read_text(encoding="utf-8"))
        self.assertEqual(budget["project_doc_max_bytes"], config["project_doc_max_bytes"])
        self.assertEqual(budget["tool_output_token_limit"], config["tool_output_token_limit"])
        self.assertEqual(budget["skills_catalog_max_tokens"], config["skills"]["max_context_tokens"])
        self.assertTrue(config["features"]["hooks"])
        hook = config["hooks"]["UserPromptSubmit"][0]["hooks"][0]
        self.assertEqual("command", hook["type"])
        self.assertLessEqual(
            hook["additionalContextLimit"],
            budget["hook_additional_context_max_bytes"],
        )
        self.assertIn("user_prompt_submit.py", hook["command"])
        hook_source = (ROOT / ".codex/hooks/user_prompt_submit.py").read_text(encoding="utf-8")
        self.assertIn(".context/codex-hook-context.md", hook_source)
        self.assertIn(".context/codex-hook-context.json", hook_source)
        self.assertNotIn('root / ".context/codex-context.json"', hook_source)

    def test_agent_skills_use_progressive_disclosure(self):
        roots = (
            ROOT / ".agents/skills/chatgpt-exact-sha-review/SKILL.md",
            ROOT / ".agents/skills/pr-recovery-guided/SKILL.md",
        )
        references = (
            ROOT / ".agents/skills/chatgpt-exact-sha-review/references/review-runbook.md",
            ROOT / ".agents/skills/pr-recovery-guided/references/recovery-runbook.md",
        )
        for path in roots:
            self.assertLessEqual(len(path.read_bytes()), 2048)
            self.assertIn("Progressive disclosure", path.read_text(encoding="utf-8"))
        for path in references:
            self.assertTrue(path.is_file())

    def test_legacy_prompts_are_deleted_from_tracked_tree(self):
        import subprocess
        tracked = subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines()
        self.assertFalse(any(path.startswith(("archive/legacy-prompts/", "instruction/dev/", "instruction/ui/")) for path in tracked))
        self.assertFalse((ROOT / "archive/legacy-prompts").exists())
        handoff = (ROOT / "docs/project/CODEX_HANDOFFS.md").read_text(encoding="utf-8")
        self.assertNotIn("archive/legacy-prompts", handoff)
        self.assertLessEqual(len(handoff.encode("utf-8")), 2048)

    def test_codex_profiles_are_installed_by_ansible_without_overwriting_base_config(self):
        tasks = (
            ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml"
        ).read_text(encoding="utf-8")
        profile_tasks = (
            ROOT / "platform/ansible/roles/developer_toolchain/tasks/codex_profiles.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("import_tasks: codex_profiles.yml", tasks)
        self.assertIn("ecommerce-minimal", profile_tasks)
        self.assertIn("ecommerce-openai", profile_tasks)
        self.assertNotIn('dest: "{{ ansible_env.HOME }}/.codex/config.toml"', profile_tasks)

    def test_context_diagnostics_and_review_handoff_use_central_budget(self):
        controller = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        monitor = (ROOT / "scripts/pr_monitor.py").read_text(encoding="utf-8")
        self.assertIn('budget["diff_context_max_bytes"]', controller)
        self.assertIn('budget["failure_context_max_lines"]', controller)
        self.assertIn('budget["failure_context_max_bytes"]', controller)
        self.assertIn('"review_handoff_max_bytes"', monitor)

        review_policy = (ROOT / "config/contracts/review-policy.yaml").read_text(encoding="utf-8")
        self.assertIn("payload_budget_bytes: 8192", review_policy)

    def test_minimal_codex_profile_declares_no_repository_owned_mcp(self):
        budget = json.loads(
            (ROOT / "config/contracts/codex-token-budget.json").read_text(encoding="utf-8")
        )
        minimal = tomllib.loads(
            (ROOT / "config/codex/profiles/ecommerce-minimal.config.toml").read_text(encoding="utf-8")
        )
        self.assertNotIn("mcp_servers", minimal)
        self.assertEqual(budget["tool_output_token_limit"], minimal["tool_output_token_limit"])
        self.assertEqual(budget["skills_catalog_max_tokens"], minimal["skills"]["max_context_tokens"])

    def test_openai_codex_profile_allowlists_and_caps_known_docs_tools(self):
        budget = json.loads(
            (ROOT / "config/contracts/codex-token-budget.json").read_text(encoding="utf-8")
        )
        profile = tomllib.loads(
            (ROOT / "config/codex/profiles/ecommerce-openai.config.toml").read_text(encoding="utf-8")
        )
        server = profile["mcp_servers"]["openaiDeveloperDocs"]
        self.assertEqual(budget["mcp"]["known_openai_docs_tools"], server["enabled_tools"])
        for tool in budget["mcp"]["known_openai_docs_tools"]:
            self.assertEqual(
                budget["mcp"]["per_tool_output_token_limit"],
                server["tools"][tool]["output_token_limit"],
            )


if __name__ == "__main__":
    unittest.main()
