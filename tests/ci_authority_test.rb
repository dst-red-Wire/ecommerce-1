# frozen_string_literal: true

require "json"
require "minitest/autorun"
require "yaml"

class CIAuthorityTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  REQUIRED_TEKTON = %w[
    platform/tekton/kustomization.yaml
    platform/tekton/tasks/source-checkout.yaml
    platform/tekton/tasks/global-gates.yaml
    platform/tekton/tasks/affected-components.yaml
    platform/tekton/tasks/component-gates.yaml
    platform/tekton/tasks/finalize-evidence.yaml
    platform/tekton/tasks/frontend-gates.yaml
    platform/tekton/tasks/go-service-gates.yaml
    platform/tekton/tasks/platform-gates.yaml
    platform/tekton/pipelines/global.yaml
    platform/tekton/pipelines/frontend.yaml
    platform/tekton/pipelines/go-service.yaml
    platform/tekton/pipelines/platform.yaml
    platform/tekton/pipelines/affected.yaml
    platform/tekton/triggers/README.md
  ].freeze

  def read(relative) = File.read(File.join(ROOT, relative))
  def yaml(relative) = YAML.safe_load(read(relative))

  def test_single_control_plane_authorities
    lock = yaml("architecture.lock.yaml")
    topology = yaml("config/contracts/ci-topology.yaml")
    assert_equal "tekton", lock.dig("platform", "ci")
    assert_equal "tekton", lock.dig("management_plane", "ci")
    assert_equal "rancher-fleet", lock.dig("platform", "gitops")
    assert_equal "gitea", topology.dig("authorities", "forge")
    assert_equal "tekton", topology.dig("authorities", "ci")
    assert_equal "rancher-fleet", topology.dig("authorities", "gitops_cd")
    assert_equal true, topology.dig("repository", "affected_only")
    assert_equal false, topology.dig("gitea_actions", "ci_authority")
    assert_equal false, topology.dig("gitea_actions", "cd_authority")
  end

  def test_developer_accelerators_are_not_control_planes
    accelerators = yaml("config/contracts/ci-topology.yaml").fetch("developer_accelerators")
    assert_equal %w[bazel nx turborepo], accelerators.keys.sort
    accelerators.each do |name, contract|
      assert_equal false, contract["source_of_truth"], name
      assert_equal false, contract["ci_authority"], name
      assert_equal false, contract["may_deploy"], name
    end
  end

  def test_ansible_first_developer_automation_contract
    automation = yaml("config/contracts/ci-topology.yaml").fetch("developer_automation")
    assert_equal "ansible", automation.fetch("state_reconciliation")
    assert_equal "python", automation.fetch("stateless_controller")
    assert_equal "forbidden", automation.fetch("shell_policy")
    assert_equal true, automation.fetch("shell_state_mutation_forbidden")
    assert_equal true, automation.fetch("tekton_remains_ci_authority")
  end

  def test_repository_has_no_shell_automation
    candidates = `git -C #{ROOT} ls-files --cached --others --exclude-standard -- '*.sh'`.split("\n").reject(&:empty?)
    worktree_shell = candidates.select { |relative| File.file?(File.join(ROOT, relative)) }
    assert_empty worktree_shell
    refute_includes read("BUILD.bazel"), "sh_binary("
    REQUIRED_TEKTON.grep(/\.yaml\z/).each do |relative|
      content = read(relative)
      refute_match(%r{scripts/[^\s'\"]+\.sh\b}, content, relative)
      refute_includes content, "#!/bin/sh", relative
      refute_includes content, "#!/usr/bin/env bash", relative
    end
  end

  def test_parallel_ci_configuration_is_absent
    %w[.woodpecker/ci.yaml .gitlab-ci.yml Jenkinsfile .drone.yml].each do |relative|
      refute File.exist?(File.join(ROOT, relative)), relative
    end
    assert_empty Dir[File.join(ROOT, ".github/workflows/*.{yml,yaml}")]
  end

  def test_tekton_pipeline_classes_are_present_and_do_not_use_latest
    REQUIRED_TEKTON.each { |relative| assert File.file?(File.join(ROOT, relative)), relative }
    manifests = REQUIRED_TEKTON.grep(/\.yaml\z/).map { |relative| read(relative) }.join("\n")
    refute_match(/image:\s*\S+:latest\b/, manifests)
  end

  def test_tekton_trigger_runtime_prerequisites_are_fail_closed
    topology = yaml("config/contracts/ci-topology.yaml")
    runtime_path = topology.dig("trigger_flow", "runtime_prerequisites_contract")
    assert_equal "config/contracts/tekton-trigger-runtime.yaml", runtime_path
    runtime = yaml(runtime_path)
    assert_equal "exact-prerequisites", runtime.fetch("status")
    assert_equal "tekton.dev/v1", runtime.dig("api_contract", "pipelines")
    assert_equal "triggers.tekton.dev/v1beta1", runtime.dig("api_contract", "triggers")
    assert_equal true, runtime.dig("api_contract", "crds_must_be_proven_before_activation")
    assert_equal "harbor", runtime.dig("runner_image", "registry_authority")
    assert_equal true, runtime.dig("runner_image", "immutable_digest_required")
    assert_equal true, runtime.dig("runner_image", "default_forbidden")
    assert_equal true, runtime.dig("identity", "event_listener_service_account", "least_privilege")
    assert_equal true, runtime.dig("identity", "event_listener_service_account", "wildcard_rbac_forbidden")
    assert_equal "openbao-via-eso", runtime.dig("webhook_authentication", "secret", "source")
    assert_equal true, runtime.dig("webhook_authentication", "secret", "plaintext_in_git_forbidden")
    assert_equal true, runtime.dig("network", "default_deny_required")
    assert_equal "blocked-until-prerequisites-proven", runtime.dig("activation", "trigger_manifests")
    assert_equal false, runtime.dig("activation", "static_contract_is_runtime_proof")
  end

  def test_frontend_ci_uses_declared_pnpm_workspace
    package = JSON.parse(read("frontend/package.json"))
    assert_match(/\Apnpm@\d/, package.fetch("packageManager"))
    assert File.file?(File.join(ROOT, "frontend/pnpm-lock.yaml"))
    assert File.file?(File.join(ROOT, "frontend/pnpm-workspace.yaml"))
    refute File.exist?(File.join(ROOT, "frontend/package-lock.json"))
    controller = read("scripts/repoctl.py")
    refute_match(/\bnpm ci\b/, controller)
    refute_includes controller, "package-lock.json"
  end
end
