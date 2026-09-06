# frozen_string_literal: true

require "json"
require "minitest/autorun"
require "yaml"

class CIAuthorityTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  REQUIRED_TEKTON = %w[
    platform/tekton/kustomization.yaml
    platform/tekton/tasks/global-gates.yaml
    platform/tekton/tasks/frontend-gates.yaml
    platform/tekton/tasks/go-service-gates.yaml
    platform/tekton/tasks/platform-gates.yaml
    platform/tekton/pipelines/global.yaml
    platform/tekton/pipelines/frontend.yaml
    platform/tekton/pipelines/go-service.yaml
    platform/tekton/pipelines/platform.yaml
    platform/tekton/triggers/README.md
  ].freeze

  def read(relative)
    File.read(File.join(ROOT, relative))
  end

  def yaml(relative)
    YAML.safe_load(read(relative))
  end

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

    assert_equal "gitea", topology.dig("trigger_flow", "source")
    assert_equal %w[push pull_request], topology.dig("trigger_flow", "events")
    assert_equal "webhook", topology.dig("trigger_flow", "transport")
    assert_equal "tekton-eventlistener", topology.dig("trigger_flow", "receiver")
    assert_equal "tekton-triggerbinding", topology.dig("trigger_flow", "binding")
    assert_equal "tekton-triggertemplate", topology.dig("trigger_flow", "template")
    assert_equal "tekton-pipelinerun", topology.dig("trigger_flow", "output")
    assert_equal true, topology.dig("trigger_flow", "webhook_authentication", "required")
    assert_equal false, topology.dig("gitea_actions", "ci_authority")
    assert_equal false, topology.dig("gitea_actions", "cd_authority")
    assert_equal false, topology.dig("gitea_actions", "may_trigger_tekton")
    assert_includes topology.dig("authorities", "forbidden_parallel_ci"), "gitea-actions-as-ci"
    refute_includes topology.dig("authorities", "forbidden_parallel_ci"), "gitea-actions"
  end

  def test_parallel_ci_configuration_is_absent
    %w[
      .woodpecker/ci.yaml
      .gitlab-ci.yml
      Jenkinsfile
      .drone.yml
    ].each { |relative| refute File.exist?(File.join(ROOT, relative)), relative }
    assert_empty Dir[File.join(ROOT, ".github/workflows/*.{yml,yaml}")]
  end

  def test_tekton_pipeline_classes_are_present_and_do_not_use_latest
    REQUIRED_TEKTON.each { |relative| assert File.file?(File.join(ROOT, relative)), relative }
    manifests = REQUIRED_TEKTON.grep(/\.yaml\z/).map { |relative| read(relative) }.join("\n")
    refute_match(/image:\s*\S+:latest\b/, manifests)
  end

  def test_frontend_ci_uses_declared_pnpm_workspace
    package = JSON.parse(read("frontend/package.json"))
    assert_match(/\Apnpm@\d/, package.fetch("packageManager"))
    assert File.file?(File.join(ROOT, "frontend/pnpm-lock.yaml"))
    assert File.file?(File.join(ROOT, "frontend/pnpm-workspace.yaml"))
    refute File.exist?(File.join(ROOT, "frontend/package-lock.json"))

    %w[scripts/ci-lint.sh scripts/ci-test.sh scripts/ci-frontend.sh].each do |relative|
      content = read(relative)
      refute_match(/\bnpm ci\b/, content, relative)
      refute_includes content, "package-lock.json", relative
    end
  end
end
