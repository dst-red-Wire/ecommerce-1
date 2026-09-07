# frozen_string_literal: true

require "fileutils"
require "minitest/autorun"
require "open3"
require "tmpdir"
require_relative "../scripts/ci-affected"

class CIAffectedTest < Minitest::Test
  SERVICES = %w[catalog product inventory cart pricing tax order payment shipping tracking returns billing fraud-risk search review user-profile notification].freeze
  PUBLIC = {
    "contracts/openapi/product.v1.yaml" => {"service" => "product", "audiences" => ["admin"]}
  }.freeze
  TEMPORARY_GIT_ENV = {
    "GIT_CONFIG_NOSYSTEM" => "1",
    "GIT_CONFIG_GLOBAL" => File::NULL
  }.freeze

  # Temporary repositories must not inherit any repository context from a
  # pre-commit/pre-push hook. Clearing every inherited GIT_* variable is more
  # robust than maintaining a version-specific list of Git local env names.
  def temporary_git_env
    ENV.keys.grep(/\AGIT_/).to_h { |key| [key, nil] }.merge(TEMPORARY_GIT_ENV)
  end

  def isolated_git(*args, chdir: nil)
    command = ["git", "-c", "core.hooksPath=#{File::NULL}"]
    command += ["-C", chdir] if chdir
    system(temporary_git_env, *command, *args, exception: true)
  end

  def isolated_git_output(*args, chdir:)
    command = ["git", "-c", "core.hooksPath=#{File::NULL}", "-C", chdir, *args]
    stdout, stderr, status = Open3.capture3(temporary_git_env, *command)
    raise "Command failed with exit #{status.exitstatus}: git #{args.join(' ')}: #{stderr.strip}" unless status.success?

    stdout.strip
  end

  def with_isolated_git_environment
    previous = ENV.to_h.select { |key, _value| key.start_with?("GIT_") }
    ENV.keys.grep(/\AGIT_/).each { |key| ENV.delete(key) }
    ENV.update(TEMPORARY_GIT_ENV)
    yield
  ensure
    ENV.keys.grep(/\AGIT_/).each { |key| ENV.delete(key) }
    ENV.update(previous)
  end

  def initialize_temporary_git_repository(dir)
    isolated_git("init", "-q", dir)
    isolated_git("config", "user.email", "test@example.invalid", chdir: dir)
    isolated_git("config", "user.name", "Test User", chdir: dir)
  end

  def test_isolated_git_environment_clears_inherited_repository_context
    inherited = {
      "GIT_DIR" => "/tmp/outer-repository/.git",
      "GIT_WORK_TREE" => "/tmp/outer-repository",
      "GIT_INDEX_FILE" => "/tmp/outer-repository/.git/index"
    }
    previous = inherited.keys.to_h { |key| [key, ENV[key]] }
    ENV.update(inherited)

    with_isolated_git_environment do
      inherited.each_key { |key| refute ENV.key?(key), "#{key} leaked into isolated Git context" }
      assert_equal "1", ENV["GIT_CONFIG_NOSYSTEM"]
      assert_equal File::NULL, ENV["GIT_CONFIG_GLOBAL"]
    end
  ensure
    inherited.each_key { |key| ENV.delete(key) }
    previous.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
  end

  def classify(*paths, contract_impact: {})
    AffectedComponents.classify(paths, services: SERVICES, public_contracts: PUBLIC,
                                 common_openapi: "contracts/openapi/common.v1.yaml",
                                 contract_impact: contract_impact)
  end

  def test_storefront_change_is_component_scoped
    assert_equal %w[frontend:storefront global], classify("frontend/apps/storefront/app/page.tsx")
  end

  def test_shared_frontend_package_impacts_both_apps
    assert_equal %w[frontend:admin frontend:storefront global], classify("frontend/packages/ui/button.tsx")
  end

  def test_service_change_is_scoped_to_the_service
    assert_equal %w[global service:product], classify("services/product/internal/domain/product.go")
  end

  def test_public_contract_impacts_owner_and_declared_frontend_audience
    assert_equal %w[frontend:admin global service:product], classify("contracts/openapi/product.v1.yaml")
  end

  def test_semantic_contract_uses_supplied_delta_instead_of_all_services
    impact = {"config/contracts/dependency-map.yaml" => %w[service:cart service:product]}
    assert_equal %w[global service:cart service:product system],
                 classify("config/contracts/dependency-map.yaml", contract_impact: impact)
  end

  def test_dependency_delta_resolves_internal_sync_dependency
    before = {"services" => {"cart" => {"sync" => ["pricing"], "events_in" => []}}}
    after = {"services" => {"cart" => {"sync" => ["pricing", "product"], "events_in" => []}}}
    impact = AffectedComponents.semantic_contract_impact(
      "config/contracts/dependency-map.yaml",
      before: before,
      after: after,
      services: SERVICES,
      frontends: %w[storefront admin],
      context: {before_events: {}, after_events: {}}
    )
    assert_equal %w[service:cart service:pricing service:product], impact
  end

  def test_event_delta_routes_only_producer_and_consumers
    before = {"events" => {"product.ProductUpdated.v1" => {"consumers" => ["catalog"]}}}
    after = {"events" => {"product.ProductUpdated.v1" => {"consumers" => %w[catalog search]}}}
    impact = AffectedComponents.semantic_contract_impact(
      "config/contracts/event-contracts.yaml",
      before: before,
      after: after,
      services: SERVICES,
      frontends: %w[storefront admin]
    )
    assert_equal %w[service:catalog service:product service:search], impact
  end

  def test_public_api_registry_delta_routes_owner_and_audience
    before = {"status" => "exact", "contracts" => {"product" => {"audiences" => ["admin"]}}}
    after = {"status" => "exact", "contracts" => {"product" => {"audiences" => %w[admin storefront]}}}
    impact = AffectedComponents.semantic_contract_impact(
      "config/contracts/public-api-contracts.yaml",
      before: before,
      after: after,
      services: SERVICES,
      frontends: %w[storefront admin]
    )
    assert_equal %w[frontend:admin frontend:storefront service:product], impact
  end

  def test_ci_control_change_fails_closed_to_all_component_classes
    affected = classify("scripts/repoctl.py")
    assert_includes affected, "frontend:storefront"
    assert_includes affected, "frontend:admin"
    SERVICES.each { |service| assert_includes affected, "service:#{service}" }
    assert_includes affected, "platform:terraform"
    assert_includes affected, "platform:ansible"
    assert_includes affected, "system"
  end

  def test_changed_paths_reads_exact_git_range
    Dir.mktmpdir("ci-affected-git") do |dir|
      with_isolated_git_environment do
        initialize_temporary_git_repository(dir)
        File.write(File.join(dir, "a.txt"), "one\n")
        isolated_git("add", "a.txt", chdir: dir)
        isolated_git("commit", "-qm", "base", chdir: dir)
        base = isolated_git_output("rev-parse", "HEAD", chdir: dir)
        File.write(File.join(dir, "b.txt"), "two\n")
        isolated_git("add", "b.txt", chdir: dir)
        isolated_git("commit", "-qm", "head", chdir: dir)
        head = isolated_git_output("rev-parse", "HEAD", chdir: dir)
        assert_equal ["b.txt"], AffectedComponents.changed_paths(dir, base, head)
      end
    end
  end

  def test_worktree_mode_includes_untracked_files
    Dir.mktmpdir("ci-affected-worktree") do |dir|
      with_isolated_git_environment do
        initialize_temporary_git_repository(dir)
        File.write(File.join(dir, "a.txt"), "one\n")
        isolated_git("add", "a.txt", chdir: dir)
        isolated_git("commit", "-qm", "base", chdir: dir)
        base = isolated_git_output("rev-parse", "HEAD", chdir: dir)
        File.write(File.join(dir, "new.txt"), "new\n")
        assert_equal ["new.txt"], AffectedComponents.changed_paths(dir, base, "WORKTREE")
      end
    end
  end

  def test_unknown_service_path_fails_closed
    assert_raises(ArgumentError) { classify("services/warehouse/main.go") }
  end

  def test_unregistered_openapi_contract_fails_closed
    assert_raises(ArgumentError) { classify("contracts/openapi/unknown.v1.yaml") }
  end
end
