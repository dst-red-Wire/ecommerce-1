# frozen_string_literal: true

require "fileutils"
require "minitest/autorun"
require "shellwords"
require "tmpdir"
require_relative "../scripts/ci-affected"

class CIAffectedTest < Minitest::Test
  SERVICES = %w[catalog product inventory cart pricing tax order payment shipping tracking returns billing fraud-risk search review user-profile notification].freeze
  PUBLIC = {
    "contracts/openapi/product.v1.yaml" => {"service" => "product", "audiences" => ["admin"]}
  }.freeze

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
      system("git", "init", "-q", dir, exception: true)
      system("git", "-C", dir, "config", "user.email", "ci@example.invalid", exception: true)
      system("git", "-C", dir, "config", "user.name", "CI Test", exception: true)
      File.write(File.join(dir, "a.txt"), "one\n")
      system("git", "-C", dir, "add", "a.txt", exception: true)
      system("git", "-C", dir, "commit", "-qm", "base", exception: true)
      base = `git -C #{Shellwords.escape(dir)} rev-parse HEAD`.strip
      File.write(File.join(dir, "b.txt"), "two\n")
      system("git", "-C", dir, "add", "b.txt", exception: true)
      system("git", "-C", dir, "commit", "-qm", "head", exception: true)
      head = `git -C #{Shellwords.escape(dir)} rev-parse HEAD`.strip
      assert_equal ["b.txt"], AffectedComponents.changed_paths(dir, base, head)
    end
  end

  def test_worktree_mode_includes_untracked_files
    Dir.mktmpdir("ci-affected-worktree") do |dir|
      system("git", "init", "-q", dir, exception: true)
      system("git", "-C", dir, "config", "user.email", "ci@example.invalid", exception: true)
      system("git", "-C", dir, "config", "user.name", "CI Test", exception: true)
      File.write(File.join(dir, "a.txt"), "one\n")
      system("git", "-C", dir, "add", "a.txt", exception: true)
      system("git", "-C", dir, "commit", "-qm", "base", exception: true)
      base = `git -C #{Shellwords.escape(dir)} rev-parse HEAD`.strip
      File.write(File.join(dir, "new.txt"), "new\n")
      assert_equal ["new.txt"], AffectedComponents.changed_paths(dir, base, "WORKTREE")
    end
  end

  def test_unknown_service_path_fails_closed
    assert_raises(ArgumentError) { classify("services/warehouse/main.go") }
  end

  def test_unregistered_openapi_contract_fails_closed
    assert_raises(ArgumentError) { classify("contracts/openapi/unknown.v1.yaml") }
  end
end
