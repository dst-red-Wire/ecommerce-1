# frozen_string_literal: true

require "fileutils"
require "minitest/autorun"
require "tmpdir"
require_relative "../scripts/ci-affected"

class CIAffectedTest < Minitest::Test
  SERVICES = %w[catalog product inventory cart pricing tax order payment shipping tracking returns billing fraud-risk search review user-profile notification].freeze
  PUBLIC = {
    "contracts/openapi/product.v1.yaml" => {"service" => "product", "audiences" => ["admin"]}
  }.freeze

  def classify(*paths)
    AffectedComponents.classify(paths, services: SERVICES, public_contracts: PUBLIC,
                                 common_openapi: "contracts/openapi/common.v1.yaml")
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

  def test_ci_control_change_fails_closed_to_all_component_classes
    affected = classify("scripts/ci-test.sh")
    assert_includes affected, "frontend:storefront"
    assert_includes affected, "frontend:admin"
    SERVICES.each { |service| assert_includes affected, "service:#{service}" }
    assert_includes affected, "platform:terraform"
    assert_includes affected, "platform:ansible"
    assert_includes affected, "system"
  end

  def test_changed_paths_reads_exact_git_range
    Dir.mktmpdir("ci-affected-git") do |dir|
      Dir.chdir(dir) do
        system("git", "init", "-q", exception: true)
        system("git", "config", "user.email", "ci@example.invalid", exception: true)
        system("git", "config", "user.name", "CI Test", exception: true)
        File.write("a.txt", "one\n")
        system("git", "add", "a.txt", exception: true)
        system("git", "commit", "-qm", "base", exception: true)
        base = `git rev-parse HEAD`.strip
        File.write("b.txt", "two\n")
        system("git", "add", "b.txt", exception: true)
        system("git", "commit", "-qm", "head", exception: true)
        head = `git rev-parse HEAD`.strip
        assert_equal ["b.txt"], AffectedComponents.changed_paths(base, head)
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
