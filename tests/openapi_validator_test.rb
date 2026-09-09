# frozen_string_literal: true

require "fileutils"
require "minitest/autorun"
require "tmpdir"
require "yaml"
require_relative "../scripts/validate-openapi"

class OpenApiValidatorTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  SPEC_PATH = "contracts/openapi/product.v1.yaml"
  REGISTRY_PATH = "config/contracts/public-api-contracts.yaml"
  OWNERSHIP_PATH = "config/contracts/service-ownership.yaml"

  def test_repository_contracts_pass
    assert_empty OpenApiContractValidator.validate(ROOT)
  end

  def test_missing_operation_id_fails_closed
    spec = product_spec
    spec.fetch("paths").fetch("/v1/products").fetch("get").delete("operationId")

    errors = validate_product(spec)

    assert errors.any? { |error| error.include?("must declare operationId") }, errors.inspect
  end

  def test_ownership_mismatch_is_rejected
    spec = product_spec
    spec["x-ecommerce-ownership"] = ["prices"]

    errors = validate_product(spec)

    assert errors.any? { |error| error.include?("must match exact service ownership") }, errors.inspect
  end

  def test_registered_checkout_contract_is_allowed
    Dir.mktmpdir("openapi-checkout") do |root|
      %w[
        architecture.lock.yaml
        config/contracts/dependency-map.yaml
        config/contracts/public-api-contracts.yaml
        config/contracts/service-ownership.yaml
        contracts/openapi/common.v1.yaml
        contracts/openapi/product.v1.yaml
      ].each do |relative|
        target = File.join(root, relative)
        FileUtils.mkdir_p(File.dirname(target))
        FileUtils.cp(File.join(ROOT, relative), target)
      end

      ownership = ArchitectureValidator.load_yaml(root, OWNERSHIP_PATH).fetch("services").fetch("checkout")
      checkout = product_spec
      checkout["x-ecommerce-service"] = "checkout"
      checkout["x-ecommerce-authoritative-store"] = ownership.fetch("db")
      checkout["x-ecommerce-ownership"] = ownership.fetch("owns")
      checkout["x-ecommerce-audiences"] = ["storefront"]
      checkout["paths"] = {
        "/v1/checkout" => {
          "get" => {
            "operationId" => "getCheckoutSession",
            "responses" => {"200" => {"description" => "ok"}}
          }
        }
      }
      checkout_path = "contracts/openapi/checkout.v1.yaml"
      File.write(File.join(root, checkout_path), YAML.dump(checkout))

      registry_path = File.join(root, REGISTRY_PATH)
      registry = YAML.safe_load_file(registry_path, aliases: false)
      registry.fetch("contracts")["checkout"] = {
        "path" => checkout_path,
        "api_version" => "1.0.0",
        "path_major" => "v1",
        "audiences" => ["storefront"]
      }
      File.write(registry_path, YAML.dump(registry))

      assert_empty OpenApiContractValidator.validate(root)
    end
  end

  def test_write_without_idempotency_key_is_rejected
    spec = product_spec
    spec.fetch("paths").fetch("/v1/products").fetch("post")["parameters"] = []

    errors = validate_product(spec)

    assert errors.any? { |error| error.include?("must require Idempotency-Key") }, errors.inspect
  end

  def test_patch_without_if_match_is_rejected
    spec = product_spec
    patch = spec.fetch("paths").fetch("/v1/products/{productId}").fetch("patch")
    patch["parameters"] = patch.fetch("parameters").reject do |parameter|
      parameter["$ref"]&.end_with?("/IfMatch")
    end

    errors = validate_product(spec)

    assert errors.any? { |error| error.include?("must require If-Match") }, errors.inspect
  end

  def test_remote_ref_is_rejected
    spec = product_spec
    spec.fetch("paths").fetch("/v1/products").fetch("get").fetch("responses").fetch("200").fetch("content").fetch("application/json")["schema"] = {
      "$ref" => "https://example.invalid/schema.yaml#/Product"
    }

    errors = validate_product(spec)

    assert errors.any? { |error| error.include?("remote $ref is forbidden") }, errors.inspect
  end

  private

  def product_spec
    Marshal.load(Marshal.dump(ArchitectureValidator.load_yaml(ROOT, SPEC_PATH)))
  end

  def validate_product(spec)
    registry = ArchitectureValidator.load_yaml(ROOT, REGISTRY_PATH)
    ownership = ArchitectureValidator.load_yaml(ROOT, OWNERSHIP_PATH).fetch("services").fetch("product")
    entry = registry.fetch("contracts").fetch("product")

    OpenApiContractValidator.validate_document(
      root: ROOT,
      spec_path: SPEC_PATH,
      spec: spec,
      service: "product",
      entry: entry,
      ownership: ownership,
      registry: registry,
      cache: { SPEC_PATH => spec },
      operation_ids: {}
    )
  end
end
