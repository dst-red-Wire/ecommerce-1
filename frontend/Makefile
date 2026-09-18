SCOPE ?= all
.PHONY: generate check run-storefront run-admin

generate:
	@python3 ../scripts/repoctl.py frontend generate all

check:
	@python3 ../scripts/repoctl.py frontend check $(SCOPE)

run-storefront:
	@go run ./apps/storefront

run-admin:
	@go run ./apps/admin
