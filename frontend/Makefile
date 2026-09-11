SCOPE ?= all
.PHONY: generate check run-storefront run-admin
generate:
	@go run github.com/a-h/templ/cmd/templ@v0.3.960 generate
check:
	@python3 ../scripts/repoctl.py frontend check $(SCOPE)
run-storefront:
	@go run ./apps/storefront
run-admin:
	@go run ./apps/admin
