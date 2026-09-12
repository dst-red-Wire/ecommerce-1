SCOPE ?= all
TEMPL_VERSION := $(shell sed -n 's/^TEMPL_VERSION=//p' ../config/toolchain/versions.env)
.PHONY: generate check run-storefront run-admin
generate:
	@test -n "$(TEMPL_VERSION)"
	@go run github.com/a-h/templ/cmd/templ@v$(TEMPL_VERSION) generate
check:
	@python3 ../scripts/repoctl.py frontend check $(SCOPE)
run-storefront:
	@go run ./apps/storefront
run-admin:
	@go run ./apps/admin
