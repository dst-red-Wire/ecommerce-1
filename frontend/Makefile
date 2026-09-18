SCOPE ?= all
.PHONY: generate check run-storefront run-admin

generate:
	@python3 ../scripts/repoctl.py frontend generate all

check:
	@python3 ../scripts/repoctl.py frontend check $(SCOPE)

run-storefront:
	@python3 ../scripts/repoctl.py frontend run storefront

run-admin:
	@python3 ../scripts/repoctl.py frontend run admin
