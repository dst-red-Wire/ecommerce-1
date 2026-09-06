SHELL := /bin/sh

.PHONY: install dev dev-storefront dev-admin lint typecheck test e2e build check

install:
	corepack pnpm install --frozen-lockfile

dev:
	corepack pnpm dev

dev-storefront:
	corepack pnpm dev:storefront

dev-admin:
	corepack pnpm dev:admin

lint:
	corepack pnpm lint

typecheck:
	corepack pnpm typecheck

test:
	corepack pnpm test

e2e:
	corepack pnpm test:e2e

build:
	corepack pnpm build

check: lint typecheck test build
