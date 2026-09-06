SHELL := /bin/sh

.PHONY: site install dev dev-storefront dev-admin lint typecheck test e2e build check

install:
	corepack pnpm install --frozen-lockfile

site: install
	@printf 'Storefront: http://localhost:3000\nAdmin:      http://localhost:3001\nTablet:     http://localhost:3001/tablet\nMobile:     http://localhost:3001/mobile\nStop:       Ctrl+C\n'
	corepack pnpm dev

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
