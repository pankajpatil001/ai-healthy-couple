# Developer entrypoints for the Healthy Couple Foundation slice.
#
# Uses the project virtualenv if present so contributors don't have to activate
# it manually. Override with `make PY=python3 <target>` when needed.

PY ?= $(shell [ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)
ALEMBIC := $(PY) -m alembic
PYTEST := $(PY) -m pytest

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: migrate
migrate: ## Apply all migrations up to head
	$(ALEMBIC) upgrade head

.PHONY: downgrade
downgrade: ## Roll back one migration (make downgrade REV=-1)
	$(ALEMBIC) downgrade $(or $(REV),-1)

.PHONY: migration
migration: ## Autogenerate a migration (make migration MSG="add users")
	$(ALEMBIC) revision --autogenerate -m "$(MSG)"

.PHONY: migration-history
migration-history: ## Show migration history
	$(ALEMBIC) history --verbose

.PHONY: test
test: ## Run the test suite
	$(PYTEST)

.PHONY: test-fast
test-fast: ## Run tests excluding the slow property-based tests
	$(PYTEST) -m "not property"
