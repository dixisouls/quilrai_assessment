# Developer entry points. CI runs the same commands (see .github/workflows/ci.yml).
.DEFAULT_GOAL := help
SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

.PHONY: help install fmt lint typecheck test security check

help: ## Show this help
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

install: ## Sync deps and install git hooks
	uv sync --all-groups
	uv run pre-commit install

fmt: ## Auto-format and auto-fix lint
	uv run ruff format .
	uv run ruff check --fix .

lint: ## Format check + lint (no changes)
	uv run ruff format --check .
	uv run ruff check .

typecheck: ## mypy --strict
	uv run mypy

test: ## Full test suite with coverage gate
	uv run pytest --cov

security: ## Lockfile, CVEs, Trojan Source, and (if installed) gitleaks/actionlint
	uv lock --check
	uv export --all-groups --no-emit-workspace --format requirements.txt -o .req-audit.txt
	status=0; uv run pip-audit -r .req-audit.txt --require-hashes --disable-pip --strict \
	  --progress-spinner off || status=$$?; rm -f .req-audit.txt; exit $$status
	uv run python scripts/check_bidi.py
	@if command -v gitleaks >/dev/null; then gitleaks git --config .gitleaks.toml --redact .; \
	  else echo "gitleaks not installed; skipped (CI runs it)"; fi
	@if command -v actionlint >/dev/null; then actionlint; \
	  else echo "actionlint not installed; skipped (CI runs it)"; fi

check: lint typecheck test security ## Everything CI runs
