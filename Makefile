.PHONY: help install install-dev install-tools setup lint format typecheck
.PHONY: test test-unit test-security test-integration test-all coverage
.PHONY: run run-sse run-dev inspect clean doctor
.PHONY: install-tools-osint install-tools-secrets install-tools-container
.PHONY: install-tools-cloud install-tools-api install-tools-ad
.PHONY: install-tools-wireless install-tools-stealth

# ============================================================
# CONFIGURATION
# ============================================================
PYTHON := uv run python
PYTEST := uv run pytest
PROJECT := tengu

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ============================================================
# INSTALLATION & SETUP
# ============================================================
install: ## Install project dependencies
	uv sync

install-dev: ## Install dev dependencies (tests, lint, types)
	uv sync --extra dev

install-tools: ## Install external pentesting tools
	chmod +x scripts/install-tools.sh
	./scripts/install-tools.sh --all

install-tools-recon: ## Install recon tools only
	./scripts/install-tools.sh --recon

install-tools-web: ## Install web scanning tools only
	./scripts/install-tools.sh --web

install-tools-osint: ## Install OSINT tools (theHarvester, whatweb)
	./scripts/install-tools.sh --osint

install-tools-secrets: ## Install secret scanning tools (trufflehog, gitleaks)
	./scripts/install-tools.sh --secrets

install-tools-container: ## Install container security tools (trivy)
	./scripts/install-tools.sh --container

install-tools-cloud: ## Install cloud security tools (scoutsuite, checkov)
	./scripts/install-tools.sh --cloud

install-tools-api: ## Install API security tools (arjun)
	./scripts/install-tools.sh --api

install-tools-ad: ## Install Active Directory tools (enum4linux-ng, nxc, impacket)
	./scripts/install-tools.sh --ad

install-tools-wireless: ## Install wireless tools (aircrack-ng)
	./scripts/install-tools.sh --wireless

install-tools-stealth: ## Install stealth/OPSEC tools (tor, torsocks, proxychains4, socat)
	./scripts/install-tools.sh --stealth

setup: install-dev ## Full setup (Python)
	@echo "Tengu setup complete! Run 'make install-tools' to install pentesting tools."

# ============================================================
# CODE QUALITY
# ============================================================
lint: ## Lint with ruff
	uv run ruff check src/ tests/

format: ## Format with ruff
	uv run ruff format src/ tests/

typecheck: ## Type-check with mypy
	uv run mypy src/

check: lint typecheck ## Lint + typecheck

# ============================================================
# TESTS
# ============================================================
test: test-unit test-security ## Fast tests (unit + security)

test-unit: ## Unit tests
	$(PYTEST) tests/unit -v

test-security: ## Security tests (command injection, input validation)
	$(PYTEST) tests/security -v

test-integration: ## Integration tests (requires tools installed)
	$(PYTEST) tests/integration -v

test-all: ## All tests
	$(PYTEST) tests/ -v

coverage: ## Tests with coverage report
	$(PYTEST) tests/ --cov=src/$(PROJECT) --cov-report=html --cov-report=term-missing
	@echo "HTML report at htmlcov/index.html"

# ============================================================
# RUNNING
# ============================================================
run: ## Start MCP server (stdio transport)
	uv run tengu

run-sse: ## Start MCP server (SSE transport, binds 0.0.0.0 for remote access)
	uv run tengu --transport sse --host 0.0.0.0

run-dev: ## Start with debug logging
	TENGU_LOG_LEVEL=DEBUG uv run tengu

inspect: ## Open MCP Inspector to test tools interactively
	npx @modelcontextprotocol/inspector uv run tengu

# ============================================================
# TOOLS
# ============================================================
doctor: ## Check which pentesting tools are installed
	$(PYTHON) -c "import asyncio; from tengu.executor.registry import check_all; asyncio.run(check_all())"

# ============================================================
# CLEANUP
# ============================================================
clean: ## Remove build artifacts and cache
	rm -rf dist/ build/ .pytest_cache/ htmlcov/ .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
