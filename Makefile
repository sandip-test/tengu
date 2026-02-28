.PHONY: help install install-dev install-tools setup lint format typecheck
.PHONY: test test-unit test-security test-integration test-all coverage
.PHONY: run run-sse run-dev inspect clean doctor
.PHONY: install-tools-osint install-tools-secrets install-tools-container
.PHONY: install-tools-cloud install-tools-api install-tools-ad
.PHONY: install-tools-wireless install-tools-stealth

# ============================================================
# CONFIGURAÇÃO
# ============================================================
PYTHON := uv run python
PYTEST := uv run pytest
PROJECT := tengu

help: ## Mostra esta ajuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ============================================================
# INSTALAÇÃO E SETUP
# ============================================================
install: ## Instala dependências do projeto
	uv sync

install-dev: ## Instala dependências de dev (testes, lint, types)
	uv sync --extra dev

install-tools: ## Instala ferramentas externas de pentesting
	chmod +x scripts/install-tools.sh
	./scripts/install-tools.sh --all

install-tools-recon: ## Instala apenas ferramentas de reconhecimento
	./scripts/install-tools.sh --recon

install-tools-web: ## Instala apenas ferramentas de web scanning
	./scripts/install-tools.sh --web

install-tools-osint: ## Instala ferramentas OSINT (theHarvester, whatweb)
	./scripts/install-tools.sh --osint

install-tools-secrets: ## Instala ferramentas de secret scanning (trufflehog, gitleaks)
	./scripts/install-tools.sh --secrets

install-tools-container: ## Instala ferramentas de container security (trivy)
	./scripts/install-tools.sh --container

install-tools-cloud: ## Instala ferramentas de cloud security (scoutsuite, checkov)
	./scripts/install-tools.sh --cloud

install-tools-api: ## Instala ferramentas de API security (arjun)
	./scripts/install-tools.sh --api

install-tools-ad: ## Instala ferramentas de Active Directory (enum4linux-ng, nxc, impacket)
	./scripts/install-tools.sh --ad

install-tools-wireless: ## Instala ferramentas de wireless (aircrack-ng)
	./scripts/install-tools.sh --wireless

install-tools-stealth: ## Instala ferramentas stealth/OPSEC (tor, torsocks, proxychains4, socat)
	./scripts/install-tools.sh --stealth

setup: install-dev ## Setup completo (Python)
	@echo "Tengu setup completo! Execute 'make install-tools' para instalar ferramentas de pentesting."

# ============================================================
# QUALIDADE DE CÓDIGO
# ============================================================
lint: ## Lint com ruff
	uv run ruff check src/ tests/

format: ## Formata com ruff
	uv run ruff format src/ tests/

typecheck: ## Verifica tipos com mypy
	uv run mypy src/

check: lint typecheck ## Lint + typecheck

# ============================================================
# TESTES
# ============================================================
test: test-unit test-security ## Testes rápidos (unit + security)

test-unit: ## Testes unitários
	$(PYTEST) tests/unit -v

test-security: ## Testes de segurança (command injection, validation)
	$(PYTEST) tests/security -v

test-integration: ## Testes de integração (requer ferramentas instaladas)
	$(PYTEST) tests/integration -v

test-all: ## Todos os testes
	$(PYTEST) tests/ -v

coverage: ## Testes com cobertura
	$(PYTEST) tests/ --cov=src/$(PROJECT) --cov-report=html --cov-report=term-missing
	@echo "Relatório HTML em htmlcov/index.html"

# ============================================================
# EXECUÇÃO
# ============================================================
run: ## Inicia o MCP server (stdio)
	uv run tengu

run-sse: ## Inicia o MCP server (SSE transport)
	uv run tengu --transport sse

run-dev: ## Inicia com hot-reload e debug logging
	TENGU_LOG_LEVEL=DEBUG uv run tengu

inspect: ## Abre o MCP Inspector para testar tools interativamente
	npx @modelcontextprotocol/inspector uv run tengu

# ============================================================
# FERRAMENTAS
# ============================================================
doctor: ## Verifica quais ferramentas de pentest estão disponíveis
	$(PYTHON) -c "import asyncio; from tengu.executor.registry import check_all; asyncio.run(check_all())"

# ============================================================
# LIMPEZA
# ============================================================
clean: ## Remove artefatos de build e cache
	rm -rf dist/ build/ .pytest_cache/ htmlcov/ .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
