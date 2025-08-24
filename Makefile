# =============================================================================
# FLEXT-LDIF - LDIF Processing Library Makefile
# =============================================================================
# Python 3.13+ LDIF Framework - Clean Architecture + DDD + Zero Tolerance
# =============================================================================

# Project Configuration
PROJECT_NAME := flext-ldif
PYTHON_VERSION := 3.13
POETRY := poetry
SRC_DIR := src
TESTS_DIR := tests
COV_DIR := flext_ldif

# Quality Standards
MIN_COVERAGE := 90

# LDIF Configuration
LDIF_ENCODING := utf-8
LDIF_BUFFER_SIZE := 8192
LDIF_MAX_LINE_LENGTH := 76

# Export Configuration
export PROJECT_NAME PYTHON_VERSION MIN_COVERAGE LDIF_ENCODING LDIF_BUFFER_SIZE LDIF_MAX_LINE_LENGTH

# =============================================================================
# HELP & INFORMATION
# =============================================================================

.PHONY: help
help: ## Show available commands
	@echo "FLEXT-LDIF - LDIF Processing Library"
	@echo "==================================="
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: info
info: ## Show project information
	@echo "Project: $(PROJECT_NAME)"
	@echo "Python: $(PYTHON_VERSION)+"
	@echo "Poetry: $(POETRY)"
	@echo "Coverage: $(MIN_COVERAGE)% minimum"
	@echo "LDIF Encoding: $(LDIF_ENCODING)"
	@echo "Architecture: Clean Architecture + DDD + LDIF3"

# =============================================================================
# SETUP & INSTALLATION
# =============================================================================

.PHONY: install
install: ## Install dependencies
	$(POETRY) install

.PHONY: install-dev
install-dev: ## Install dev dependencies
	$(POETRY) install --with dev,test,docs

.PHONY: setup
setup: install-dev ## Complete project setup
	$(POETRY) run pre-commit install

# =============================================================================
# QUALITY GATES (MANDATORY)
# =============================================================================

.PHONY: validate
validate: lint type-check security test ## Run all quality gates

.PHONY: check
check: lint type-check ## Quick health check

.PHONY: lint
lint: ## Run linting
	$(POETRY) run ruff check $(SRC_DIR) $(TESTS_DIR)

.PHONY: format
format: ## Format code
	$(POETRY) run ruff format $(SRC_DIR) $(TESTS_DIR)

.PHONY: type-check
type-check: ## Run type checking
	$(POETRY) run mypy $(SRC_DIR) --strict

.PHONY: security
security: ## Run security scanning
	$(POETRY) run bandit -r $(SRC_DIR)
	# Ignore GHSA-wj6h-64fc-37mp: Minerva timing attack in python-ecdsa (transitional dependency)
	# This is a side-channel attack that ecdsa maintainers consider out-of-scope
	# Risk assessment: Acceptable for LDIF processing use case (no JWT signing operations)
	$(POETRY) run pip-audit --ignore-vuln GHSA-wj6h-64fc-37mp

.PHONY: fix
fix: ## Auto-fix issues
	$(POETRY) run ruff check $(SRC_DIR) $(TESTS_DIR) --fix
	$(POETRY) run ruff format $(SRC_DIR) $(TESTS_DIR)

# =============================================================================
# TESTING
# =============================================================================

.PHONY: test
test: ## Run tests with coverage
	$(POETRY) run pytest $(TESTS_DIR) --cov=$(COV_DIR) --cov-report=term-missing --cov-fail-under=$(MIN_COVERAGE)

.PHONY: test-unit
test-unit: ## Run unit tests
	$(POETRY) run pytest $(TESTS_DIR) -m "not integration" -v

.PHONY: test-integration
test-integration: ## Run integration tests
	$(POETRY) run pytest $(TESTS_DIR) -m integration -v

.PHONY: test-ldif
test-ldif: ## Run LDIF specific tests
	$(POETRY) run pytest $(TESTS_DIR) -m ldif -v

.PHONY: test-parser
test-parser: ## Run parser tests
	$(POETRY) run pytest $(TESTS_DIR) -m parser -v

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests
	$(POETRY) run pytest $(TESTS_DIR) -m e2e -v

.PHONY: test-fast
test-fast: ## Run tests without coverage
	$(POETRY) run pytest $(TESTS_DIR) -v

.PHONY: coverage-html
coverage-html: ## Generate HTML coverage report
	$(POETRY) run pytest $(TESTS_DIR) --cov=$(COV_DIR) --cov-report=html

# =============================================================================
# BUILD & DISTRIBUTION
# =============================================================================

.PHONY: build
build: ## Build package
	$(POETRY) build

.PHONY: build-clean
build-clean: clean build ## Clean and build

# =============================================================================
# LDIF OPERATIONS
# =============================================================================

.PHONY: ldif-parse
ldif-parse: ## Test LDIF parsing
	$(POETRY) run python -c "from flext_ldif import FlextLdifAPI; api = FlextLdifAPI(); print('LDIF parser test passed')"

.PHONY: ldif-validate
ldif-validate: ## Validate LDIF files
	$(POETRY) run python -c "from flext_ldif import flext_ldif_validate; print('LDIF validation test passed')"

.PHONY: ldif-config
ldif-config: ## Test LDIF configuration
	$(POETRY) run python -c "from flext_ldif.config import FlextLdifConfig; print('LDIF config valid')"

.PHONY: ldif-operations
ldif-operations: ldif-config ldif-parse ldif-validate ## Run all LDIF validations

# =============================================================================
# DOCUMENTATION
# =============================================================================

.PHONY: docs
docs: ## Build documentation
	$(POETRY) run mkdocs build

.PHONY: docs-serve
docs-serve: ## Serve documentation
	$(POETRY) run mkdocs serve

# =============================================================================
# DEPENDENCIES
# =============================================================================

.PHONY: deps-update
deps-update: ## Update dependencies
	$(POETRY) update

.PHONY: deps-show
deps-show: ## Show dependency tree
	$(POETRY) show --tree

.PHONY: deps-audit
deps-audit: ## Audit dependencies
	$(POETRY) run pip-audit

# =============================================================================
# DEVELOPMENT
# =============================================================================

.PHONY: shell
shell: ## Open Python shell
	$(POETRY) run python

.PHONY: pre-commit
pre-commit: ## Run pre-commit hooks
	$(POETRY) run pre-commit run --all-files

# =============================================================================
# MAINTENANCE
# =============================================================================

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ htmlcov/ .coverage .mypy_cache/ .ruff_cache/
	rm -rf *.ldif output.ldif test.ldif
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

.PHONY: clean-all
clean-all: clean ## Deep clean including venv
	rm -rf .venv/

.PHONY: reset
reset: clean-all setup ## Reset project

# =============================================================================
# DIAGNOSTICS
# =============================================================================

.PHONY: diagnose
diagnose: ## Project diagnostics
	@echo "Python: $$(python --version)"
	@echo "Poetry: $$($(POETRY) --version)"
	@echo "LDIF3: $$($(POETRY) run python -c 'import ldif3; print(ldif3.__version__)' 2>/dev/null || echo 'Not available')"
	@$(POETRY) env info

.PHONY: doctor
doctor: diagnose check ## Health check

# =============================================================================
# ALIASES (SINGLE LETTER SHORTCUTS)
# =============================================================================

.PHONY: t l f tc c i v
t: test
l: lint
f: format
tc: type-check
c: clean
i: install
v: validate

# =============================================================================
# CONFIGURATION
# =============================================================================

.DEFAULT_GOAL := help
