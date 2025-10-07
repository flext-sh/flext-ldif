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
MIN_COVERAGE := 65

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
	@echo "Coverage: $(MIN_COVERAGE)% minimum (WORKSPACE STANDARD)"
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
# QUALITY GATES (MANDATORY - ZERO TOLERANCE)
# =============================================================================

.PHONY: validate
validate: lint type-check security test ## Run all quality gates (MANDATORY ORDER)

.PHONY: check
check: lint type-check ## Quick health check

.PHONY: lint
lint: ## Run linting (ZERO TOLERANCE)
	$(POETRY) run ruff check .

.PHONY: format
format: ## Format code
	$(POETRY) run ruff format .

.PHONY: type-check
type-check: ## Run type checking with Pyrefly (ZERO TOLERANCE)
	PYTHONPATH=. $(POETRY) run pyrefly check $(SRC_DIR) $(TESTS_DIR)

.PHONY: security
security: ## Run security scanning
	$(POETRY) run bandit -r $(SRC_DIR)
	# Ignore GHSA-wj6h-64fc-37mp: Minerva timing attack in python-ecdsa (transitional dependency)
	# This is a side-channel attack that ecdsa maintainers consider out-of-scope
	# Risk assessment: Acceptable for LDIF processing use case (no JWT signing operations)
	# Ignore GHSA-mw26-5g2v-hqw3: deepdiff vulnerability (transitive dependency via dbt-common)
	# Risk assessment: Acceptable for LDIF processing use case (not directly used in LDIF operations)
	$(POETRY) run pip-audit --ignore-vuln GHSA-wj6h-64fc-37mp --ignore-vuln GHSA-mw26-5g2v-hqw3

.PHONY: fix
fix: ## Auto-fix issues
	$(POETRY) run ruff check . --fix
	$(POETRY) run ruff format .

# =============================================================================
# TESTING (MANDATORY - MINIMUM COVERAGE)
# =============================================================================

.PHONY: test
test: ## Run tests with minimum coverage (WORKSPACE STANDARD)
	PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest -q --maxfail=10000 --cov=$(COV_DIR) --cov-report=term-missing:skip-covered --cov-fail-under=$(MIN_COVERAGE)

.PHONY: test-unit
test-unit: ## Run unit tests
	PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest -m "not integration" -v

.PHONY: test-integration
test-integration: ## Run integration tests with Docker
	PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest -m integration -v

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
	PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest -v

.PHONY: coverage-html
coverage-html: ## Generate HTML coverage report
	PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest --cov=$(COV_DIR) --cov-report=html

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
	PYTHONPATH=$(SRC_DIR) $(POETRY) run python -c "from flext_ldif import FlextLdif; api = FlextLdif(); print('LDIF parser test passed')"

.PHONY: ldif-validate
ldif-validate: ## Validate LDIF files
	PYTHONPATH=$(SRC_DIR) $(POETRY) run python -c "from flext_ldif import flext_ldif_validate; print('LDIF validation test passed')"

.PHONY: ldif-config
ldif-config: ## Test LDIF configuration
	PYTHONPATH=$(SRC_DIR) $(POETRY) run python -c "from flext_ldif.config import FlextLdifConfig; print('LDIF config valid')"

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
	PYTHONPATH=$(SRC_DIR) $(POETRY) run python

.PHONY: pre-commit
pre-commit: ## Run pre-commit hooks
	$(POETRY) run pre-commit run --all-files

# =============================================================================
# MAINTENANCE
# =============================================================================

.PHONY: clean
clean: ## Clean build artifacts and cruft
	@echo "🧹 Cleaning $(PROJECT_NAME) - removing build artifacts, cache files, and cruft..."

	# Build artifacts
	rm -rf build/ dist/ *.egg-info/

	# Test artifacts
	rm -rf .pytest_cache/ htmlcov/ .coverage .coverage.* coverage.xml

	# Python cache directories
	rm -rf .mypy_cache/ .pyrefly_cache/ .ruff_cache/

	# Python bytecode
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true

	# LDIF-specific files
	rm -rf *.ldif output.ldif test.ldif input.ldif

	# Data directories
	rm -rf data/input/ data/output/ data/test/

	# Temporary files
	find . -type f -name "*.tmp" -delete 2>/dev/null || true
	find . -type f -name "*.temp" -delete 2>/dev/null || true
	find . -type f -name ".DS_Store" -delete 2>/dev/null || true

	# Log files
	find . -type f -name "*.log" -delete 2>/dev/null || true

	# Editor files
	find . -type f -name ".vscode/settings.json" -delete 2>/dev/null || true
	find . -type f -name ".idea/" -type d -exec rm -rf {} + 2>/dev/null || true

	@echo "✅ $(PROJECT_NAME) cleanup complete"

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
	@echo "LDIF3: $$(PYTHONPATH=$(SRC_DIR) $(POETRY) run python -c 'import ldif3; print(ldif3.__version__)' 2>/dev/null || echo 'Not available')"
	@$(POETRY) env info

.PHONY: doctor
doctor: diagnose check ## Health check

# =============================================================================

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
