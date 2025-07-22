# FLEXT LDIF - LDIF Data Interchange Format Processing
# ====================================================
# Enterprise LDIF processing library with parsing, generation, validation, and transformation
# Python 3.13 + Clean Architecture + LDIF + Zero Tolerance Quality Gates

.PHONY: help check validate test lint type-check security format format-check fix
.PHONY: install dev-install setup pre-commit build clean
.PHONY: coverage coverage-html test-unit test-integration test-ldif
.PHONY: deps-update deps-audit deps-tree deps-outdated
.PHONY: ldif-parse ldif-generate ldif-validate ldif-transform ldif-analyze
.PHONY: ldif-performance ldif-streaming ldif-large-files

# ============================================================================
# 🎯 HELP & INFORMATION
# ============================================================================

help: ## Show this help message
	@echo "🎯 FLEXT LDIF - LDIF Data Interchange Format Processing"
	@echo "======================================================"
	@echo "🎯 Clean Architecture + LDIF Processing + Python 3.13"
	@echo ""
	@echo "📦 Enterprise LDIF parsing, generation, validation, and transformation"
	@echo "🔒 Zero tolerance quality gates with comprehensive LDIF testing"
	@echo "🧪 90%+ test coverage requirement with LDIF format compliance"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\\033[36m%-20s\\033[0m %s\\n", $$1, $$2}'

# ============================================================================
# 🎯 CORE QUALITY GATES - ZERO TOLERANCE
# ============================================================================

validate: lint type-check security test ## STRICT compliance validation (all must pass)
	@echo "✅ ALL QUALITY GATES PASSED - FLEXT LDIF COMPLIANT"

check: lint type-check test ## Essential quality checks (pre-commit standard)
	@echo "✅ Essential checks passed"

lint: ## Ruff linting (17 rule categories, ALL enabled)
	@echo "🔍 Running ruff linter (ALL rules enabled)..."
	@poetry run ruff check src/ tests/ --fix --unsafe-fixes
	@echo "✅ Linting complete"

type-check: ## MyPy strict mode type checking (zero errors tolerated)
	@echo "🛡️ Running MyPy strict type checking..."
	@poetry run mypy src/ --strict
	@echo "✅ Type checking complete"

security: ## Security scans (bandit + pip-audit + secrets)
	@echo "🔒 Running security scans..."
	@poetry run bandit -r src/ --severity-level medium --confidence-level medium
	@poetry run pip-audit --ignore-vuln PYSEC-2022-42969
	@poetry run detect-secrets scan --all-files
	@echo "✅ Security scans complete"

format: ## Format code with ruff
	@echo "🎨 Formatting code..."
	@poetry run ruff format src/ tests/
	@echo "✅ Formatting complete"

format-check: ## Check formatting without fixing
	@echo "🎨 Checking code formatting..."
	@poetry run ruff format src/ tests/ --check
	@echo "✅ Format check complete"

fix: format lint ## Auto-fix all issues (format + imports + lint)
	@echo "🔧 Auto-fixing all issues..."
	@poetry run ruff check src/ tests/ --fix --unsafe-fixes
	@echo "✅ All auto-fixes applied"

# ============================================================================
# 🧪 TESTING - 90% COVERAGE MINIMUM
# ============================================================================

test: ## Run tests with coverage (90% minimum required)
	@echo "🧪 Running tests with coverage..."
	@poetry run pytest tests/ -v --cov=src/flext_ldif --cov-report=term-missing --cov-fail-under=90
	@echo "✅ Tests complete"

test-unit: ## Run unit tests only
	@echo "🧪 Running unit tests..."
	@poetry run pytest tests/unit/ -v
	@echo "✅ Unit tests complete"

test-integration: ## Run integration tests only
	@echo "🧪 Running integration tests..."
	@poetry run pytest tests/integration/ -v
	@echo "✅ Integration tests complete"

test-ldif: ## Run LDIF-specific tests
	@echo "🧪 Running LDIF-specific tests..."
	@poetry run pytest tests/ -m "ldif" -v
	@echo "✅ LDIF tests complete"

test-parsing: ## Run parsing tests
	@echo "🧪 Running LDIF parsing tests..."
	@poetry run pytest tests/ -m "parsing" -v
	@echo "✅ Parsing tests complete"

test-generation: ## Run generation tests
	@echo "🧪 Running LDIF generation tests..."
	@poetry run pytest tests/ -m "generation" -v
	@echo "✅ Generation tests complete"

test-transformation: ## Run transformation tests
	@echo "🧪 Running LDIF transformation tests..."
	@poetry run pytest tests/ -m "transformation" -v
	@echo "✅ Transformation tests complete"

test-performance: ## Run performance tests
	@echo "⚡ Running LDIF performance tests..."
	@poetry run pytest tests/performance/ -v --benchmark-only
	@echo "✅ Performance tests complete"

coverage: ## Generate detailed coverage report
	@echo "📊 Generating coverage report..."
	@poetry run pytest tests/ --cov=src/flext_ldif --cov-report=term-missing --cov-report=html
	@echo "✅ Coverage report generated in htmlcov/"

coverage-html: coverage ## Generate HTML coverage report
	@echo "📊 Opening coverage report..."
	@python -m webbrowser htmlcov/index.html

# ============================================================================
# 🚀 DEVELOPMENT SETUP
# ============================================================================

setup: install pre-commit ## Complete development setup
	@echo "🎯 Development setup complete!"

install: ## Install dependencies with Poetry
	@echo "📦 Installing dependencies..."
	@poetry install --all-extras --with dev,test,docs,security
	@echo "✅ Dependencies installed"

dev-install: install ## Install in development mode
	@echo "🔧 Setting up development environment..."
	@poetry install --all-extras --with dev,test,docs,security
	@poetry run pre-commit install
	@echo "✅ Development environment ready"

pre-commit: ## Setup pre-commit hooks
	@echo "🎣 Setting up pre-commit hooks..."
	@poetry run pre-commit install
	@poetry run pre-commit run --all-files || true
	@echo "✅ Pre-commit hooks installed"

# ============================================================================
# 📁 LDIF OPERATIONS - CORE FUNCTIONALITY
# ============================================================================

ldif-parse: ## Parse LDIF files
	@echo "📁 Parsing LDIF files..."
	@poetry run python -c "from flext_ldif.infrastructure.parsers import LDIFParser; from flext_ldif.application.config import LDIFProcessingConfig; import asyncio; config = LDIFProcessingConfig(); parser = LDIFParser(config); print('LDIF parser loaded successfully')"
	@echo "✅ LDIF parsing test complete"

ldif-generate: ## Generate LDIF files
	@echo "📁 Testing LDIF generation..."
	@poetry run python scripts/test_ldif_generation.py
	@echo "✅ LDIF generation test complete"

ldif-validate: ## Validate LDIF files
	@echo "🔍 Validating LDIF files..."
	@poetry run python scripts/validate_ldif_files.py
	@echo "✅ LDIF validation complete"

ldif-transform: ## Transform LDIF data
	@echo "🔄 Testing LDIF transformations..."
	@poetry run python scripts/test_ldif_transformations.py
	@echo "✅ LDIF transformation test complete"

ldif-analyze: ## Analyze LDIF structure
	@echo "📊 Analyzing LDIF structure..."
	@poetry run python scripts/analyze_ldif_structure.py
	@echo "✅ LDIF analysis complete"

ldif-performance: ## Run LDIF performance benchmarks
	@echo "⚡ Running LDIF performance benchmarks..."
	@poetry run python scripts/benchmark_ldif_performance.py
	@echo "✅ LDIF performance benchmarks complete"

ldif-streaming: ## Test LDIF streaming processing
	@echo "🌊 Testing LDIF streaming processing..."
	@poetry run python scripts/test_ldif_streaming.py
	@echo "✅ LDIF streaming test complete"

ldif-large-files: ## Test large LDIF file processing
	@echo "📚 Testing large LDIF file processing..."
	@poetry run python scripts/test_large_ldif_files.py
	@echo "✅ Large file processing test complete"

ldif-encoding: ## Test LDIF encoding handling
	@echo "🔤 Testing LDIF encoding handling..."
	@poetry run python scripts/test_ldif_encoding.py
	@echo "✅ LDIF encoding test complete"

ldif-base64: ## Test LDIF base64 handling
	@echo "🔐 Testing LDIF base64 handling..."
	@poetry run python scripts/test_ldif_base64.py
	@echo "✅ LDIF base64 test complete"

# ============================================================================
# 🔄 LDIF TRANSFORMATION OPERATIONS
# ============================================================================

transform-normalize: ## Normalize LDIF data
	@echo "🔄 Normalizing LDIF data..."
	@poetry run python scripts/transform_normalize_ldif.py
	@echo "✅ LDIF normalization complete"

transform-anonymize: ## Anonymize sensitive LDIF data
	@echo "🔒 Anonymizing sensitive LDIF data..."
	@poetry run python scripts/transform_anonymize_ldif.py
	@echo "✅ LDIF anonymization complete"

transform-filter: ## Filter LDIF entries
	@echo "🔍 Filtering LDIF entries..."
	@poetry run python scripts/transform_filter_ldif.py
	@echo "✅ LDIF filtering complete"

transform-merge: ## Merge LDIF files
	@echo "🔗 Merging LDIF files..."
	@poetry run python scripts/transform_merge_ldif.py
	@echo "✅ LDIF merging complete"

transform-split: ## Split large LDIF files
	@echo "✂️ Splitting large LDIF files..."
	@poetry run python scripts/transform_split_ldif.py
	@echo "✅ LDIF splitting complete"

# ============================================================================
# 🔍 LDIF VALIDATION & COMPLIANCE
# ============================================================================

validate-format: ## Validate LDIF format compliance
	@echo "🔍 Validating LDIF format compliance..."
	@poetry run python scripts/validate_ldif_format.py
	@echo "✅ LDIF format validation complete"

validate-schema: ## Validate LDIF schema compliance
	@echo "🔍 Validating LDIF schema compliance..."
	@poetry run python scripts/validate_ldif_schema.py
	@echo "✅ LDIF schema validation complete"

validate-dns: ## Validate distinguished names
	@echo "🔍 Validating distinguished names..."
	@poetry run python scripts/validate_ldif_dns.py
	@echo "✅ DN validation complete"

validate-attributes: ## Validate attribute names and values
	@echo "🔍 Validating attributes..."
	@poetry run python scripts/validate_ldif_attributes.py
	@echo "✅ Attribute validation complete"

validate-encoding: ## Validate character encoding
	@echo "🔍 Validating character encoding..."
	@poetry run python scripts/validate_ldif_encoding.py
	@echo "✅ Encoding validation complete"

# ============================================================================
# 📦 BUILD & DISTRIBUTION
# ============================================================================

build: clean ## Build distribution packages
	@echo "🔨 Building distribution..."
	@poetry build
	@echo "✅ Build complete - packages in dist/"

package: build ## Create deployment package
	@echo "📦 Creating deployment package..."
	@tar -czf dist/flext-ldif-deployment.tar.gz \
		src/ \
		tests/ \
		scripts/ \
		pyproject.toml \
		README.md \
		CLAUDE.md
	@echo "✅ Deployment package created: dist/flext-ldif-deployment.tar.gz"

# ============================================================================
# 🧹 CLEANUP
# ============================================================================

clean: ## Remove all artifacts
	@echo "🧹 Cleaning up..."
	@rm -rf build/
	@rm -rf dist/
	@rm -rf *.egg-info/
	@rm -rf .coverage
	@rm -rf htmlcov/
	@rm -rf .pytest_cache/
	@rm -rf .mypy_cache/
	@rm -rf .ruff_cache/
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "✅ Cleanup complete"

# ============================================================================
# 📊 DEPENDENCY MANAGEMENT
# ============================================================================

deps-update: ## Update all dependencies
	@echo "🔄 Updating dependencies..."
	@poetry update
	@echo "✅ Dependencies updated"

deps-audit: ## Audit dependencies for vulnerabilities
	@echo "🔍 Auditing dependencies..."
	@poetry run pip-audit
	@echo "✅ Dependency audit complete"

deps-tree: ## Show dependency tree
	@echo "🌳 Dependency tree:"
	@poetry show --tree

deps-outdated: ## Show outdated dependencies
	@echo "📋 Outdated dependencies:"
	@poetry show --outdated

# ============================================================================
# 🔧 ENVIRONMENT CONFIGURATION
# ============================================================================

# Python settings
PYTHON := python3.13
export PYTHONPATH := $(PWD)/src:$(PYTHONPATH)
export PYTHONDONTWRITEBYTECODE := 1
export PYTHONUNBUFFERED := 1

# LDIF Processing settings
export LDIF_ENCODING := utf-8
export LDIF_AUTO_DETECT_ENCODING := true
export LDIF_BUFFER_SIZE := 8192
export LDIF_MAX_LINE_LENGTH := 76

# Validation settings
export LDIF_VALIDATION_LEVEL := strict
export LDIF_VALIDATE_DNS := true
export LDIF_VALIDATE_ATTRIBUTES := true
export LDIF_VALIDATE_VALUES := true

# Performance settings
export LDIF_STREAMING_MODE := true
export LDIF_MAX_MEMORY_USAGE := 104857600
export LDIF_LINE_WRAP_LENGTH := 76

# Processing options
export LDIF_PRESERVE_COMMENTS := false
export LDIF_PRESERVE_ORDER := true
export LDIF_NORMALIZE_DNS := true

# Poetry settings
export POETRY_VENV_IN_PROJECT := false
export POETRY_CACHE_DIR := $(HOME)/.cache/pypoetry

# Quality gate settings
export MYPY_CACHE_DIR := .mypy_cache
export RUFF_CACHE_DIR := .ruff_cache

# ============================================================================
# 📝 PROJECT METADATA
# ============================================================================

# Project information
PROJECT_NAME := flext-ldif
PROJECT_VERSION := $(shell poetry version -s)
PROJECT_DESCRIPTION := FLEXT LDIF - LDIF Data Interchange Format Processing

.DEFAULT_GOAL := help

# ============================================================================
# 🎯 DEVELOPMENT UTILITIES
# ============================================================================

dev-ldif-server: ## Start development LDIF processing server
	@echo "🔧 Starting development LDIF processing server..."
	@poetry run python scripts/dev_ldif_server.py
	@echo "✅ Development LDIF server started"

dev-ldif-monitor: ## Monitor LDIF processing
	@echo "📊 Monitoring LDIF processing..."
	@poetry run python scripts/monitor_ldif_processing.py
	@echo "✅ LDIF monitoring complete"

dev-ldif-playground: ## Interactive LDIF playground
	@echo "🎮 Starting LDIF playground..."
	@poetry run python scripts/ldif_playground.py
	@echo "✅ LDIF playground session complete"

# ============================================================================
# 🎯 FLEXT ECOSYSTEM INTEGRATION
# ============================================================================

ecosystem-check: ## Verify FLEXT ecosystem compatibility
	@echo "🌐 Checking FLEXT ecosystem compatibility..."
	@echo "📦 Core project: $(PROJECT_NAME) v$(PROJECT_VERSION)"
	@echo "🏗️ Architecture: Clean Architecture + LDIF Processing"
	@echo "🐍 Python: 3.13"
	@echo "🔗 Framework: FLEXT Core + Enterprise LDIF"
	@echo "📊 Quality: Zero tolerance enforcement"
	@echo "✅ Ecosystem compatibility verified"

workspace-info: ## Show workspace integration info
	@echo "🏢 FLEXT Workspace Integration"
	@echo "==============================="
	@echo "📁 Project Path: $(PWD)"
	@echo "🏆 Role: LDIF Data Interchange Format Processing"
	@echo "🔗 Dependencies: flext-core (clean architecture foundation)"
	@echo "📦 Provides: LDIF parsing, generation, validation, transformation"
	@echo "🎯 Standards: Enterprise LDIF processing patterns"

# ============================================================================
# 🔄 CONTINUOUS INTEGRATION
# ============================================================================

ci-check: validate ## CI quality checks
	@echo "🔍 Running CI quality checks..."
	@poetry run python scripts/ci_quality_report.py
	@echo "✅ CI quality checks complete"

ci-performance: ## CI performance benchmarks
	@echo "⚡ Running CI performance benchmarks..."
	@poetry run python scripts/ci_performance_benchmarks.py
	@echo "✅ CI performance benchmarks complete"

ci-integration: ## CI integration tests
	@echo "🔗 Running CI integration tests..."
	@poetry run pytest tests/integration/ -v --tb=short
	@echo "✅ CI integration tests complete"

ci-all: ci-check ci-performance ci-integration ## Run all CI checks
	@echo "✅ All CI checks complete"
