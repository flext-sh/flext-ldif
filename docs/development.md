# FLEXT-LDIF Development Guide

**Version**: 0.9.0 | **Updated**: September 17, 2025

This guide covers development workflows, contribution guidelines, and technical standards for FLEXT-LDIF development within the FLEXT ecosystem.

## Development Environment Setup

### Prerequisites

- Python 3.13 or higher
- Poetry for dependency management
- Git with access to FLEXT repositories
- Understanding of FLEXT ecosystem patterns

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/flext-sh/flext-ldif.git
cd flext-ldif

# Set up development environment
make setup

# Verify installation
python -c "from flext_ldif import FlextLDIFAPI; print('Development environment ready')"
```

### Development Commands

```bash
# Code quality
make lint           # Ruff linting
make type-check     # MyPy type checking
make format         # Code formatting
make validate       # Complete validation pipeline

# Testing
make test           # Run test suite
pytest -m unit      # Unit tests only
pytest -m integration  # Integration tests
pytest --cov=src/flext_ldif  # Coverage report

# Development utilities
make clean          # Clean build artifacts
make reset          # Full reset of environment
```

## Architecture Guidelines

### Service-Oriented Architecture

FLEXT-LDIF follows a service-oriented architecture with clear separation of concerns:

```python
# ✅ Good: Clear service boundaries
class FlextLDIFParserService:
    """Single responsibility: LDIF parsing."""

    def parse_string(self, content: str) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Parse LDIF string with explicit error handling."""
        if not content.strip():
            return FlextResult[list[FlextLDIFModels.Entry]].ok([])

        try:
            # Parse using ldif3 library
            # Return FlextResult for composable error handling
            pass
        except Exception as e:
            return FlextResult[list[FlextLDIFModels.Entry]].fail(f"Parse failed: {e}")

# ❌ Avoid: Mixed responsibilities
class BadLdifService:
    def parse_and_validate_and_write(self, content: str, output_file: str):
        """Too many responsibilities in one method."""
        pass
```

### Railway-Oriented Programming

All operations must use FlextResult for consistent error handling:

```python
# ✅ Good: Railway-oriented programming
def process_ldif_file(file_path: str) -> FlextResult[dict]:
    """Process LDIF file with composable error handling."""
    api = FlextLDIFAPI()

    return (
        api.parse_file(file_path)
        .flat_map(api.validate_entries)
        .flat_map(lambda entries: api.filter_persons(entries))
        .map(lambda persons: {'person_count': len(persons)})
        .map_error(lambda error: f"Processing failed: {error}")
    )

# ❌ Avoid: Exception-based error handling
def bad_process_ldif_file(file_path: str) -> dict:
    """Avoid exception-based control flow."""
    try:
        api = FlextLDIFAPI()
        entries = api.parse_file(file_path).unwrap()  # Could raise
        api.validate_entries(entries).unwrap()  # Could raise
        persons = api.filter_persons(entries).unwrap()  # Could raise
        return {'person_count': len(persons)}
    except Exception as e:
        raise Exception(f"Processing failed: {e}")
```

### Type Safety Requirements

Complete type annotations are mandatory:

```python
# ✅ Good: Complete type annotations
def process_entries(
    entries: list[FlextLDIFModels.Entry],
    filter_func: Callable[[FlextLDIFModels.Entry], bool]
) -> FlextResult[list[FlextLDIFModels.Entry]]:
    """Process entries with explicit types."""
    try:
        filtered = [entry for entry in entries if filter_func(entry)]
        return FlextResult[list[FlextLDIFModels.Entry]].ok(filtered)
    except Exception as e:
        return FlextResult[list[FlextLDIFModels.Entry]].fail(str(e))

# ❌ Avoid: Missing type annotations
def bad_process_entries(entries, filter_func):
    """Missing type information."""
    return [entry for entry in entries if filter_func(entry)]
```

## Code Quality Standards

### Linting Configuration

FLEXT-LDIF uses Ruff for comprehensive linting:

```toml
# pyproject.toml - Ruff configuration
[tool.ruff]
line-length = 100
target-version = "py313"

[tool.ruff.lint]
select = [
    "E",    # pycodestyle errors
    "W",    # pycodestyle warnings
    "F",    # Pyflakes
    "I",    # isort
    "B",    # flake8-bugbear
    "C4",   # flake8-comprehensions
    "UP",   # pyupgrade
]

[tool.ruff.lint.per-file-ignores]
"tests/*" = ["S101"]  # Allow assert in tests
```

### Type Checking Configuration

MyPy configuration for strict type checking:

```toml
# pyproject.toml - MyPy configuration
[tool.mypy]
python_version = "3.13"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_incomplete_defs = true

[[tool.mypy.overrides]]
module = "ldif3"
ignore_missing_imports = true
```

### Testing Standards

Comprehensive testing with pytest:

```python
# tests/unit/test_parser_service.py
import pytest
from flext_ldif import FlextLDIFAPI
from flext_core import FlextResult

class TestParserService:
    """Test parser service functionality."""

    def setup_method(self) -> None:
        """Setup test environment."""
        self.api = FlextLDIFAPI()

    def test_parse_valid_ldif(self) -> None:
        """Test parsing valid LDIF content."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""
        result = self.api.parse_string(ldif_content)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1
        assert entries[0].dn == "cn=test,dc=example,dc=com"

    def test_parse_empty_content(self) -> None:
        """Test parsing empty content."""
        result = self.api.parse_string("")
        assert result.is_success
        assert len(result.unwrap()) == 0

    def test_parse_invalid_ldif(self) -> None:
        """Test parsing invalid LDIF content."""
        invalid_ldif = "invalid ldif content"
        result = self.api.parse_string(invalid_ldif)
        assert result.is_failure
        assert "parse" in result.error.lower()

    @pytest.mark.integration
    def test_parse_file_integration(self, tmp_path) -> None:
        """Test file parsing integration."""
        ldif_file = tmp_path / "test.ldif"
        ldif_file.write_text("""dn: cn=integration,dc=test,dc=com
cn: integration
objectClass: person
""")

        result = self.api.parse_file(ldif_file)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1
```

## Contribution Workflow

### Branch Management

```bash
# Create feature branch
git checkout -b feature/new-ldif-feature

# Development cycle
make validate  # Ensure quality before commit
git add .
git commit -m "feat: add new LDIF feature

- Implement new parsing capability
- Add comprehensive tests
- Update documentation"

# Push and create pull request
git push origin feature/new-ldif-feature
```

### Commit Message Standards

Follow conventional commit format:

```
feat: add new LDIF validation rule
fix: resolve parsing issue with special characters
docs: update API reference
test: add integration tests for writer service
refactor: improve service architecture
```

### Pull Request Checklist

- [ ] All tests pass (`make test`)
- [ ] Code passes linting (`make lint`)
- [ ] Type checking passes (`make type-check`)
- [ ] Coverage maintained or improved
- [ ] Documentation updated
- [ ] FLEXT patterns followed
- [ ] No breaking changes (or properly documented)

## Testing Strategy

### Test Categories

```python
# Mark tests by category
@pytest.mark.unit
def test_unit_functionality():
    """Unit test for isolated functionality."""
    pass

@pytest.mark.integration
def test_integration_workflow():
    """Integration test for component interaction."""
    pass

@pytest.mark.performance
def test_performance_benchmark():
    """Performance test for optimization validation."""
    pass

@pytest.mark.ldif
def test_ldif_specific():
    """LDIF-specific functionality test."""
    pass
```

### Test Data Management

```python
# tests/fixtures/ldif_samples.py
class LdifSamples:
    """Test LDIF data samples."""

    BASIC_PERSON = """dn: cn=John Doe,ou=People,dc=example,dc=com
cn: John Doe
sn: Doe
objectClass: person
objectClass: organizationalPerson
mail: john.doe@example.com
"""

    BASIC_GROUP = """dn: cn=Admins,ou=Groups,dc=example,dc=com
cn: Administrators
objectClass: groupOfNames
member: cn=John Doe,ou=People,dc=example,dc=com
"""

    INVALID_LDIF = """invalid ldif content
no proper structure
"""

    @classmethod
    def get_large_sample(cls, entry_count: int = 1000) -> str:
        """Generate large LDIF sample for performance testing."""
        entries = []
        for i in range(entry_count):
            entries.append(f"""dn: cn=User{i:04d},ou=People,dc=test,dc=com
cn: User{i:04d}
sn: TestUser{i:04d}
objectClass: person
mail: user{i:04d}@test.com

""")
        return "\n".join(entries)
```

### Coverage Requirements

Maintain high test coverage with meaningful tests:

```bash
# Check coverage
pytest --cov=src/flext_ldif --cov-report=html --cov-report=term-missing

# Coverage requirements
# - Overall coverage: 85%+
# - New code coverage: 95%+
# - Critical paths: 100%
```

## Performance Considerations

### Memory Usage Optimization

```python
# ✅ Good: Memory-efficient processing
def process_large_ldif_efficiently(file_path: str) -> FlextResult[dict]:
    """Process large LDIF with memory considerations."""
    api = FlextLDIFAPI(FlextLDIFModels.Config(max_entries=50000))

    # Process in chunks to manage memory
    return (
        api.parse_file(file_path)
        .map(lambda entries: process_entries_in_chunks(entries))
        .map_error(lambda error: f"Large file processing failed: {error}")
    )

def process_entries_in_chunks(entries: list, chunk_size: int = 1000) -> dict:
    """Process entries in memory-efficient chunks."""
    results = {'processed': 0, 'errors': 0}

    for i in range(0, len(entries), chunk_size):
        chunk = entries[i:i + chunk_size]
        # Process chunk and update results
        results['processed'] += len(chunk)

    return results

# ❌ Avoid: Memory-intensive operations
def bad_process_large_ldif(file_path: str):
    """Avoid loading everything into memory simultaneously."""
    api = FlextLDIFAPI()
    entries = api.parse_file(file_path).unwrap()
    # Multiple copies in memory
    validated = api.validate_entries(entries).unwrap()
    persons = api.filter_persons(validated).unwrap()
    groups = api.filter_groups(validated).unwrap()
    # Memory usage multiplied
```

### Performance Testing

```python
# tests/performance/test_parsing_performance.py
import time
import pytest
from flext_ldif import FlextLDIFAPI

class TestParsingPerformance:
    """Performance tests for LDIF parsing."""

    @pytest.mark.performance
    def test_large_file_parsing_performance(self) -> None:
        """Test parsing performance with large files."""
        api = FlextLDIFAPI()

        # Generate test data
        large_ldif = self._generate_test_ldif(10000)

        # Measure parsing time
        start_time = time.time()
        result = api.parse_string(large_ldif)
        end_time = time.time()

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 10000

        parsing_time = end_time - start_time
        entries_per_second = len(entries) / parsing_time

        # Performance assertions
        assert parsing_time < 30.0  # Should parse 10k entries in <30 seconds
        assert entries_per_second > 300  # Should parse >300 entries/second

    def _generate_test_ldif(self, count: int) -> str:
        """Generate test LDIF content."""
        entries = []
        for i in range(count):
            entries.append(f"""dn: cn=User{i:05d},ou=People,dc=test,dc=com
cn: User{i:05d}
sn: TestUser{i:05d}
objectClass: person
mail: user{i:05d}@test.com

""")
        return "\n".join(entries)
```

## Debugging and Troubleshooting

### Debug Configuration

```python
# Enable debug logging
from flext_ldif import FlextLDIFAPI, FlextLDIFModels

debug_config = FlextLDIFModels.Config(
    strict_validation=True,  # Catch issues early
    log_level='DEBUG'        # Verbose logging
)

api = FlextLDIFAPI(config=debug_config)

# Process with debug information
from flext_core import FlextLogger
logger = FlextLogger(__name__)
logger.set_level('DEBUG')
```

### Common Issues and Solutions

#### Parse Errors

```python
# Debug parsing issues
def debug_parse_issue(content: str) -> None:
    """Debug LDIF parsing issues."""
    api = FlextLDIFAPI()
    result = api.parse_string(content)

    if result.is_failure:
        print(f"Parse error: {result.error}")
        print(f"Content preview: {content[:200]}...")

        # Check common issues
        lines = content.split('\n')
        print(f"Line count: {len(lines)}")
        print(f"First few lines: {lines[:5]}")

        # Validate character encoding
        try:
            content.encode('utf-8')
            print("✓ UTF-8 encoding valid")
        except UnicodeError as e:
            print(f"✗ Encoding issue: {e}")
```

#### Memory Issues

```python
# Monitor memory usage
import psutil
import os

def monitor_memory_usage(func):
    """Decorator to monitor memory usage."""
    def wrapper(*args, **kwargs):
        process = psutil.Process(os.getpid())
        mem_before = process.memory_info().rss / 1024 / 1024  # MB

        result = func(*args, **kwargs)

        mem_after = process.memory_info().rss / 1024 / 1024  # MB
        mem_diff = mem_after - mem_before

        print(f"Memory usage: {mem_before:.1f}MB -> {mem_after:.1f}MB (+{mem_diff:.1f}MB)")

        return result
    return wrapper

@monitor_memory_usage
def process_with_memory_monitoring(file_path: str):
    """Process LDIF with memory monitoring."""
    api = FlextLDIFAPI()
    return api.parse_file(file_path)
```

## Release Process

### Version Management

```python
# Update version in __init__.py
__version__ = "0.9.1"

# Update version in pyproject.toml
[tool.poetry]
version = "0.9.1"

# Update documentation versions
# docs/getting-started.md: **Version**: 0.9.1
# docs/api-reference.md: **Version**: 0.9.1
```

### Release Checklist

- [ ] All tests pass on CI
- [ ] Documentation updated
- [ ] Version numbers updated
- [ ] CHANGELOG.md updated
- [ ] No security vulnerabilities
- [ ] Performance benchmarks maintained
- [ ] Integration tests pass with dependent projects

### Compatibility Guidelines

Maintain backward compatibility:

```python
# ✅ Good: Backward compatible changes
def parse_file(self, file_path: Path | str, **kwargs) -> FlextResult[list[FlextLDIFModels.Entry]]:
    """Parse LDIF file with backward compatibility."""
    # Support both Path and string inputs
    # Additional kwargs for future expansion

# ❌ Avoid: Breaking changes
def parse_file(self, file_path: Path) -> FlextResult[list[NewEntryModel]]:
    """Breaking change: only Path input, different return type."""
```

---

This development guide provides comprehensive standards for contributing to FLEXT-LDIF while maintaining consistency with FLEXT ecosystem patterns and professional development practices.