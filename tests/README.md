# FLEXT-LDIF Test Suite

This directory contains the comprehensive test suite for FLEXT-LDIF, implementing enterprise-grade testing standards with multiple test categories, fixtures, and quality validation patterns.

## Overview

The test suite provides comprehensive coverage across all architectural layers, test categories, and integration scenarios while maintaining high-quality standards and performance benchmarks for enterprise LDIF processing operations.

## Test Organization

### Test Categories (Pytest Markers)

```bash
# Unit Tests - Individual component testing
pytest -m unit

# Integration Tests - Cross-component testing
pytest -m integration

# End-to-End Tests - Complete workflow testing
pytest -m e2e

# LDIF-Specific Tests - Domain-specific testing
pytest -m ldif

# Parser Tests - Parsing functionality testing
pytest -m parser

# Performance Tests - Benchmark and performance validation
pytest -m performance
```

### Test File Structure

```
tests/
├── conftest.py                     # Pytest configuration and fixtures
├── docker_fixtures.py             # Docker-based integration test fixtures
├── test_api_*.py                   # Application layer tests
├── test_core_*.py                  # Infrastructure layer tests
├── test_models*.py                 # Domain layer tests
├── test_cli*.py                    # Interface layer tests
├── test_*_enterprise.py            # Enterprise scenario tests
├── test_*_coverage.py              # Coverage-focused tests
└── test_e2e_*.py                   # End-to-end workflow tests
```

## Test Categories

### Unit Tests (`test_*_unit.py`)

**Purpose**: Test individual components in isolation with mocked dependencies.

**Coverage**:

- Domain entities and value objects
- Individual service methods
- Utility functions and helpers
- Configuration validation

**Example**:

```python
def test_flext_ldif_entry_validation(sample_entry):
    """Test domain entity validation rules."""
    entry = sample_entry
    result = entry.validate_semantic_rules()  # Should succeed
    assert result.success

    # Test business rule violations
    invalid_entry = FlextLdifEntry(dn="", attributes={})
    with pytest.raises(FlextLdifValidationError):
        result = invalid_entry.validate_semantic_rules()
        assert not result.success
```

### Integration Tests (`test_*_integration.py`)

**Purpose**: Test component interactions and cross-layer integration.

**Coverage**:

- API service integration with domain services
- Configuration loading and validation
- Database and file system integration
- Service dependency injection

**Example**:

```python
def test_api_service_integration(flext_ldif_api, sample_ldif_content):
    """Test API service with real dependencies."""
    result = flext_ldif_api.parse(sample_ldif_content)
    assert result.success

    validation_result = flext_ldif_api.validate(result.data)
    assert validation_result.success
```

### End-to-End Tests (`test_e2e_*.py`)

**Purpose**: Test complete user workflows and system behavior.

**Coverage**:

- CLI command execution and output validation
- File processing workflows
- Error handling and recovery scenarios
- Performance benchmarks

**Example**:

```python
def test_e2e_ldif_processing_workflow(tmp_path):
    """Test complete LDIF processing workflow."""
    input_file = tmp_path / "input.ldif"
    output_file = tmp_path / "output.ldif"

    # Create test LDIF file
    input_file.write_text(SAMPLE_LDIF_CONTENT)

    # Execute CLI command (pseudo-code helper)
    rc, out, err = run_cli([sys.executable, "-m", "flext_ldif.cli", "transform", "--filter", "objectClass=person", str(input_file), str(output_file)])
    assert rc == 0
    assert output_file.exists()
```

### LDIF-Specific Tests (`test_*_ldif.py`)

**Purpose**: Test LDIF format compliance and domain-specific scenarios.

**Coverage**:

- RFC 2849 compliance validation
- LDIF parsing edge cases
- DN hierarchy operations
- Attribute validation rules

**Example**:

```python
def test_ldif_rfc_compliance(rfc_compliant_ldif):
    """Test RFC 2849 LDIF specification compliance."""
    result = TLdif.parse(rfc_compliant_ldif)
    assert result.success

    # Validate specific RFC requirements
    entries = result.data
    for entry in entries:
        assert entry.dn.value  # DN is required
        assert len(entry.dn.value) <= 255  # DN length limit
```

### Performance Tests (`test_*_performance.py`)

**Purpose**: Validate performance benchmarks and resource usage.

**Coverage**:

- Large file processing benchmarks
- Memory usage validation
- Processing speed requirements
- Scalability testing

**Example**:

```python
@pytest.mark.performance
def test_large_file_processing_performance():
    """Test processing performance with large LDIF files."""
    large_ldif = generate_ldif_with_entries(10000)

    start_time = time.time()
    result = TLdif.parse(large_ldif)
    processing_time = time.time() - start_time

    assert result.success
    assert processing_time < 30.0  # Max 30 seconds for 10k entries
    assert len(result.data) == 10000
```

## Test Fixtures and Utilities

### Core Fixtures (`conftest.py`)

```python
@pytest.fixture
def flext_ldif_api():
    """Configured FlextLdifAPI instance for testing."""
    config = FlextLdifConfig(
        max_entries=1000,
        strict_validation=True,
        enable_observability=False  # Disable for testing
    )
    return FlextLdifAPI(config)

@pytest.fixture
def sample_entries():
    """Sample LDIF entries for testing."""
    return [
        FlextLdifEntry.model_validate({
            "dn": FlextLdifDistinguishedName(value="cn=John Doe,ou=people,dc=example,dc=com"),
            "attributes": FlextLdifAttributes(attributes={
                "cn": ["John Doe"],
                "objectClass": ["person", "inetOrgPerson"],
                "mail": ["john@example.com"]
            })
        })
    ]

@pytest.fixture
def ldif_test_data():
    """Sample LDIF data for parsing tests."""
    return """
dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
objectClass: person
objectClass: inetOrgPerson
mail: john.doe@example.com

dn: cn=Jane Smith,ou=people,dc=example,dc=com
cn: Jane Smith
objectClass: person
objectClass: inetOrgPerson
mail: jane.smith@example.com
""".strip()
```

### Docker Integration Fixtures (`docker_fixtures.py`)

```python
@pytest.fixture(scope="session")
def ldap_server():
    """Docker-based LDAP server for integration testing."""
    container = docker_client.containers.run(
        "osixia/openldap:1.5.0",
        environment={
            "LDAP_ORGANISATION": "Example Corp",
            "LDAP_DOMAIN": "example.com",
        },
        ports={"389/tcp": 1389},
        detach=True
    )

    # Wait for container to be ready
    wait_for_ldap_ready("localhost", 1389)

    yield container

    container.remove(force=True)
```

## Test Data Management

### Sample LDIF Files

```
tests/data/
├── sample_basic.ldif              # Basic LDIF with standard entries
├── sample_complex.ldif            # Complex LDIF with all features
├── sample_invalid.ldif            # Invalid LDIF for error testing
├── sample_large.ldif              # Large LDIF for performance testing
└── rfc_examples/                  # RFC 2849 example files
    ├── basic_entry.ldif
    ├── change_record.ldif
    └── binary_attributes.ldif
```

### Test Data Generation

```python
def generate_ldif_with_entries(count: int) -> str:
    """Generate LDIF content with specified number of entries."""
    entries = []
    for i in range(count):
        entry = f"""
dn: cn=user{i:05d},ou=people,dc=example,dc=com
cn: user{i:05d}
objectClass: person
objectClass: inetOrgPerson
mail: user{i:05d}@example.com
uid: user{i:05d}
"""
        entries.append(entry.strip())

    return "\n\n".join(entries)
```

## Quality Assurance

### Coverage Requirements

- **Overall Coverage**: 90% minimum across all modules
- **Unit Test Coverage**: 95% minimum for domain and application layers
- **Integration Coverage**: 80% minimum for cross-component scenarios
- **E2E Coverage**: 70% minimum for user workflows

### Coverage Validation

```bash
# Generate coverage report
pytest --cov=src/flext_ldif --cov-report=html --cov-report=term-missing

# Enforce coverage thresholds
pytest --cov=src/flext_ldif --cov-fail-under=90

# Generate coverage by test category
pytest -m unit --cov=src/flext_ldif --cov-report=term
pytest -m integration --cov=src/flext_ldif --cov-report=term
```

### Quality Gates

```bash
# Run all quality checks
make test                          # Full test suite
make test-unit                     # Unit tests only
make test-integration              # Integration tests only
make test-performance              # Performance benchmarks

# Continuous testing
pytest --watch                     # Watch mode for development
pytest --lf                        # Run last failed tests
pytest -x                          # Stop on first failure
```

## Performance Benchmarks

### Benchmark Targets

- **Parsing Speed**: >1000 entries/second for standard LDIF
- **Memory Usage**: <1MB per 1000 entries processed
- **File Size**: Support files up to 1GB without memory issues
- **Validation Speed**: >2000 entries/second for business rules

### Benchmark Execution

```bash
# Run performance benchmarks
pytest -m performance --benchmark-only

# Generate performance reports
pytest -m performance --benchmark-save=baseline
pytest -m performance --benchmark-compare=baseline
```

## Development Workflow

### Running Tests During Development

```bash
# Quick feedback loop
pytest -m "not slow" --ff        # Fast tests first, skip slow tests

# Comprehensive validation
pytest --strict-markers           # Enforce marker usage
pytest --strict-config            # Enforce configuration compliance

# Debug test failures
pytest --pdb                      # Drop into debugger on failure
pytest -vvv                       # Maximum verbosity
pytest --tb=long                  # Detailed traceback
```

### Test-Driven Development

```python
def test_new_feature_specification():
    """Test specification for new feature (TDD)."""
    # Arrange - Set up test conditions
    api = FlextLdifAPI()
    test_data = create_test_ldif()

    # Act - Execute the feature
    result = api.new_feature(test_data)

    # Assert - Validate expected behavior
    assert result.success
    assert result.data.meets_requirements()
```

## Continuous Integration

### CI Pipeline Integration

```yaml
# .github/workflows/test.yml
- name: Run Test Suite
  run: |
    pytest --cov=src/flext_ldif --cov-report=xml
    pytest -m performance --benchmark-json=benchmark.json

- name: Upload Coverage
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage.xml
```

### Quality Metrics

- **Test Execution Time**: <5 minutes for full suite
- **Coverage Reporting**: Automated coverage tracking
- **Performance Regression**: Automated benchmark comparison
- **Flaky Test Detection**: Identify and fix unstable tests

## Contributing Guidelines

When adding new tests:

1. **Follow Naming Conventions**: Use descriptive test names with behavior description
2. **Use Appropriate Markers**: Tag tests with correct pytest markers
3. **Maintain Coverage**: Ensure new code has 90%+ test coverage
4. **Include Edge Cases**: Test boundary conditions and error scenarios
5. **Performance Awareness**: Add performance tests for critical paths
6. **Documentation**: Document complex test scenarios and fixtures

## Related Documentation

- **[API Documentation](../docs/api/API.md)** - Complete API reference for testing
- **[Architecture Guide](../docs/architecture/ARCHITECTURE.md)** - Understanding system design for testing
- **[Development Guide](../CLAUDE.md)** - Development patterns and practices
