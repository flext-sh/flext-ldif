# Integration Test Suite for FlextLdif

Comprehensive integration testing for LDIF parsing, writing, and roundtrip validation across multiple LDAP server types (OID, OUD, OpenLDAP, RFC).

## 📋 Test Organization

### Test Structure

```
tests/integration/
├── README.md                                      # This file
├── conftest.py                                    # Centralized pytest fixtures
├── __init__.py
│
├── test_roundtrip_deep_validation.py             # Deep content validation roundtrips
├── test_rfc_compliance_validation.py             # RFC 2849/4512 format validation
├── test_systematic_fixture_coverage.py           # Server×fixture type matrix coverage
├── test_error_recovery.py                        # Malformed LDIF and error handling
├── test_edge_cases.py                            # Boundary conditions and edge cases
│
├── test_oid_integration.py                       # OID server-specific tests
├── test_oud_integration.py                       # OUD server-specific tests
├── test_cross_quirk_conversion.py                # Server-to-server conversion tests
│
├── test_real_ldap_export.py                      # Real LDAP container export tests
├── test_real_ldap_import.py                      # Real LDAP container import tests
├── test_real_ldap_roundtrip.py                   # Real LDAP roundtrip tests
├── test_real_ldap_validation.py                  # Real LDAP validation tests
├── test_real_ldap_crud.py                        # Real LDAP CRUD operations
└── test_real_ldap_config.py                      # Real LDAP configuration tests
```

### Test Categories

#### 1. **Comprehensive Validation Tests** (Phase 3-5)

These tests validate core LDIF functionality across all server types using centralized fixtures.

**test_roundtrip_deep_validation.py** (9 tests)

- Tests: parse → write → parse roundtrips
- Coverage: Single/multiple entries, multi-valued attributes, special characters, hierarchical structures
- Parametrized: OID and OUD schema/integration fixtures
- Validates: Deep content preservation (not just entry counts)

**test_rfc_compliance_validation.py** (15 tests)

- Tests: RFC 2849 (LDIF format) and RFC 4512 (schema) compliance
- Coverage: DN syntax (RFC 4514), LDIF format rules, attribute encoding, line length limits
- Validates: Strict RFC compliance for all operations

**test_systematic_fixture_coverage.py** (10 tests)

- Tests: All server types × all fixture types (coverage matrix)
- Coverage:
  - Schema fixtures (2 tests)
  - ACL fixtures (2 tests)
  - Entry fixtures (2 tests)
  - Integration fixtures (2 tests)
  - Fixture availability meta-test (1 test)
  - Basic LDIF operations baseline (1 test)
- Validates: Complete fixture matrix coverage

**test_error_recovery.py** (22 tests)

- Tests: Malformed LDIF handling and error recovery
- Coverage:
  - Malformed content: missing DN, incomplete syntax, invalid format, orphaned continuations (12 tests)
  - Incomplete entries: truncated LDIF, unclosed multiline values (3 tests)
  - Invalid schema: malformed OID, missing required fields, unclosed parentheses (3 tests)
  - Encoding errors: UTF-8, base64, mixed encodings (4 tests)
- Validates: Graceful handling and best-effort recovery

**test_edge_cases.py** (20 tests)

- Tests: Boundary conditions and edge cases
- Coverage:
  - Empty/minimal cases: empty LDIF, whitespace only, comments only, minimal entries (5 tests)
  - Large/complex cases: many attributes (100+), many values (100+), very long values (10KB+), deep nesting (10+ levels) (4 tests)
  - Boundary values: single characters, special characters, maximum RDN components, minimum valid DN (4 tests)
  - Unicode boundaries: BMP, supplementary plane, zero-width, combining characters (4 tests)
  - Roundtrip edge cases: empty roundtrip, single minimal entry, many entries (5 tests)
- Validates: Correct handling of boundary values

#### 2. **Server-Specific Tests**

**test_oid_integration.py**

- Tests: Oracle Internet Directory specific features
- Uses: OID-specific fixtures and OID quirks

**test_oud_integration.py**

- Tests: Oracle Unified Directory specific features
- Uses: OUD-specific fixtures and OUD quirks

**test_cross_quirk_conversion.py**

- Tests: Server-to-server conversion (OID ↔ OUD)
- Validates: Data integrity during server-specific transformations

#### 3. **Real LDAP Tests** (Requires Docker)

These tests require a running LDAP container (Docker).

**test_real_ldap_export.py**

- Tests: Export entries from real LDAP container
- Validates: Container connectivity and export integrity

**test_real_ldap_import.py**

- Tests: Import LDIF entries into real LDAP container
- Validates: Import success and consistency

**test_real_ldap_roundtrip.py**

- Tests: LDAP → LDIF → LDAP roundtrip
- Validates: Complete roundtrip data integrity

**test_real_ldap_validation.py**

- Tests: Validation and modification operations
- Validates: Entry consistency and constraints

**test_real_ldap_crud.py**

- Tests: Create, read, update, delete operations
- Validates: CRUD operation completeness

**test_real_ldap_config.py**

- Tests: Configuration and setup operations
- Validates: Configuration consistency

## 🔧 Running Tests

### Quick Start

```bash
# Run all integration tests
PYTHONPATH=src poetry run pytest tests/integration/ -v

# Run specific test class
PYTHONPATH=src poetry run pytest tests/integration/test_roundtrip_deep_validation.py::TestRoundtripDeepValidation -v

# Run specific test method
PYTHONPATH=src poetry run pytest tests/integration/test_roundtrip_deep_validation.py::TestRoundtripDeepValidation::test_roundtrip_single_entry -v
```

### Running Test Categories

```bash
# Run comprehensive validation tests (no Docker required)
PYTHONPATH=src poetry run pytest tests/integration/test_roundtrip_deep_validation.py tests/integration/test_rfc_compliance_validation.py tests/integration/test_systematic_fixture_coverage.py tests/integration/test_error_recovery.py tests/integration/test_edge_cases.py -v

# Run server-specific tests (no Docker required)
PYTHONPATH=src poetry run pytest tests/integration/test_oid_integration.py tests/integration/test_oud_integration.py tests/integration/test_cross_quirk_conversion.py -v

# Run real LDAP tests (requires Docker)
PYTHONPATH=src poetry run pytest tests/integration/test_real_ldap_*.py -v

# Run with coverage
PYTHONPATH=src poetry run pytest tests/integration/ --cov=src/flext_ldif --cov-report=term-missing
```

### Test Markers

```bash
# Run only fast tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Run LDIF-specific tests
pytest -m ldif

# Run parser tests
pytest -m parser

# Run end-to-end tests
pytest -m e2e
```

### Running with Specific Fixtures

```bash
# Run tests using OID fixtures
PYTHONPATH=src poetry run pytest tests/integration/ -k "oid" -v

# Run tests using OUD fixtures
PYTHONPATH=src poetry run pytest tests/integration/ -k "oud" -v

# Run parametrized tests with specific fixture type
PYTHONPATH=src poetry run pytest tests/integration/test_systematic_fixture_coverage.py::TestSystematicFixtureCoverage::test_schema_fixture_coverage -v
```

## 📦 Centralized Fixtures (conftest.py)

All tests use centralized fixtures defined in `tests/integration/conftest.py`. This eliminates duplication and ensures consistent fixture usage across all test files.

### Fixture Organization

Fixtures are organized by **server type** and **fixture type**:

**Server Types**: `oid`, `oud`, `openldap`, `rfc`

**Fixture Types**: `schema`, `acl`, `entries`, `integration`

### Available Fixtures

#### API Fixture

```python
@pytest.fixture
def api() -> FlextLdif:
    """FlextLdif API instance."""
    return FlextLdif.get_instance()
```

#### Parser/Writer Fixtures

```python
@pytest.fixture
def parser():
    """LDIF parser service."""

@pytest.fixture
def writer():
    """LDIF writer service."""
```

#### Server-Specific Schema Fixtures

```python
@pytest.fixture
def oid_schema_fixture() -> str:
    """OID server schema LDIF fixture."""

@pytest.fixture
def oud_schema_fixture() -> str:
    """OUD server schema LDIF fixture."""
```

#### Server-Specific Entry Fixtures

```python
@pytest.fixture
def oid_entries_fixture() -> str:
    """OID server entries LDIF fixture."""

@pytest.fixture
def oud_entries_fixture() -> str:
    """OUD server entries LDIF fixture."""
```

#### Server-Specific ACL Fixtures

```python
@pytest.fixture
def oid_acl_fixture() -> str:
    """OID server ACL LDIF fixture."""

@pytest.fixture
def oud_acl_fixture() -> str:
    """OUD server ACL LDIF fixture."""
```

#### Server-Specific Integration Fixtures

```python
@pytest.fixture
def oid_integration_fixture() -> str:
    """OID server complete integration fixture (schema + ACL + entries)."""

@pytest.fixture
def oud_integration_fixture() -> str:
    """OUD server complete integration fixture (schema + ACL + entries)."""
```

### Using Fixtures in Tests

```python
import pytest
from flext_ldif import FlextLdif

class TestMyFeature:
    @pytest.fixture
    def api(self) -> FlextLdif:
        """FlextLdif API instance."""
        return FlextLdif.get_instance()

    def test_with_fixture(self, api: FlextLdif, oid_schema_fixture: str) -> None:
        """Test using centralized fixture."""
        # Use the fixture directly
        result = api.parse(oid_schema_fixture)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0
```

### Parametrized Testing with Fixtures

```python
import pytest
from flext_ldif import FlextLdif

class TestAllServers:
    @pytest.fixture
    def api(self) -> FlextLdif:
        """FlextLdif API instance."""
        return FlextLdif.get_instance()

    @pytest.mark.parametrize(
        "server_fixture",
        ["oid_schema_fixture", "oud_schema_fixture"],
        ids=["OID", "OUD"],
    )
    def test_all_servers(
        self,
        api: FlextLdif,
        server_fixture: str,
        request: pytest.FixtureRequest,
    ) -> None:
        """Test across all server types using parametrization."""
        fixture_data = request.getfixturevalue(server_fixture)

        # Use fixture data
        result = api.parse(fixture_data)
        assert result.is_success
```

## 🛠️ Best Practices for Integration Tests

### 1. Use Centralized Fixtures

✅ **DO**: Use fixtures from conftest.py

```python
def test_example(self, api: FlextLdif, oid_schema_fixture: str) -> None:
    result = api.parse(oid_schema_fixture)
    assert result.is_success
```

❌ **DON'T**: Create hardcoded LDIF content

```python
def test_example(self) -> None:
    ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"
    # Duplicates fixture data across multiple tests
```

### 2. Test Complete Roundtrips

✅ **DO**: Validate parse → write → parse cycles

```python
def test_roundtrip(self, api: FlextLdif) -> None:
    # Parse
    parse1 = api.parse(ldif_content)
    entries1 = parse1.unwrap()

    # Write
    written = api.write(entries1).unwrap()

    # Parse again
    parse2 = api.parse(written)
    entries2 = parse2.unwrap()

    # Validate preservation
    assert len(entries1) == len(entries2)
```

❌ **DON'T**: Only test individual operations

```python
def test_parse(self) -> None:
    # Only tests parse, doesn't validate roundtrip
    result = api.parse(ldif_content)
    assert result.is_success
```

### 3. Validate Deep Content, Not Just Counts

✅ **DO**: Validate attribute values and structure

```python
def test_attributes(self, api: FlextLdif) -> None:
    result = api.parse(ldif_content)
    entries = result.unwrap()

    # Validate specific attributes
    assert entries[0].dn == expected_dn
    assert "mail" in entries[0].attributes
    assert entries[0].attributes["mail"] == expected_values
```

❌ **DON'T**: Only count entries

```python
def test_entries(self, api: FlextLdif) -> None:
    result = api.parse(ldif_content)
    entries = result.unwrap()
    assert len(entries) == 5  # Doesn't validate content
```

### 4. Use Parametrization for Server Compatibility

✅ **DO**: Parametrize across server types

```python
@pytest.mark.parametrize(
    "server_fixture",
    ["oid_entries_fixture", "oud_entries_fixture"],
    ids=["OID", "OUD"],
)
def test_all_servers(self, api: FlextLdif, server_fixture: str, request) -> None:
    fixture_data = request.getfixturevalue(server_fixture)
    result = api.parse(fixture_data)
    # Tests both OID and OUD with same test logic
```

❌ **DON'T**: Write separate tests for each server

```python
def test_oid_entries(self) -> None:
    result = api.parse(oid_fixture)
    # Duplicates logic

def test_oud_entries(self) -> None:
    result = api.parse(oud_fixture)
    # Same test logic, not DRY
```

### 5. Handle FlextResult Patterns

✅ **DO**: Check both success and error cases

```python
def test_parse(self, api: FlextLdif) -> None:
    result = api.parse(ldif_content)

    if result.is_success:
        entries = result.unwrap()
        assert len(entries) > 0
    else:
        error = result.error
        # Validate error message
        assert "expected error message" in str(error)
```

❌ **DON'T**: Assume success without checking

```python
def test_parse(self, api: FlextLdif) -> None:
    result = api.parse(ldif_content)
    entries = result.unwrap()  # Crashes if result is error
```

### 6. Test Error Cases

✅ **DO**: Include tests for error handling

```python
class TestErrorRecovery:
    def test_malformed_dn(self, api: FlextLdif) -> None:
        malformed = "dn: invalid-dn-format\ncn: test\n"
        result = api.parse(malformed)
        # Verify graceful handling
        assert result is not None
```

❌ **DON'T**: Only test happy path

```python
def test_valid_entry(self, api: FlextLdif) -> None:
    result = api.parse(valid_ldif)
    # Doesn't test error cases
    assert result.is_success
```

## 📊 Test Coverage

### Coverage by Category

- **Roundtrip Validation**: 9 tests covering parse→write→parse cycles
- **RFC Compliance**: 15 tests validating RFC 2849/4512 adherence
- **Systematic Coverage**: 10 tests ensuring server×fixture matrix
- **Error Recovery**: 22 tests for malformed input handling
- **Edge Cases**: 20 tests for boundary conditions
- **Server-Specific**: 12+ tests for OID, OUD, conversions
- **Real LDAP**: 20+ tests with actual LDAP container

**Total**: 100+ integration tests covering all core LDIF functionality

### Running with Coverage Reports

```bash
# Generate coverage report
PYTHONPATH=src poetry run pytest tests/integration/ --cov=src/flext_ldif --cov-report=html

# View report
open htmlcov/index.html

# Coverage by module
PYTHONPATH=src poetry run pytest tests/integration/ --cov=src/flext_ldif --cov-report=term-missing
```

## 🆕 Adding New Integration Tests

### Step 1: Choose Test Location

- **Validation Logic**: Add to `test_roundtrip_deep_validation.py` or `test_rfc_compliance_validation.py`
- **Error Handling**: Add to `test_error_recovery.py`
- **Edge Cases**: Add to `test_edge_cases.py`
- **Server-Specific**: Add to `test_oid_integration.py`, `test_oud_integration.py`, etc.
- **New Category**: Create new test file `test_my_feature.py`

### Step 2: Use Centralized Fixtures

Always use fixtures from `conftest.py`:

```python
import pytest
from flext_ldif import FlextLdif

class TestMyNewFeature:
    @pytest.fixture
    def api(self) -> FlextLdif:
        """FlextLdif API instance."""
        return FlextLdif.get_instance()

    def test_feature(self, api: FlextLdif, oid_entries_fixture: str) -> None:
        """Test using centralized fixture."""
        result = api.parse(oid_entries_fixture)
        assert result.is_success
        entries = result.unwrap()
        # Add your test logic here
```

### Step 3: Follow Naming Conventions

- Test classes: `Test<Feature>` (PascalCase)
- Test methods: `test_<description>` (snake_case)
- Fixture parameters: `<server>_<type>_fixture`

### Step 4: Add Parametrization for Multi-Server Testing

```python
@pytest.mark.parametrize(
    "server_fixture",
    ["oid_entries_fixture", "oud_entries_fixture"],
    ids=["OID", "OUD"],
)
def test_feature_all_servers(self, api: FlextLdif, server_fixture: str, request) -> None:
    fixture_data = request.getfixturevalue(server_fixture)
    # Test implementation
```

### Step 5: Document Test Purpose

Always include docstrings explaining:

- What the test validates
- Which scenarios it covers
- Any special requirements

```python
def test_roundtrip_preserves_attributes(self, api: FlextLdif) -> None:
    """Test roundtrip preserves all attribute values.

    Validates:
    - All attributes preserved through write cycle
    - Multi-valued attributes maintain all values
    - Special characters in values handled correctly
    """
    # Implementation
```

## 🔍 Troubleshooting

### Import Errors

**Problem**: `ModuleNotFoundError: No module named 'flext_ldif'`

**Solution**: Set PYTHONPATH before running tests

```bash
PYTHONPATH=src poetry run pytest tests/integration/
```

### Fixture Not Found

**Problem**: `fixture 'oid_schema_fixture' not found`

**Solution**: Verify fixture is defined in `conftest.py` and file is named correctly

```bash
# Check fixture availability
PYTHONPATH=src poetry run pytest tests/integration/ --fixtures | grep oid_schema
```

### Docker Container Errors

**Problem**: Real LDAP tests fail with container connection errors

**Solution**: Ensure Docker is running and LDAP container is accessible

```bash
# Check Docker status
docker ps

# View LDAP container logs
docker logs ldif-test-ldap
```

### Type Checking Errors

**Problem**: MyPy errors when running with strict mode

**Solution**: Ensure proper type annotations in test code

```bash
# Run type checker
PYTHONPATH=src poetry run mypy tests/integration/
```

## 📈 Continuous Integration

All integration tests are run in CI/CD pipelines:

```bash
# Complete validation pipeline
make validate

# Just tests
make test

# Just integration tests
PYTHONPATH=src poetry run pytest tests/integration/ -v
```

### CI Configuration

Tests run with:

- Python 3.13+
- All dependencies from `pyproject.toml`
- Strict type checking (MyPy/Pyrefly)
- Linting (Ruff)
- Coverage minimum 65%

## 📚 References

- **[FlextLdif API Documentation](../README.md)**: Main project documentation
- **[HOOK_PATTERNS.md](../HOOK_PATTERNS.md)**: Server quirk hook patterns
- **[RFC 2849](https://tools.ietf.org/html/rfc2849)**: LDIF specification
- **[RFC 4512](https://tools.ietf.org/html/rfc4512)**: LDAP schema specification
- **[RFC 4514](https://tools.ietf.org/html/rfc4514)**: DN syntax specification

## ✅ Checklist for Test Development

- [ ] Test uses centralized fixtures from `conftest.py`
- [ ] Test follows naming conventions (`Test<Feature>`, `test_<description>`)
- [ ] Test has docstring explaining validation
- [ ] Test validates complete roundtrip (parse→write→parse)
- [ ] Test checks deep content, not just counts
- [ ] Test includes parametrization for multiple servers
- [ ] Test handles both success and error cases
- [ ] Test uses FlextResult patterns correctly
- [ ] Test passes linting and type checking
- [ ] Test follows "Best Practices" guidelines above

---

**Integration Test Suite** for FlextLdif LDIF processing library.

**Purpose**: Comprehensive testing of LDIF parsing, writing, and roundtrip validation across all LDAP server types with centralized fixture management.

**Maintained**: 2025 | **Test Count**: 100+ | **Coverage**: 65%+ minimum
