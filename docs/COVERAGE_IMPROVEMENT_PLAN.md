# Test Coverage Improvement Plan

**Current Coverage**: 52%
**Target Coverage**: 75% minimum (100% aspirational)
**Gap**: ~100 additional tests needed
**Estimated Effort**: 4-6 hours

---

## 📊 Current Status

### Coverage Analysis (2025-10-01)

```bash
# Run coverage report
poetry run pytest tests/ --cov=src/flext_ldif --cov-report=term-missing --cov-report=html
```

**Note**: Full coverage reports timeout after 2 minutes, indicating large test suite (389 tests).

### Existing Test Files

```
tests/
├── e2e/
│   └── test_enterprise.py              # End-to-end enterprise tests
├── unit/
│   ├── test_acl.py                     # ACL parsing tests
│   ├── test_api.py                     # Main API facade tests ✅
│   ├── test_config.py                  # Configuration tests
│   ├── test_constants.py               # Constants tests
│   ├── test_entry_builder.py           # Entry builder tests
│   ├── test_exceptions.py              # Exception handling tests
│   ├── test_facade_properties.py       # Facade property tests
│   ├── test_mixins.py                  # Mixin tests
│   ├── test_models.py                  # Domain model tests ✅
│   ├── test_rfc.py                     # RFC parser/writer tests ✅
│   ├── test_rfc_writer_comprehensive.py # Comprehensive writer tests ✅
│   └── test_utilities.py               # Utility function tests
├── test_support/
│   └── test_files.py                   # Test file utilities
└── test_flext_ldif_unified.py         # Unified integration tests ✅
```

**Total Test Files**: 15 files
**Total Tests**: 389 passing

---

## 🎯 High-Impact Modules Needing Tests

### Priority 1: Critical Path (Highest Impact)

#### 1. `src/flext_ldif/handlers.py` - CQRS Handlers

- **Lines**: ~350 lines
- **Current Tests**: Indirectly tested via `test_api.py`
- **Missing**: Direct unit tests for handler methods
- **Impact**: HIGH - Central processing hub, all operations go through here
- **Estimated Tests**: 15-20 tests

**What to Test**:

```python
# Test command handlers
- LdifParseMessageHandler.execute() - various input types
- LdifWriteMessageHandler.execute() - file vs string output
- LdifValidateMessageHandler.execute() - validation edge cases
- SchemaParseMessageHandler.execute() - schema parsing paths

# Test query handlers
- GetEntriesQueryHandler.execute() - entry retrieval
- GetSchemaQueryHandler.execute() - schema queries

# Test error handling
- Invalid input types
- Missing required parameters
- Empty inputs
- Malformed LDIF
```

#### 2. `src/flext_ldif/migration_pipeline.py` - Generic Transformation

- **Lines**: ~200 lines
- **Current Tests**: None (only indirectly via e2e)
- **Missing**: Unit tests for pipeline stages
- **Impact**: HIGH - Core migration functionality
- **Estimated Tests**: 10-15 tests

**What to Test**:

```python
# Test pipeline initialization
- FlextLdifMigrationPipeline.__init__() - various server combinations
- Input/output directory validation
- quirk_registry parameter handling

# Test pipeline execution
- execute() - successful migration
- execute() - with errors
- execute() - empty input directory
- execute() - various server type combinations (OID→OUD, OpenLDAP1→OpenLDAP2, etc.)

# Test transformation stages
- Source parsing with quirks
- RFC normalization
- Target writing with quirks

# Test error recovery
- Partial file processing
- Invalid LDIF in batch
- Filesystem errors
```

#### 3. `src/flext_ldif/quirks/registry.py` - Quirk Management

- **Lines**: ~150 lines
- **Current Tests**: None (indirectly via RFC parser tests)
- **Missing**: Direct unit tests for registry operations
- **Impact**: HIGH - Core quirks resolution
- **Estimated Tests**: 10-12 tests

**What to Test**:

```python
# Test quirk registration
- QuirkRegistryService.__init__() - loads all quirks
- get_quirk() - retrieves correct quirk by server_type
- get_quirk() - returns None for unknown server

# Test priority resolution
- Multiple quirks handling
- Priority ordering (10 > 15 > 20)
- Fallback behavior

# Test nested quirks
- SchemaQuirk contains AclQuirk
- SchemaQuirk contains EntryQuirk
- Nested quirk access patterns

# Test error cases
- Invalid server_type
- Missing quirks
- Quirk initialization failures
```

### Priority 2: RFC Processing (High Impact)

#### 4. `src/flext_ldif/rfc/rfc_ldif_parser.py` - RFC 2849 Parser

- **Lines**: ~300 lines
- **Current Tests**: Basic tests in `test_rfc.py`
- **Missing**: Comprehensive edge case tests
- **Impact**: HIGH - Core LDIF parsing
- **Estimated Tests**: 15-20 tests

**What to Test**:

```python
# Test basic parsing
- Single entry parsing
- Multiple entries parsing
- Base64-encoded values
- Continuation lines

# Test quirks integration
- Parsing with OID quirks
- Parsing with OUD quirks
- Parsing with OpenLDAP quirks
- Parsing without quirks (pure RFC)

# Test error cases
- Malformed DN
- Invalid attribute syntax
- Missing separators
- Empty content
- Large files (memory limits)

# Test edge cases
- Binary attributes
- Long lines (>80 chars)
- Special characters
- Unicode handling
```

#### 5. `src/flext_ldif/rfc/rfc_ldif_writer.py` - RFC 2849 Writer

- **Lines**: ~200 lines
- **Current Tests**: Comprehensive tests in `test_rfc_writer_comprehensive.py` ✅
- **Missing**: Few additional quirks integration tests
- **Impact**: MEDIUM - Already well tested
- **Estimated Tests**: 5-10 additional tests

**What to Test**:

```python
# Test quirks integration (not yet covered)
- Writing with server-specific quirks
- Format conversion (OID→RFC, OUD→RFC, etc.)
- Entry transformation during write

# Test edge cases
- Very long attribute values
- Binary data encoding
- Special character escaping
```

#### 6. `src/flext_ldif/rfc/rfc_schema_parser.py` - RFC 4512 Schema Parser

- **Lines**: ~250 lines
- **Current Tests**: Basic tests in `test_rfc.py` (some skipped)
- **Missing**: Complete implementation tests
- **Impact**: HIGH - Schema processing
- **Estimated Tests**: 10-15 tests

**What to Test**:

```python
# Test attribute type parsing
- Basic attribute types
- Custom OIDs
- Syntax specifications
- Multi-valued attributes

# Test object class parsing
- Structural object classes
- Auxiliary object classes
- Abstract object classes
- Inheritance chains

# Test quirks integration
- OID schema quirks
- OUD schema quirks
- OpenLDAP schema quirks

# Test error cases
- Invalid schema syntax
- Missing required fields
- Circular dependencies
```

### Priority 3: Schema Processing (Medium Impact)

#### 7. `src/flext_ldif/schema/objectclass_manager.py`

- **Current Tests**: None
- **Estimated Tests**: 8-10 tests
- **What to Test**: Object class registration, inheritance, validation

#### 8. `src/flext_ldif/schema/validator.py`

- **Current Tests**: Indirectly via API
- **Estimated Tests**: 10-12 tests
- **What to Test**: Entry validation against schema, required attributes, allowed attributes

#### 9. `src/flext_ldif/schema/builder.py`

- **Current Tests**: None
- **Estimated Tests**: 6-8 tests
- **What to Test**: Schema building, attribute type creation, object class definition

#### 10. `src/flext_ldif/schema/extractor.py`

- **Current Tests**: None
- **Estimated Tests**: 6-8 tests
- **What to Test**: Schema extraction from entries, cn=schema parsing

### Priority 4: Support Modules (Lower Impact)

#### 11. `src/flext_ldif/quirks/manager.py`

- **Estimated Tests**: 6-8 tests
- **What to Test**: Quirk selection, priority resolution, nested quirk access

#### 12. `src/flext_ldif/quirks/base.py`

- **Estimated Tests**: 5-7 tests
- **What to Test**: Base quirk protocol compliance, default methods

#### 13. `src/flext_ldif/quirks/entry_quirks.py`

- **Estimated Tests**: 8-10 tests
- **What to Test**: Entry transformation, attribute mapping, DN manipulation

#### 14. `src/flext_ldif/protocols.py`

- **Current Tests**: None (protocol definitions)
- **Estimated Tests**: 3-5 tests (if testable)
- **What to Test**: Protocol compliance checks

---

## 📝 Test Writing Guidelines

### 1. Use Real Services Over Mocks

```python
# ✅ PREFERRED: Real service testing
def test_parse_ldif_real(real_parser_service):
    result = real_parser_service.parse_content(ldif_content)
    assert result.is_success
    entries = result.unwrap()
    assert len(entries) == 2

# ❌ AVOID: Over-mocking
def test_parse_ldif_mocked(mocker):
    mock_parser = mocker.Mock()
    mock_parser.parse.return_value = FlextResult.ok([])
    # This doesn't test real behavior
```

### 2. Test FlextResult Pattern

```python
# Test success paths
def test_operation_success():
    result = service.operation(valid_input)
    assert result.is_success
    data = result.unwrap()
    assert data["expected_key"] == "expected_value"

# Test failure paths
def test_operation_failure():
    result = service.operation(invalid_input)
    assert result.is_failure
    assert "expected error" in result.error.lower()
```

### 3. Test Quirks Integration

```python
# Test with different server types
@pytest.mark.parametrize("server_type", ["oid", "oud", "openldap", "openldap1"])
def test_parsing_with_server_quirks(server_type):
    quirk_registry = QuirkRegistryService()
    parser = RfcLdifParserService(
        params={"content": ldif_content},
        quirk_registry=quirk_registry,
        server_type=server_type,
    )
    result = parser.execute()
    assert result.is_success
```

### 4. Test Edge Cases

```python
# Empty inputs
def test_parse_empty_ldif():
    result = api.parse("")
    assert result.is_success
    assert len(result.unwrap()) == 0

# Large inputs (memory limits)
def test_parse_large_ldif():
    # Create large LDIF content
    large_ldif = "\\n\\n".join([
        f"dn: cn=user{i},dc=example,dc=com\\ncn: user{i}\\n"
        for i in range(10000)
    ])
    result = api.parse(large_ldif)
    # Either succeeds or fails gracefully

# Invalid inputs
def test_parse_invalid_dn():
    invalid_ldif = "dn: not a valid dn\\ncn: test\\n"
    result = api.parse(invalid_ldif)
    assert result.is_failure
```

---

## 🔄 Test Development Workflow

### Step 1: Impact Analysis

```bash
# Find largest uncovered modules
pytest --cov=src/flext_ldif --cov-report=term-missing | \
  grep -E "\.py.*\d+\s+\d+.*%" | \
  sort -k2 -nr | \
  head -20
```

### Step 2: Create Test File

```bash
# Create test file for target module
touch tests/unit/test_[module_name].py
```

### Step 3: Write Tests Incrementally

```bash
# Run tests for specific module
pytest tests/unit/test_[module_name].py -v

# Check coverage impact
pytest tests/unit/test_[module_name].py --cov=src/flext_ldif/[module_name].py --cov-report=term
```

### Step 4: Validate

```bash
# Run full test suite
pytest tests/ -v

# Check overall coverage improvement
pytest tests/ --cov=src/flext_ldif --cov-report=term | grep TOTAL
```

---

## 📊 Progress Tracking

### Coverage Milestones

| Milestone    | Coverage | Tests Added    | Estimated Effort |
| ------------ | -------- | -------------- | ---------------- |
| Current      | 52%      | 0              | 0 hours          |
| Phase 1      | 60%      | ~30 tests      | 1.5-2 hours      |
| Phase 2      | 65%      | ~50 tests      | 2.5-3 hours      |
| Phase 3      | 70%      | ~75 tests      | 3.5-4.5 hours    |
| **Target**   | **75%**  | **~100 tests** | **4-6 hours**    |
| Aspirational | 100%     | ~200 tests     | 10-15 hours      |

### Test File Checklist

- [ ] `tests/unit/test_handlers.py` - CQRS handlers (15-20 tests)
- [ ] `tests/unit/test_migration_pipeline.py` - Migration pipeline (10-15 tests)
- [ ] `tests/unit/test_quirks_registry.py` - Quirk registry (10-12 tests)
- [ ] `tests/unit/test_rfc_ldif_parser.py` - RFC parser edge cases (15-20 tests)
- [ ] `tests/unit/test_rfc_schema_parser.py` - Schema parser (10-15 tests)
- [ ] `tests/unit/test_schema_objectclass_manager.py` - Object class management (8-10 tests)
- [ ] `tests/unit/test_schema_validator.py` - Schema validation (10-12 tests)
- [ ] `tests/unit/test_schema_builder.py` - Schema building (6-8 tests)
- [ ] `tests/unit/test_schema_extractor.py` - Schema extraction (6-8 tests)
- [ ] `tests/unit/test_quirks_manager.py` - Quirk manager (6-8 tests)

---

## 🎯 Success Criteria

### Definition of Done

1. **Coverage Target**: Minimum 75% overall coverage
2. **Critical Path**: 100% coverage for handlers.py, migration_pipeline.py, quirks/registry.py
3. **Quality**: All tests pass (make test)
4. **Validation**: Complete validation pipeline passes (make validate)
5. **Documentation**: Test docstrings explain what is tested and why

### Verification Commands

```bash
# Verify coverage target met
pytest tests/ --cov=src/flext_ldif --cov-report=term --cov-fail-under=75

# Verify all tests pass
make test

# Verify complete validation
make validate

# Generate HTML coverage report
pytest tests/ --cov=src/flext_ldif --cov-report=html
# Open htmlcov/index.html in browser
```

---

## 📚 Resources

- **Pytest Documentation**: <https://docs.pytest.org/>
- **Coverage.py Documentation**: <https://coverage.readthedocs.io/>
- **FlextResult Pattern**: `flext-core` documentation
- **Existing Tests**: `tests/unit/test_api.py` - Good example of API testing
- **Existing Tests**: `tests/unit/test_rfc_writer_comprehensive.py` - Good example of comprehensive testing

---

**Last Updated**: 2025-10-01
**Next Review**: After 75% coverage achieved
