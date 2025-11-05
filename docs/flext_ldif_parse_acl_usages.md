# flext-ldif: parse() and format_acl() Usage Locations

**Analysis Date**: 2025-10-28
**Scope**: Comprehensive mapping of ACL method usage in flext-ldif library

---

## SUMMARY

The `parse()` and `format_acl()` methods are defined in the flext-ldif library and have **13 server quirks implementations** plus extensive test coverage.

**Files Affected by Return Type Change**: ~45+ files
**Lines of Code Affected**: ~520+ lines in quirks implementations + ~1000+ lines in tests
**Risk Level**: HIGH - Extensive refactoring required

---

## 1. METHOD DEFINITIONS

### Base Class Definition

**File**: `/home/marlonsc/flext/flext-ldif/src/flext_ldif/quirks/base.py`

```python
class FlextLdifServersBase.Acl(ABC, QuirkRegistrationMixin):
    """Base class for ACL quirks."""

    def parse(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
        """Parse server-specific ACL definition.

        Args:
            acl_line: ACL line from LDIF file

        Returns:
            FlextResult[FlextLdifModels.Acl]
        """
```

### Protocol Definition

**File**: `/home/marlonsc/flext/flext-ldif/src/flext_ldif/protocols.py`

```python
class AclProtocol(Protocol):
    """Protocol for ACL quirks."""

    def parse(self, acl_line: str) -> FlextResult[dict[str, object]]:
        """Parse ACL - returns FlextResult with dict or Acl model."""
```

---

## 2. SERVER QUIRKS IMPLEMENTATIONS

### 13 Server Quirks Classes Implementing parse()

| #   | File                  | Location                                         | Server Type             |
| --- | --------------------- | ------------------------------------------------ | ----------------------- |
| 1   | `oid.py`              | `/flext_ldif/quirks/servers/oid.py`              | Oracle OID              |
| 2   | `ouds.py`       | `/flext_ldif/quirks/servers/ouds.py`       | Oracle OUD              |
| 3   | `openldap.py`         | `/flext_ldif/quirks/servers/openldap.py`         | OpenLDAP (generic)      |
| 4   | `openldap1.py`        | `/flext_ldif/quirks/servers/openldap1.py`        | OpenLDAP 1.x            |
| 5   | `openldap2s.py` | `/flext_ldif/quirks/servers/openldap2s.py` | OpenLDAP 2.x            |
| 6   | `tivoli.py`           | `/flext_ldif/quirks/servers/tivoli.py`           | IBM Tivoli              |
| 7   | `novell.py`           | `/flext_ldif/quirks/servers/novell.py`           | Novell eDirectory       |
| 8   | `ad.py`               | `/flext_ldif/quirks/servers/ad.py`               | Active Directory        |
| 9   | `ds389.py`            | `/flext_ldif/quirks/servers/ds389.py`            | 389 Directory Server    |
| 10  | `apache.py`           | `/flext_ldif/quirks/servers/apache.py`           | Apache DS               |
| 11  | `relaxed.py`          | `/flext_ldif/quirks/servers/relaxed.py`          | RFC-compliant (relaxed) |
| 12  | `rfcs.py`       | `/flext_ldif/quirks/servers/rfcs.py`       | RFC baseline            |
| 13  | `generics.py`   | `/flext_ldif/quirks/servers/generics.py`   | Generic fallback        |

### Implementation Pattern

Each server quirks class has:

- `class XyzAcl(FlextLdifServersBase.Acl):`
- `def parse(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:`
- Server-specific parsing logic
- Returns `FlextResult.ok(Acl(...))` or `FlextResult.fail(...)`

**Affected Lines**: ~40-50 lines per file × 13 files = ~520-650 lines

---

## 3. SERVICE LAYER USAGE

### ACL Service

**File**: `/home/marlonsc/flext/flext-ldif/src/flext_ldif/services/acl.py`

**Method**: `parse()`

```python
def parse(
    self, acl_line: str, server_type: str | None = None
) -> FlextResult[FlextLdifModels.Acl]:
    """Parse ACL line using appropriate quirks.

    Delegates to quirks.parse() internally.
    """
    quirk_result = self._get_for_server(server_type)
    if quirk_result.is_failure:
        return FlextResult[FlextLdifModels.Acl].fail(...)

    quirk = quirk_result.unwrap()
    return quirk.parse(acl_line)  # ← Calls quirk.parse()
```

**Lines Affected**: 30-40 lines

### Categorized Pipeline

**File**: `/home/marlonsc/flext/flext-ldif/src/flext_ldif/categorized_pipeline.py`

**Method**: `_transform_categories()`

```python
def _transform_categories(
    self, categorized: dict[str, list[FlextTypes.Dict]]
) -> FlextResult[dict[str, list[FlextTypes.Dict]]]:
    """Transform ACL entries using OID→OUD pipeline.

    Uses parse()
    """
    # Lines 668-771: Complete ACL transformation logic
    for entry in categorized.get("acl", []):
        for acl_attr in ["orclaci", "orclentrylevelaci"]:
            parse_result = oid_acl.parse(f"{acl_attr}: {acl_value}")
            # ↑ Uses parse() to parse OID format
```

**Lines Affected**: 100+ lines for ACL transformation logic

---

## 4. TEST COVERAGE

### Unit Test Files Using parse()

| File                                 | Location                                           | Test Count   |
| ------------------------------------ | -------------------------------------------------- | ------------ |
| `tests_acl.py`                 | `/tests/unit/quirks/tests_acl.py`            | 20+ tests    |
| `tests_acl_conversion.py`      | `/tests/unit/quirks/tests_acl_conversion.py` | 15+ tests    |
| `test_acl_service.py`                | `/tests/unit/test_acl_service.py`                  | 10+ tests    |
| `test_acl_utils.py`                  | `/tests/unit/test_acl_utils.py`                    | 5+ tests     |
| `test_acl_service_operations.py.bak` | Backup file                                        | Legacy tests |

### Test Pattern

```python
def test_parse_oracle_oid():
    """Test OID ACL parsing."""
    quirk = FlextLdifServersOid.Acl()
    acl_line = "orclaci: access to entry by * (browse)"

    result = quirk.parse(acl_line)

    assert result.is_success
    acl = result.unwrap()
    assert isinstance(acl, FlextLdifModels.Acl)  # ← Tests Acl return type
    assert acl.server_type == "oid"
```

**Total Tests**: ~50+ test methods using parse()

---

## 5. INTEGRATION POINTS

### FlextLdifCategorizedMigrationPipeline

**File**: `/home/marlonsc/flext/flext-ldif/src/flext_ldif/categorized_pipeline.py`

**Usage Context**:

- Initializes OID and OUD quirks
- Calls `_transform_categories()` which uses parse()
- Returns transformed entries with OUD format ACLs

**Impact**: HIGH - Core migration pipeline uses parse()

### FlextLdif High-Level API

**File**: `/home/marlonsc/flext/flext-ldif/src/flext_ldif/__init__.py`

**Exposure**:

- `FlextLdif.parse()` uses quirks internally but doesn't expose parse()
- Higher-level API returns Entry models (not Acl models)
- client-a-oud-mig uses this API (already compatible with Entry return)

---

## 6. CURRENT DATA FLOW

```
Input LDIF with OID ACL (orclaci:)
    ↓
FlextLdif.parse() → FlextLdifModels.Entry[]
    ↓ (internal quirks usage)
parse(acl_line: str) → FlextResult[FlextLdifModels.Acl]
    ↓
Entry model with aci attributes (after transformation)
    ↓
Output LDIF with OUD format (aci:)
```

---

## 7. AFFECTED CODE LOCATIONS (SUMMARY)

### Must Be Updated (High Impact)

1. **Protocol Definition** (3-5 lines)
   - `/flext_ldif/protocols.py` - Update AclProtocol signature

2. **Base Class** (10-15 lines)
   - `/flext_ldif/quirks/base.py` - Update FlextLdifServersBase.Acl.parse()

3. **13 Server Quirks** (520-650 lines)
   - All 13 quirks files in `/flext_ldif/quirks/servers/`
   - Each file needs parse() method signature updated

4. **Service Layer** (30-50 lines)
   - `/flext_ldif/services/acl.py` - Update parse() wrapper
   - `/flext_ldif/categorized_pipeline.py` - Update transformation logic

5. **Tests** (1000+ lines)
   - 50+ test methods in 4+ test files
   - Mock returns, assertions, fixture data

### Should Review (Medium Impact)

1. **Integration Tests** (tests/integration/)
   - May have parse() calls in fixtures or helpers

2. **Examples** (examples/06_acl_processing.py)
   - Documentation examples using parse()

3. **Type Hints**
   - Any type hints expecting Acl model need updating

---

## 8. MIGRATION STRATEGY

### Phase 1: Update Interfaces (2-3 hours)

- [ ] Update protocol definition in protocols.py
- [ ] Update base class in quirks/base.py
- [ ] Update service wrapper in services/acl.py

### Phase 2: Update Implementations (4-6 hours)

- [ ] Update all 13 server quirks
- [ ] Create Entry wrapper logic if needed
- [ ] Update categorized_pipeline.py

### Phase 3: Update Tests (2-3 hours)

- [ ] Update test files to expect Entry return
- [ ] Update assertions and mocks
- [ ] Add Entry wrapping tests

### Phase 4: Validation (2-3 hours)

- [ ] Run full test suite
- [ ] Test with real LDIF data
- [ ] Verify client-a-oud-mig compatibility (should be automatic)

**Total Estimated Time**: 10-15 hours of development

---

## 9. ECOSYSTEM IMPACT

### Projects Using flext-ldif

**Dependent on parse()/format_acl()**:

1. client-a-oud-mig - Uses via FlextLdif.parse() (COMPATIBLE)
2. Any other projects importing from flext-ldif

**Risk Assessment**:

- client-a-oud-mig: 🟢 **NO CHANGES NEEDED** (uses high-level API)
- flext-ldif itself: 🔴 **EXTENSIVE CHANGES REQUIRED**
- Other ecosytem projects: 🟡 **REVIEW REQUIRED** (depends on usage)

---

## CONCLUSION

The parse() and format_acl() return type change requires **significant refactoring** within flext-ldif but does **NOT impact client-a-oud-mig** because:

1. client-a-oud-mig uses `FlextLdif.parse()` (high-level API) which returns Entry models
2. client-a-oud-mig does not directly call parse() or format_acl()
3. The change is internal to flext-ldif's quirks system

**Recommendation**: Implement the change in flext-ldif, test thoroughly, then verify client-a-oud-mig continues to work (should be automatic with no code changes).

---

**Generated By**: Claude Code
**Tools Used**: Grep, Read, Bash
**Scope**: Complete flext-ldif ACL method analysis
