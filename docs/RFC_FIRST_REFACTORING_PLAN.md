# FLEXT-LDIF RFC-First Architecture Refactoring Plan

**Version**: 1.0
**Created**: 2025-10-01
**Status**: IN PROGRESS
**Goal**: Transform flext-ldif into a totally generic, library-only LDIF processor with RFC-first architecture

---

## Executive Summary

This plan transforms flext-ldif from a mixed-purpose library into a **pure RFC-compliant LDIF processing library** with pluggable quirks for server-specific extensions. The library will work with ANY LDAP server (known or unknown) through a generic RFC 2849/4512 baseline with optional server-specific quirks.

### Core Principles

1. **RFC-First Architecture**: RFC 2849 (LDIF) and RFC 4512 (Schema) as the baseline for ALL servers
2. **Zero Bypass Paths**: ALL parse/write/validate operations MUST go through RFC parsers + quirks
3. **Library-Only**: NO CLI code, tools, or applications - pure library functionality
4. **Generic Transformation**: Source → RFC → Target pipeline works with any server combination
5. **Pluggable Quirks**: Server-specific extensions enhance (never replace) RFC parsing

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    FlextLdif API (Facade)                    │
│  parse() | write() | validate() | migrate() | analyze()     │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                   CQRS Handlers Layer                        │
│  ParseQueryHandler | WriteCommandHandler | ValidateHandler  │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              RFC Parsers/Writers (Baseline)                  │
│  RfcLdifParserService | RfcSchemaParserService |            │
│  RfcLdifWriterService                                       │
│                                                              │
│  ┌──────────────────────────────────────────────┐          │
│  │        Quirks Registry (Extensions)          │          │
│  │  ┌─────────────┐  ┌─────────────┐          │          │
│  │  │ OpenLDAP 1/2│  │     OID     │          │          │
│  │  │  (complete) │  │  (complete) │          │          │
│  │  └─────────────┘  └─────────────┘          │          │
│  │  ┌─────────────┐  ┌─────────────┐          │          │
│  │  │     OUD     │  │     AD      │          │          │
│  │  │  (complete) │  │   (stub)    │          │          │
│  │  └─────────────┘  └─────────────┘          │          │
│  │       [Apache DS, 389DS, Novell, Tivoli    │          │
│  │         stubs for future completion]       │          │
│  └──────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

---

## Refactoring Phases

### ✅ Phase 1: Code Audit & Cleanup (COMPLETED)

**Status**: 100% Complete
**Duration**: Completed
**Tests**: 388/389 passing (99.7%)

**Achievements**:
- Fixed all lint errors (Ruff 100% clean)
- Fixed type annotations in tests/conftest.py
- Fixed container registration in api.py (lambdas → instances)
- Fixed Path → str conversion in parse() method
- Verified zero unused code in core modules

**Deliverables**:
- ✅ All lint checks passing (MyPy 100%, Ruff 100%)
- ✅ Container registration uses direct instances
- ✅ Tests improved from 387 → 388 passing

---

### ✅ Phase 2: Documentation Updates (PARTIAL - 33% Complete)

**Status**: README.md complete, architecture.md and api-reference.md pending
**Current Progress**: 1/3 files updated

#### Phase 2.1: README.md ✅ (COMPLETED)
- Updated status to "LIBRARY-ONLY"
- Updated quality gates metrics (388/389 tests, 52% coverage)
- Changed API examples from FlextLdifAPI → FlextLdif
- Added MANDATORY quirk_registry documentation
- Documented RFC-first architecture with quirks

#### Phase 2.2: docs/architecture.md ❌ (PENDING)
**Tasks**:
- [ ] Add RFC-first architecture diagram
- [ ] Document quirks priority system (lower number = higher priority)
- [ ] Explain generic transformation pipeline (Source → RFC → Target)
- [ ] Document nested quirks (SchemaQuirk contains AclQuirk and EntryQuirk)
- [ ] Remove any CLI architecture references

#### Phase 2.3: docs/api-reference.md ❌ (PENDING)
**Tasks**:
- [ ] Document FlextLdif facade methods (parse, write, validate, migrate, analyze)
- [ ] Document quirk_registry parameter as MANDATORY
- [ ] Add examples for each server type (rfc, oid, oud, openldap1, openldap2)
- [ ] Document error handling patterns with FlextResult
- [ ] Remove CLI command references

---

### ✅ Phase 3: Code Path Verification (COMPLETED)

**Status**: 100% Complete
**Verification Method**: grep + Read tools

**Verified Components**:
1. ✅ **handlers.py**: All handlers use RFC parsers from container
2. ✅ **api.py**: Facade correctly delegates to CQRS handlers
3. ✅ **migration_pipeline.py**: Uses RFC parsers with quirk_registry
4. ✅ **acl/parser.py**: Only parses ACL strings (not LDIF bypass)
5. ✅ **NO bypass patterns found**: splitlines() only in RFC parser (correct)

**Key Finding**: All parse/write/validate operations go through RFC + quirks - ZERO bypass paths.

---

### ⚠️ Phase 4: CLI Removal (NOT STARTED)

**Status**: 0% Complete
**Priority**: CRITICAL - User explicitly requested "Remove ALL CLI"

#### Phase 4.1: Search for CLI Code
**Tasks**:
- [ ] Search for Click imports: `grep -r "import click\|from click" src/`
- [ ] Search for CLI decorators: `grep -r "@click\|@command\|@group" src/`
- [ ] Search for argparse: `grep -r "import argparse\|ArgumentParser" src/`
- [ ] Search for CLI entry points in pyproject.toml: `[tool.poetry.scripts]`
- [ ] Search for CLI tests: `grep -r "cli\|command\|click" tests/`

#### Phase 4.2: Remove CLI Dependencies
**Tasks**:
- [ ] Remove Click from pyproject.toml dependencies
- [ ] Remove CLI modules (src/flext_ldif/cli.py if exists)
- [ ] Remove CLI tests (tests/*/test_cli*.py)
- [ ] Remove CLI documentation from README.md
- [ ] Update pyproject.toml to remove [tool.poetry.scripts] section

#### Phase 4.3: Verify Library-Only Interface
**Tasks**:
- [ ] Ensure FlextLdif facade is the ONLY public API
- [ ] Verify no main() or __main__ blocks in src/
- [ ] Confirm library can ONLY be imported, not executed

---

### ⚠️ Phase 5: Quirks Verification (NOT STARTED)

**Status**: 0% Complete
**Priority**: HIGH - Core requirement for RFC-first architecture

#### Phase 5.1: Verify Complete Implementations
**Complete Implementations Required**:
- [ ] **OpenLDAP 1.x**: Verify OpenLdap1SchemaQuirk implementation
- [ ] **OpenLDAP 2.x**: Verify OpenLdapSchemaQuirk implementation
- [ ] **OID (Oracle Internet Directory)**: Verify OidSchemaQuirk implementation
- [ ] **OUD (Oracle Unified Directory)**: Verify OudSchemaQuirk implementation

**Verification Checklist (per quirk)**:
- [ ] SchemaQuirk: can_handle_attribute(), parse_attribute(), can_handle_objectclass(), parse_objectclass()
- [ ] AclQuirk (nested): can_handle(), parse(), transform()
- [ ] EntryQuirk (nested): can_handle(), parse(), transform()
- [ ] Priority set correctly (lower = higher priority)
- [ ] Registered in api.py _register_default_quirks()
- [ ] Tests exist for each quirk in tests/unit/

#### Phase 5.2: Verify Stub Implementations
**Stub Implementations Required**:
- [ ] **Active Directory (AD)**: Verify AdSchemaQuirk stub
- [ ] **Apache Directory Server**: Verify ApacheSchemaQuirk stub
- [ ] **389 Directory Server**: Verify Ds389SchemaQuirk stub
- [ ] **Novell eDirectory**: Verify NovellSchemaQuirk stub
- [ ] **IBM Tivoli Directory Server**: Verify TivoliSchemaQuirk stub

**Stub Requirements**:
- [ ] Class exists with server_type and priority
- [ ] Methods exist but return "Not implemented" errors
- [ ] Registered in api.py _register_default_quirks()
- [ ] Documented as "stub" in README.md

#### Phase 5.3: Verify Quirks Priority System
**Tasks**:
- [ ] Verify priority ordering: Complete quirks (10), Stubs (15), OpenLDAP1 (20)
- [ ] Verify QuirkRegistryService.get_*_quirks() returns sorted by priority
- [ ] Verify RFC parsers try quirks FIRST, RFC as FALLBACK
- [ ] Test priority resolution with multiple quirks

---

### ⚠️ Phase 6: Generic LDIF Interface Verification (NOT STARTED)

**Status**: 0% Complete
**Priority**: HIGH - Core requirement "library totally generic"

#### Phase 6.1: Verify Schema Processing is Generic
**Tasks**:
- [ ] Verify RfcSchemaParserService accepts any server_type
- [ ] Verify parser works WITHOUT quirks (pure RFC mode)
- [ ] Verify parser enhances WITH quirks (server-specific mode)
- [ ] Test with unknown server type (should use RFC only)

#### Phase 6.2: Verify Entry Processing is Generic
**Tasks**:
- [ ] Verify RfcLdifParserService accepts any server_type
- [ ] Verify entry parsing works WITHOUT quirks
- [ ] Verify entry parsing enhances WITH quirks
- [ ] Test with unknown server type

#### Phase 6.3: Verify ACL Processing is Generic
**Tasks**:
- [ ] Verify ACL extraction works for any entry format
- [ ] Verify ACL parsing uses RFC baseline + quirks
- [ ] Test ACL processing with unknown server type

#### Phase 6.4: Verify Migration is Generic
**Tasks**:
- [ ] Verify LdifMigrationPipelineService accepts any source/target combination
- [ ] Test migration: RFC → RFC (identity transformation)
- [ ] Test migration: OID → Unknown (uses RFC as target baseline)
- [ ] Test migration: Unknown → OUD (uses RFC as source baseline)

---

### ⚠️ Phase 7: Systematic Unused Code Removal (NOT STARTED)

**Status**: 0% Complete
**Priority**: MEDIUM - Code hygiene requirement

#### Phase 7.1: Identify All Modules
**Command**:
```bash
find src/flext_ldif -name "*.py" -not -path "*/tests/*" | sort > all_modules.txt
```

#### Phase 7.2: Verify Each Module is Used
**For each module**:
```bash
# Check if module is imported anywhere
MODULE="module_name"
grep -r "from flext_ldif.*import.*$MODULE\|import.*flext_ldif.*$MODULE" src/ tests/
```

**Modules to Check**:
- [ ] src/flext_ldif/*.py (all root modules)
- [ ] src/flext_ldif/acl/*.py
- [ ] src/flext_ldif/entry/*.py
- [ ] src/flext_ldif/rfc/*.py
- [ ] src/flext_ldif/schema/*.py
- [ ] src/flext_ldif/quirks/*.py
- [ ] src/flext_ldif/quirks/servers/*.py

#### Phase 7.3: Remove Unused Modules
**Action**: Delete modules with ZERO references (excluding __init__.py)

---

### ⚠️ Phase 8: Coverage Improvement (NOT STARTED)

**Status**: 0% Complete - Currently at 52%
**Target**: 75% minimum (industry standard)
**Priority**: HIGH - QA requirement

#### Phase 8.1: Coverage Analysis
**Commands**:
```bash
# Generate coverage report
poetry run pytest --cov=src --cov-report=term-missing --cov-report=html

# Identify uncovered modules
poetry run pytest --cov=src --cov-report=term | grep -E "\.py.*[0-9]+%$" | sort -t% -k2 -n
```

#### Phase 8.2: Prioritize Coverage by Impact
**Strategy**: Target large, critical modules first
1. Find largest modules: `wc -l src/flext_ldif/**/*.py | sort -n`
2. Find most used modules: grep references
3. Prioritize: Large + High-usage + Low-coverage

#### Phase 8.3: Write Missing Tests
**Focus Areas**:
- [ ] RFC parsers (rfc_ldif_parser.py, rfc_schema_parser.py)
- [ ] Migration pipeline (migration_pipeline.py)
- [ ] Quirks (all server quirks)
- [ ] Handlers (handlers.py)
- [ ] Models (models.py)

**Test Requirements**:
- Real execution tests (not mocked)
- Edge cases (empty input, malformed LDIF, encoding issues)
- RFC compliance tests
- Quirks priority resolution tests

#### Phase 8.4: Validate 75% Coverage Achieved
**Command**:
```bash
poetry run pytest --cov=src --cov-report=term --cov-fail-under=75
```

---

### ⚠️ Phase 9: Examples Cleanup (NOT STARTED)

**Status**: 0% Complete
**Priority**: MEDIUM - Documentation quality

#### Phase 9.1: Remove Old Examples
**Tasks**:
- [ ] List all example files: `ls -la examples/`
- [ ] Remove examples using old FlextLdifProcessor API
- [ ] Remove examples with CLI code
- [ ] Remove examples directory if empty

#### Phase 9.2: Create New API Examples
**Required Examples**:
- [ ] `examples/01_basic_parsing.py` - Parse LDIF string/file
- [ ] `examples/02_server_specific_quirks.py` - Parse with server_type
- [ ] `examples/03_writing_ldif.py` - Write entries to LDIF
- [ ] `examples/04_validation.py` - Validate entries
- [ ] `examples/05_migration.py` - Migrate OID → OUD
- [ ] `examples/06_custom_quirks.py` - Register custom quirk

**Example Template**:
```python
"""Example: <Title>

Demonstrates <functionality> using flext-ldif library-only API.
"""
from flext_ldif import FlextLdif
from pathlib import Path

# Example code here
ldif = FlextLdif()
result = ldif.parse("dn: cn=test,dc=example,dc=com\ncn: test\n")
if result.is_success:
    entries = result.unwrap()
    print(f"Parsed {len(entries)} entries")
```

---

### ⚠️ Phase 10: Final Validation (NOT STARTED)

**Status**: 0% Complete
**Priority**: CRITICAL - Delivery requirement

#### Phase 10.1: Complete Validation Pipeline
**Commands**:
```bash
make validate       # Runs lint + type + security + test
make test           # All tests passing
make coverage       # 75%+ coverage
make docs           # Generate documentation
```

**Success Criteria**:
- [ ] MyPy: 100% clean in src/
- [ ] Ruff: 100% clean
- [ ] Tests: 389/389 passing (100%)
- [ ] Coverage: ≥75%
- [ ] Documentation: All 3 docs files updated

#### Phase 10.2: Update CHANGELOG
**Tasks**:
- [ ] Document RFC-first architecture changes
- [ ] Document CLI removal
- [ ] Document quirks system enhancements
- [ ] Document breaking changes (if any)
- [ ] Document new FlextLdif facade API

#### Phase 10.3: Final Commit
**Commit Message**:
```
refactor(flext-ldif): RFC-first architecture with library-only interface

BREAKING CHANGES:
- Removed all CLI code and dependencies
- Changed API from FlextLdifProcessor to FlextLdif facade
- Enforced RFC-first parsing (all operations go through RFC + quirks)

Features:
- Generic LDIF processing for ANY LDAP server
- Complete quirks: OpenLDAP 1/2, OID, OUD
- Stub quirks: AD, Apache DS, 389DS, Novell, Tivoli
- Zero bypass paths - guaranteed RFC compliance

Quality:
- Tests: 389/389 passing (100%)
- Coverage: 75%+
- Lint: 100% clean (MyPy + Ruff)
- Documentation: Complete (README, architecture, API reference)

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

---

## Completion Checklist

### Critical Path (Must Complete)
- [x] Phase 1: Code Audit & Cleanup
- [x] Phase 2.1: README.md Update
- [x] Phase 3: Code Path Verification
- [ ] Phase 4: CLI Removal
- [ ] Phase 5: Quirks Verification
- [ ] Phase 6: Generic Interface Verification
- [ ] Phase 10: Final Validation

### Quality Path (Should Complete)
- [ ] Phase 7: Systematic Unused Code Removal
- [ ] Phase 8: Coverage Improvement (75%+)
- [ ] Phase 9: Examples Cleanup

### Documentation Path (Should Complete)
- [ ] Phase 2.2: docs/architecture.md
- [ ] Phase 2.3: docs/api-reference.md

---

## Progress Tracking

**Overall Completion**: 30% (3 of 10 phases complete)

| Phase | Status | Progress | Blocker |
|-------|--------|----------|---------|
| 1. Code Audit | ✅ Complete | 100% | - |
| 2. Documentation | ⚠️ Partial | 33% (1/3 files) | Need architecture.md, api-reference.md |
| 3. Code Path Verification | ✅ Complete | 100% | - |
| 4. CLI Removal | ❌ Not Started | 0% | Need to search and remove |
| 5. Quirks Verification | ❌ Not Started | 0% | Need to verify all implementations |
| 6. Generic Interface | ❌ Not Started | 0% | Need to test generic usage |
| 7. Unused Code Removal | ❌ Not Started | 0% | Need systematic check |
| 8. Coverage Improvement | ❌ Not Started | 0% | Need to write tests |
| 9. Examples Cleanup | ❌ Not Started | 0% | Need to create new examples |
| 10. Final Validation | ❌ Not Started | 0% | Blocked by all above |

---

## Success Criteria

**Library Quality**:
- ✅ 100% MyPy compliance in src/
- ✅ 100% Ruff compliance
- ⚠️ 99.7% tests passing (388/389) - need 100%
- ❌ 75%+ coverage - currently 52%

**Architecture Requirements**:
- ✅ RFC-first enforcement (verified)
- ❌ Zero CLI code (not verified)
- ❌ Generic LDIF interface (not verified)
- ❌ Complete quirks (not verified)

**Documentation**:
- ⚠️ 33% complete (1/3 files)
- ❌ Examples not updated
- ❌ CHANGELOG not updated

**Overall Status**: 🔴 30% Complete - Significant work remaining

---

## Next Steps

1. **CLI Removal** (Phase 4) - Search and remove all CLI code
2. **Quirks Verification** (Phase 5) - Verify complete implementations
3. **Generic Interface Testing** (Phase 6) - Test with unknown servers
4. **Coverage Improvement** (Phase 8) - Write tests to reach 75%
5. **Documentation Completion** (Phase 2.2, 2.3) - Finish docs files
6. **Final Validation** (Phase 10) - Complete quality gates

---

**Document Status**: Living document - Updated as phases complete
**Next Review**: After Phase 4 completion
