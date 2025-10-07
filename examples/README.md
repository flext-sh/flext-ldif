# FLEXT-LDIF Examples

This directory contains comprehensive examples demonstrating all functionality of the flext-ldif library.

## 📚 Library-Only Examples

All examples showcase **library usage only** - no CLI patterns, no `main()` functions, no print statements. Each example demonstrates specific FlextLdif functionality through clean, reusable function patterns.

## 🎯 Example Overview

### 01_basic_usage.py - Core API Operations
**Demonstrates**: `parse()`, `write()`, FlextResult error handling

Learn the fundamentals:
- Parse LDIF from strings and files
- Write LDIF to strings and files
- Railway-oriented programming with FlextResult
- Entry model inspection

**Key Functions**:
- `parse_ldif_string()` - Parse LDIF content
- `parse_ldif_file()` - Parse from file
- `write_ldif_string()` - Write to string
- `write_ldif_file()` - Write to file
- `railway_oriented_pipeline()` - Error handling chains

### 02_entry_operations.py - Entry Building & Manipulation
**Demonstrates**: EntryBuilder, models, filtering operations

Master entry operations:
- Build person, group, OU, and custom entries
- Filter entries by objectClass
- Convert entries to/from JSON and dict
- Work with Entry models

**Key Functions**:
- `build_person_entries()` - Create person entries
- `build_group_entries()` - Create group entries
- `build_organizational_unit()` - Create OU entries
- `filter_entries_by_objectclass()` - Filter by objectClass
- `convert_entries_json_dict()` - Format conversions

### 03_validation_analysis.py - Validation & Analytics
**Demonstrates**: `validate_entries()`, `analyze()`

Ensure data quality:
- Validate entries against RFC 2849 rules
- Generate comprehensive statistics
- Create validation pipelines
- Filter and analyze by objectClass

**Key Functions**:
- `validate_entries()` - RFC validation
- `analyze_entries()` - Generate statistics
- `railway_validation_pipeline()` - Validation chains
- `validate_and_filter_valid_entries()` - Filter valid entries

### 04_server_migration.py - Server-Specific Operations
**Demonstrates**: `migrate()`, server_type parameter, quirks handling

Handle server differences:
- Parse with server-specific quirks (OID, OUD, OpenLDAP, RFC)
- Migrate between different LDAP servers
- Server-agnostic migration pipeline
- Compare server parsing behavior

**Key Functions**:
- `parse_with_server_quirks()` - Server-specific parsing
- `migrate_between_servers()` - Full migration workflow
- `migrate_openldap_to_oud()` - OpenLDAP → OUD migration
- `migrate_to_rfc_compliant()` - Normalize to RFC format

### 05_schema_operations.py - Schema Building & Validation
**Demonstrates**: SchemaBuilder, SchemaValidator

Work with LDAP schemas:
- Build custom schema definitions
- Use standard schemas (person, group)
- Validate entries against schemas
- Schema-driven entry creation

**Key Functions**:
- `build_basic_schema()` - Custom schema definition
- `build_standard_person_schema()` - Standard person schema
- `validate_entries_with_schema()` - Schema validation
- `schema_building_pipeline()` - End-to-end schema workflow

### 06_acl_processing.py - ACL Operations
**Demonstrates**: AclService, ACL extraction and processing

Process access control lists:
- Extract ACLs from LDIF entries
- Create ACL rules (composite, permission, subject)
- Evaluate ACL rules
- Filter entries with ACLs

**Key Functions**:
- `extract_acls_from_entry()` - Extract ACL information
- `create_acl_rules()` - Build ACL rules
- `parse_and_evaluate_acls()` - Parse and evaluate
- `filter_entries_with_acls()` - Find ACL-enabled entries

### 07_advanced_processing.py - Processors & Utilities
**Demonstrates**: FlextProcessors, utility functions

Advanced processing capabilities:
- Batch processing with FlextProcessors
- Parallel processing for performance
- DN, text, time, validation utilities
- Encoding and file utilities

**Key Functions**:
- `basic_batch_processing()` - Batch operations
- `parallel_processing()` - Parallel execution
- `use_dn_utilities()` - DN parsing and validation
- `use_validation_utilities()` - Validation helpers
- `access_all_utilities()` - Complete utility access

### 08_complete_workflow.py - Real-World Integration
**Demonstrates**: Complete API integration, production patterns

Production-ready workflows:
- End-to-end LDIF processing pipelines
- Multi-step validation and transformation
- Error handling and recovery
- Access to all namespace classes (Models, Constants, Types, Protocols, Exceptions, Mixins, Utilities)

**Key Functions**:
- `complete_ldif_processing_workflow()` - Full pipeline
- `server_migration_workflow()` - Migration with validation
- `schema_driven_workflow()` - Schema-first approach
- `batch_processing_workflow()` - Large-scale processing
- `access_all_namespace_classes()` - Complete API surface
- `error_handling_and_recovery()` - Error patterns

## 🚀 Usage Patterns

All examples follow library-only patterns:

```python
from flext_ldif import FlextLdif

# Initialize API
api = FlextLdif()

# Use functionality
result = api.parse("dn: cn=test,dc=example,dc=com\ncn: test\n")

if result.is_success:
    entries = result.unwrap()
    # Process entries
else:
    error = result.error
    # Handle error
```

## 📖 Learning Path

**Beginners**: Start with 01 → 02 → 03
- Learn core parsing, writing, and validation

**Intermediate**: Continue with 04 → 05 → 06
- Master server migration, schemas, and ACLs

**Advanced**: Complete with 07 → 08
- Explore processors, utilities, and integration patterns

## 🎓 Example Features

### ✅ What These Examples Are
- **Library demonstrations** - Pure library API usage
- **Reusable patterns** - Copy-paste friendly code
- **Complete coverage** - All FlextLdif functionality
- **Production-ready** - FlextResult error handling

### ❌ What These Examples Are NOT
- **CLI applications** - No command-line interfaces
- **Standalone scripts** - No `if __name__ == "__main__"`
- **Interactive tools** - No user input prompts
- **Over-engineered** - Clean, focused demonstrations

## 📝 Sample LDIF Files

- `sample_basic.ldif` - Basic person entries
- `sample_complex.ldif` - Complex multi-entry LDIF
- `sample_invalid.ldif` - Invalid LDIF for testing
- `output_basic.ldif` - Generated output (from examples)

## 🔍 Finding Functionality

Looking for specific features? Use this quick reference:

- **Parsing**: Example 01, 04
- **Writing**: Example 01, 02
- **Validation**: Example 03, 05
- **Filtering**: Example 02, 03
- **Migration**: Example 04
- **Schemas**: Example 05
- **ACLs**: Example 06
- **Batch Processing**: Example 07
- **Utilities**: Example 07
- **Integration**: Example 08

## 🛠️ API Surface Coverage

### Core Operations (Example 01)
- `api.parse()` - Parse LDIF
- `api.write()` - Write LDIF

### Entry Operations (Example 02)
- `api.EntryBuilder` - Build entries
- `api.filter_by_objectclass()` - Filter entries
- `api.filter_persons()` - Filter persons
- `api.models.Entry` - Entry model

### Validation & Analysis (Example 03)
- `api.validate_entries()` - Validate entries
- `api.analyze()` - Generate statistics

### Server Operations (Example 04)
- `api.parse(server_type=...)` - Server-specific parsing
- `api.migrate()` - Server migration

### Schema Operations (Example 05)
- `api.SchemaBuilder` - Build schemas
- `api.SchemaValidator` - Validate against schemas

### ACL Operations (Example 06)
- `api.AclService` - ACL processing

### Advanced Operations (Example 07)
- `api.processors` - Batch/parallel processing
- `api.utilities` - Helper functions

### Namespace Access (Example 08)
- `api.models` - Domain models
- `api.config` - Configuration
- `api.constants` - Constants
- `api.types` - Type definitions
- `api.protocols` - Protocol definitions
- `api.exceptions` - Exception factory
- `api.mixins` - Reusable mixins
- `api.utilities` - Utility functions

## 💡 Tips

1. **Always use FlextResult** - Check `is_success` before `unwrap()`
2. **Access through API** - Use `api.*` properties, not direct imports
3. **Railway-oriented** - Chain operations with early returns on failure
4. **Type hints** - Examples show proper typing patterns

## 🤝 Contributing

When adding examples:
- Use FlextLdif (api.py) exclusively
- No CLI patterns (main, print, argparse)
- Include FlextResult error handling
- Demonstrate specific functionality
- Add clear docstrings

---

**FLEXT-LDIF** - RFC-compliant LDIF processing for the FLEXT ecosystem
