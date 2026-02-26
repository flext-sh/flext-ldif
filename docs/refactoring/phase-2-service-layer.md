# Phase 2: Proper Service Layer Implementation

<!-- TOC START -->

- [Overview](#overview)
- [Current Architecture Problem](#current-architecture-problem)
  - [As Is](#as-is)
- [Target Architecture](#target-architecture)
  - [To Be](#to-be)
- [Implementation Plan](#implementation-plan)
  - [Phase 2.A: Design Service Layer Architecture](#phase-2a-design-service-layer-architecture)
  - [Phase 2.B: Create FlextLdiifSchema](#phase-2b-create-flextldiifschema)
  - [Phase 2.C: Create FlextLdifAcl](#phase-2c-create-flextldifacl)
  - [Phase 2.D: Create EntryTransformationService](#phase-2d-create-entrytransformationservice)
  - [Phase 2.E: Create ServerConfig Abstraction](#phase-2e-create-serverconfig-abstraction)
  - [Phase 2.F: Integrate Services into Servers](#phase-2f-integrate-services-into-servers)
- [Service Composition Pattern](#service-composition-pattern)
- [Migration Path](#migration-path)
  - [Step 1: Create ServiceConfig abstraction](#step-1-create-serviceconfig-abstraction)
  - [Step 2: Create services with new functionality](#step-2-create-services-with-new-functionality)
  - [Step 3: Integrate services gradually](#step-3-integrate-services-gradually)
  - [Step 4: Deprecate nested classes](#step-4-deprecate-nested-classes)
- [Success Criteria](#success-criteria)
- [Related Documentation](#related-documentation)

<!-- TOC END -->

## Overview

Phase 2 refactors the flext-ldif architecture to create a proper service layer where business logic is centralized in services, and servers become configuration providers.

**Current State**: Servers contain nested classes (Schema, Acl, Entry) with inline parsing/writing/transformation logic.

**Target State**: Services handle all business logic; servers provide configuration and delegate to services.

---

## Current Architecture Problem

### As Is

```
FlextLdifServersRfc
├── Schema (nested class)
│   ├── _parse_attribute()
│   ├── _parse_objectclass()
│   ├── _write_attribute()
│   └── _write_objectclass()
├── Acl (nested class)
│   ├── _parse_acl()
│   ├── _write_acl()
│   └── can_handle_*()
└── Entry (nested class)
    ├── _parse_entry()
    ├── _write_entry()
    └── can_handle_*()

FlextLdifServersOud (extends FlextLdifServersRfc)
├── Schema (overrides parent)
│   ├── _parse_attribute() - OUD-specific logic
│   └── ...
├── Acl (overrides parent)
│   └── _parse_acl() - OUD-specific logic
└── Entry (overrides parent)
    └── ...
```

**Issues**:

- Logic duplication across 12+ servers
- Hard to test service logic separately from servers
- Services in `/services` directory are underutilized (3 usages)
- Each server reimplements similar logic with minor variations

---

## Target Architecture

### To Be

```
FlextLdifSchemaService
├── parse_attribute() - uses RFC parser + server config
├── parse_objectclass() - uses RFC parser + server config
├── validate_attribute()
├── validate_objectclass()
├── transform_attribute_for_write()
├── transform_objectclass_for_write()
└── write_attribute() / write_objectclass()

FlextLdifAclService
├── parse_acl() - uses RFC ACL logic + server config
├── write_acl() - formats for specific server
├── validate_acl()
└── transform_acl_for_write()

FlextLdifEntryService
├── parse_entry() - uses RFC entry parsing + server config
├── write_entry()
├── validate_entry()
└── transform_entry_for_write()

FlextLdifServerSettings (replaces nested Constants)
├── schema_patterns
├── acl_patterns
├── entry_patterns
├── transformation_rules
└── validation_rules

FlextLdifServersRfc (uses services)
├── config: FlextLdifServerSettings
├── schema_service: FlextLdifSchemaService
├── acl_service: FlextLdifAclService
├── entry_service: FlextLdifEntryService
└── delegate to services for all operations

FlextLdifServersOud (extends FlextLdifServersRfc)
├── config: OUD-specific FlextLdifServerSettings
└── services with OUD configuration
```

**Benefits**:

- ✅ Single source of truth for each service
- ✅ Services are testable in isolation
- ✅ Servers become configuration providers
- ✅ Easy to add new server types
- ✅ Better separation of concerns
- ✅ Cleaner code with less duplication

---

## Implementation Plan

### Phase 2.A: Design Service Layer Architecture

- [x] Analyze current service/server relationship
- [ ] Document service interfaces
- [ ] Create ServerConfig abstraction
- [ ] Design service composition pattern

### Phase 2.B: Create FlextLdiifSchema

**Goal**: Centralize all schema parsing/validation/writing logic

**Key Methods**:

- `parse_attribute(definition: str, config: ServerConfig) -> SchemaAttribute`
- `parse_objectclass(definition: str, config: ServerConfig) -> SchemaObjectClass`
- `validate_attribute(attr: SchemaAttribute, config: ServerConfig) -> ValidationResult`
- `validate_objectclass(oc: SchemaObjectClass, config: ServerConfig) -> ValidationResult`
- `transform_attribute_for_write(attr: SchemaAttribute, config: ServerConfig) -> SchemaAttribute`
- `transform_objectclass_for_write(oc: SchemaObjectClass, config: ServerConfig) -> SchemaObjectClass`
- `write_attribute(attr: SchemaAttribute, config: ServerConfig) -> str`
- `write_objectclass(oc: SchemaObjectClass, config: ServerConfig) -> str`

**Leverage Existing**:

- `FlextLdifParser` - LDIF parsing
- `FlextLdifWriter` - LDIF writing
- `FlextLdifUtilitiesSchema` - Schema utilities

### Phase 2.C: Create FlextLdifAcl

**Goal**: Centralize all ACL parsing/validation/writing logic

**Key Methods**:

- `parse_acl(acl_line: str, config: ServerConfig) -> Acl`
- `can_handle_acl(acl_line: str, config: ServerConfig) -> bool`
- `validate_acl(acl: Acl, config: ServerConfig) -> ValidationResult`
- `transform_acl_for_write(acl: Acl, config: ServerConfig) -> Acl`
- `write_acl(acl: Acl, config: ServerConfig) -> str`

**Leverage Existing**:

- `FlextLdifAcl` - ACL utilities
- `FlextLdifUtilitiesSchema.normalize_attribute_name()` - Normalization

### Phase 2.D: Create EntryTransformationService

**Goal**: Centralize all entry parsing/validation/writing logic

**Key Methods**:

- `parse_entry(entry_dn: str, attributes: dict, config: ServerConfig) -> Entry`
- `can_handle_entry(entry: Entry, config: ServerConfig) -> bool`
- `validate_entry(entry: Entry, config: ServerConfig) -> ValidationResult`
- `transform_entry_for_write(entry: Entry, config: ServerConfig) -> Entry`
- `write_entry(entry: Entry, config: ServerConfig) -> str`

**Leverage Existing**:

- `FlextLdifEntry` - Entry utilities
- `FlextLdifWriter` - LDIF writing

### Phase 2.E: Create ServerConfig Abstraction

**Goal**: Extract server configuration from nested Constants classes

**Properties**:

- `server_type: str` (e.g., "oud", "oid")
- `server_priority: int`
- `schema_patterns: dict` - Regex patterns for schema
- `acl_patterns: dict` - Regex patterns for ACL
- `entry_patterns: dict` - Regex patterns for entries
- `transformation_rules: dict` - Transformation rules per server
- `validation_rules: dict` - Validation rules per server
- `boolean_attributes: set[str]` - Server-specific boolean attributes
- `matching_rule_replacements: dict` - Matching rule mappings
- `constant mappings: dict` - Server-specific constants

### Phase 2.F: Integrate Services into Servers

**Goal**: Update servers to use services instead of nested classes

**Changes**:

```python
# Before
class FlextLdifServersOud(FlextLdifServersRfc):
    class Schema(FlextLdifServersRfc.Schema):
        def _parse_attribute(self, attr_def):
            # 100+ lines of OUD-specific logic

# After
class FlextLdifServersOud(FlextLdifServersRfc):
    def __init__(self):
        super().__init__()
        self.config = OudServerConfig()  # Configuration
        self.schema_service = FlextLdifSchemaService(self.config)
        self.acl_service = FlextLdifAclService(self.config)
        self.entry_service = FlextLdifEntryService(self.config)

    def parse_attribute(self, attr_def):
        return self.schema_service.parse_attribute(attr_def)
```

---

## Service Composition Pattern

```python
class FlextLdifServiceComposer:
    """Composes services for a given server type."""

    @classmethod
    def create_services(cls, config: ServerConfig) -> Services:
        """Create and configure services for server."""
        return Services(
            schema=FlextLdifSchemaService(config),
            acl=FlextLdifAclService(config),
            entry=FlextLdifEntryService(config),
        )

# Usage in servers
services = FlextLdifServiceComposer.create_services(self.config)
attribute = services.schema.parse_attribute(attr_def)
```

---

## Migration Path

### Step 1: Create ServiceConfig abstraction

- Extract Constants from servers
- Create config classes for each server type
- Keep backward compatibility with Constants

### Step 2: Create services with new functionality

- FlextLdiifSchema
- FlextLdifAcl
- EntryTransformationService

### Step 3: Integrate services gradually

- Update RFC base server first
- Test thoroughly
- Roll out to other servers

### Step 4: Deprecate nested classes

- Move nested class logic to services
- Update all server implementations
- Remove nested classes

---

## Success Criteria

- [ ] All nested Schema, Acl, Entry classes moved to services
- [ ] Servers use ServiceComposer to get services
- [ ] Zero duplication of parsing/writing logic
- [ ] All tests pass with new architecture
- [ ] Services are independently testable
- [ ] Server-specific logic is in config, not code
- [ ] Documentation updated with new patterns

---

## Related Documentation

- Hook system patterns (_Documentation coming soon_)
- [RFC 2849](https://tools.ietf.org/html/rfc2849) - LDIF Format Specification
- [RFC 4512](https://tools.ietf.org/html/rfc4512) - LDAP Schema Specification
