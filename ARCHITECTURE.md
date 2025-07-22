# FLEXT LDIF - Architecture & Migration Guide

🏗️ **Clean Architecture Implementation**  
🔄 **Semantic Reorganization in Progress**

## Overview

FLEXT LDIF has been completely reorganized following **Clean Architecture** and **Domain-Driven Design** patterns, built on top of the `flext-core` foundation. This document outlines the new architecture and provides migration guidance for LDIF processing.

## Architecture Layers

### 🎯 Domain Layer (Pure Business Logic)

The domain layer contains pure business logic for LDIF processing with no external dependencies:

```
src/flext_ldif/domain/
├── aggregates.py      # LDIFDocument (aggregate root)
├── entities.py        # LDIFEntry, LDIFRecord
├── events.py          # Domain events (LDIFDocumentParsed, etc.)
├── interfaces.py      # Abstract contracts (LDIFParser, LDIFValidator, etc.)
├── specifications.py  # Business rules (ValidLDIFSpecification, etc.)
└── values.py          # Immutable values (DistinguishedName, LDIFAttributes, etc.)
```

#### Key Domain Patterns

- **Aggregates**: Document processing boundaries (LDIFDocument)
- **Entities**: Objects with identity (LDIFEntry, LDIFRecord)
- **Value Objects**: Immutable concepts (DistinguishedName, LDIFAttributes)
- **Events**: Processing occurrences (LDIFDocumentParsed)
- **Specifications**: Reusable validation rules
- **Interfaces**: Contracts for infrastructure

### 🎯 Application Layer (Use Cases)

*To be implemented* - LDIF processing services, commands, and queries.

```
src/flext_ldif/application/
├── services/          # LDIFProcessingService, LDIFTransformationService
├── commands/          # ProcessLDIFCommand, TransformLDIFCommand
├── queries/           # GetLDIFEntriesQuery, ValidateLDIFQuery
└── handlers/          # Event handlers
```

### 🎯 Infrastructure Layer (External Concerns)

*To be implemented* - Concrete implementations of LDIF processing.

```
src/flext_ldif/infrastructure/
├── parsers/           # RFC 2849 compliant LDIF parsers
├── writers/           # LDIF output formatters
├── validators/        # Schema validators
└── transformers/      # Data transformation engines
```

### 🎯 Interface Layer (Adapters)

*To be implemented* - Controllers and adapters for LDIF operations.

```
src/flext_ldif/interfaces/
├── controllers/       # LDIF processing controllers
├── presenters/        # Output formatters
└── mappers/           # Data transformation
```

## Foundation Integration

FLEXT LDIF is built on `flext-core` foundation patterns:

### Core Dependencies

```python
from flext_core.foundation import (
    AbstractEntity,
    AbstractValueObject,
    SpecificationPattern,
)
from flext_core.domain.pydantic_base import (
    DomainAggregateRoot,
    DomainEntity,
    DomainEvent,
    DomainValueObject,
)
from flext_core.domain.types import ServiceResult
```

### Key Patterns Used

- **ServiceResult**: Type-safe error handling for LDIF operations
- **Specification Pattern**: Composable LDIF validation rules
- **Domain Events**: Processing lifecycle notifications
- **Aggregate Pattern**: Document consistency boundaries

## Migration Guide

### 🚨 Deprecation Strategy

Old LDIF processing code continues to work with deprecation warnings:

```python
# ❌ DEPRECATED (shows warning)
from flext_ldif import LDIFProcessor, LDIFValidator

# ✅ NEW APPROACH (recommended)
from flext_ldif.domain.aggregates import LDIFDocument
from flext_ldif.domain.interfaces import LDIFParser, LDIFValidator
from flext_ldif.domain.values import LDIFContent, DistinguishedName
```

### Migration Steps

1. **Update Imports** - Use new semantic structure
2. **Adopt ServiceResult** - Replace exception handling with ServiceResult
3. **Use Value Objects** - Replace primitives with typed value objects
4. **Apply Specifications** - Use business rules for validation
5. **Use Aggregates** - Process LDIF documents as aggregates

### Example Migration

#### Before (Deprecated)
```python
from flext_ldif import LDIFProcessor, LDIFValidator

processor = LDIFProcessor()
validator = LDIFValidator()

try:
    entries = processor.parse_ldif_file("data.ldif")
    if validator.validate_entries(entries):
        print(f"Processed {len(entries)} entries")
except LDIFError as e:
    print(f"Error: {e}")
```

#### After (New Architecture)
```python
from flext_ldif.domain.aggregates import LDIFDocument
from flext_ldif.domain.interfaces import LDIFParser
from flext_ldif.domain.specifications import ValidLDIFSpecification
from flext_ldif.domain.values import LDIFContent

# Use dependency injection (configured elsewhere)
parser: LDIFParser = get_ldif_parser()

# Create aggregate root
document = LDIFDocument(content="", entries=[])

# Read and parse content
with open("data.ldif", "r") as f:
    content = LDIFContent(f.read())

# ServiceResult pattern
parse_result = parser.parse_content(content)
if parse_result.is_success:
    entries = parse_result.data
    
    # Update aggregate
    document.parse_content(content)
    for entry in entries:
        document.add_entry(entry)
    
    # Apply business rules
    spec = ValidLDIFSpecification()
    valid_entries = [e for e in entries if spec.is_satisfied_by(e)]
    
    # Validate and complete processing
    if document.validate_document():
        document.complete_processing()
        print(f"Processed {document.get_entry_count()} entries")
```

## Value Objects Reference

### DistinguishedName
```python
from flext_ldif.domain.values import DistinguishedName

dn = DistinguishedName(value="cn=john,ou=users,dc=example,dc=com")
print(dn.get_rdn())  # "cn=john"
print(dn.get_parent_dn())  # "ou=users,dc=example,dc=com"
print(dn.get_depth())  # 3
```

### LDIFAttributes
```python
from flext_ldif.domain.values import LDIFAttributes

attrs = LDIFAttributes(attributes={
    "cn": ["John Doe"],
    "mail": ["john@example.com"],
    "objectClass": ["person", "inetOrgPerson"]
})

email = attrs.get_single_value("mail")  # "john@example.com"
classes = attrs.get_values("objectClass")  # ["person", "inetOrgPerson"]
total_values = attrs.get_total_values()  # 4
```

### LDIFChangeType
```python
from flext_ldif.domain.values import LDIFChangeType

change_type = LDIFChangeType(value="modify")
print(change_type.is_modify())  # True
print(change_type.is_add())     # False
```

### LDIFVersion & LDIFEncoding
```python
from flext_ldif.domain.values import LDIFVersion, LDIFEncoding

version = LDIFVersion(value=1)
encoding = LDIFEncoding(value="utf-8")

print(version.is_current())  # True
print(encoding.is_utf8())    # True
```

## Specifications Reference

### LDIF Validation Rules
```python
from flext_ldif.domain.specifications import (
    ValidLDIFSpecification,
    PersonLDIFSpecification,
    GroupLDIFSpecification,
    RequiredAttributesSpecification
)

# Basic validation
valid_spec = ValidLDIFSpecification()
assert valid_spec.is_satisfied_by(entry)

# Type-specific validation
person_spec = PersonLDIFSpecification()
group_spec = GroupLDIFSpecification()

# Attribute requirements
required_spec = RequiredAttributesSpecification(["cn", "sn"])
assert required_spec.is_satisfied_by(person_entry)
```

### Operation-based Specifications
```python
from flext_ldif.domain.specifications import (
    AddOperationSpecification,
    ModifyOperationSpecification,
    DeleteOperationSpecification
)

add_spec = AddOperationSpecification()
modify_spec = ModifyOperationSpecification()

# Filter entries by operation type
add_entries = [e for e in entries if add_spec.is_satisfied_by(e)]
modify_entries = [e for e in entries if modify_spec.is_satisfied_by(e)]
```

## Events Reference

### Document Processing Events
```python
from flext_ldif.domain.events import (
    LDIFDocumentParsed,
    LDIFEntryValidated,
    LDIFProcessingCompleted
)

# Events are raised automatically by aggregates
document = LDIFDocument(content="", entries=[])

# This raises LDIFDocumentParsed event
document.parse_content(content)

# This raises LDIFProcessingCompleted event
document.complete_processing()
```

## Aggregate Reference

### LDIFDocument Aggregate
```python
from flext_ldif.domain.aggregates import LDIFDocument
from flext_ldif.domain.entities import LDIFEntry

# Create document aggregate
document = LDIFDocument(content="", entries=[])

# Add entries
for entry_data in parsed_entries:
    entry = LDIFEntry(
        dn=DistinguishedName(value=entry_data["dn"]),
        attributes=LDIFAttributes(attributes=entry_data["attrs"])
    )
    document.add_entry(entry)

# Validate and process
if document.validate_document():
    # Get entries by type
    person_entries = document.get_entries_by_objectclass("person")
    group_entries = document.get_entries_by_objectclass("groupOfNames")
    
    # Complete processing
    document.complete_processing()
```

## Quality Standards

- **Zero Tolerance**: All quality gates must pass
- **Type Safety**: 100% MyPy compliance in strict mode
- **Test Coverage**: 90%+ coverage requirement
- **Clean Architecture**: Strict dependency rules enforced
- **RFC 2849 Compliance**: Full LDIF standard compliance

## Best Practices

1. **Use Aggregates** - Process LDIF documents as aggregate roots
2. **Apply Specifications** - Validate using composable business rules
3. **Handle Results** - Use ServiceResult pattern for error handling
4. **Immutable Values** - Use value objects for LDIF concepts
5. **Raise Events** - Track processing lifecycle with domain events

## Testing Strategy

```python
# Domain layer tests - pure unit tests
def test_ldif_attributes_immutability():
    attrs = LDIFAttributes(attributes={"cn": ["test"]})
    new_attrs = attrs.add_value("mail", "test@example.com")
    assert attrs != new_attrs  # Original unchanged

# Specification tests
def test_person_ldif_specification():
    spec = PersonLDIFSpecification()
    assert spec.is_satisfied_by(person_entry)
    assert not spec.is_satisfied_by(group_entry)

# Aggregate tests
def test_ldif_document_processing():
    document = LDIFDocument(content="", entries=[])
    document.add_entry(valid_entry)
    assert document.validate_document()
    assert document.get_entry_count() == 1
```

## Performance Considerations

- **Streaming Support**: Large LDIF files processed in chunks
- **Memory Management**: Configurable memory limits
- **Lazy Validation**: Validation on demand
- **Event Batching**: Batch processing for large documents

## Security Considerations

- **Input Validation**: All LDIF input is validated
- **DN Injection**: Distinguished names are properly validated
- **Encoding Safety**: Character encoding is enforced
- **Memory Limits**: Protection against memory exhaustion

## LDIF Standard Compliance

- **RFC 2849**: Full compliance with LDIF specification
- **Line Folding**: Proper handling of long lines
- **Base64 Encoding**: Support for binary attributes
- **Change Records**: Support for modify, add, delete operations

---

**Status**: ✅ Domain layer complete, Application layer in progress  
**Migration**: Backward compatibility maintained with deprecation warnings  
**Quality**: Zero tolerance for lint/type/test failures  
**RFC Compliance**: Full LDIF 2849 standard support