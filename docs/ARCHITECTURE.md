# 🏗️ FLEXT LDIF Architecture

## Overview

FLEXT LDIF follows **Clean Architecture** and **Domain-Driven Design** principles, built on the **flext-core** foundation. This document describes the architectural decisions, patterns, and structure.

## 🎯 Architectural Principles

### 1. **Clean Architecture Layers**

```
┌─────────────────────────────────────────────────────────────┐
│                    🌐 Interface Layer                       │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │            📊 Application Layer                         │ │
│  │  ┌─────────────────────────────────────────────────────┐ │ │
│  │  │              🎯 Domain Layer                        │ │ │
│  │  │                                                     │ │ │
│  │  │  • Entities (FlextLdifEntry, FlextLdifRecord)      │ │ │
│  │  │  • Value Objects (FlextLdifDistinguishedName)      │ │ │
│  │  │  • Aggregates (FlextLdifDocument)                  │ │ │
│  │  │  • Domain Events                                   │ │ │
│  │  │  • Specifications                                  │ │ │
│  │  │                                                     │ │ │
│  │  └─────────────────────────────────────────────────────┘ │ │
│  │                                                           │ │
│  │  • Processors (FlextLdifProcessor)                       │ │
│  │  • Services & Use Cases                                  │ │
│  │                                                           │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  • API Models (FlextLdifEntry in models.py)                  │
│  • Parsers, Writers, Validators                              │
│  • Simple Functions (parse_ldif, write_ldif)                 │
│                                                               │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│               🔧 Infrastructure Layer                       │
│                                                             │
│  • Dependency Injection Container                          │
│  • External Library Adapters                               │
│  • I/O Operations                                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2. **Dependency Direction**

- **Domain Layer**: Zero dependencies on external layers
- **Application Layer**: Depends only on Domain
- **Interface Layer**: Depends on Application and Domain
- **Infrastructure Layer**: Implements interfaces defined in Domain

### 3. **flext-core Foundation**

All domain objects inherit from flext-core base classes:

```python
# Domain Entities
class FlextLdifEntry(FlextEntity):
    def validate_domain_rules(self) -> None: ...

# Value Objects
class FlextLdifDistinguishedName(FlextValueObject):
    def __eq__(self, other) -> bool: ...

# Aggregate Roots
class FlextLdifDocument(FlextAggregateRoot):
    def add_domain_event(self, event: FlextDomainEvent) -> None: ...

# Service Results
def parse_ldif(content: str) -> FlextResult[list[FlextLdifEntry]]: ...
```

## 📂 Directory Structure

```
src/flext_ldif/
├── 🎯 domain/                    # Core business logic (pure)
│   ├── entities.py              # Business entities with identity
│   ├── values.py                # Immutable value objects
│   ├── aggregates.py            # Aggregate roots & consistency boundaries
│   ├── events.py                # Domain events for integration
│   ├── specifications.py        # Business rules & validation logic
│   └── interfaces.py            # Domain service interfaces
│
├── 🔧 infrastructure/           # External concerns
│   └── di_container.py          # Dependency injection setup
│
├── 📊 Application Layer Files
│   ├── processor.py             # Application services & use cases
│   └── adapters/                # Interface adapters
│       └── ldif_adapter.py      # External format adapters
│
├── 🌐 Interface Layer Files
│   ├── __init__.py              # Public API exports
│   ├── models.py                # API data models
│   ├── parser.py                # LDIF parsing interface
│   ├── writer.py                # LDIF writing interface
│   ├── validator.py             # Validation interface
│   └── utils.py                 # Utility functions
│
└── 🛠️ Supporting Files
    ├── config.py                # Configuration management
    ├── exceptions.py            # Exception definitions
    ├── types.py                 # Type definitions
    └── _deprecated.py           # Deprecation warnings
```

## 🎯 Domain Layer Design

### Entities

**FlextLdifEntry** - Core business entity representing an LDIF entry:

```python
class FlextLdifEntry(FlextEntity):
    dn: FlextLdifDistinguishedName
    attributes: FlextLdifAttributes
    change_type: str | None
    
    def get_object_classes(self) -> list[str]:
        """Business logic for object class extraction"""
    
    def validate_domain_rules(self) -> None:
        """Domain-specific validation rules"""
```

**FlextLdifRecord** - Entity representing a collection of entries:

```python
class FlextLdifRecord(FlextEntity):
    entries: list[FlextLdifEntry]
    ldif_version: int
    encoding: str
    
    def validate_domain_rules(self) -> None:
        """Ensure record consistency and business rules"""
```

### Value Objects

**FlextLdifDistinguishedName** - Immutable DN representation:

```python
class FlextLdifDistinguishedName(FlextValueObject):
    value: str
    
    def get_rdn(self) -> str:
        """Extract relative distinguished name"""
    
    def get_parent_dn(self) -> FlextLdifDistinguishedName | None:
        """Navigate DN hierarchy"""
    
    def is_child_of(self, parent: FlextLdifDistinguishedName) -> bool:
        """Check hierarchical relationships"""
```

**FlextLdifAttributes** - Immutable attribute collection:

```python
class FlextLdifAttributes(FlextValueObject):
    attributes: dict[str, list[str]]
    
    def add_value(self, name: str, value: str) -> FlextLdifAttributes:
        """Return new instance with added value (immutable)"""
    
    def get_values(self, name: str) -> list[str]:
        """Retrieve attribute values"""
```

### Aggregates

**FlextLdifDocument** - Aggregate root for LDIF document processing:

```python
class FlextLdifDocument(FlextAggregateRoot):
    content: LDIFContent
    entries: list[FlextLdifEntry]
    is_parsed: bool
    is_validated: bool
    
    def parse_content(self, entries: list[FlextLdifEntry]) -> None:
        """Parse content and raise domain events"""
        
    def complete_processing(self, success: bool, errors: list[str]) -> None:
        """Complete processing and raise completion event"""
```

### Domain Events

```python
class FlextLdifDocumentParsed(FlextDomainEvent):
    aggregate_id: str
    entry_count: int
    content_length: int

class FlextLdifProcessingCompleted(FlextDomainEvent):
    aggregate_id: str
    entry_count: int
    success: bool
    errors: list[str]
```

### Specifications

Business rules encoded as specifications:

```python
class FlextLdifPersonSpecification(FlextSpecification[FlextLdifEntry]):
    """Specification for person entries"""
    
    def is_satisfied_by(self, entry: FlextLdifEntry) -> bool:
        person_classes = {"person", "organizationalPerson", "inetOrgPerson"}
        return any(oc in person_classes for oc in entry.get_object_classes())

class FlextLdifValidSpecification(FlextSpecification[FlextLdifEntry]):
    """Specification for valid LDIF entries"""
    
    def is_satisfied_by(self, entry: FlextLdifEntry) -> bool:
        try:
            entry.validate_domain_rules()
            return True
        except Exception:
            return False
```

## 📊 Application Layer Design

### FlextLdifProcessor

Main application service orchestrating LDIF operations:

```python
class FlextLdifProcessor:
    def __init__(self):
        self._parser = FlextLdifParser()
        self._validator = FlextLdifValidator()
        self._person_spec = FlextLdifPersonSpecification()
        self._valid_spec = FlextLdifValidSpecification()
    
    def parse_ldif_content(self, content: str) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content using domain objects"""
    
    def validate_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate entries using domain specifications"""
    
    def filter_entries(self, entries: list[FlextLdifEntry], 
                      spec: FlextSpecification[FlextLdifEntry]) -> list[FlextLdifEntry]:
        """Filter entries using specification pattern"""
```

## 🌐 Interface Layer Design

### Simple API Functions

Facade functions providing simple interface:

```python
def parse_ldif(content: str | LDIFContent) -> list[FlextLdifEntry]:
    """Simple parsing function - internally uses FlextLdifProcessor"""
    
def write_ldif(entries: list[FlextLdifEntry], output_path: str | None = None) -> str:
    """Simple writing function - internally uses FlextLdifWriter"""
    
def validate_ldif(content: str | LDIFContent) -> bool:
    """Simple validation function - internally uses FlextLdifValidator"""
```

### API Models

**FlextLdifEntry** in `models.py` - Public API model:

```python
class FlextLdifEntry(FlextValueObject):
    """Public API model for LDIF entries"""
    dn: FlextLdifDistinguishedName
    attributes: FlextLdifAttributes
    
    # Convenience methods delegating to domain objects
    def get_object_classes(self) -> list[str]:
        return self.attributes.get_values("objectClass")
    
    def to_ldif(self) -> str:
        """Convert to LDIF string format"""
```

### Processing Classes

**FlextLdifParser** - Interface for LDIF parsing:

```python
class FlextLdifParser:
    def parse_ldif_content(self, content: str) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content with error handling"""
    
    def parse_ldif_file(self, file_path: Path) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF file with error handling"""
```

**FlextLdifWriter** - Interface for LDIF writing:

```python
class FlextLdifWriter:
    def write_entries_to_file(self, file_path: Path, 
                             entries: list[dict]) -> FlextResult[str]:
        """Write entries to file with error handling"""
    
    def write_flext_entries_to_file(self, file_path: Path,
                                   entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write FlextLdifEntry objects to file"""
```

## 🔧 Infrastructure Layer Design

### Dependency Injection

Container providing domain services:

```python
def flext_ldif_get_domain_entity() -> type[FlextEntity]:
    """Get domain entity base class"""
    return FlextLdifEntry

def flext_ldif_get_domain_value_object() -> type[FlextValueObject]:
    """Get domain value object base class"""
    return FlextLdifDistinguishedName

def flext_ldif_get_service_result() -> type[FlextResult]:
    """Get service result wrapper"""
    return FlextResult
```

## 🎯 Design Patterns Used

### 1. **Repository Pattern**
- Abstract data access through domain interfaces
- Concrete implementations in infrastructure layer

### 2. **Specification Pattern**
- Encapsulate business rules as specifications
- Composable and reusable validation logic

### 3. **Factory Pattern**
- `FlextLdifEntry.from_ldif_block()` - Create entries from LDIF text
- `FlextLdifDistinguishedName.model_validate()` - Value object creation

### 4. **Strategy Pattern**
- Different parsing strategies for various LDIF formats
- Pluggable validation strategies

### 5. **Observer Pattern**
- Domain events for integration and side effects
- Event-driven architecture support

### 6. **Facade Pattern**
- Simple API functions (`parse_ldif`, `write_ldif`) hiding complexity
- Clean interface for common operations

### 7. **Value Object Pattern**
- Immutable domain values (DN, Attributes)
- Equality based on value, not identity

## 🚀 Extension Points

### Adding New Domain Entities

1. Create entity in `domain/entities.py`:
```python
class FlextLdifSchema(FlextEntity):
    def validate_domain_rules(self) -> None: ...
```

2. Add to exports in `__init__.py`
3. Create corresponding API model in `models.py` if needed

### Adding New Specifications

1. Create specification in `domain/specifications.py`:
```python
class FlextLdifGroupSpecification(FlextSpecification[FlextLdifEntry]):
    def is_satisfied_by(self, entry: FlextLdifEntry) -> bool: ...
```

2. Register in processor or DI container

### Adding New Domain Events

1. Create event in `domain/events.py`:
```python
class FlextLdifSchemaValidated(FlextDomainEvent):
    schema_name: str
    validation_result: bool
```

2. Raise from appropriate aggregate methods

## 🔒 Quality Assurance

### Type Safety
- **MyPy strict mode**: All code type-checked
- **Pydantic models**: Runtime validation
- **Generic types**: Parameterized specifications and results

### Testing Strategy
- **Unit tests**: Each domain object and service
- **Integration tests**: Cross-layer interactions
- **Property-based tests**: Domain invariants
- **Contract tests**: Interface compliance

### Code Quality
- **Ruff linting**: Comprehensive static analysis
- **PEP compliance**: Python style standards
- **Architecture tests**: Dependency direction validation
- **Documentation coverage**: All public APIs documented

## 📈 Performance Considerations

### Memory Efficiency
- **Immutable value objects**: Safe sharing across contexts
- **Lazy loading**: Parse only when needed
- **Efficient collections**: Optimized data structures

### Processing Efficiency
- **Batch operations**: Process multiple entries together
- **Streaming support**: Handle large LDIF files
- **Caching**: Memoize expensive operations

### Scalability
- **Stateless design**: Easy horizontal scaling
- **Event-driven**: Asynchronous processing support
- **Clean interfaces**: Easy to add caching layers

---

This architecture ensures **maintainability**, **testability**, **extensibility**, and **performance** while following industry best practices and flext-core patterns.