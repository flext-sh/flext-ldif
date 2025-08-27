# 🏗️ FLEXT-LDIF Architecture Guide

**Version**: 0.9.0 | **Target**: 0.9.0
**Status**: Clean Architecture Implementation
**Integration**: FLEXT Ecosystem Compatible

Complete architectural documentation for FLEXT-LDIF enterprise LDIF processing library.

---

## 🎯 Architectural Vision

FLEXT-LDIF implements **Clean Architecture** with **Domain-Driven Design** principles, built on the **FLEXT ecosystem** foundation. The architecture prioritizes:

- **Business Logic Isolation**: Pure domain logic free from external dependencies
- **Testability**: Comprehensive testing at all architectural layers
- **Maintainability**: Clear separation of concerns and explicit dependencies
- **Extensibility**: Plugin points for ecosystem integration
- **Performance**: Enterprise-grade scalability and efficiency

---

## 🏛️ Clean Architecture Layers

### Current Architecture (v0.9.0)

```
┌─────────────────────────────────────────────────────────────────┐
│                    🌐 PRESENTATION LAYER                       │
│                                                                 │
│  cli.py                    # Command-line interface             │
│  __init__.py               # Public API exports                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                   📊 APPLICATION LAYER                         │
│                                                                 │
│  api.py                    # FlextLdifAPI - main service        │
│  models.py                 # API models and DTOs               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                     🎯 DOMAIN LAYER                            │
│                                                                 │
│  Domain Objects (in models.py):                                │
│  ├── FlextLdifEntry           # Main domain entity             │
│  ├── FlextLdifDistinguishedName # DN value object              │
│  ├── FlextLdifAttributes      # Attributes value object        │
│  └── Domain Rules & Validation                                 │
│                                                                 │
│  Business Logic:                                                │
│  ├── validate_domain_rules()  # Business rule validation       │
│  ├── get_object_classes()     # Domain operations              │
│  └── Specifications (planned) # Business rule encapsulation    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                  🔧 INFRASTRUCTURE LAYER                       │
│                                                                 │
│  services.py               # Domain services implementation     │
│  core.py                   # LDIF processing core              │
│  config.py                 # Configuration management          │
│  modernized_ldif.py        # Modern LDIF handling              │
│  exceptions.py             # Exception definitions             │
│  utils/                    # Utility modules                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Target Architecture (v1.0.0)

```
┌─────────────────────────────────────────────────────────────────┐
│                    🌐 PRESENTATION LAYER                       │
│                                                                 │
│  presentation/                                                  │
│  ├── cli/                  # Command-line interface            │
│  │   ├── __init__.py                                           │
│  │   ├── commands.py       # CLI command definitions           │
│  │   └── formatters.py     # Output formatting                 │
│  └── api/                  # REST API (future)                 │
│      ├── __init__.py                                           │
│      ├── routes.py         # API endpoints                     │
│      └── serializers.py    # Response serialization           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                   📊 APPLICATION LAYER                         │
│                                                                 │
│  application/                                                   │
│  ├── __init__.py                                               │
│  ├── api.py                # FlextLdifAPI - application service │
│  ├── handlers/             # Command/Query handlers (CQRS)     │
│  │   ├── __init__.py                                           │
│  │   ├── parse_handler.py  # Parse LDIF command handler        │
│  │   ├── validate_handler.py # Validate command handler        │
│  │   └── write_handler.py   # Write LDIF command handler       │
│  ├── queries/              # Query handlers                    │
│  │   ├── __init__.py                                           │
│  │   ├── entry_queries.py   # Entry query operations           │
│  │   └── stats_queries.py   # Statistics queries               │
│  └── dto/                  # Data Transfer Objects             │
│      ├── __init__.py                                           │
│      ├── entry_dto.py      # Entry DTOs                        │
│      └── request_dto.py     # Request/Response DTOs             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                     🎯 DOMAIN LAYER                            │
│                                                                 │
│  domain/                                                        │
│  ├── __init__.py                                               │
│  ├── entities/             # Domain entities with identity     │
│  │   ├── __init__.py                                           │
│  │   ├── ldif_entry.py     # FlextLdifEntry entity             │
│  │   └── ldif_document.py  # FlextLdifDocument aggregate       │
│  ├── values/               # Immutable value objects           │
│  │   ├── __init__.py                                           │
│  │   ├── distinguished_name.py # DN value object               │
│  │   ├── attributes.py     # Attributes value object           │
│  │   └── ldif_content.py   # Content value object              │
│  ├── aggregates/           # Aggregate roots                   │
│  │   ├── __init__.py                                           │
│  │   └── ldif_processing_aggregate.py # Processing aggregate   │
│  ├── events/               # Domain events                     │
│  │   ├── __init__.py                                           │
│  │   ├── entry_parsed.py   # Entry parsed event                │
│  │   ├── validation_completed.py # Validation event            │
│  │   └── processing_completed.py # Processing completed event  │
│  ├── specifications/       # Business rules                    │
│  │   ├── __init__.py                                           │
│  │   ├── person_spec.py    # Person entry specification        │
│  │   ├── valid_entry_spec.py # Valid entry specification       │
│  │   └── schema_compliance_spec.py # Schema compliance         │
│  └── interfaces/           # Domain service interfaces         │
│      ├── __init__.py                                           │
│      ├── parser_interface.py # Parser contract                 │
│      ├── validator_interface.py # Validator contract           │
│      └── repository_interface.py # Repository contract         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                  🔧 INFRASTRUCTURE LAYER                       │
│                                                                 │
│  infrastructure/                                                │
│  ├── __init__.py                                               │
│  ├── persistence/          # Data access implementations       │
│  │   ├── __init__.py                                           │
│  │   ├── file_repository.py # File-based repository            │
│  │   └── memory_repository.py # In-memory repository           │
│  ├── parsers/              # Parser implementations            │
│  │   ├── __init__.py                                           │
│  │   ├── ldif_parser.py    # Core LDIF parser                  │
│  │   └── modernized_parser.py # Modern LDIF parser             │
│  ├── validators/           # Validator implementations         │
│  │   ├── __init__.py                                           │
│  │   ├── format_validator.py # Format validation               │
│  │   └── schema_validator.py # Schema validation               │
│  ├── adapters/             # External service adapters        │
│  │   ├── __init__.py                                           │
│  │   ├── ldap_adapter.py    # LDAP integration (future)        │
│  │   └── singer_adapter.py  # Singer ecosystem (future)        │
│  ├── configuration/        # Configuration management         │
│  │   ├── __init__.py                                           │
│  │   ├── config.py         # Configuration models              │
│  │   └── settings.py       # Settings management               │
│  └── di/                   # Dependency injection              │
│      ├── __init__.py                                           │
│      ├── container.py      # DI container setup                │
│      └── registry.py       # Service registration              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Domain Layer Design

### Core Domain Concepts

#### Domain Entities

**FlextLdifEntry** - Main domain entity representing LDIF entries:

```python
# domain/entities/ldif_entry.py
from flext_core import FlextEntity, FlextResult
from ..values.distinguished_name import FlextLdifDistinguishedName
from ..values.attributes import FlextLdifAttributes

class FlextLdifEntry(FlextEntity):
    """
    Domain entity representing an LDIF entry with business logic.

    Encapsulates all business rules and domain operations for LDIF entries,
    ensuring data integrity and business rule compliance.
    """

    def __init__(
        self,
        dn: FlextLdifDistinguishedName,
        attributes: FlextLdifAttributes,
        changetype: str | None = None
    ) -> None:
        super().__init__()
        self._dn = dn
        self._attributes = attributes
        self._changetype = changetype

    @property
    def dn(self) -> FlextLdifDistinguishedName:
        """Distinguished name (immutable)."""
        return self._dn

    @property
    def attributes(self) -> FlextLdifAttributes:
        """Entry attributes (immutable)."""
        return self._attributes

    @property
    def changetype(self) -> str | None:
        """LDIF changetype (add, modify, delete, etc.)."""
        return self._changetype

    def get_object_classes(self) -> list[str]:
        """
        Get all objectClass values for this entry.

        Business rule: Every LDIF entry must have at least one objectClass.
        """
        return self._attributes.get_values("objectClass")

    def has_object_class(self, object_class: str) -> bool:
        """Check if entry has specific object class."""
        return object_class in self.get_object_classes()

    def get_attribute_values(self, name: str) -> list[str]:
        """Get all values for specified attribute."""
        return self._attributes.get_values(name)

    def has_attribute(self, name: str) -> bool:
        """Check if entry has specific attribute."""
        return self._attributes.has_attribute(name)

    def validate_domain_rules(self) -> None:
        """
        Validate entry against domain business rules.

        Business Rules:
        1. DN must not be empty
        2. Must have at least one objectClass
        3. Attribute names must be valid LDAP attribute names
        4. Required attributes for object classes must be present
        """
        if not self._dn.value.strip():
            raise ValueError("Entry DN cannot be empty")

        object_classes = self.get_object_classes()
        if not object_classes:
            raise ValueError("Entry must have at least one objectClass")

        # Validate required attributes for known object classes
        self._validate_required_attributes(object_classes)

        # Validate attribute name format
        self._validate_attribute_names()

    def _validate_required_attributes(self, object_classes: list[str]) -> None:
        """Validate required attributes for object classes."""
        required_attrs = self._get_required_attributes(object_classes)
        for attr in required_attrs:
            if not self.has_attribute(attr):
                raise ValueError(f"Required attribute '{attr}' missing for objectClass")

    def _validate_attribute_names(self) -> None:
        """Validate LDAP attribute name format."""
        import re
        attr_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*$")

        for attr_name in self._attributes.get_attribute_names():
            if not attr_pattern.match(attr_name):
                raise ValueError(f"Invalid attribute name format: {attr_name}")

    def _get_required_attributes(self, object_classes: list[str]) -> set[str]:
        """Get required attributes for object classes."""
        # Business knowledge: Required attributes by object class
        required_map = {
            "person": {"cn", "sn"},
            "organizationalPerson": {"cn", "sn"},
            "inetOrgPerson": {"cn", "sn"},
        }

        required = set()
        for oc in object_classes:
            if oc in required_map:
                required.update(required_map[oc])

        return required

    def is_person_entry(self) -> bool:
        """Business rule: Check if entry represents a person."""
        person_classes = {"person", "organizationalPerson", "inetOrgPerson"}
        return any(oc in person_classes for oc in self.get_object_classes())

    def is_add_operation(self) -> bool:
        """Check if entry is an add operation."""
        return self._changetype == "add"

    def is_modify_operation(self) -> bool:
        """Check if entry is a modify operation."""
        return self._changetype == "modify"

    def is_delete_operation(self) -> bool:
        """Check if entry is a delete operation."""
        return self._changetype == "delete"
```

**FlextLdifDocument** - Aggregate root for LDIF document processing:

```python
# domain/aggregates/ldif_processing_aggregate.py
from flext_core import FlextAggregateRoot, FlextDomainEvent
from ..entities.ldif_entry import FlextLdifEntry
from ..events.processing_completed import FlextLdifProcessingCompleted

class FlextLdifDocument(FlextAggregateRoot):
    """
    Aggregate root for LDIF document processing operations.

    Ensures consistency and transactional boundaries for LDIF processing,
    coordinating between parsing, validation, and transformation operations.
    """

    def __init__(self, content: str, document_id: str | None = None) -> None:
        super().__init__()
        self._content = content
        self._document_id = document_id or self._generate_id()
        self._entries: list[FlextLdifEntry] = []
        self._is_parsed = False
        self._is_validated = False
        self._validation_errors: list[str] = []

    @property
    def document_id(self) -> str:
        """Unique document identifier."""
        return self._document_id

    @property
    def content(self) -> str:
        """Original LDIF content."""
        return self._content

    @property
    def entries(self) -> list[FlextLdifEntry]:
        """Parsed LDIF entries."""
        return self._entries.copy()  # Return copy to maintain encapsulation

    @property
    def is_parsed(self) -> bool:
        """Whether document has been parsed."""
        return self._is_parsed

    @property
    def is_validated(self) -> bool:
        """Whether document has been validated."""
        return self._is_validated

    @property
    def validation_errors(self) -> list[str]:
        """Validation errors found during processing."""
        return self._validation_errors.copy()

    def parse_entries(self, entries: list[FlextLdifEntry]) -> None:
        """
        Set parsed entries and mark document as parsed.

        Business Rule: Document can only be parsed once.
        """
        if self._is_parsed:
            raise ValueError("Document has already been parsed")

        self._entries = entries
        self._is_parsed = True

        # Raise domain event
        event = FlextLdifDocumentParsed(
            aggregate_id=self._document_id,
            entry_count=len(entries),
            content_length=len(self._content)
        )
        self.add_domain_event(event)

    def validate_all_entries(self) -> bool:
        """
        Validate all entries and record results.

        Business Rule: Document must be parsed before validation.
        """
        if not self._is_parsed:
            raise ValueError("Document must be parsed before validation")

        self._validation_errors.clear()

        for i, entry in enumerate(self._entries):
            try:
                entry.validate_domain_rules()
            except ValueError as e:
                self._validation_errors.append(f"Entry {i}: {e}")

        self._is_validated = True
        success = len(self._validation_errors) == 0

        # Raise domain event
        event = FlextLdifProcessingCompleted(
            aggregate_id=self._document_id,
            entry_count=len(self._entries),
            success=success,
            errors=self._validation_errors
        )
        self.add_domain_event(event)

        return success

    def get_person_entries(self) -> list[FlextLdifEntry]:
        """Get entries that represent persons (business logic)."""
        if not self._is_parsed:
            raise ValueError("Document must be parsed first")

        return [entry for entry in self._entries if entry.is_person_entry()]

    def get_valid_entries(self) -> list[FlextLdifEntry]:
        """Get entries that pass domain validation."""
        if not self._is_validated:
            raise ValueError("Document must be validated first")

        valid_entries = []
        for entry in self._entries:
            try:
                entry.validate_domain_rules()
                valid_entries.append(entry)
            except ValueError:
                pass  # Skip invalid entries

        return valid_entries
```

#### Value Objects

**FlextLdifDistinguishedName** - Immutable DN representation:

```python
# domain/values/distinguished_name.py
from flext_core import FlextValue
import re

class FlextLdifDistinguishedName(FlextValue):
    """
    Immutable value object representing LDAP Distinguished Names.

    Encapsulates DN parsing, validation, and hierarchical operations
    while maintaining immutability and value semantics.
    """

    def __init__(self, value: str) -> None:
        self._value = value.strip()
        self._validate_dn_format()
        self._components = self._parse_components()

    @property
    def value(self) -> str:
        """The DN string value."""
        return self._value

    def _validate_dn_format(self) -> None:
        """Validate DN format according to LDAP standards."""
        if not self._value:
            raise ValueError("DN cannot be empty")

        if "=" not in self._value:
            raise ValueError("DN must contain at least one attribute=value pair")

        # Validate each component
        components = self._value.split(",")
        for component in components:
            component = component.strip()
            if "=" not in component:
                raise ValueError(f"Invalid DN component: {component}")

            attr_name, attr_value = component.split("=", 1)
            if not attr_name.strip() or not attr_value.strip():
                raise ValueError(f"Invalid DN component: {component}")

    def _parse_components(self) -> list[str]:
        """Parse DN into components."""
        return [comp.strip() for comp in self._value.split(",")]

    def get_components(self) -> list[str]:
        """Get DN components as list."""
        return self._components.copy()

    def get_rdn(self) -> str:
        """Get Relative Distinguished Name (first component)."""
        return self._components[0] if self._components else ""

    def get_parent_dn(self) -> "FlextLdifDistinguishedName | None":
        """Get parent DN or None if this is root."""
        if len(self._components) <= 1:
            return None

        parent_components = self._components[1:]
        parent_value = ",".join(parent_components)
        return FlextLdifDistinguishedName(parent_value)

    def is_child_of(self, parent: "FlextLdifDistinguishedName") -> bool:
        """Check if this DN is a child of the given parent DN."""
        if len(self._components) <= len(parent._components):
            return False

        # Check if parent components match the suffix of this DN
        parent_suffix = self._components[len(self._components) - len(parent._components):]
        return parent_suffix == parent._components

    def get_depth(self) -> int:
        """Get DN depth (number of components)."""
        return len(self._components)

    def is_root(self) -> bool:
        """Check if this is a root DN."""
        return len(self._components) == 1

    def __eq__(self, other: object) -> bool:
        """Value equality based on normalized DN."""
        if isinstance(other, str):
            try:
                other_dn = FlextLdifDistinguishedName(other)
                return self._value.lower() == other_dn._value.lower()
            except ValueError:
                return False
        elif isinstance(other, FlextLdifDistinguishedName):
            return self._value.lower() == other._value.lower()
        return False

    def __hash__(self) -> int:
        """Hash based on normalized DN value."""
        return hash(self._value.lower())

    def __str__(self) -> str:
        """String representation."""
        return self._value

    def __repr__(self) -> str:
        """Developer representation."""
        return f"FlextLdifDistinguishedName(value='{self._value}')"
```

**FlextLdifAttributes** - Immutable attribute collection:

```python
# domain/values/attributes.py
from flext_core import FlextValue
from typing import Dict, List

class FlextLdifAttributes(FlextValue):
    """
    Immutable value object representing LDIF entry attributes.

    Provides immutable operations for attribute manipulation while
    maintaining value semantics and business rule validation.
    """

    def __init__(self, attributes: Dict[str, List[str]]) -> None:
        # Validate and normalize attributes
        self._attributes = self._normalize_attributes(attributes)
        self._validate_attributes()

    def _normalize_attributes(self, attributes: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Normalize attribute names and values."""
        normalized = {}
        for name, values in attributes.items():
            # Normalize attribute name (case-insensitive per LDAP standards)
            norm_name = name.strip()
            if not norm_name:
                continue

            # Normalize values (remove empty strings)
            norm_values = [v.strip() for v in values if v.strip()]
            if norm_values:  # Only include attributes with values
                normalized[norm_name] = norm_values

        return normalized

    def _validate_attributes(self) -> None:
        """Validate attribute format and business rules."""
        import re
        attr_name_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*$")

        for name, values in self._attributes.items():
            # Validate attribute name format
            if not attr_name_pattern.match(name):
                raise ValueError(f"Invalid attribute name format: {name}")

            # Validate attribute has values
            if not values:
                raise ValueError(f"Attribute '{name}' must have at least one value")

            # Validate no duplicate values
            if len(values) != len(set(values)):
                raise ValueError(f"Attribute '{name}' contains duplicate values")

    @property
    def attributes(self) -> Dict[str, List[str]]:
        """Get attributes dictionary (deep copy for immutability)."""
        return {name: values.copy() for name, values in self._attributes.items()}

    def get_values(self, name: str) -> List[str]:
        """Get all values for an attribute."""
        return self._attributes.get(name, []).copy()

    def get_single_value(self, name: str) -> str | None:
        """Get first value of attribute or None."""
        values = self._attributes.get(name, [])
        return values[0] if values else None

    def has_attribute(self, name: str) -> bool:
        """Check if attribute exists."""
        return name in self._attributes

    def get_attribute_names(self) -> List[str]:
        """Get list of all attribute names."""
        return list(self._attributes.keys())

    def get_total_values(self) -> int:
        """Get total number of values across all attributes."""
        return sum(len(values) for values in self._attributes.values())

    def is_empty(self) -> bool:
        """Check if no attributes are defined."""
        return len(self._attributes) == 0

    # Immutable operations that return new instances

    def add_value(self, name: str, value: str) -> "FlextLdifAttributes":
        """Return new instance with added value."""
        if not name.strip() or not value.strip():
            raise ValueError("Attribute name and value cannot be empty")

        new_attributes = self.attributes  # Get copy

        if name in new_attributes:
            if value not in new_attributes[name]:  # Avoid duplicates
                new_attributes[name].append(value)
        else:
            new_attributes[name] = [value]

        return FlextLdifAttributes(new_attributes)

    def remove_value(self, name: str, value: str) -> "FlextLdifAttributes":
        """Return new instance with removed value."""
        new_attributes = self.attributes  # Get copy

        if name in new_attributes and value in new_attributes[name]:
            new_attributes[name].remove(value)
            # Remove attribute if no values left
            if not new_attributes[name]:
                del new_attributes[name]

        return FlextLdifAttributes(new_attributes)

    def remove_attribute(self, name: str) -> "FlextLdifAttributes":
        """Return new instance with removed attribute."""
        new_attributes = self.attributes  # Get copy
        new_attributes.pop(name, None)
        return FlextLdifAttributes(new_attributes)

    def replace_values(self, name: str, values: List[str]) -> "FlextLdifAttributes":
        """Return new instance with replaced attribute values."""
        if not name.strip():
            raise ValueError("Attribute name cannot be empty")

        new_attributes = self.attributes  # Get copy
        clean_values = [v.strip() for v in values if v.strip()]

        if clean_values:
            new_attributes[name] = clean_values
        else:
            new_attributes.pop(name, None)  # Remove if no valid values

        return FlextLdifAttributes(new_attributes)

    def __eq__(self, other: object) -> bool:
        """Value equality based on attributes."""
        if isinstance(other, FlextLdifAttributes):
            return self._attributes == other._attributes
        return False

    def __hash__(self) -> int:
        """Hash based on attribute content."""
        # Create hash from sorted attribute items for consistency
        items = []
        for name in sorted(self._attributes.keys()):
            values = tuple(sorted(self._attributes[name]))
            items.append((name, values))
        return hash(tuple(items))

    def __len__(self) -> int:
        """Number of attributes."""
        return len(self._attributes)

    def __bool__(self) -> bool:
        """Boolean conversion - True if has attributes."""
        return not self.is_empty()
```

#### Domain Events

```python
# domain/events/processing_completed.py
from flext_core import FlextDomainEvent
from datetime import datetime
from typing import List

class FlextLdifProcessingCompleted(FlextDomainEvent):
    """
    Domain event raised when LDIF document processing is completed.

    Used for integration with observability, audit logging, and
    downstream processing systems.
    """

    def __init__(
        self,
        aggregate_id: str,
        entry_count: int,
        success: bool,
        errors: List[str],
        processing_duration_ms: int | None = None
    ) -> None:
        super().__init__()
        self.aggregate_id = aggregate_id
        self.entry_count = entry_count
        self.success = success
        self.errors = errors.copy()
        self.processing_duration_ms = processing_duration_ms
        self.occurred_at = datetime.utcnow()

    @property
    def event_type(self) -> str:
        """Event type identifier."""
        return "ldif_processing_completed"

    def to_dict(self) -> dict:
        """Convert event to dictionary for serialization."""
        return {
            "event_id": str(self.event_id),
            "event_type": self.event_type,
            "aggregate_id": self.aggregate_id,
            "entry_count": self.entry_count,
            "success": self.success,
            "errors": self.errors,
            "processing_duration_ms": self.processing_duration_ms,
            "occurred_at": self.occurred_at.isoformat()
        }
```

#### Domain Specifications

```python
# domain/specifications/person_spec.py
from flext_core import FlextSpecification
from ..entities.ldif_entry import FlextLdifEntry

class FlextLdifPersonSpecification(FlextSpecification[FlextLdifEntry]):
    """
    Business specification for identifying person entries in LDIF.

    Encapsulates the business rule: "An entry is a person if it has
    person-related objectClass values."
    """

    def __init__(self) -> None:
        self._person_object_classes = {
            "person",
            "organizationalPerson",
            "inetOrgPerson",
            "uidObject"  # Often used with person entries
        }

    def is_satisfied_by(self, entry: FlextLdifEntry) -> bool:
        """Check if entry satisfies person specification."""
        entry_classes = set(entry.get_object_classes())
        return bool(entry_classes.intersection(self._person_object_classes))

    def get_required_attributes(self) -> set[str]:
        """Get attributes required for person entries."""
        return {"cn", "sn"}  # Common name and surname required

    def validate_person_entry(self, entry: FlextLdifEntry) -> list[str]:
        """Validate person entry and return list of violations."""
        violations = []

        if not self.is_satisfied_by(entry):
            violations.append("Entry is not a person type")
            return violations

        # Check required attributes
        required_attrs = self.get_required_attributes()
        for attr in required_attrs:
            if not entry.has_attribute(attr):
                violations.append(f"Missing required person attribute: {attr}")

        # Business rule: Person should have email or phone
        has_contact = (entry.has_attribute("mail") or
                      entry.has_attribute("telephoneNumber") or
                      entry.has_attribute("mobile"))

        if not has_contact:
            violations.append("Person entry should have at least one contact method")

        return violations


# domain/specifications/valid_entry_spec.py
from flext_core import FlextSpecification
from ..entities.ldif_entry import FlextLdifEntry

class FlextLdifValidSpecification(FlextSpecification[FlextLdifEntry]):
    """
    Business specification for validating LDIF entries.

    Encapsulates all business rules for entry validity.
    """

    def is_satisfied_by(self, entry: FlextLdifEntry) -> bool:
        """Check if entry satisfies validity specification."""
        try:
            entry.validate_domain_rules()
            return True
        except ValueError:
            return False

    def get_validation_errors(self, entry: FlextLdifEntry) -> list[str]:
        """Get detailed validation errors for entry."""
        errors = []

        try:
            entry.validate_domain_rules()
        except ValueError as e:
            errors.append(str(e))

        # Additional business validations
        if entry.get_depth() > 10:  # Arbitrary business limit
            errors.append("DN depth exceeds maximum allowed (10 levels)")

        if len(entry.get_object_classes()) > 20:  # Arbitrary business limit
            errors.append("Too many objectClass values (max 20)")

        return errors
```

---

## 📊 Application Layer Design

### CQRS Implementation

```python
# application/handlers/parse_handler.py
from flext_core import FlextResult
from ..dto.request_dto import ParseLdifRequest
from ..dto.entry_dto import FlextLdifEntryDTO
from ...domain.aggregates.ldif_processing_aggregate import FlextLdifDocument
from ...infrastructure.parsers.ldif_parser import LdifParserService

class ParseLdifHandler:
    """
    Command handler for parsing LDIF content.

    Orchestrates the parsing operation using domain aggregates
    and infrastructure services.
    """

    def __init__(self, parser_service: LdifParserService) -> None:
        self._parser_service = parser_service

    def handle(self, request: ParseLdifRequest) -> FlextResult[list[FlextLdifEntryDTO]]:
        """Handle LDIF parsing command."""
        try:
            # Create domain aggregate
            document = FlextLdifDocument(
                content=request.content,
                document_id=request.document_id
            )

            # Use infrastructure service to parse
            parse_result = self._parser_service.parse_content(request.content)

            if parse_result.is_failure:
                return FlextResult[None].fail(parse_result.error)

            # Update aggregate with parsed entries
            document.parse_entries(parse_result.value)

            # Convert to DTOs for application layer
            entry_dtos = [
                FlextLdifEntryDTO.from_domain_entity(entry)
                for entry in document.entries
            ]

            return FlextResult[None].ok(entry_dtos)

        except Exception as e:
            return FlextResult[None].fail(f"Parse operation failed: {e}")
```

### Application Services

```python
# application/api.py
from flext_core import FlextResult, get_logger
from flext_observability import flext_monitor_function, flext_create_trace
from .handlers.parse_handler import ParseLdifHandler
from .handlers.validate_handler import ValidateHandler
from .handlers.write_handler import WriteHandler
from .dto.request_dto import ParseLdifRequest, ValidateRequest, WriteRequest
from .dto.entry_dto import FlextLdifEntryDTO

class FlextLdifAPI:
    """
    Main application service providing unified LDIF operations.

    Orchestrates commands and queries while maintaining clean
    boundaries between application and domain layers.
    """

    def __init__(
        self,
        parse_handler: ParseLdifHandler,
        validate_handler: ValidateHandler,
        write_handler: WriteHandler,
        config: FlextLdifConfig | None = None
    ) -> None:
        self._parse_handler = parse_handler
        self._validate_handler = validate_handler
        self._write_handler = write_handler
        self._config = config or FlextLdifConfig()
        self._logger = get_logger(self.__class__.__name__)

    @flext_monitor_function("ldif_parse")
    def parse(self, content: str) -> FlextResult[list[FlextLdifEntryDTO]]:
        """Parse LDIF content into domain objects."""
        with flext_create_trace("parse_ldif_content") as trace:
            self._logger.debug("Parsing LDIF content (%d chars)", len(content))

            request = ParseLdifRequest(
                content=content,
                max_entries=self._config.max_entries,
                strict_validation=self._config.strict_validation
            )

            result = self._parse_handler.handle(request)

            if result.is_success:
                trace.set_attribute("entries_parsed", len(result.value))
                trace.set_status("success")
                self._logger.info("Successfully parsed %d entries", len(result.value))
            else:
                trace.set_status("error", result.error)
                self._logger.error("Parse failed: %s", result.error)

            return result

    @flext_monitor_function("ldif_validate")
    def validate(self, entries: list[FlextLdifEntryDTO]) -> FlextResult[bool]:
        """Validate LDIF entries against business rules."""
        with flext_create_trace("validate_ldif_entries") as trace:
            self._logger.debug("Validating %d LDIF entries", len(entries))

            request = ValidateRequest(
                entries=entries,
                strict_mode=self._config.strict_validation
            )

            result = self._validate_handler.handle(request)

            if result.is_success:
                trace.set_attribute("validation_passed", result.value)
                trace.set_status("success")
                self._logger.info("Validation %s", "passed" if result.value else "failed")
            else:
                trace.set_status("error", result.error)
                self._logger.error("Validation error: %s", result.error)

            return result

    @flext_monitor_function("ldif_write")
    def write(self, entries: list[FlextLdifEntryDTO]) -> FlextResult[str]:
        """Generate LDIF output from domain objects."""
        with flext_create_trace("write_ldif_entries") as trace:
            self._logger.debug("Writing %d LDIF entries", len(entries))

            request = WriteRequest(
                entries=entries,
                format_options=self._config.get_format_options()
            )

            result = self._write_handler.handle(request)

            if result.is_success:
                trace.set_attribute("output_length", len(result.value))
                trace.set_status("success")
                self._logger.info("Successfully generated LDIF output (%d chars)", len(result.value))
            else:
                trace.set_status("error", result.error)
                self._logger.error("Write failed: %s", result.error)

            return result
```

---

## 🔧 Infrastructure Layer Design

### Service Implementations

```python
# infrastructure/parsers/ldif_parser.py
from flext_core import FlextResult, get_logger
from ...domain.entities.ldif_entry import FlextLdifEntry
from ...domain.values.distinguished_name import FlextLdifDistinguishedName
from ...domain.values.attributes import FlextLdifAttributes
from ...domain.interfaces.parser_interface import ILdifParser

class LdifParserService(ILdifParser):
    """
    Infrastructure implementation of LDIF parsing.

    Handles low-level LDIF format parsing while delegating
    business logic to domain objects.
    """

    def __init__(self, config: FlextLdifConfig) -> None:
        self._config = config
        self._logger = get_logger(self.__class__.__name__)

    def parse_content(self, content: str) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content into domain entities."""
        try:
            self._logger.debug("Starting LDIF content parsing")

            # Low-level parsing logic
            raw_entries = self._parse_ldif_text(content)

            # Convert to domain entities
            domain_entries = []
            for raw_entry in raw_entries:
                try:
                    domain_entry = self._create_domain_entry(raw_entry)
                    domain_entries.append(domain_entry)
                except ValueError as e:
                    if self._config.strict_validation:
                        return FlextResult[None].fail(f"Entry validation failed: {e}")
                    else:
                        self._logger.warning("Skipping invalid entry: %s", e)
                        continue

            self._logger.info("Successfully parsed %d entries", len(domain_entries))
            return FlextResult[None].ok(domain_entries)

        except Exception as e:
            self._logger.error("LDIF parsing failed: %s", e)
            return FlextResult[None].fail(f"Parsing failed: {e}")

    def _parse_ldif_text(self, content: str) -> list[dict]:
        """Low-level LDIF text parsing."""
        entries = []
        current_entry = {}

        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.rstrip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                if current_entry:
                    entries.append(current_entry)
                    current_entry = {}
                continue

            # Handle line continuations
            if line.startswith(' ') or line.startswith('\t'):
                if not current_entry:
                    raise ValueError(f"Line {line_num}: Continuation without attribute")
                # Continue previous attribute
                last_attr = list(current_entry.keys())[-1]
                current_entry[last_attr] += line[1:]
                continue

            # Parse attribute: value
            if ':' not in line:
                raise ValueError(f"Line {line_num}: Invalid LDIF format")

            attr_name, attr_value = line.split(':', 1)
            attr_name = attr_name.strip()
            attr_value = attr_value.strip()

            # Handle base64 encoding
            if attr_value.startswith(':'):
                attr_value = self._decode_base64_value(attr_value[1:].strip())

            # Add to current entry
            if attr_name in current_entry:
                if isinstance(current_entry[attr_name], list):
                    current_entry[attr_name].append(attr_value)
                else:
                    current_entry[attr_name] = [current_entry[attr_name], attr_value]
            else:
                current_entry[attr_name] = attr_value

        # Add final entry
        if current_entry:
            entries.append(current_entry)

        return entries

    def _create_domain_entry(self, raw_entry: dict) -> FlextLdifEntry:
        """Convert raw entry to domain entity."""
        # Extract DN
        if 'dn' not in raw_entry:
            raise ValueError("Entry missing required 'dn' attribute")

        dn = FlextLdifDistinguishedName(raw_entry['dn'])

        # Extract attributes (exclude dn and changetype)
        attributes_dict = {}
        changetype = None

        for name, value in raw_entry.items():
            if name == 'dn':
                continue
            elif name == 'changetype':
                changetype = value
            else:
                # Ensure value is list
                if isinstance(value, str):
                    attributes_dict[name] = [value]
                else:
                    attributes_dict[name] = value

        attributes = FlextLdifAttributes(attributes_dict)

        # Create domain entity
        entry = FlextLdifEntry(dn=dn, attributes=attributes, changetype=changetype)

        # Domain validation happens in entity constructor
        entry.validate_domain_rules()

        return entry
```

### Repository Implementation

```python
# infrastructure/persistence/file_repository.py
from flext_core import FlextResult, get_logger
from pathlib import Path
from ...domain.entities.ldif_entry import FlextLdifEntry
from ...domain.interfaces.repository_interface import ILdifRepository

class FileLdifRepository(ILdifRepository):
    """
    File-based repository implementation for LDIF data.

    Provides persistence operations while maintaining domain
    abstractions and transaction boundaries.
    """

    def __init__(self, base_path: Path) -> None:
        self._base_path = base_path
        self._logger = get_logger(self.__class__.__name__)
        self._ensure_base_path_exists()

    def save_entries(
        self,
        entries: list[FlextLdifEntry],
        filename: str
    ) -> FlextResult[bool]:
        """Save entries to file."""
        try:
            file_path = self._base_path / filename

            self._logger.debug("Saving %d entries to %s", len(entries), file_path)

            # Generate LDIF content
            ldif_content = self._generate_ldif_content(entries)

            # Write to file atomically
            temp_path = file_path.with_suffix(file_path.suffix + '.tmp')

            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(ldif_content)

            temp_path.rename(file_path)

            self._logger.info("Successfully saved entries to %s", file_path)
            return FlextResult[None].ok(data=True)

        except Exception as e:
            self._logger.error("Failed to save entries: %s", e)
            return FlextResult[None].fail(f"Save operation failed: {e}")

    def load_entries(self, filename: str) -> FlextResult[list[FlextLdifEntry]]:
        """Load entries from file."""
        try:
            file_path = self._base_path / filename

            if not file_path.exists():
                return FlextResult[None].fail(f"File not found: {filename}")

            self._logger.debug("Loading entries from %s", file_path)

            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Use parser to load entries
            from ..parsers.ldif_parser import LdifParserService
            parser = LdifParserService(self._get_default_config())

            return parser.parse_content(content)

        except Exception as e:
            self._logger.error("Failed to load entries: %s", e)
            return FlextResult[None].fail(f"Load operation failed: {e}")

    def _generate_ldif_content(self, entries: list[FlextLdifEntry]) -> str:
        """Generate LDIF content from domain entities."""
        lines = []

        for entry in entries:
            # Add DN
            lines.append(f"dn: {entry.dn.value}")

            # Add changetype if present
            if entry.changetype:
                lines.append(f"changetype: {entry.changetype}")

            # Add attributes in sorted order for consistency
            for attr_name in sorted(entry.attributes.get_attribute_names()):
                values = entry.attributes.get_values(attr_name)
                for value in values:
                    lines.append(f"{attr_name}: {value}")

            lines.append("")  # Empty line between entries

        return "\n".join(lines)
```

---

## 🔌 FLEXT Ecosystem Integration

### Dependency Injection Setup

```python
# infrastructure/di/container.py
from flext_core import get_flext_container, FlextContainer
from ..parsers.ldif_parser import LdifParserService
from ..validators.format_validator import FormatValidatorService
from ..persistence.file_repository import FileLdifRepository
from ...application.handlers.parse_handler import ParseLdifHandler
from ...application.api import FlextLdifAPI

def register_ldif_services(container: FlextContainer) -> None:
    """Register FLEXT-LDIF services in DI container."""

    # Infrastructure services
    container.register_singleton(LdifParserService, lambda: LdifParserService(
        config=container.get(FlextLdifConfig)
    ))

    container.register_singleton(FormatValidatorService, FormatValidatorService)

    container.register_singleton(FileLdifRepository, lambda: FileLdifRepository(
        base_path=Path("/tmp/ldif_data")  # Default path
    ))

    # Application handlers
    container.register_transient(ParseLdifHandler, lambda: ParseLdifHandler(
        parser_service=container.get(LdifParserService)
    ))

    # Application API
    container.register_singleton(FlextLdifAPI, lambda: FlextLdifAPI(
        parse_handler=container.get(ParseLdifHandler),
        validate_handler=container.get(ValidateHandler),
        write_handler=container.get(WriteHandler),
        config=container.get(FlextLdifConfig)
    ))

def get_ldif_api() -> FlextLdifAPI:
    """Get configured LDIF API from container."""
    container = FlextContainer.get_global()
    register_ldif_services(container)
    return container.get(FlextLdifAPI)
```

### Observability Integration

```python
# infrastructure/observability/metrics.py
from flext_observability import FlextObservabilityMonitor, MetricType
from ...domain.events.processing_completed import FlextLdifProcessingCompleted

class LdifMetricsCollector:
    """
    Collects and reports LDIF processing metrics.

    Integrates with FLEXT observability system for monitoring
    and alerting on LDIF processing operations.
    """

    def __init__(self) -> None:
        self._monitor = FlextObservabilityMonitor("flext_ldif")
        self._setup_metrics()

    def _setup_metrics(self) -> None:
        """Setup metric definitions."""
        self._monitor.create_counter(
            name="entries_parsed_total",
            description="Total number of LDIF entries parsed",
            tags=["operation", "status"]
        )

        self._monitor.create_histogram(
            name="parse_duration_seconds",
            description="Time spent parsing LDIF content",
            buckets=[0.001, 0.01, 0.1, 1.0, 10.0]
        )

        self._monitor.create_gauge(
            name="active_documents",
            description="Number of LDIF documents currently being processed"
        )

    def record_processing_completed(self, event: FlextLdifProcessingCompleted) -> None:
        """Record metrics from processing completed event."""
        # Record entry count
        self._monitor.increment_counter(
            "entries_parsed_total",
            value=event.entry_count,
            tags={
                "operation": "parse",
                "status": "success" if event.success else "failure"
            }
        )

        # Record processing duration
        if event.processing_duration_ms:
            self._monitor.record_histogram(
                "parse_duration_seconds",
                value=event.processing_duration_ms / 1000.0
            )
```

---

## 🚨 Architecture Validation

### Architecture Tests

```python
# tests/architecture/test_layer_dependencies.py
import pytest
from pathlib import Path
import ast
import importlib.util

class ArchitectureTest:
    """Test architectural constraints and layer dependencies."""

    def test_domain_has_no_infrastructure_dependencies(self):
        """Domain layer must not depend on infrastructure."""
        domain_path = Path("src/flext_ldif/domain")
        violations = []

        for py_file in domain_path.rglob("*.py"):
            violations.extend(self._check_file_imports(py_file, [
                "infrastructure", "application", "presentation",
                "sqlalchemy", "requests", "ldap3"  # External libs
            ]))

        assert not violations, f"Domain layer violations: {violations}"

    def test_application_only_depends_on_domain(self):
        """Application layer should only depend on domain."""
        app_path = Path("src/flext_ldif/application")
        violations = []

        for py_file in app_path.rglob("*.py"):
            violations.extend(self._check_file_imports(py_file, [
                "infrastructure", "presentation"
            ]))

        assert not violations, f"Application layer violations: {violations}"

    def _check_file_imports(self, file_path: Path, forbidden_imports: list[str]) -> list[str]:
        """Check file for forbidden imports."""
        violations = []

        try:
            with open(file_path, 'r') as f:
                tree = ast.parse(f.read())

            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    module_name = getattr(node, 'module', None)
                    if module_name:
                        for forbidden in forbidden_imports:
                            if forbidden in module_name:
                                violations.append(f"{file_path}: imports {module_name}")

        except Exception as e:
            violations.append(f"{file_path}: parsing error {e}")

        return violations
```

### Domain Rule Tests

```python
# tests/domain/test_domain_rules.py
import pytest
from src.flext_ldif.domain.entities.ldif_entry import FlextLdifEntry
from src.flext_ldif.domain.values.distinguished_name import FlextLdifDistinguishedName
from src.flext_ldif.domain.values.attributes import FlextLdifAttributes

class TestDomainRules:
    """Test domain business rules and invariants."""

    def test_entry_must_have_objectclass(self):
        """Business rule: Every entry must have objectClass."""
        dn = FlextLdifDistinguishedName("cn=test,dc=example,dc=com")
        attrs = FlextLdifAttributes({"cn": ["test"]})  # No objectClass

        entry = FlextLdifEntry(dn=dn, attributes=attrs)

        with pytest.raises(ValueError, match="objectClass"):
            entry.validate_domain_rules()

    def test_person_entry_requires_common_name_and_surname(self):
        """Business rule: Person entries need cn and sn."""
        dn = FlextLdifDistinguishedName("cn=test,dc=example,dc=com")
        attrs = FlextLdifAttributes({
            "objectClass": ["person"],
            "cn": ["John Doe"]  # Missing sn
        })

        entry = FlextLdifEntry(dn=dn, attributes=attrs)

        with pytest.raises(ValueError, match="sn"):
            entry.validate_domain_rules()

    def test_dn_hierarchy_validation(self):
        """Test DN parent-child relationships."""
        parent = FlextLdifDistinguishedName("ou=people,dc=example,dc=com")
        child = FlextLdifDistinguishedName("cn=john,ou=people,dc=example,dc=com")
        unrelated = FlextLdifDistinguishedName("cn=jane,ou=groups,dc=example,dc=com")

        assert child.is_child_of(parent)
        assert not unrelated.is_child_of(parent)
        assert not parent.is_child_of(child)
```

---

## 📈 Performance Architecture

### Streaming and Batch Processing

```python
# infrastructure/streaming/ldif_stream_processor.py
from typing import Iterator, Generator
from flext_core import FlextResult
from ...domain.entities.ldif_entry import FlextLdifEntry

class LdifStreamProcessor:
    """
    Streaming processor for handling large LDIF files.

    Processes LDIF content in chunks to handle enterprise-scale
    files without memory exhaustion.
    """

    def __init__(self, chunk_size: int = 1000) -> None:
        self._chunk_size = chunk_size

    def stream_parse(self, file_path: Path) -> Generator[list[FlextLdifEntry], None, None]:
        """Stream parse large LDIF files in batches."""
        current_batch = []

        with open(file_path, 'r', encoding='utf-8') as f:
            current_entry_lines = []

            for line in f:
                line = line.rstrip()

                # Empty line indicates end of entry
                if not line:
                    if current_entry_lines:
                        entry = self._parse_entry_lines(current_entry_lines)
                        if entry:
                            current_batch.append(entry)

                        if len(current_batch) >= self._chunk_size:
                            yield current_batch
                            current_batch = []

                        current_entry_lines = []
                else:
                    current_entry_lines.append(line)

            # Yield final batch
            if current_batch:
                yield current_batch

    def _parse_entry_lines(self, lines: list[str]) -> FlextLdifEntry | None:
        """Parse entry from lines."""
        # Implementation similar to main parser but for single entry
        pass
```

### Caching Strategy

```python
# infrastructure/caching/entry_cache.py
from typing import Dict, Optional, LRU
from ...domain.entities.ldif_entry import FlextLdifEntry

class LdifEntryCache:
    """
    LRU cache for frequently accessed LDIF entries.

    Improves performance for repeated access patterns
    while maintaining memory bounds.
    """

    def __init__(self, max_size: int = 10000) -> None:
        self._cache: Dict[str, FlextLdifEntry] = {}
        self._max_size = max_size
        self._access_order = []

    def get(self, dn: str) -> Optional[FlextLdifEntry]:
        """Get cached entry by DN."""
        if dn in self._cache:
            # Update access order
            self._access_order.remove(dn)
            self._access_order.append(dn)
            return self._cache[dn]
        return None

    def put(self, entry: FlextLdifEntry) -> None:
        """Cache entry."""
        dn = entry.dn.value

        if dn in self._cache:
            # Update existing entry
            self._access_order.remove(dn)
        elif len(self._cache) >= self._max_size:
            # Evict LRU entry
            lru_dn = self._access_order.pop(0)
            del self._cache[lru_dn]

        self._cache[dn] = entry
        self._access_order.append(dn)
```

---

## 🔄 Migration Path

### Current → Target Architecture

#### Phase 1: Domain Layer Extraction (v0.9.5)

- [ ] Extract domain entities from `models.py` to `domain/entities/`
- [ ] Create value objects in `domain/values/`
- [ ] Implement domain specifications in `domain/specifications/`
- [ ] Add domain events in `domain/events/`

#### Phase 2: Application Layer Restructure (v0.9.7)

- [ ] Move `api.py` to `application/`
- [ ] Implement CQRS handlers in `application/handlers/`
- [ ] Create DTOs in `application/dto/`
- [ ] Separate queries in `application/queries/`

#### Phase 3: Infrastructure Organization (v0.9.9)

- [ ] Move services to `infrastructure/`
- [ ] Implement repository pattern
- [ ] Create proper adapter interfaces
- [ ] Setup dependency injection container

#### Phase 4: Clean Architecture Compliance (v1.0.0)

- [ ] Complete dependency direction validation
- [ ] Add architecture tests
- [ ] Implement presentation layer abstraction
- [ ] Add comprehensive observability integration

---

## 🏆 Success Metrics

### Architecture Quality Indicators

- **Dependency Direction**: 100% compliance with dependency rules
- **Test Coverage**: >95% across all architectural layers
- **Domain Purity**: Zero infrastructure dependencies in domain layer
- **Specification Coverage**: All business rules encoded as specifications
- **Performance**: Handle 1M+ entries with <2GB memory usage
- **Integration**: Seamless FLEXT ecosystem compatibility

### Monitoring & Observability

- **Business Metrics**: Entries processed, validation success rate
- **Performance Metrics**: Parse duration, memory usage, throughput
- **Error Metrics**: Validation failures, parsing errors, integration issues
- **Domain Events**: Complete audit trail of business operations

---

**Architecture Version**: 0.9.0 → 0.9.0
**Last Updated**: 2025-08-03
**Status**: Migration In Progress
**FLEXT Ecosystem**: Full Integration Target

This architecture guide provides the roadmap for evolving FLEXT-LDIF into a fully compliant Clean Architecture implementation within the FLEXT ecosystem.
