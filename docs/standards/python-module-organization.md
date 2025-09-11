# Python Module Organization Standards - FLEXT-LDIF

**Version**: 0.9.0
**Status**: Production Standard
**Scope**: FLEXT-LDIF Python Module Architecture
**Authority**: FLEXT Ecosystem Standards
**Last Updated**: 2025-08-03

---

## 🏗️ Overview

This document defines the **Python module organization standards** for the **FLEXT-LDIF** project, ensuring consistency with the broader **FLEXT ecosystem architecture**. These standards implement **Clean Architecture**, **Domain-Driven Design (DDD)**, and **Railway-Oriented Programming** patterns while maintaining seamless integration with the **flext-core** foundation library.

### **Key Architectural Principles**

1. **Clean Architecture Compliance**: Clear separation of domain, application, and infrastructure concerns
2. **Domain-Driven Design**: Rich domain model with business logic encapsulation
3. **Railway-Oriented Programming**: FlextResult pattern for consistent error handling
4. **FLEXT Ecosystem Integration**: Seamless integration with flext-core, flext-observability, and flext-ldap
5. **Type Safety**: 95%+ type annotation coverage with strict MyPy validation

---

## 📁 Current Module Structure

### **Project Root Organization**

```
flext-ldif/
├── src/flext_ldif/              # Main package directory
│   ├── __init__.py              # Public API exports
│   ├── py.typed
│   └── version.py               # Version management
├── tests/                       # Comprehensive test suite
├── docs/                        # Documentation
├── examples/                    # Usage examples
├── pyproject.toml              # Poetry configuration
├── Makefile                    # Development commands
├── CLAUDE.md                   # Development guidance
└── README.md                   # Project overview
```

### **Current Source Structure (v0.9.0)**

```python
src/flext_ldif/
├── __init__.py                  # Public API gateway
├── py.typed
├── version.py                   # Version management

# Application Layer (Mixed with Infrastructure)
├── api.py                       # FlextLDIFAPI - main application service
├── cli.py                       # Command-line interface

# Domain Layer (Consolidated)
├── models.py                    # Domain entities and value objects
├── exceptions.py                # Domain exceptions

# Infrastructure Layer
├── core.py                      # Core LDIF processing
├── services.py                  # Domain services (planned)
├── config.py                    # Configuration management
├── modernized_ldif.py           # Modern LDIF support

# Utilities (Cross-cutting)
└── utils/
    ├── __init__.py
    ├── validation.py            # Validation utilities
    ├── error_handling.py        # Error handling patterns
    ├── logging.py               # Logging configuration
    └── cli_utils.py             # CLI helper functions
```

---

## 🎯 Target Module Structure (v1.0.0)

### **Clean Architecture Compliant Structure**

```python
src/flext_ldif/
├── __init__.py                  # Public API exports with FlextResult patterns
├── py.typed
├── version.py                   # Version management

# Domain Layer - Core Business Logic (No Dependencies)
├── domain/
│   ├── __init__.py              # Domain exports
│   ├── entities.py              # FlextLDIFEntry, FlextLDIFDocument
│   ├── value_objects.py         # FlextLDIFDistinguishedName, FlextLDIFAttributes
│   ├── aggregates.py            # FlextLDIFAggregate (batch operations)
│   ├── services.py              # Domain services (business logic)
│   ├── specifications.py        # Business rules specifications
│   ├── events.py                # Domain events
│   └── repositories.py          # Repository interfaces (abstractions)

# Application Layer - Use Cases and Orchestration
├── application/
│   ├── __init__.py              # Application exports
│   ├── services.py              # FlextLDIFAPI - main application service
│   ├── handlers.py              # Command/Query handlers (CQRS)
│   ├── commands.py              # LDIF processing commands
│   ├── queries.py               # LDIF data queries
│   └── workflows.py             # Complex business workflows

# Infrastructure Layer - External Concerns
├── infrastructure/
│   ├── __init__.py              # Infrastructure exports
│   ├── config.py                # FlextLDIFSettings (extends FlextConfig)
│   ├── parsers.py               # LDIF parsing implementations
│   ├── writers.py               # LDIF output generation
│   ├── validators.py            # LDIF validation implementations
│   ├── repositories.py          # Repository concrete implementations
│   ├── adapters.py              # External service adapters
│   └── exceptions.py            # Infrastructure-specific exceptions

# Interface Layer - User Interfaces and APIs
├── interfaces/
│   ├── __init__.py              # Interface exports
│   ├── cli.py                   # Command-line interface
│   ├── api.py                   # Public API facade
│   └── web.py                   # Web interface (future)

# Cross-cutting Concerns
└── utils/
    ├── __init__.py              # Utility exports
    ├── logging.py               # Structured logging with flext-core
    ├── validation.py            # Cross-layer validation utilities
    ├── transformations.py       # LDIF transformation utilities
    └── performance.py           # Performance monitoring utilities
```

---

## 🏛️ Layer-by-Layer Architecture

### **1. Domain Layer** (`domain/`)

**Purpose**: Contains pure business logic with no external dependencies.

#### **entities.py** - Domain Entities

```python
"""
FLEXT-LDIF Domain Entities

This module contains the core domain entities for LDIF processing, implementing
Domain-Driven Design patterns with Clean Architecture principles.

All entities extend FlextModels.Entity from flext-core and encapsulate business logic
and invariants specific to LDIF data processing.

Key Components:
    - FlextLDIFEntry: Core LDIF entry entity with business rules
    - FlextLDIFChangeRecord: LDIF change operation entity
    - FlextLDIFSchema: LDAP schema entity for validation

Architecture:
    Part of Domain Layer in Clean Architecture, contains no infrastructure
    dependencies. All business logic and domain rules are encapsulated here.

Example:
    >>> from flext_ldif.domain import FlextLDIFEntry
    >>> entry = FlextLDIFEntry.create(dn="cn=user,dc=example,dc=com")
    >>> entry.add_attribute("objectClass", ["person"])
    >>> entry.validate_domain_rules()

Integration:
    - Built on flext-core FlextModels.Entity foundation
    - Implements Domain-Driven Design patterns
    - Used by Application Layer services
    - Validated by Domain Services

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from typing import List, Dict, Optional, Set
from flext_core import FlextModels.Entity, FlextResult
from .value_objects import FlextLDIFDistinguishedName, FlextLDIFAttributes
from .events import LdifEntryCreated, LdifEntryModified

class FlextLDIFEntry(FlextModels.Entity):
    """
    Core LDIF entry domain entity encapsulating business logic and invariants.

    This entity represents a single LDIF entry with its distinguished name
    and attributes, implementing all business rules and validation logic
    for LDIF data processing.

    Attributes:
        dn: Distinguished name value object
        attributes: Attributes value object containing all entry attributes
        change_type: Optional change operation type (add, modify, delete)

    Business Rules:
        - DN cannot be empty or None
        - objectClass attribute is required for standard entries
        - Attribute names must follow LDAP naming conventions
        - Change records must have valid change operations
    """

    def __init__(
        self,
        dn: FlextLDIFDistinguishedName,
        attributes: FlextLDIFAttributes,
        change_type: Optional[str] = None
    ) -> None:
        super().__init__()
        self._dn = dn
        self._attributes = attributes
        self._change_type = change_type
        self._validate_invariants()

        # Raise domain event
        self._raise_event(LdifEntryCreated(entry_id=self.id, dn=dn.value))

    @property
    def dn(self) -> FlextLDIFDistinguishedName:
        """Get the distinguished name."""
        return self._dn

    @property
    def attributes(self) -> FlextLDIFAttributes:
        """Get the attributes collection."""
        return self._attributes

    def validate_domain_rules(self) -> None:
        """
        Validate business rules and invariants for this LDIF entry.

        Raises:
            FlextLDIFDomainError: When business rules are violated
        """
        self._validate_invariants()
        self._validate_object_classes()
        self._validate_attribute_semantics()

    def add_attribute(self, name: str, values: List[str]) -> None:
        """
        Add attribute values to this entry with business rule validation.

        Args:
            name: Attribute name following LDAP conventions
            values: List of attribute values

        Raises:
            FlextLDIFDomainError: When attribute addition violates business rules
        """
        self._attributes = self._attributes.add_values(name, values)
        self._raise_event(LdifEntryModified(entry_id=self.id, attribute=name))

    def remove_attribute(self, name: str, values: Optional[List[str]] = None) -> None:
        """
        Remove attribute or specific values with business rule validation.

        Args:
            name: Attribute name to remove
            values: Specific values to remove, or None to remove entire attribute

        Raises:
            FlextLDIFDomainError: When removal violates business rules
        """
        if values is None:
            self._attributes = self._attributes.remove_attribute(name)
        else:
            self._attributes = self._attributes.remove_values(name, values)

        self._raise_event(LdifEntryModified(entry_id=self.id, attribute=name))

    def get_object_classes(self) -> Set[str]:
        """Get all objectClass values for this entry."""
        return set(self._attributes.get_values("objectClass"))

    def has_object_class(self, object_class: str) -> bool:
        """Check if entry has specific objectClass."""
        return object_class.lower() in {oc.lower() for oc in self.get_object_classes()}

    def is_structural_entry(self) -> bool:
        """Determine if this is a structural entry (not auxiliary)."""
        structural_classes = {"person", "organizationalPerson", "inetOrgPerson", "organizationalUnit"}
        return bool(self.get_object_classes().intersection(structural_classes))

    def _validate_invariants(self) -> None:
        """Validate core business invariants."""
        if not self._dn or not self._dn.value:
            raise FlextLDIFDomainError("Distinguished name cannot be empty")

        if self._change_type and self._change_type not in {"add", "modify", "delete", "moddn"}:
            raise FlextLDIFDomainError(f"Invalid change type: {self._change_type}")

    def _validate_object_classes(self) -> None:
        """Validate objectClass requirements."""
        if not self._change_type and not self._attributes.has_attribute("objectClass"):
            raise FlextLDIFDomainError("Standard entries must have objectClass attribute")

    def _validate_attribute_semantics(self) -> None:
        """Validate attribute semantic rules."""
        for name in self._attributes.get_attribute_names():
            if not name.replace("-", "").replace("_", "").isalnum():
                raise FlextLDIFDomainError(f"Invalid attribute name: {name}")

class FlextLDIFChangeRecord(FlextModels.Entity):
    """
    LDIF change record entity for modification operations.

    Represents LDIF change records with proper change semantics and
    business rule validation for modification operations.
    """

    def __init__(
        self,
        dn: FlextLDIFDistinguishedName,
        change_type: str,
        modifications: List[Dict[str, any]]
    ) -> None:
        super().__init__()
        self._dn = dn
        self._change_type = change_type
        self._modifications = modifications
        self._validate_change_semantics()

    def validate_domain_rules(self) -> None:
        """Validate change record business rules."""
        self._validate_change_semantics()
        self._validate_modification_consistency()

    def _validate_change_semantics(self) -> None:
        """Validate change operation semantics."""
        valid_changes = {"add", "delete", "modify", "moddn"}
        if self._change_type not in valid_changes:
            raise FlextLDIFDomainError(f"Invalid change type: {self._change_type}")

    def _validate_modification_consistency(self) -> None:
        """Validate modification consistency rules."""
        # Implementation of complex change validation logic
        pass
```

#### **value_objects.py** - Domain Value Objects

```python
"""
FLEXT-LDIF Domain Value Objects

This module contains immutable value objects for LDIF processing, implementing
Domain-Driven Design patterns with strong typing and validation.

All value objects extend FlextModels.Value from flext-core and provide
immutable data structures with business rule validation.

Key Components:
    - FlextLDIFDistinguishedName: DN value object with hierarchy operations
    - FlextLDIFAttributes: Attribute collection with validation
    - FlextLDIFModification: Change modification value object

Architecture:
    Part of Domain Layer in Clean Architecture, implements immutable value
    objects with business logic encapsulation and validation rules.

Example:
    >>> from flext_ldif.domain import FlextLDIFDistinguishedName
    >>> dn = FlextLDIFDistinguishedName("cn=user,ou=people,dc=example,dc=com")
    >>> parent = dn.get_parent()
    >>> print(parent.value)  # "ou=people,dc=example,dc=com"

Integration:
    - Built on flext-core FlextModels.Value foundation
    - Used by Domain Entities for data encapsulation
    - Implements immutability patterns
    - Provides business logic for data validation

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from flext_core import FlextModels.Value
import re
from .exceptions import FlextLDIFDomainError

@dataclass(frozen=True)
class FlextLDIFDistinguishedName(FlextModels.Value):
    """
    Immutable distinguished name value object with hierarchy operations.

    Represents LDAP distinguished names with business logic for DN manipulation,
    validation, and hierarchical operations following RFC standards.

    Attributes:
        value: The DN string value

    Business Rules:
        - DN must follow LDAP DN syntax (RFC 4514)
        - Components must be properly formatted (attribute=value)
        - Special characters must be properly escaped
        - Empty DNs are not allowed for standard entries
    """

    value: str

    def __post_init__(self) -> None:
        """Validate DN format and business rules."""
        if not self.value:
            raise FlextLDIFDomainError("Distinguished name cannot be empty")

        self._validate_dn_syntax()

    def get_rdn(self) -> str:
        """
        Get the relative distinguished name (leftmost component).

        Returns:
            The RDN string (e.g., "cn=John Doe")

        Example:
            >>> dn = FlextLDIFDistinguishedName("cn=user,ou=people,dc=example,dc=com")
            >>> rdn = dn.get_rdn()
            >>> print(rdn)  # "cn=user"
        """
        components = self._parse_components()
        return components[0] if components else ""

    def get_parent(self) -> Optional['FlextLDIFDistinguishedName']:
        """
        Get parent DN by removing the RDN.

        Returns:
            Parent DN or None if this is a root DN

        Example:
            >>> dn = FlextLDIFDistinguishedName("cn=user,ou=people,dc=example,dc=com")
            >>> parent = dn.get_parent()
            >>> print(parent.value)  # "ou=people,dc=example,dc=com"
        """
        components = self._parse_components()
        if len(components) <= 1:
            return None

        parent_dn = ",".join(components[1:])
        return FlextLDIFDistinguishedName(parent_dn)

    def get_depth(self) -> int:
        """
        Get DN depth (number of components).

        Returns:
            Number of DN components

        Example:
            >>> dn = FlextLDIFDistinguishedName("cn=user,ou=people,dc=example,dc=com")
            >>> depth = dn.get_depth()
            >>> print(depth)  # 4
        """
        return len(self._parse_components())

    def is_child_of(self, parent: 'FlextLDIFDistinguishedName') -> bool:
        """
        Check if this DN is a child of the specified parent DN.

        Args:
            parent: Potential parent DN

        Returns:
            True if this DN is a direct child of parent

        Example:
            >>> child = FlextLDIFDistinguishedName("cn=user,ou=people,dc=example,dc=com")
            >>> parent = FlextLDIFDistinguishedName("ou=people,dc=example,dc=com")
            >>> print(child.is_child_of(parent))  # True
        """
        my_parent = self.get_parent()
        return my_parent is not None and my_parent.value.lower() == parent.value.lower()

    def is_ancestor_of(self, descendant: 'FlextLDIFDistinguishedName') -> bool:
        """
        Check if this DN is an ancestor of the specified descendant DN.

        Args:
            descendant: Potential descendant DN

        Returns:
            True if this DN is an ancestor of descendant
        """
        return descendant.value.lower().endswith(self.value.lower())

    def get_components(self) -> List[str]:
        """
        Get all DN components as a list.

        Returns:
            List of DN components from RDN to root

        Example:
            >>> dn = FlextLDIFDistinguishedName("cn=user,ou=people,dc=example,dc=com")
            >>> components = dn.get_components()
            >>> print(components)  # ["cn=user", "ou=people", "dc=example", "dc=com"]:
        """
        return self._parse_components()

    def get_attribute_type(self) -> str:
        """
        Get the attribute type of the RDN.

        Returns:
            Attribute type of the leftmost RDN component

        Example:
            >>> dn = FlextLDIFDistinguishedName("cn=user,ou=people,dc=example,dc=com")
            >>> attr_type = dn.get_attribute_type()
            >>> print(attr_type)  # "cn"
        """
        rdn = self.get_rdn()
        if "=" not in rdn:
            raise FlextLDIFDomainError(f"Invalid RDN format: {rdn}")

        return rdn.split("=", 1)[0].strip()

    def get_attribute_value(self) -> str:
        """
        Get the attribute value of the RDN.

        Returns:
            Attribute value of the leftmost RDN component

        Example:
            >>> dn = FlextLDIFDistinguishedName("cn=user,ou=people,dc=example,dc=com")
            >>> attr_value = dn.get_attribute_value()
            >>> print(attr_value)  # "user"
        """
        rdn = self.get_rdn()
        if "=" not in rdn:
            raise FlextLDIFDomainError(f"Invalid RDN format: {rdn}")

        return rdn.split("=", 1)[1].strip()

    def _parse_components(self) -> List[str]:
        """Parse DN into components handling escaped characters."""
        # Simplified parsing - in production, use proper LDAP DN parser
        components = []
        current = ""
        escaped = False

        for char in self.value:
            if escaped:
                current += char
                escaped = False
            elif char == "\\":
                current += char
                escaped = True
            elif char == ",":
                components.append(current.strip())
                current = ""
            else:
                current += char

        if current.strip():
            components.append(current.strip())

        return components

    def _validate_dn_syntax(self) -> None:
        """Validate DN syntax according to RFC standards."""
        # Basic DN validation - enhance with proper RFC 4514 validation
        components = self._parse_components()

        for component in components:
            if "=" not in component:
                raise FlextLDIFDomainError(f"Invalid DN component: {component}")

            attr_type, attr_value = component.split("=", 1)

            if not attr_type.strip():
                raise FlextLDIFDomainError(f"Empty attribute type in: {component}")

            if not attr_value.strip():
                raise FlextLDIFDomainError(f"Empty attribute value in: {component}")

@dataclass(frozen=True)
class FlextLDIFAttributes(FlextModels.Value):
    """
    Immutable attributes collection with business rule validation.

    Represents LDIF entry attributes as an immutable collection with
    business logic for attribute manipulation and validation.

    Attributes:
        attributes: Dictionary mapping attribute names to value lists

    Business Rules:
        - Attribute names must follow LDAP naming conventions
        - Values cannot be empty unless explicitly allowed
        - objectClass attribute has special validation rules
        - Binary attributes must be properly encoded
    """

    attributes: Dict[str, List[str]]

    def __post_init__(self) -> None:
        """Validate attributes and business rules."""
        self._validate_attribute_names()
        self._validate_attribute_values()

    def get_values(self, name: str) -> List[str]:
        """
        Get all values for an attribute.

        Args:
            name: Attribute name (case-insensitive)

        Returns:
            List of attribute values, empty list if attribute doesn't exist

        Example:
            >>> attrs = FlextLDIFAttributes({"mail": ["user@example.com", "alt@example.com"]})
            >>> emails = attrs.get_values("mail")
            >>> print(emails)  # ["user@example.com", "alt@example.com"]:
        """
        return self.attributes.get(name.lower(), [])

    def get_single_value(self, name: str) -> Optional[str]:
        """
        Get first value of an attribute.

        Args:
            name: Attribute name (case-insensitive)

        Returns:
            First attribute value or None if attribute doesn't exist

        Example:
            >>> attrs = FlextLDIFAttributes({"cn": ["John Doe"]})
            >>> name = attrs.get_single_value("cn")
            >>> print(name)  # "John Doe"
        """
        values = self.get_values(name)
        return values[0] if values else None

    def has_attribute(self, name: str) -> bool:
        """
        Check if attribute exists.

        Args:
            name: Attribute name (case-insensitive)

        Returns:
            True if attribute exists with at least one value
        """
        return bool(self.get_values(name))

    def add_values(self, name: str, values: List[str]) -> 'FlextLDIFAttributes':
        """
        Return new instance with added attribute values.

        Args:
            name: Attribute name
            values: Values to add

        Returns:
            New FlextLDIFAttributes instance with added values

        Example:
            >>> attrs = FlextLDIFAttributes({"cn": ["John"]})
            >>> new_attrs = attrs.add_values("mail", ["john@example.com"])
            >>> print(new_attrs.get_values("mail"))  # ["john@example.com"]:
        """
        new_attributes = dict(self.attributes)
        existing_values = new_attributes.get(name.lower(), [])
        new_attributes[name.lower()] = existing_values + [v for v in values if v not in existing_values]

        return FlextLDIFAttributes(new_attributes)

    def remove_values(self, name: str, values: List[str]) -> 'FlextLDIFAttributes':
        """
        Return new instance with removed attribute values.

        Args:
            name: Attribute name
            values: Values to remove

        Returns:
            New FlextLDIFAttributes instance with removed values
        """
        new_attributes = dict(self.attributes)
        existing_values = new_attributes.get(name.lower(), [])
        new_values = [v for v in existing_values if v not in values]

        if new_values:
            new_attributes[name.lower()] = new_values
        else:
            new_attributes.pop(name.lower(), None)

        return FlextLDIFAttributes(new_attributes)

    def remove_attribute(self, name: str) -> 'FlextLDIFAttributes':
        """
        Return new instance with entire attribute removed.

        Args:
            name: Attribute name to remove

        Returns:
            New FlextLDIFAttributes instance without the attribute
        """
        new_attributes = dict(self.attributes)
        new_attributes.pop(name.lower(), None)
        return FlextLDIFAttributes(new_attributes)

    def get_attribute_names(self) -> Set[str]:
        """
        Get all attribute names.

        Returns:
            Set of attribute names
        """
        return set(self.attributes.keys())

    def get_total_values(self) -> int:
        """
        Get total number of values across all attributes.

        Returns:
            Total value count
        """
        return sum(len(values) for values in self.attributes.values())

    def is_empty(self) -> bool:
        """
        Check if no attributes are defined.

        Returns:
            True if no attributes exist
        """
        return len(self.attributes) == 0

    def _validate_attribute_names(self) -> None:
        """Validate attribute naming conventions."""
        for name in self.attributes.keys():
            if not re.match(r'^[a-zA-Z][a-zA-Z0-9-]*$', name):
                raise FlextLDIFDomainError(f"Invalid attribute name: {name}")

    def _validate_attribute_values(self) -> None:
        """Validate attribute values according to business rules."""
        for name, values in self.attributes.items():
            if not values:
                raise FlextLDIFDomainError(f"Empty value list for attribute: {name}")

            for value in values:
                if not isinstance(value, str):
                    raise FlextLDIFDomainError(f"Non-string value for attribute {name}: {value}")
```

### **2. Application Layer** (`application/`)

**Purpose**: Orchestrates domain objects and implements use cases.

#### **services.py** - Application Services

```python
"""
FLEXT-LDIF Application Services

This module contains application services that orchestrate domain operations
and implement use cases for LDIF processing, following Clean Architecture
and CQRS patterns.

Key Components:
    - FlextLDIFAPI: Main application service for LDIF operations
    - FlextLDIFQueryService: Read-side query operations
    - FlextLDIFCommandService: Write-side command operations

Architecture:
    Part of Application Layer in Clean Architecture, orchestrates domain
    objects and implements business use cases without containing business logic.

Example:
    >>> from flext_ldif.application import FlextLDIFAPI
    >>> api = FlextLDIFAPI()
    >>> result = api.parse_ldif(content)
    >>> if result.is_success:
    >>>     entries = result.value

Integration:
    - Uses flext-core FlextResult for error handling
    - Orchestrates Domain Layer entities and services
    - Coordinates with Infrastructure Layer services
    - Implements CQRS patterns for command/query separation

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from typing import List, Optional, Dict, object
from pathlib import Path
from flext_core import FlextResult, FlextLogger
from ..domain import FlextLDIFEntry, FlextLDIFDistinguishedName, FlextLDIFAttributes
from ..infrastructure import FlextLDIFSettings, FlextLDIFServices.ParserService, FlextLDIFServices.ValidatorService, FlextLDIFServices.WriterService
from .commands import ParseLdifCommand, ValidateLdifCommand, WriteLdifCommand
from .queries import GetEntriesQuery, SearchEntriesQuery

logger = FlextLogger(__name__)

class FlextLDIFAPI:
    """
    Main application service providing unified LDIF operations.

    This service orchestrates domain operations and provides a clean API
    for LDIF parsing, validation, transformation, and output generation,
    implementing use cases with proper error handling and logging.

    The service follows the Application Service pattern from Clean Architecture,
    delegating business logic to domain objects and coordinating with
    infrastructure services.
    """

    def __init__(
        self,
        settings: Optional[FlextLDIFSettings] = None,
        parser_service: Optional[FlextLDIFServices.ParserService] = None,
        validator_service: Optional[FlextLDIFServices.ValidatorService] = None,
        writer_service: Optional[FlextLDIFServices.WriterService] = None
    ) -> None:
        """
        Initialize LDIF API with optional service dependencies.

        Args:
            settings: Configuration settings, uses defaults if None
            parser_service: LDIF parser service, creates default if None
            validator_service: Validator service, creates default if None
            writer_service: Writer service, creates default if None
        """
        self._settings = settings or FlextLDIFSettings()
        self._parser = parser_service or FlextLDIFServices.ParserService(self._settings)
        self._validator = validator_service or FlextLDIFServices.ValidatorService(self._settings)
        self._writer = writer_service or FlextLDIFServices.WriterService(self._settings)

        logger.info("FlextLDIFAPI initialized", extra={
            "max_entries": self._settings.max_entries,
            "strict_validation": self._settings.strict_validation
        })

    def parse_ldif(self, content: str) -> FlextResult[List[FlextLDIFEntry]]:
        """
        Parse LDIF content into domain entities.

        This method implements the "Parse LDIF Content" use case, orchestrating
        the parsing process with proper error handling and validation.

        Args:
            content: LDIF content string to parse

        Returns:
            FlextResult containing list of parsed entries or error details

        Example:
            >>> api = FlextLDIFAPI()
            >>> content = "dn: cn=user,dc=example,dc=com\\ncn: user\\n"
            >>> result = api.parse_ldif(content)
            >>> if result.is_success:
            >>>     entries = result.value
            >>>     print(f"Parsed {len(entries)} entries")
        """
        logger.debug("Starting LDIF parsing", extra={"content_length": len(content)})

        # Create and execute parse command
        command = ParseLdifCommand(content=content, settings=self._settings)
        result = self._parser.execute_parse_command(command)

        if result.is_success:
            entries = result.value
            logger.info("LDIF parsing completed successfully", extra={
                "entries_count": len(entries),
                "content_length": len(content)
            })
        else:
            logger.error("LDIF parsing failed", extra={
                "error": result.error,
                "content_length": len(content)
            })

        return result

    def parse_ldif_file(self, file_path: Path) -> FlextResult[List[FlextLDIFEntry]]:
        """
        Parse LDIF file into domain entities.

        This method implements the "Parse LDIF File" use case, handling
        file I/O operations and delegating parsing to the content parser.

        Args:
            file_path: Path to LDIF file

        Returns:
            FlextResult containing list of parsed entries or error details

        Example:
            >>> api = FlextLDIFAPI()
            >>> result = api.parse_ldif_file(Path("data.ldif"))
            >>> if result.is_success:
            >>>     entries = result.value
        """
        logger.debug("Starting LDIF file parsing", extra={"file_path": str(file_path)})

        try:
            if not file_path.exists():
                return FlextResult[None].fail(f"LDIF file not found: {file_path}")

            # Read file with proper encoding
            content = file_path.read_text(encoding=self._settings.input_encoding)

            # Delegate to content parser
            return self.parse_ldif(content)

        except Exception as e:
            error_msg: str = f"Failed to read LDIF file {file_path}: {str(e)}"
            logger.error("LDIF file parsing failed", extra={
                "file_path": str(file_path),
                "error": str(e)
            })
            return FlextResult[None].fail(error_msg)

    def validate_entries(self, entries: List[FlextLDIFEntry]) -> FlextResult[bool]:
        """
        Validate LDIF entries against business rules.

        This method implements the "Validate LDIF Entries" use case,
        orchestrating validation across all entries with comprehensive reporting.

        Args:
            entries: List of LDIF entries to validate

        Returns:
            FlextResult indicating validation success/failure

        Example:
            >>> api = FlextLDIFAPI()
            >>> result = api.validate_entries(entries)
            >>> if result.is_success:
            >>>     print("All entries are valid")
        """
        logger.debug("Starting LDIF validation", extra={"entries_count": len(entries)})

        # Create and execute validation command
        command = ValidateLdifCommand(entries=entries, settings=self._settings)
        result = self._validator.execute_validate_command(command)

        if result.is_success:
            logger.info("LDIF validation completed successfully", extra={
                "entries_count": len(entries),
                "validation_passed": True
            })
        else:
            logger.warning("LDIF validation failed", extra={
                "entries_count": len(entries),
                "error": result.error
            })

        return result

    def write_ldif(self, entries: List[FlextLDIFEntry]) -> FlextResult[str]:
        """
        Generate LDIF output from domain entities.

        This method implements the "Generate LDIF Output" use case,
        orchestrating the writing process with proper formatting and validation.

        Args:
            entries: List of LDIF entries to write

        Returns:
            FlextResult containing generated LDIF string or error details

        Example:
            >>> api = FlextLDIFAPI()
            >>> result = api.write_ldif(entries)
            >>> if result.is_success:
            >>>     ldif_content = result.value
            >>>     print(ldif_content)
        """
        logger.debug("Starting LDIF writing", extra={"entries_count": len(entries)})

        # Create and execute write command
        command = WriteLdifCommand(entries=entries, settings=self._settings)
        result = self._writer.execute_write_command(command)

        if result.is_success:
            content = result.value
            logger.info("LDIF writing completed successfully", extra={
                "entries_count": len(entries),
                "output_length": len(content)
            })
        else:
            logger.error("LDIF writing failed", extra={
                "entries_count": len(entries),
                "error": result.error
            })

        return result

    def write_ldif_file(self, entries: List[FlextLDIFEntry], file_path: Path) -> FlextResult[bool]:
        """
        Write LDIF entries to file.

        This method implements the "Write LDIF File" use case,
        handling file I/O operations and delegating content generation.

        Args:
            entries: List of LDIF entries to write
            file_path: Output file path

        Returns:
            FlextResult indicating write success/failure

        Example:
            >>> api = FlextLDIFAPI()
            >>> result = api.write_ldif_file(entries, Path("output.ldif"))
            >>> if result.is_success:
            >>>     print("File written successfully")
        """
        logger.debug("Starting LDIF file writing", extra={
            "entries_count": len(entries),
            "file_path": str(file_path)
        })

        try:
            # Generate LDIF content
            content_result = self.write_ldif(entries)
            if content_result.is_failure:
                return FlextResult[None].fail(f"Failed to generate LDIF content: {content_result.error}")

            # Write to file with proper encoding
            file_path.write_text(content_result.value, encoding=self._settings.output_encoding)

            logger.info("LDIF file writing completed successfully", extra={
                "entries_count": len(entries),
                "file_path": str(file_path)
            })

            return FlextResult[None].ok(data=True)

        except Exception as e:
            error_msg: str = f"Failed to write LDIF file {file_path}: {str(e)}"
            logger.error("LDIF file writing failed", extra={
                "file_path": str(file_path),
                "error": str(e)
            })
            return FlextResult[None].fail(error_msg)

    def search_entries(
        self,
        entries: List[FlextLDIFEntry],
        filter_criteria: Dict[str, object]
    ) -> FlextResult[List[FlextLDIFEntry]]:
        """
        Search LDIF entries based on filter criteria.

        This method implements the "Search LDIF Entries" use case,
        providing flexible entry filtering capabilities.

        Args:
            entries: List of entries to search
            filter_criteria: Search criteria (objectClass, attributes, etc.)

        Returns:
            FlextResult containing filtered entries or error details

        Example:
            >>> api = FlextLDIFAPI()
            >>> criteria = {"objectClass": "person", "mail": "*@example.com"}
            >>> result = api.search_entries(entries, criteria)
            >>> if result.is_success:
            >>>     matching_entries = result.value
        """
        logger.debug("Starting LDIF entry search", extra={
            "entries_count": len(entries),
            "filter_criteria": filter_criteria
        })

        # Create and execute search query
        query = SearchEntriesQuery(entries=entries, criteria=filter_criteria)
        # Implementation would use a query handler service

        # Simplified implementation for example
        try:
            filtered_entries = []
            for entry in entries:
                if self._matches_criteria(entry, filter_criteria):
                    filtered_entries.append(entry)

            logger.info("LDIF entry search completed", extra={
                "entries_count": len(entries),
                "matches_found": len(filtered_entries)
            })

            return FlextResult[None].ok(filtered_entries)

        except Exception as e:
            error_msg: str = f"Search failed: {str(e)}"
            logger.error("LDIF entry search failed", extra={"error": str(e)})
            return FlextResult[None].fail(error_msg)

    def _matches_criteria(self, entry: FlextLDIFEntry, criteria: Dict[str, object]) -> bool:
        """Check if entry matches search criteria."""
        for key, value in criteria.items():
            if key == "objectClass":
                if not entry.has_object_class(value):
                    return False
            elif key == "dn":
                if value not in entry.dn.value:
                    return False
            else:
                # Attribute-based filtering
                entry_values = entry.attributes.get_values(key)
                if isinstance(value, str) and value.endswith("*"):
                    # Wildcard matching
                    prefix = value[:-1]
                    if not any(v.startswith(prefix) for v in entry_values):
                        return False
                else:
                    if value not in entry_values:
                        return False

        return True
```

### **3. Infrastructure Layer** (`infrastructure/`)

**Purpose**: Handles external concerns and technical implementation details.

#### **config.py** - Configuration Management

```python
"""
FLEXT-LDIF Infrastructure Configuration

This module contains configuration management for LDIF processing infrastructure,
extending flext-core configuration patterns with LDIF-specific settings.

Key Components:
    - FlextLDIFSettings: Main configuration class extending FlextConfig
    - Environment variable integration
    - Validation and defaults management

Architecture:
    Part of Infrastructure Layer in Clean Architecture, handles external
    configuration concerns and provides typed configuration objects.

Example:
    >>> from flext_ldif.infrastructure import FlextLDIFSettings
    >>> settings = FlextLDIFSettings()
    >>> print(settings.max_entries)  # 10000

Integration:
    - Extends flext-core FlextConfig
    - Supports environment variable configuration
    - Integrates with Pydantic validation
    - Used by Application and Infrastructure services

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from typing import Optional, Dict, List

from pathlib import Path
from flext_core import FlextConfig
from pydantic import Field, validator

class FlextLDIFSettings(FlextConfig):
    """
    LDIF processing configuration extending FLEXT foundation settings.

    This configuration class provides comprehensive settings for LDIF processing
    operations, including parsing limits, validation rules, encoding options,
    and performance tuning parameters.

    All settings support environment variable override using the LDIF_ prefix
    and provide sensible defaults for production use.

    Attributes:
        Processing Limits:
            max_entries: Maximum number of entries to process
            max_attribute_values: Maximum values per attribute
            max_dn_length: Maximum DN length in characters
            max_line_length: Maximum LDIF line length

        Validation Settings:
            strict_validation: Enable strict business rule validation
            allow_empty_attributes: Allow attributes with empty values
            validate_object_classes: Validate objectClass requirements
            validate_dn_syntax: Validate DN syntax according to RFC

        Encoding Settings:
            input_encoding: File input encoding
            output_encoding: File output encoding
            line_separator: Line separator for output

        Performance Settings:
            buffer_size: I/O buffer size for file operations
            enable_streaming: Enable streaming for large files
            parse_timeout: Parse timeout in seconds
            memory_limit_mb: Memory limit for processing

        Output Formatting:
            wrap_lines: Wrap long lines at specified length
            sort_attributes: Sort attributes alphabetically in output
            include_empty_lines: Include empty lines between entries
            fold_line_length: Line folding length (RFC 2849)
    """

    # Processing Limits
    max_entries: int = Field(
        default=10000,
        ge=1,
        le=1000000,
        description="Maximum number of LDIF entries to process in a single operation"
    )

    max_attribute_values: int = Field(
        default=1000,
        ge=1,
        le=10000,
        description="Maximum number of values allowed per attribute"
    )

    max_dn_length: int = Field(
        default=1024,
        ge=1,
        le=8192,
        description="Maximum length of distinguished names in characters"
    )

    max_line_length: int = Field(
        default=10000,
        ge=76,
        le=100000,
        description="Maximum LDIF line length before folding"
    )

    # Validation Settings
    strict_validation: bool = Field(
        default=True,
        description="Enable strict business rule validation for all operations"
    )

    allow_empty_attributes: bool = Field(
        default=False,
        description="Allow attributes with empty or whitespace-only values"
    )

    validate_object_classes: bool = Field(
        default=True,
        description="Validate objectClass attribute requirements and dependencies"
    )

    validate_dn_syntax: bool = Field(
        default=True,
        description="Validate DN syntax according to RFC 4514 standards"
    )

    require_dn_for_entries: bool = Field(
        default=True,
        description="Require DN attribute for all non-change entries"
    )

    # Encoding Settings
    input_encoding: str = Field(
        default="utf-8",
        description="Character encoding for input LDIF files"
    )

    output_encoding: str = Field(
        default="utf-8",
        description="Character encoding for output LDIF files"
    )

    line_separator: str = Field(
        default="\n",
        description="Line separator character for output formatting"
    )

    # Performance Settings
    buffer_size: int = Field(
        default=8192,
        ge=1024,
        le=1048576,
        description="I/O buffer size in bytes for file operations"
    )

    enable_streaming: bool = Field(
        default=False,
        description="Enable streaming mode for processing large LDIF files"
    )

    parse_timeout: float = Field(
        default=300.0,
        ge=1.0,
        le=3600.0,
        description="Parse operation timeout in seconds"
    )

    memory_limit_mb: int = Field(
        default=512,
        ge=64,
        le=8192,
        description="Memory limit in megabytes for LDIF processing"
    )

    # Output Formatting
    wrap_lines: bool = Field(
        default=True,
        description="Wrap long lines according to LDIF specification"
    )

    fold_line_length: int = Field(
        default=76,
        ge=20,
        le=200,
        description="Line folding length according to RFC 2849"
    )

    sort_attributes: bool = Field(
        default=False,
        description="Sort attributes alphabetically in output"
    )

    include_empty_lines: bool = Field(
        default=True,
        description="Include empty lines between entries in output"
    )

    # Integration Settings
    enable_observability: bool = Field(
        default=True,
        description="Enable observability integration with flext-observability"
    )

    enable_ldap_integration: bool = Field(
        default=False,
        description="Enable LDAP server integration with flext-ldap"
    )

    log_level: str = Field(
        default="INFO",
        description="Logging level for LDIF operations"
    )

    metric_prefix: str = Field(
        default="flext_ldif",
        description="Prefix for metrics collection"
    )

    # Feature Flags
    enable_schema_validation: bool = Field(
        default=False,
        description="Enable LDAP schema validation (requires flext-ldap integration)"
    )

    enable_change_records: bool = Field(
        default=True,
        description="Enable processing of LDIF change records"
    )

    enable_binary_attributes: bool = Field(
        default=True,
        description="Enable processing of binary attributes with base64 encoding"
    )

    enable_url_attributes: bool = Field(
        default=False,
        description="Enable processing of URL-based attribute values"
    )

    # LDAP Integration Settings (when enabled)
    ldap_server_url: Optional[str] = Field(
        default=None,
        description="LDAP server URL for schema validation and integration"
    )

    ldap_bind_dn: Optional[str] = Field(
        default=None,
        description="LDAP bind DN for authenticated operations"
    )

    ldap_base_dn: Optional[str] = Field(
        default=None,
        description="Base DN for LDAP operations and validation"
    )

    # Development and Testing
    debug_mode: bool = Field(
        default=False,
        description="Enable debug mode with verbose logging and validation"
    )

    test_mode: bool = Field(
        default=False,
        description="Enable test mode with relaxed validation"
    )

    @validator("log_level")
    def validate_log_level(cls, v: str) -> str:
        """Validate log level values."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v.upper()

    @validator("input_encoding", "output_encoding")
    def validate_encoding(cls, v: str) -> str:
        """Validate encoding names."""
        try:
            import codecs
            codecs.lookup(v)
            return v
        except LookupError:
            raise ValueError(f"Invalid encoding: {v}")

    @validator("line_separator")
    def validate_line_separator(cls, v: str) -> str:
        """Validate line separator values."""
        valid_separators = {"\n", "\r\n", "\r"}
        if v not in valid_separators:
            raise ValueError(f"Invalid line separator. Must be one of {valid_separators}")
        return v

    @validator("ldap_server_url")
    def validate_ldap_url(cls, v: Optional[str]) -> Optional[str]:
        """Validate LDAP server URL format."""
        if v is None:
            return v

        if not v.lower().startswith(("ldap://", "ldaps://")):
            raise ValueError("LDAP server URL must start with ldap:// or ldaps://")

        return v

    def get_effective_memory_limit_bytes(self) -> int:
        """Get memory limit in bytes."""
        return self.memory_limit_mb * 1024 * 1024

    def is_large_file_mode_enabled(self) -> bool:
        """Check if large file processing optimizations should be enabled."""
        return self.enable_streaming or self.max_entries > 50000

    def get_performance_profile(self) -> Dict[str, object]:
        """Get performance configuration profile."""
        return {
            "streaming_enabled": self.enable_streaming,
            "buffer_size": self.buffer_size,
            "memory_limit_mb": self.memory_limit_mb,
            "parse_timeout": self.parse_timeout,
            "max_entries": self.max_entries,
            "large_file_mode": self.is_large_file_mode_enabled()
        }

    def get_validation_profile(self) -> Dict[str, object]:
        """Get validation configuration profile."""
        return {
            "strict_validation": self.strict_validation,
            "validate_object_classes": self.validate_object_classes,
            "validate_dn_syntax": self.validate_dn_syntax,
            "allow_empty_attributes": self.allow_empty_attributes,
            "schema_validation": self.enable_schema_validation
        }

    class Config:
        """Pydantic configuration for FlextLDIFSettings."""

        env_prefix = "LDIF_"
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        validate_assignment = True
        extra = "forbid"  # Prevent unknown configuration keys

        # JSON schema configuration
        schema_extra = {
            "example": {
                "max_entries": 10000,
                "strict_validation": True,
                "input_encoding": "utf-8",
                "enable_observability": True,
                "log_level": "INFO"
            }
        }
```

### **4. Interface Layer** (`interfaces/`)

**Purpose**: Provides user interfaces and external API contracts.

#### **cli.py** - Command Line Interface

```python
"""
FLEXT-LDIF Command Line Interface

This module implements the command-line interface for FLEXT-LDIF operations,
providing a comprehensive CLI for LDIF processing, validation, and transformation.

Key Components:
    - Main CLI application with Click framework
    - Command groups for different operations
    - Rich output formatting and progress indicators
    - Configuration file support

Architecture:
    Part of Interface Layer in Clean Architecture, provides user interface
    for accessing application services without containing business logic.

Example:
    $ flext-ldif parse sample.ldif
    $ flext-ldif validate --strict data.ldif
    $ flext-ldif transform --filter "objectClass=person" input.ldif output.ldif

Integration:
    - Uses Application Layer services for business operations
    - Integrates with flext-core logging and configuration
    - Provides unified CLI experience across FLEXT ecosystem
    - Supports observability and monitoring integration

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

import click
from typing import Optional, Dict, List

from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
import json
import sys

from flext_core import FlextLogger, FlextResult
from ..application import FlextLDIFAPI
from ..infrastructure import FlextLDIFSettings
from ..domain import FlextLDIFEntry

logger = FlextLogger(__name__)
console = Console()

# CLI Configuration
CONTEXT_SETTINGS = dict(
    help_option_names=['-h', '--help'],
    max_content_width=120,
    show_default=True
)

@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version='0.9.0', prog_name='flext-ldif')
@click.option(
    '--config', '-c',
    type=click.Path(exists=True, path_type=Path),
    help='Configuration file path'
)
@click.option(
    '--log-level', '-l',
    type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], case_sensitive=False),
    default='INFO',
    help='Set logging level'
)
@click.option(
    '--quiet', '-q',
    is_flag=True,
    help='Suppress output except errors'
)
@click.option(
    '--verbose', '-v',
    is_flag=True,
    help='Enable verbose output'
)
@click.pass_context
def cli(ctx: click.Context, config: Optional[Path], log_level: str, quiet: bool, verbose: bool):
    """
    FLEXT-LDIF - Enterprise LDIF Processing Tool

    A comprehensive command-line tool for LDIF (LDAP Data Interchange Format)
    processing, validation, transformation, and analysis.

    Examples:
        flext-ldif parse sample.ldif
        flext-ldif validate --strict users.ldif
        flext-ldif transform --filter "objectClass=person" input.ldif output.ldif
        flext-ldif analyze --report json data.ldif
    """
    # Initialize CLI context
    ctx.ensure_object(dict)

    # Load configuration
    if config:
        try:
            settings = FlextLDIFSettings.from_file(config)
        except Exception as e:
            console.print(f"[red]Error loading config file: {e}[/red]")
            sys.exit(1)
    else:
        settings = FlextLDIFSettings()

    # Override log level from command line
    settings.log_level = log_level

    # Set quiet/verbose modes
    if quiet:
        settings.log_level = "ERROR"
    elif verbose:
        settings.log_level = "DEBUG"

    # Initialize API
    api = FlextLDIFAPI(settings)

    # Store in context
    ctx.obj['api'] = api
    ctx.obj['settings'] = settings
    ctx.obj['quiet'] = quiet
    ctx.obj['verbose'] = verbose

@cli.command()
@click.argument('input_file', type=click.Path(exists=True, path_type=Path))
@click.option(
    '--output', '-o',
    type=click.Path(path_type=Path),
    help='Output file path (default: stdout)'
)
@click.option(
    '--format', '-f',
    type=click.Choice(['ldif', 'json', 'yaml', 'csv'], case_sensitive=False),
    default='ldif',
    help='Output format'
)
@click.option(
    '--max-entries', '-n',
    type=int,
    help='Maximum number of entries to parse'
)
@click.option(
    '--encoding',
    default='utf-8',
    help='Input file encoding'
)
@click.pass_context
def parse(
    ctx: click.Context,
    input_file: Path,
    output: Optional[Path],
    format: str,
    max_entries: Optional[int],
    encoding: str
):
    """
    Parse LDIF file and optionally convert to other formats.

    This command parses an LDIF file, validates the content, and can output
    the parsed data in various formats for analysis or integration.

    Examples:
        flext-ldif parse users.ldif
        flext-ldif parse --format json --output users.json data.ldif
        flext-ldif parse --max-entries 100 large-file.ldif
    """
    api: FlextLDIFAPI = ctx.obj['api']
    settings: FlextLDIFSettings = ctx.obj['settings']
    quiet: bool = ctx.obj['quiet']

    # Override settings if specified
    if max_entries:
        settings.max_entries = max_entries
    if encoding:
        settings.input_encoding = encoding

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            disable=quiet
        ) as progress:
            task = progress.add_task("Parsing LDIF file...", total=None)

            # Parse LDIF file
            result = api.parse_ldif_file(input_file)

            if result.is_failure:
                console.print(f"[red]Parse failed: {result.error}[/red]")
                sys.exit(1)

            entries = result.value
            progress.update(task, description=f"Parsed {len(entries)} entries")

        if not quiet:
            console.print(f"[green]✓[/green] Successfully parsed {len(entries)} entries")

        # Output results
        if output:
            _write_output(entries, output, format, settings)
            if not quiet:
                console.print(f"[green]✓[/green] Output written to {output}")
        else:
            _print_output(entries, format, quiet)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.exception("CLI parse command failed")
        sys.exit(1)

@cli.command()
@click.argument('input_file', type=click.Path(exists=True, path_type=Path))
@click.option(
    '--strict',
    is_flag=True,
    help='Enable strict validation mode'
)
@click.option(
    '--schema',
    type=click.Path(exists=True, path_type=Path),
    help='LDAP schema file for validation'
)
@click.option(
    '--report', '-r',
    type=click.Choice(['summary', 'detailed', 'json'], case_sensitive=False),
    default='summary',
    help='Validation report format'
)
@click.option(
    '--output', '-o',
    type=click.Path(path_type=Path),
    help='Save validation report to file'
)
@click.pass_context
def validate(
    ctx: click.Context,
    input_file: Path,
    strict: bool,
    schema: Optional[Path],
    report: str,
    output: Optional[Path]
):
    """
    Validate LDIF file against business rules and optionally LDAP schema.

    This command performs comprehensive validation of LDIF files, checking
    syntax, business rules, and optionally validating against LDAP schema.

    Examples:
        flext-ldif validate users.ldif
        flext-ldif validate --strict --report detailed data.ldif
        flext-ldif validate --schema company.schema users.ldif
    """
    api: FlextLDIFAPI = ctx.obj['api']
    settings: FlextLDIFSettings = ctx.obj['settings']
    quiet: bool = ctx.obj['quiet']

    # Configure validation settings
    if strict:
        settings.strict_validation = True
        settings.validate_object_classes = True
        settings.validate_dn_syntax = True

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            disable=quiet
        ) as progress:
            # Parse file first
            parse_task = progress.add_task("Parsing LDIF file...", total=None)
            parse_result = api.parse_ldif_file(input_file)

            if parse_result.is_failure:
                console.print(f"[red]Parse failed: {parse_result.error}[/red]")
                sys.exit(1)

            entries = parse_result.value
            progress.update(parse_task, description=f"Parsed {len(entries)} entries")

            # Validate entries
            validate_task = progress.add_task("Validating entries...", total=None)
            validate_result = api.validate_entries(entries)

            progress.update(validate_task, description="Validation complete")

        # Generate validation report
        validation_report = _generate_validation_report(
            entries, validate_result, report, strict, schema
        )

        # Output report
        if output:
            output.write_text(validation_report, encoding='utf-8')
            if not quiet:
                console.print(f"[green]✓[/green] Validation report saved to {output}")
        else:
            console.print(validation_report)

        # Exit with appropriate code
        if validate_result.is_success:
            if not quiet:
                console.print("[green]✓ All entries are valid[/green]")
            sys.exit(0)
        else:
            if not quiet:
                console.print("[red]✗ Validation failed[/red]")
            sys.exit(1)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.exception("CLI validate command failed")
        sys.exit(1)

@cli.command()
@click.argument('input_file', type=click.Path(exists=True, path_type=Path))
@click.argument('output_file', type=click.Path(path_type=Path))
@click.option(
    '--filter',
    'filter_expr',
    help='Filter expression (e.g., "objectClass=person")'
)
@click.option(
    '--transform',
    help='Transformation rules (JSON format)'
)
@click.option(
    '--sort-by',
    help='Sort entries by attribute'
)
@click.option(
    '--limit', '-n',
    type=int,
    help='Limit number of output entries'
)
@click.pass_context
def transform(
    ctx: click.Context,
    input_file: Path,
    output_file: Path,
    filter_expr: Optional[str],
    transform: Optional[str],
    sort_by: Optional[str],
    limit: Optional[int]
):
    """
    Transform LDIF file with filtering, sorting, and modification.

    This command provides comprehensive LDIF transformation capabilities
    including filtering, attribute modification, sorting, and reformatting.

    Examples:
        flext-ldif transform --filter "objectClass=person" input.ldif output.ldif
        flext-ldif transform --sort-by cn --limit 100 users.ldif sorted.ldif
        flext-ldif transform --transform '{"add": {"department": "IT"}}' input.ldif output.ldif
    """
    api: FlextLDIFAPI = ctx.obj['api']
    quiet: bool = ctx.obj['quiet']

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            disable=quiet
        ) as progress:
            # Parse input file
            parse_task = progress.add_task("Parsing input file...", total=None)
            parse_result = api.parse_ldif_file(input_file)

            if parse_result.is_failure:
                console.print(f"[red]Parse failed: {parse_result.error}[/red]")
                sys.exit(1)

            entries = parse_result.value
            progress.update(parse_task, description=f"Parsed {len(entries)} entries")

            # Apply transformations
            transform_task = progress.add_task("Applying transformations...", total=None)

            # Apply filter
            if filter_expr:
                filter_criteria = _parse_filter_expression(filter_expr)
                filter_result = api.search_entries(entries, filter_criteria)
                if filter_result.is_success:
                    entries = filter_result.value
                    progress.update(transform_task, description=f"Filtered to {len(entries)} entries")

            # Apply transformations
            if transform:
                transform_rules = json.loads(transform)
                entries = _apply_transformations(entries, transform_rules)

            # Apply sorting
            if sort_by:
                entries = _sort_entries(entries, sort_by)

            # Apply limit
            if limit:
                entries = entries[:limit]
                progress.update(transform_task, description=f"Limited to {len(entries)} entries")

            # Write output
            write_task = progress.add_task("Writing output file...", total=None)
            write_result = api.write_ldif_file(entries, output_file)

            if write_result.is_failure:
                console.print(f"[red]Write failed: {write_result.error}[/red]")
                sys.exit(1)

            progress.update(write_task, description="Output written")

        if not quiet:
            console.print(f"[green]✓[/green] Transformed {len(entries)} entries to {output_file}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.exception("CLI transform command failed")
        sys.exit(1)

@cli.command()
@click.argument('input_file', type=click.Path(exists=True, path_type=Path))
@click.option(
    '--report',
    type=click.Choice(['summary', 'detailed', 'json', 'html'], case_sensitive=False),
    default='summary',
    help='Analysis report format'
)
@click.option(
    '--output', '-o',
    type=click.Path(path_type=Path),
    help='Save analysis report to file'
)
@click.option(
    '--include-stats',
    is_flag=True,
    help='Include detailed statistics'
)
@click.pass_context
def analyze(
    ctx: click.Context,
    input_file: Path,
    report: str,
    output: Optional[Path],
    include_stats: bool
):
    """
    Analyze LDIF file and generate comprehensive reports.

    This command performs detailed analysis of LDIF files, generating
    statistics, validation reports, and data quality assessments.

    Examples:
        flext-ldif analyze users.ldif
        flext-ldif analyze --report json --output analysis.json data.ldif
        flext-ldif analyze --include-stats --report html data.ldif
    """
    api: FlextLDIFAPI = ctx.obj['api']
    quiet: bool = ctx.obj['quiet']

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            disable=quiet
        ) as progress:
            # Parse and analyze
            task = progress.add_task("Analyzing LDIF file...", total=None)

            parse_result = api.parse_ldif_file(input_file)
            if parse_result.is_failure:
                console.print(f"[red]Parse failed: {parse_result.error}[/red]")
                sys.exit(1)

            entries = parse_result.value
            progress.update(task, description=f"Analyzing {len(entries)} entries")

            # Generate analysis report
            analysis_report = _generate_analysis_report(
                entries, report, include_stats, input_file
            )

            progress.update(task, description="Analysis complete")

        # Output report
        if output:
            output.write_text(analysis_report, encoding='utf-8')
            if not quiet:
                console.print(f"[green]✓[/green] Analysis report saved to {output}")
        else:
            console.print(analysis_report)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.exception("CLI analyze command failed")
        sys.exit(1)

# Helper Functions

def _write_output(entries: List[FlextLDIFEntry], output_path: Path, format: str, settings: FlextLDIFSettings):
    """Write entries to file in specified format."""
    if format == 'ldif':
        # Use API to write LDIF
        api = FlextLDIFAPI(settings)
        result = api.write_ldif_file(entries, output_path)
        if result.is_failure:
            raise Exception(f"Failed to write LDIF: {result.error}")

    elif format == 'json':
        # Convert to JSON
        data = [_entry_to_dict(entry) for entry in entries]
        output_path.write_text(json.dumps(data, indent=2), encoding='utf-8')

    elif format == 'yaml':
        import yaml
        data = [_entry_to_dict(entry) for entry in entries]
        output_path.write_text(yaml.dump(data, default_flow_style=False), encoding='utf-8')

    elif format == 'csv':
        import csv
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            if entries:
                # Get all possible attribute names
                all_attrs = set()
                for entry in entries:
                    all_attrs.update(entry.attributes.get_attribute_names())

                fieldnames = ['dn'] + sorted(all_attrs)
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for entry in entries:
                    row = {'dn': entry.dn.value}
                    for attr in all_attrs:
                        values = entry.attributes.get_values(attr)
                        row[attr] = '; '.join(values) if values else ''
                    writer.writerow(row)

def _print_output(entries: List[FlextLDIFEntry], format: str, quiet: bool):
    """Print entries to stdout in specified format."""
    if quiet:
        return

    if format == 'ldif':
        for entry in entries:
            # Convert entry back to LDIF format
            print(f"dn: {entry.dn.value}")
            for attr_name in sorted(entry.attributes.get_attribute_names()):
                values = entry.attributes.get_values(attr_name)
                for value in values:
                    print(f"{attr_name}: {value}")
            print()  # Empty line between entries

    elif format == 'json':
        data = [_entry_to_dict(entry) for entry in entries]
        print(json.dumps(data, indent=2))

    else:
        # Table format for summary
        table = Table(title="LDIF Entries")
        table.add_column("DN", style="cyan")
        table.add_column("Object Classes", style="green")
        table.add_column("Attributes", style="yellow")

        for entry in entries[:20]:  # Limit to first 20 for display
            object_classes = ', '.join(entry.get_object_classes())
            attr_count = len(entry.attributes.get_attribute_names())
            table.add_row(
                entry.dn.value[:50] + "..." if len(entry.dn.value) > 50 else entry.dn.value,
                object_classes,
                str(attr_count)
            )

        console.print(table)

        if len(entries) > 20:
            console.print(f"... and {len(entries) - 20} more entries")

def _entry_to_dict(entry: FlextLDIFEntry) -> Dict[str, object]:
    """Convert entry to dictionary representation."""
    return {
        'dn': entry.dn.value,
        'attributes': dict(entry.attributes.attributes)
    }

def _parse_filter_expression(filter_expr: str) -> Dict[str, object]:
    """Parse filter expression into criteria dictionary."""
  
    criteria = {}

    if '=' in filter_expr:
        key, value = filter_expr.split('=', 1)
        criteria[key.strip()] = value.strip()

    return criteria

def _apply_transformations(entries: List[FlextLDIFEntry], rules: Dict[str, object]) -> List[FlextLDIFEntry]:
    """Apply transformation rules to entries."""
    # Implementation would apply various transformation rules
    # This is a simplified version
    return entries

def _sort_entries(entries: List[FlextLDIFEntry], sort_by: str) -> List[FlextLDIFEntry]:
    """Sort entries by specified attribute."""
    def get_sort_key(entry: FlextLDIFEntry) -> str:
        if sort_by == 'dn':
            return entry.dn.value
        else:
            value = entry.attributes.get_single_value(sort_by)
            return value.lower() if value else ''

    return sorted(entries, key=get_sort_key)

def _generate_validation_report(
    entries: List[FlextLDIFEntry],
    result: FlextResult[bool],
    format: str,
    strict: bool,
    schema: Optional[Path]
) -> str:
    """Generate validation report in specified format."""
    if format == 'json':
        report = {
            'validation_passed': result.is_success,
            'total_entries': len(entries),
            'strict_mode': strict,
            'schema_file': str(schema) if schema else None,
            'errors': [result.error] if result.is_failure else []
        }
        return json.dumps(report, indent=2)

    else:
        # Text format
        lines = []
        lines.append("LDIF Validation Report")
        lines.append("=" * 50)
        lines.append(f"Total entries: {len(entries)}")
        lines.append(f"Strict mode: {'Yes' if strict else 'No'}")
        lines.append(f"Schema validation: {'Yes' if schema else 'No'}")
        lines.append(f"Result: {'PASSED' if result.is_success else 'FAILED'}")

        if result.is_failure:
            lines.append("\nErrors:")
            lines.append(f"  - {result.error}")

        return '\n'.join(lines)

def _generate_analysis_report(
    entries: List[FlextLDIFEntry],
    format: str,
    include_stats: bool,
    input_file: Path
) -> str:
    """Generate analysis report in specified format."""
    # Collect statistics
    stats = {
        'total_entries': len(entries),
        'object_classes': {},
        'attributes': {},
        'dn_components': {},
        'file_size': input_file.stat().st_size
    }

    for entry in entries:
        # Count object classes
        for oc in entry.get_object_classes():
            stats['object_classes'][oc] = stats['object_classes'].get(oc, 0) + 1

        # Count attributes
        for attr in entry.attributes.get_attribute_names():
            stats['attributes'][attr] = stats['attributes'].get(attr, 0) + 1

        # Count DN components
        depth = entry.dn.get_depth()
        stats['dn_components'][depth] = stats['dn_components'].get(depth, 0) + 1

    if format == 'json':
        return json.dumps(stats, indent=2)

    elif format == 'html':
        # Generate HTML report
        html = f"""
        <html>
        <head><title>LDIF Analysis Report</title></head>
        <body>
        <h1>LDIF Analysis Report</h1>
        <p>File: {input_file}</p>
        <p>Total Entries: {stats['total_entries']}</p>
        <p>File Size: {stats['file_size']} bytes</p>

        <h2>Object Classes</h2>
        <ul>
        """
        for oc, count in sorted(stats['object_classes'].items()):
            html += f"<li>{oc}: {count}</li>"
        html += "</ul></body></html>"
        return html

    else:
        # Text format
        lines = []
        lines.append("LDIF Analysis Report")
        lines.append("=" * 50)
        lines.append(f"File: {input_file}")
        lines.append(f"Total entries: {stats['total_entries']}")
        lines.append(f"File size: {stats['file_size']} bytes")

        if include_stats:
            lines.append("\nObject Class Distribution:")
            for oc, count in sorted(stats['object_classes'].items()):
                lines.append(f"  {oc}: {count}")

            lines.append("\nMost Common Attributes:")
            sorted_attrs = sorted(stats['attributes'].items(), key=lambda x: x[1], reverse=True)
            for attr, count in sorted_attrs[:10]:
                lines.append(f"  {attr}: {count}")

        return '\n'.join(lines)

if __name__ == '__main__':
    cli()
```

---

## 🔧 Utility Organization (`utils/`)

### **Cross-cutting Concerns Structure**

```python
utils/
├── __init__.py                  # Utility exports
├── logging.py                   # Structured logging with flext-core
├── validation.py                # Cross-layer validation utilities
├── transformations.py           # LDIF transformation utilities
├── performance.py               # Performance monitoring utilities
├── security.py                  # Security and sanitization utilities
└── testing.py                   # Test helper utilities
```

---

## 📋 Migration Roadmap (v0.9.0 → v1.0.0)

### **Phase 1: Foundation Refactoring**

1. **Create clean directory structure** following target architecture
2. **Move domain logic** from `models.py` to `domain/` layer
3. **Separate infrastructure concerns** from application logic
4. **Implement FlextResult pattern** throughout codebase

### **Phase 2: Domain Layer Implementation**

1. **Implement proper domain entities** extending FlextModels.Entity
2. **Create immutable value objects** extending FlextModels.Value
3. **Add domain services** for complex business logic
4. **Implement domain events** for integration patterns

### **Phase 3: Application Layer Refactoring**

1. **Refactor FlextLDIFAPI** to pure orchestration
2. **Implement CQRS patterns** with commands and queries
3. **Add application-level validation** and error handling
4. **Create workflow orchestration** for complex operations

### **Phase 4: Infrastructure Integration**

1. **Implement proper configuration** extending FlextConfig
2. **Add repository implementations** with abstractions
3. **Integrate observability patterns** with flext-observability
4. **Add performance monitoring** and metrics collection

### **Phase 5: Interface Layer Enhancement**

1. **Enhance CLI** with comprehensive commands and options
2. **Add web interface** for visual LDIF processing
3. **Implement API endpoints** for service integration
4. **Add monitoring dashboards** and health checks

---

## 🎯 Best Practices and Standards

### **1. Naming Conventions**

#### **Modules and Packages**

- Use lowercase with underscores: `domain_services.py`
- Package names should be singular: `domain/`, `application/`
- Avoid abbreviations: `application/` not `app/`

#### **Classes and Functions**

- Classes use PascalCase: `FlextLDIFEntry`
- Functions use snake_case: `parse_ldif_content()`
- Private members use underscore prefix: `_validate_entry()`

#### **Constants and Configuration**

- Constants use UPPER_SNAKE_CASE: `MAX_ENTRIES`
- Environment variables use prefix: `LDIF_MAX_ENTRIES`
- Configuration keys use snake_case: `max_entries`

### **2. Import Organization**

```python
# Standard library imports first
from typing import List, Dict, Optional, object
from pathlib import Path
import re

# Third-party imports second
from pydantic import BaseModel, Field
import click

# FLEXT ecosystem imports third
from flext_core import FlextResult, FlextModels.Entity, FlextLogger

# Local imports last (relative imports within same layer)
from .value_objects import FlextLDIFDistinguishedName
from ..infrastructure import FlextLDIFSettings
```

### **3. Documentation Standards**

#### **Module Docstrings**

Every module must have comprehensive docstring following the template:

```python
"""
Module Title - Brief Description

Detailed description of module purpose, key components, and integration
within the FLEXT ecosystem. Includes architecture notes and examples.

Key Components:
    - Component1: Description
    - Component2: Description

Architecture:
    Layer positioning and Clean Architecture compliance notes.

Example:
    Basic usage example with imports and operations.

Integration:
    FLEXT ecosystem integration points and dependencies.

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""
```

#### **Class and Function Documentation**

- **Comprehensive descriptions** with business context
- **Complete parameter documentation** with types and constraints
- **Return value specification** with FlextResult patterns
- **Usage examples** showing typical operations
- **Integration notes** explaining ecosystem positioning

### **4. Error Handling Patterns**

#### **FlextResult Usage**

```python
def parse_ldif(content: str) -> FlextResult[List[FlextLDIFEntry]]:
    """Parse LDIF with railway-oriented error handling."""
    try:
        entries = _parse_content(content)
        return FlextResult[None].ok(entries)
    except FlextLDIFParseError as e:
        return FlextResult[None].fail(f"Parse failed: {str(e)}")
    except Exception as e:
        logger.exception("Unexpected error in LDIF parsing")
        return FlextResult[None].fail(f"Unexpected error: {str(e)}")
```

#### **Domain Exception Hierarchy**

```python
class FlextLDIFError(Exception):
    """Base exception for LDIF operations."""
    pass

class FlextLDIFDomainError(FlextLDIFError):
    """Domain rule violation."""
    pass

class FlextLDIFParseError(FlextLDIFError):
    """LDIF parsing error."""
    def __init__(self, message: str, line_number: Optional[int] = None):
        super().__init__(message)
        self.line_number = line_number
```

### **5. Testing Organization**

#### **Test Structure**

```python
tests/
├── unit/                        # Unit tests by layer
│   ├── domain/                  # Domain layer tests
│   ├── application/             # Application layer tests
│   └── infrastructure/          # Infrastructure tests
├── integration/                 # Integration tests
├── e2e/                        # End-to-end tests
├── performance/                # Performance benchmarks
└── fixtures/                   # Test data and fixtures
```

#### **Test Naming**

- Test files: `test_<module_name>.py`
- Test classes: `TestClassName`
- Test methods: `test_should_<expected_behavior>_when_<condition>()`

### **6. Configuration Management**

#### **Settings Hierarchy**

1. **Default values** in FlextLDIFSettings class
2. **Environment variables** with LDIF\_ prefix
3. **Configuration files** (.env, config.YAML)
4. **Command-line arguments** (highest priority)

#### **Environment Variables**

```bash
# Processing limits
LDIF_MAX_ENTRIES=10000
LDIF_MAX_ATTRIBUTE_VALUES=1000

# Validation settings
LDIF_STRICT_VALIDATION=true
LDIF_VALIDATE_OBJECT_CLASSES=true

# Performance settings
LDIF_ENABLE_STREAMING=false
LDIF_BUFFER_SIZE=8192

# Integration settings
LDIF_ENABLE_OBSERVABILITY=true
LDIF_LOG_LEVEL=INFO
```

---

## 🔍 Quality Assurance Standards

### **1. Code Quality Metrics**

#### **Coverage Requirements**

- **Unit Tests**: 95% minimum coverage per layer
- **Integration Tests**: 90% coverage for critical paths
- **End-to-End Tests**: 80% coverage for user scenarios
- **Overall Project**: 90% minimum coverage

#### **Type Safety Standards**

- **MyPy Strict Mode**: All code must pass strict type checking
- **Type Annotation Coverage**: 95% minimum across all modules
- **Generic Types**: Use proper generic typing for collections
- **Protocol Usage**: Define protocols for abstract interfaces

#### **Linting Standards**

- **Ruff Configuration**: ALL rule categories enabled
- **Import Sorting**: isort configuration with proper grouping
- **Line Length**: 100 characters maximum
- **Complexity**: Maximum cyclomatic complexity of 10

### **2. Performance Standards**

#### **Memory Usage**

- **Large File Processing**: Support files up to 1GB without memory issues
- **Streaming Support**: Implement for files larger than configured threshold
- **Memory Profiling**: Regular memory usage analysis and optimization

#### **Processing Speed**

- **Parsing Performance**: Minimum 1000 entries/second for standard LDIF
- **Validation Speed**: Minimum 2000 entries/second for business rules
- **Output Generation**: Minimum 1500 entries/second for LDIF writing

#### **Scalability Requirements**

- **Concurrent Processing**: Support multiple simultaneous operations
- **Batch Operations**: Efficient handling of bulk processing
- **Resource Management**: Proper cleanup and resource disposal

### **3. Security Standards**

#### **Input Validation**

- **LDIF Content**: Comprehensive parsing validation
- **DN Validation**: RFC-compliant distinguished name checking
- **Attribute Validation**: LDAP naming convention compliance
- **Binary Data**: Proper base64 encoding/decoding

#### **Error Handling Security**

- **Information Disclosure**: No sensitive data in error messages
- **Stack Trace Security**: Sanitized error reporting in production
- **Logging Security**: No secrets or sensitive data in logs

---

## 🚀 Development Workflow

### **1. Development Setup**

```bash
# Clone and setup development environment
git clone https://github.com/flext-sh/flext-ldif.git
cd flext-ldif

# Complete development setup
make setup                       # Install tools, dependencies, pre-commit hooks
make validate                    # Run complete validation pipeline

# Development commands
make check                       # Quick health check (lint + type + test)
make test                        # Run comprehensive test suite
make format                      # Auto-format code with ruff
make build                       # Build distribution packages
```

### **2. Quality Gates (Pre-commit)**

```bash
# Automated quality checks (run before every commit)
make lint
make type-check                  # MyPy strict type checking
make security                    # Security scanning (bandit + pip-audit)
make test-quick                  # Fast test suite for immediate feedback
make docstring-validate          # Validate docstring completeness
```

### **3. Release Process**

```bash
# Release preparation
make clean                       # Clean all artifacts
make validate                    # Complete validation pipeline
make build                       # Build distribution packages
make test-all                    # Run all test categories
make coverage-report             # Generate coverage reports

# Version management
poetry version patch|minor|major
git tag -a v$(poetry version -s) -m "Release v$(poetry version -s)"
git push origin --tags
```

---

## 🎯 Success Criteria

### **Architecture Compliance Score: Target 9.0/10**

| **Category**           | **Current** | **Target** | **Actions Required**                   |
| ---------------------- | ----------- | ---------- | -------------------------------------- |
| **Clean Architecture** | 6/10        | 9/10       | Complete layer separation              |
| **DDD Implementation** | 7/10        | 9/10       | Add aggregates, events, specifications |
| **FLEXT Integration**  | 4/10        | 9/10       | Implement all ecosystem patterns       |
| **Type Safety**        | 8/10        | 9/10       | Complete type annotation coverage      |
| **Documentation**      | 9/10        | 9/10       | Maintain comprehensive documentation   |
| **Testing**            | 7/10        | 9/10       | Expand test coverage and categories    |
| **Performance**        | 6/10        | 8/10       | Implement streaming and optimization   |

### **Quality Metrics Targets**

- **Test Coverage**: 90%+ across all layers
- **Type Coverage**: 95%+ type annotations
- **Documentation**: 100% module and public API coverage
- **Performance**: Handle 1GB+ files efficiently
- **Security**: Zero critical vulnerabilities
- **Integration**: Seamless FLEXT ecosystem compatibility

---

## 📚 References and Resources

### **FLEXT Ecosystem Documentation**

- **[flext-core Standards](../../../flext-core/docs/standards/python-module-organization.md)** - Foundation patterns
- **[FLEXT Architecture Guide](../../architecture/ARCHITECTURE.md)** - Clean Architecture implementation
- **[CLAUDE.md Development Guide](../../CLAUDE.md)** - Development standards and patterns

### **External Standards**

- **[Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)** - Robert C. Martin
- **[Domain-Driven Design](https://domainlanguage.com/ddd/)** - Eric Evans patterns
- **[Railway-Oriented Programming](https://fsharpforfunandprofit.com/rop/)** - Scott Wlaschin
- **[Python Type Hints](https://docs.python.org/3/library/typing.html)** - Official documentation

### **LDIF and LDAP Standards**

- **[RFC 2849 - LDIF Specification](https://tools.ietf.org/html/rfc2849)** - LDIF format standard
- **[RFC 4514 - LDAP DN Syntax](https://tools.ietf.org/html/rfc4514)** - DN formatting rules
- **[RFC 4511 - LDAP Protocol](https://tools.ietf.org/html/rfc4511)** - LDAP technical specification

---

**Document Version**: 0.9.0
**Last Updated**: 2025-08-03
**Status**: Production Standard
**Authority**: FLEXT Ecosystem Architecture Team

This document serves as the definitive guide for Python module organization in the FLEXT-LDIF project, ensuring consistency with FLEXT ecosystem standards while maintaining enterprise-grade code quality and architectural integrity.
