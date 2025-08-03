"""FLEXT-LDIF Domain Models and Value Objects.

This module contains the core domain model for LDIF processing, implementing
Domain-Driven Design patterns with immutable value objects and rich domain
entities built on flext-core foundation classes.

The domain model encapsulates business logic and invariants for LDIF data
processing, providing type-safe, validated, and immutable data structures
with comprehensive business rule enforcement.

Key Components:
    - FlextLdifEntry: Domain entity representing LDIF entries with business logic
    - FlextLdifDistinguishedName: Value object for DN validation and operations
    - FlextLdifAttributes: Immutable attribute collection with business rules
    - Type definitions: TypedDict structures for type-safe data exchange

Architecture:
    Part of Domain Layer in Clean Architecture, this module contains pure
    business logic without external dependencies. All domain objects extend
    flext-core base classes and implement enterprise-grade validation patterns.

Business Rules:
    - Distinguished Names must follow RFC 4514 syntax requirements
    - LDIF entries must have valid DN and consistent attribute structure
    - Attributes follow LDAP naming conventions and value constraints
    - Change records must have valid operation types and modification semantics

Example:
    Creating and validating LDIF domain objects:

    >>> from flext_ldif.models import FlextLdifEntry, FlextLdifDistinguishedName
    >>>
    >>> # Create DN with automatic validation
    >>> dn = FlextLdifDistinguishedName(value="cn=John Doe,ou=people,dc=example,dc=com")
    >>> print(dn.get_rdn())  # "cn=John Doe"
    >>> print(dn.get_depth())  # 4
    >>>
    >>> # Create entry with business rule validation
    >>> entry = FlextLdifEntry.model_validate({
    ...     "dn": dn,
    ...     "attributes": FlextLdifAttributes(attributes={
    ...         "cn": ["John Doe"],
    ...         "objectClass": ["person", "inetOrgPerson"],
    ...         "mail": ["john@example.com"]
    ...     })
    ... })
    >>>
    >>> # Validate business rules
    >>> entry.validate_semantic_rules()  # Raises exception if invalid
    >>> print(entry.has_object_class("person"))  # True

Integration:
    - Built on flext-core FlextDomainValueObject and FlextImmutableModel
    - Provides type-safe interfaces for application and infrastructure layers
    - Implements immutability patterns for thread-safe operations
    - Supports serialization for persistence and API integration

Author: FLEXT Development Team
Version: 0.9.0
License: MIT

"""

from __future__ import annotations

from typing import NewType, NotRequired, TypedDict

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import (
    FlextDomainValueObject,
    FlextImmutableModel,
    FlextResult,
    get_logger,
)
from pydantic import Field, field_validator

# Logger for models module
logger = get_logger(__name__)

# Type aliases for LDIF-specific concepts
LDIFContent = NewType("LDIFContent", str)
LDIFLines = NewType("LDIFLines", list[str])


# =============================================================================
# LDIF TYPEDDICT DEFINITIONS - Type-safe dictionaries for LDIF
# =============================================================================


class FlextLdifDNDict(TypedDict):
    """TypedDict for Distinguished Name structure."""

    value: str
    components: NotRequired[list[str]]
    depth: NotRequired[int]


class FlextLdifAttributesDict(TypedDict):
    """TypedDict for LDIF attributes structure."""

    attributes: dict[str, list[str]]
    count: NotRequired[int]


class FlextLdifEntryDict(TypedDict):
    """TypedDict for LDIF entry structure."""

    dn: str
    attributes: dict[str, list[str]]
    object_classes: NotRequired[list[str]]
    changetype: NotRequired[str]


class FlextLdifDistinguishedName(FlextDomainValueObject):
    """Distinguished Name value object for LDIF entries."""

    value: str = Field(..., description="DN string value")

    @field_validator("value")
    @classmethod
    def validate_dn(cls, v: str) -> str:
        """Validate DN format."""
        if not v or not isinstance(v, str):
            msg = "DN must be a non-empty string"
            raise ValueError(msg)

        if "=" not in v:
            msg = "DN must contain at least one attribute=value pair"
            raise ValueError(msg)

        # Validate each component
        components = v.split(",")
        for raw_component in components:
            component = raw_component.strip()
            if "=" not in component:
                msg = f"Invalid DN component: {component}"
                raise ValueError(msg)

            attr_name, attr_value = component.split("=", 1)
            if not attr_name.strip() or not attr_value.strip():
                msg = f"Invalid DN component: {component}"
                raise ValueError(msg)

        return v

    def __str__(self) -> str:
        """Return DN string value."""
        return self.value

    def __eq__(self, other: object) -> bool:
        """Compare with string or other FlextLdifDistinguishedName."""
        if isinstance(other, str):
            return self.value == other
        if isinstance(other, FlextLdifDistinguishedName):
            return self.value == other.value
        return False

    def __hash__(self) -> int:
        """Return hash of DN value."""
        return hash(self.value)

    def get_rdn(self) -> str:
        """Get relative distinguished name (first component)."""
        return self.value.split(",")[0].strip()

    def get_parent_dn(self) -> FlextLdifDistinguishedName | None:
        """Get parent DN."""
        components = self.value.split(",")
        if len(components) <= 1:
            return None

        parent_dn = ",".join(components[1:]).strip()
        return FlextLdifDistinguishedName.model_validate({"value": parent_dn})

    def is_child_of(self, parent: FlextLdifDistinguishedName) -> bool:
        """Check if this DN is a child of another DN."""
        return self.value.lower().endswith(parent.value.lower())

    def get_depth(self) -> int:
        """Get depth of DN (number of components)."""
        return len(self.value.split(","))

    def validate_semantic_rules(self) -> FlextResult[None]:
        """Validate DN semantic business rules."""
        # Validation is done in field_validator, so just check final state
        if not self.value or "=" not in self.value:
            return FlextResult.fail("DN must contain at least one attribute=value pair")
        return FlextResult.ok(None)

    def to_dn_dict(self) -> FlextLdifDNDict:
        """Convert to FlextLdifDNDict representation."""
        return FlextLdifDNDict(
            value=self.value,
            components=self.value.split(","),
            depth=self.get_depth(),
        )


class FlextLdifAttributes(FlextDomainValueObject):
    """LDIF attributes value object."""

    attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="LDIF attributes as name-value pairs",
    )

    def get_single_value(self, name: str) -> str | None:
        """Get single value for attribute."""
        values = self.attributes.get(name, [])
        return values[0] if values else None

    def get_values(self, name: str) -> list[str]:
        """Get all values for attribute."""
        return self.attributes.get(name, [])

    def has_attribute(self, name: str) -> bool:
        """Check if attribute exists."""
        return name in self.attributes

    def add_value(self, name: str, value: str) -> FlextLdifAttributes:
        """Add value to attribute (returns new instance)."""
        new_attrs = {}
        for attr_name, attr_values in self.attributes.items():
            new_attrs[attr_name] = attr_values.copy()

        if name not in new_attrs:
            new_attrs[name] = []
        new_attrs[name] += [value]
        return FlextLdifAttributes.model_validate({"attributes": new_attrs})

    def remove_value(self, name: str, value: str) -> FlextLdifAttributes:
        """Remove value from attribute (returns new instance)."""
        new_attrs = {}
        for attr_name, attr_values in self.attributes.items():
            if attr_name == name:
                new_values = [v for v in attr_values if v != value]
                if new_values:
                    new_attrs[attr_name] = new_values
            else:
                new_attrs[attr_name] = attr_values.copy()
        return FlextLdifAttributes.model_validate({"attributes": new_attrs})

    def get_attribute_names(self) -> list[str]:
        """Get all attribute names."""
        return list(self.attributes.keys())

    def get_total_values(self) -> int:
        """Get total number of attribute values."""
        return sum(len(values) for values in self.attributes.values())

    def is_empty(self) -> bool:
        """Check if attributes are empty."""
        return len(self.attributes) == 0

    def __eq__(self, other: object) -> bool:
        """Compare with dict or other FlextLdifAttributes."""
        if isinstance(other, dict):
            return self.attributes == other
        if isinstance(other, FlextLdifAttributes):
            return self.attributes == other.attributes
        return False

    def __hash__(self) -> int:
        """Return hash of attributes for use in sets/dicts."""
        return hash(
            frozenset((key, tuple(values)) for key, values in self.attributes.items()),
        )

    def validate_semantic_rules(self) -> FlextResult[None]:
        """Validate attributes semantic business rules."""
        # Validate attribute names
        for attr_name in self.attributes:
            if not attr_name.strip():
                return FlextResult.fail(f"Invalid attribute name: {attr_name}")
        return FlextResult.ok(None)

    def to_attributes_dict(self) -> FlextLdifAttributesDict:
        """Convert to FlextLdifAttributesDict representation."""
        return FlextLdifAttributesDict(
            attributes=self.attributes.copy(),
            count=len(self.attributes),
        )


class FlextLdifEntry(FlextImmutableModel):
    """LDIF entry model using flext-core patterns."""

    dn: FlextLdifDistinguishedName = Field(..., description="Distinguished Name")
    attributes: FlextLdifAttributes = Field(
        default_factory=lambda: FlextLdifAttributes.model_validate({"attributes": {}}),
        description="LDIF attributes dictionary",
    )

    @field_validator("dn", mode="before")
    @classmethod
    def validate_dn(
        cls,
        v: str | FlextLdifDistinguishedName | dict[str, str],
    ) -> FlextLdifDistinguishedName:
        """Convert string DN to FlextLdifDistinguishedName object."""
        if isinstance(v, str):
            return FlextLdifDistinguishedName.model_validate({"value": v})
        if isinstance(v, FlextLdifDistinguishedName):
            return v
        msg = f"Invalid DN type: {type(v)}"
        raise ValueError(msg)

    @field_validator("attributes", mode="before")
    @classmethod
    def validate_attributes(
        cls,
        v: dict[str, list[str]] | FlextLdifAttributes,
    ) -> FlextLdifAttributes:
        """Convert dict attributes to FlextLdifAttributes object."""
        if isinstance(v, dict):
            return FlextLdifAttributes.model_validate({"attributes": v})
        return v  # Must be FlextLdifAttributes based on type annotation

    def get_attribute(self, name: str) -> list[str] | None:
        """Get LDIF attribute values by name.

        Args:
            name: The attribute name to retrieve

        Returns:
            List of attribute values if found, None if attribute doesn't exist

        """
        if not self.attributes.has_attribute(name):
            return None
        return self.attributes.get_values(name)

    def set_attribute(self, name: str, values: list[str]) -> None:
        """Set an attribute with the given name and values."""
        new_attrs = self.attributes.attributes.copy()
        new_attrs[name] = values
        # Use property setter instead of direct assignment
        object.__setattr__(
            self,
            "attributes",
            FlextLdifAttributes.model_validate({"attributes": new_attrs}),
        )

    def has_attribute(self, name: str) -> bool:
        """Check if LDIF entry has a specific attribute.

        Args:
            name: The attribute name to check

        Returns:
            True if attribute exists, False otherwise

        """
        return self.attributes.has_attribute(name)

    def get_object_classes(self) -> list[str]:
        """Get object classes for this entry.

        Returns:
            List of object class names

        """
        return self.attributes.get_values("objectClass")

    def has_object_class(self, object_class: str) -> bool:
        """Check if entry has specific object class.

        Args:
            object_class: Object class to check

        Returns:
            True if entry has the object class

        """
        return object_class in self.get_object_classes()

    def get_attribute_values(self, name: str) -> list[str]:
        """Get attribute values by name.

        Args:
            name: Attribute name

        Returns:
            List of attribute values

        """
        return self.attributes.get_values(name)

    def is_modify_operation(self) -> bool:
        """Check if this is a modify operation."""
        changetype = self.get_attribute("changetype")
        return bool(changetype and changetype[0].lower() == "modify")

    def is_add_operation(self) -> bool:
        """Check if this is an add operation."""
        changetype = self.get_attribute("changetype")
        # Default to add operation when no changetype is specified (standard LDIF behavior)
        return not changetype or changetype[0].lower() == "add"

    def is_delete_operation(self) -> bool:
        """Check if this is a delete operation."""
        changetype = self.get_attribute("changetype")
        return bool(changetype and changetype[0].lower() == "delete")

    def get_single_attribute(self, name: str) -> str | None:
        """Get single value from an LDIF attribute.

        Args:
            name: The attribute name to retrieve

        Returns:
            First attribute value if found, None otherwise

        """
        return self.attributes.get_single_value(name)

    def to_ldif(self) -> str:
        """Convert entry to LDIF string format.

        Returns:
            LDIF string representation of the entry

        """
        lines = [f"dn: {self.dn}"]

        for attr_name, attr_values in self.attributes.attributes.items():
            lines.extend(f"{attr_name}: {value}" for value in attr_values)

        lines.append("")  # Empty line after entry
        return "\n".join(lines)

    def validate_semantic_rules(self) -> FlextResult[None]:
        """Validate LDIF entry semantic business rules using Railway-Oriented Programming.

        SOLID REFACTORING: Reduced from 4 returns to 2 returns using
        Railway-Oriented Programming + Strategy Pattern.
        """
        # Railway-Oriented Programming: Chain validations with early exit
        validation_errors = self._collect_ldif_entry_validation_errors()

        if validation_errors:
            return FlextResult.fail(
                validation_errors[0],
            )  # Return first error for clarity

        return FlextResult.ok(None)

    def _collect_ldif_entry_validation_errors(self) -> list[str]:
        """DRY helper: Collect all LDIF entry validation errors using Strategy Pattern."""
        errors = []

        # Strategy 1: DN validation
        if not self.dn or not self.dn.value:
            errors.append("LDIF entry must have a valid DN")

        # Strategy 2: Attributes existence validation
        if not self.attributes or not self.attributes.attributes:
            errors.append("LDIF entry must have at least one attribute")

        # Strategy 3: ObjectClass attribute validation
        if not self.has_attribute("objectClass"):
            errors.append("Entry missing required objectClass attribute")

        return errors

    @classmethod
    def from_ldif_block(cls, ldif_block: str) -> FlextLdifEntry:
        """Create entry from LDIF block.

        Args:
            ldif_block: LDIF text block for single entry

        Returns:
            LDIFEntry instance

        """
        lines = [
            line.strip() for line in ldif_block.strip().split("\n") if line.strip()
        ]

        if not lines:
            msg = "LDIF block cannot be empty"
            raise ValueError(msg)

        # First line must be DN
        dn_line = lines[0]
        if not dn_line.startswith("dn:"):
            msg = f"First line must be DN, got: {dn_line}"
            raise ValueError(msg)

        dn = dn_line[3:].strip()
        attributes: dict[str, list[str]] = {}

        # Parse attributes
        for line in lines[1:]:
            if ":" in line:
                attr_name, attr_value = line.split(":", 1)
                attr_name = attr_name.strip()
                attr_value = attr_value.strip()

                if attr_name not in attributes:
                    attributes[attr_name] = []
                attributes[attr_name].append(attr_value)

        return cls(
            dn=FlextLdifDistinguishedName.model_validate({"value": dn}),
            attributes=FlextLdifAttributes.model_validate({"attributes": attributes}),
        )

    @classmethod
    def from_ldif_dict(
        cls,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextLdifEntry:
        """Create entry from DN string and attributes dict (ldif3 format).

        Args:
            dn: Distinguished name string
            attributes: Dictionary of attributes with list values

        Returns:
            FlextLdifEntry instance

        """
        logger.debug("Creating FlextLdifEntry from LDIF dict: DN=%s", dn)
        logger.trace("Attributes count: %d", len(attributes))
        logger.trace("Attribute names: %s", list(attributes.keys()))

        try:
            logger.debug("Validating DN: %s", dn)
            dn_obj = FlextLdifDistinguishedName.model_validate({"value": dn})
            logger.trace("DN validation successful")

            logger.debug("Validating attributes dictionary")
            attrs_obj = FlextLdifAttributes.model_validate({"attributes": attributes})
            logger.trace("Attributes validation successful")

            entry = cls(dn=dn_obj, attributes=attrs_obj)
            logger.debug("FlextLdifEntry created successfully: %s", entry.dn)
            logger.info(
                "LDIF entry created from dict",
                dn=dn,
                attributes_count=len(attributes),
                total_values=sum(len(values) for values in attributes.values()),
            )
        except Exception as e:
            logger.debug("Exception type: %s", type(e).__name__)
            logger.trace("Entry creation exception details", exc_info=True)
            logger.exception("Failed to create FlextLdifEntry from dict")
            raise
        else:
            return entry

    def to_entry_dict(self) -> FlextLdifEntryDict:
        """Convert to FlextLdifEntryDict representation."""
        changetype = self.get_single_attribute("changetype")
        result = FlextLdifEntryDict(
            dn=str(self.dn),
            attributes=self.attributes.attributes.copy(),
            object_classes=self.get_object_classes(),
        )
        if changetype is not None:
            result["changetype"] = changetype
        return result

    # ==========================================================================
    # SPECIFICATION METHODS (Consolidated from specifications.py)
    # Using composition pattern to integrate business rules
    # ==========================================================================

    def is_valid_entry(self) -> bool:
        """Check if entry is valid (consolidated specification logic)."""
        if not self.dn or not self.attributes or self.attributes.is_empty():
            return False

        # Must have at least objectClass attribute
        if not self.has_attribute("objectClass"):
            return False

        # DN must be properly formatted
        dn_str = str(self.dn)
        return not (not dn_str or "=" not in dn_str)

    def is_person_entry(self) -> bool:
        """Check if entry represents a person (consolidated specification logic)."""
        if not self.is_valid_entry():
            return False

        # Check for person-related object classes
        person_classes = {
            "person",
            "organizationalPerson",
            "inetOrgPerson",
            "user",
            "posixAccount",
        }
        object_classes_attr = self.get_attribute("objectClass")
        if not object_classes_attr:
            return False

        object_classes = set(object_classes_attr)
        return bool(person_classes & object_classes)

    def is_group_entry(self) -> bool:
        """Check if entry represents a group (consolidated specification logic)."""
        if not self.is_valid_entry():
            return False

        # Check for group-related object classes
        group_classes = {
            "group",
            "groupOfNames",
            "groupOfUniqueNames",
            "posixGroup",
            "organizationalRole",
        }
        object_classes_attr = self.get_attribute("objectClass")
        if not object_classes_attr:
            return False

        object_classes = set(object_classes_attr)
        return bool(group_classes & object_classes)

    def is_organizational_unit(self) -> bool:
        """Check if entry represents an organizational unit (consolidated specification logic)."""
        if not self.is_valid_entry():
            return False

        # Check for OU-related object classes
        ou_classes = {
            "organizationalUnit",
            "organizationalRole",
            "dcObject",
            "domain",
        }
        object_classes_attr = self.get_attribute("objectClass")
        if not object_classes_attr:
            return False

        object_classes = set(object_classes_attr)
        return bool(ou_classes & object_classes)

    def is_change_record(self) -> bool:
        """Check if entry is a change record (consolidated specification logic)."""
        if not self.is_valid_entry():
            return False

        # Check for changetype attribute
        changetype = self.get_attribute("changetype")
        if not changetype:
            return False

        # Valid change types
        valid_change_types = {"add", "modify", "delete", "modrdn"}
        return changetype[0] in valid_change_types


__all__ = [
    "FlextLdifAttributes",
    "FlextLdifAttributesDict",
    "FlextLdifDNDict",
    "FlextLdifDistinguishedName",
    "FlextLdifEntry",
    "FlextLdifEntryDict",
    "LDIFContent",
    "LDIFLines",
]
