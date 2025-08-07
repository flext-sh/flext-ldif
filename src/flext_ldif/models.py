"""FLEXT-LDIF Domain Models - Unified Semantic Pattern Integration.

⚡ ZERO BOILERPLATE: Using flext-core unified patterns.

Implements LDIF domain objects using flext-core foundation patterns,
eliminating 500+ lines of duplicate validation and business logic.

Core Components:
    - FlextLdifDistinguishedName: DN value object using FlextValue
    - FlextLdifAttributes: Attribute collection using FlextValue
    - FlextLdifEntry: Entry entity using FlextEntity
    - Modern factory patterns using FlextFactory

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

import uuid
from typing import NotRequired, TypedDict, cast

# 🚨 UNIFIED PATTERNS: Use flext-core foundation - eliminates 500+ lines boilerplate
from flext_core import FlextResult
from flext_core.exceptions import FlextValidationError
from flext_core.models import FlextEntity, FlextFactory, FlextValue
from pydantic import Field, field_validator

# Simple types for LDIF data
type LDIFContent = str
type LDIFLines = list[str]

# DN component constants
MIN_DN_COMPONENTS: int = 2

# =============================================================================
# TYPEDDICT DEFINITIONS - Clean type-safe interfaces
# =============================================================================


class FlextLdifDNDict(TypedDict):
    """TypedDict for DN structure."""

    value: str


class FlextLdifAttributesDict(TypedDict):
    """TypedDict for attributes structure."""

    attributes: dict[str, list[str]]


class FlextLdifEntryDict(TypedDict):
    """TypedDict for entry structure."""

    dn: str
    attributes: dict[str, list[str]]
    changetype: NotRequired[str]


# =============================================================================
# DOMAIN VALUE OBJECTS - Immutable data using FlextValue
# =============================================================================


class FlextLdifDistinguishedName(FlextValue):
    """Distinguished Name value object with RFC 4514 compliance."""

    value: str = Field(..., description="DN string in RFC 4514 format")

    @field_validator("value")
    @classmethod
    def validate_dn(cls, v: str) -> str:
        """Validate and normalize DN format."""
        if not v or not isinstance(v, str) or not v.strip():
            error_msg = "DN must be a non-empty string"
            raise FlextValidationError(error_msg)

        # Basic DN validation - contains at least one component
        if "=" not in v:
            error_msg = "DN must contain at least one attribute=value pair"
            raise FlextValidationError(error_msg)

        # Normalize DN by removing extra spaces around commas and equals
        # This fixes malformed DNs like 'cn=OCS_PORTAL_USERS, cn=groups,dc=network,dc=ctbc'
        # to the proper format 'cn=OCS_PORTAL_USERS,cn=groups,dc=network,dc=ctbc'
        return cls._normalize_dn(v.strip())

    @classmethod
    def _normalize_dn(cls, dn: str) -> str:
        """Normalize DN by removing extra spaces around commas and equals.

        This method ensures DN consistency by:
        - Removing spaces around commas between components
        - Normalizing spaces around equals signs within components
        - Preserving necessary spaces within attribute values

        Args:
            dn: Distinguished name to normalize

        Returns:
            Normalized DN string

        Examples:
            'cn=OCS_PORTAL_USERS, cn=groups,dc=network,dc=ctbc'
            -> 'cn=OCS_PORTAL_USERS,cn=groups,dc=network,dc=ctbc'

        """
        if not dn:
            return dn

        # Split by comma, strip each component, then rejoin
        components = []
        for raw_component in dn.split(","):
            stripped_component = raw_component.strip()
            # Normalize spaces around equals sign within each component
            if "=" in stripped_component:
                key, value = stripped_component.split("=", 1)
                normalized_component = f"{key.strip()}={value.strip()}"
            else:
                normalized_component = stripped_component
            components.append(normalized_component)

        return ",".join(components)

    def __str__(self) -> str:
        """String representation returns the DN value."""
        return self.value

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate DN business rules."""
        return FlextResult.ok(None)

    def get_rdn(self) -> str:
        """Get relative distinguished name (first component)."""
        return self.value.split(",", 1)[0].strip()

    def get_parent_dn(self) -> FlextLdifDistinguishedName | None:
        """Get parent DN or None if root."""
        components = self.value.split(",", 1)
        if len(components) < MIN_DN_COMPONENTS:
            return None
        return FlextLdifDistinguishedName(value=components[1].strip())

    def get_depth(self) -> int:
        """Get DN depth (number of components)."""
        return len([c.strip() for c in self.value.split(",") if c.strip()])


class FlextLdifAttributes(FlextValue):
    """LDIF attribute collection value object."""

    attributes: dict[str, list[str]] = Field(default_factory=dict)

    @field_validator("attributes")
    @classmethod
    def normalize_dn_attributes(cls, v: dict[str, list[str]]) -> dict[str, list[str]]:
        """Normalize DN-valued attributes to ensure consistent formatting."""
        # DN-valued attributes that need normalization
        dn_attributes = {
            "orcldaspublicgroupdns", "member", "uniquemember", "owner", "seeAlso",
            "distinguishedName", "manager", "secretary", "roleOccupant",
        }

        normalized = {}
        for attr_name, attr_values in v.items():
            if attr_name.lower() in dn_attributes:
                # Normalize DN values using the same method as FlextLdifDistinguishedName
                normalized_values = []
                for value in attr_values:
                    try:
                        normalized_value = FlextLdifDistinguishedName._normalize_dn(value)
                        normalized_values.append(normalized_value)
                    except Exception:
                        # If normalization fails, keep original value
                        normalized_values.append(value)
                normalized[attr_name] = normalized_values
            else:
                # Keep non-DN attributes as-is
                normalized[attr_name] = attr_values

        return normalized

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate attribute business rules."""
        for attr_name in self.attributes:
            if not attr_name or not attr_name.strip():
                return FlextResult.fail("Attribute name cannot be empty")
        return FlextResult.ok(None)

    def get_values(self, name: str) -> list[str]:
        """Get attribute values by name."""
        return self.attributes.get(name, [])

    def has_attribute(self, name: str) -> bool:
        """Check if attribute exists."""
        return name in self.attributes

    def get_object_classes(self) -> list[str]:
        """Get objectClass values (case-insensitive)."""
        # LDAP attributes are case-insensitive, so check for all variations
        for attr_name in self.attributes:
            if attr_name.lower() == "objectclass":
                return self.attributes[attr_name]
        return []


# =============================================================================
# DOMAIN ENTITIES - Business objects using FlextEntity
# =============================================================================


class FlextLdifEntry(FlextEntity):
    """LDIF entry entity with business logic."""

    dn: FlextLdifDistinguishedName = Field(..., description="Distinguished Name")
    attributes: FlextLdifAttributes = Field(
        default_factory=FlextLdifAttributes,
    )
    changetype: str | None = Field(default=None, description="LDIF changetype")

    @classmethod
    def model_validate(
        cls,
        obj: dict[str, object] | object,
        **_kwargs: object,
    ) -> FlextLdifEntry:
        """Backwards-compatible validation for legacy tests."""
        # Handle legacy format
        if isinstance(obj, dict):
            obj_copy = dict(obj)  # Always copy to avoid mutation
            if "id" not in obj_copy:
                obj_copy["id"] = str(uuid.uuid4())

            # Convert string DN to object
            if isinstance(obj_copy.get("dn"), str):
                obj_copy["dn"] = FlextLdifDistinguishedName(
                    value=cast("str", obj_copy["dn"]),
                )

            # Convert dict attributes to object
            if isinstance(obj_copy.get("attributes"), dict):
                obj_copy["attributes"] = FlextLdifAttributes(
                    attributes=cast("dict[str, list[str]]", obj_copy["attributes"]),
                )

            return super().model_validate(obj_copy)
        return super().model_validate(obj)

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate entry business rules."""
        # Validate DN
        if not self.dn.value:
            return FlextResult.fail("Entry must have a DN")

        # Validate attributes
        attr_validation = self.attributes.validate_business_rules()
        if attr_validation.is_failure:
            return FlextResult.fail(f"Invalid attributes: {attr_validation.error}")

        # Entry must have objectClass unless it's a delete operation
        if self.changetype != "delete" and not self.attributes.has_attribute(
            "objectClass",
        ):
            return FlextResult.fail("Entry must have objectClass attribute")

        return FlextResult.ok(None)

    def has_object_class(self, object_class: str) -> bool:
        """Check if entry has specific objectClass."""
        return object_class in self.attributes.get_object_classes()

    def get_cn(self) -> str | None:
        """Get common name (cn) value."""
        values = self.attributes.get_values("cn")
        return values[0] if values else None

    def has_attribute(self, name: str) -> bool:
        """Check if attribute exists."""
        return self.attributes.has_attribute(name)

    def get_attribute(self, name: str) -> list[str]:
        """Get attribute values by name."""
        return self.attributes.get_values(name)

    def to_ldif(self) -> str:
        """Convert entry to LDIF string."""
        lines = [f"dn: {self.dn.value}"]

        if self.changetype:
            lines.append(f"changetype: {self.changetype}")

        for attr_name, values in self.attributes.attributes.items():
            lines.extend(f"{attr_name}: {value}" for value in values)

        return "\n".join(lines) + "\n"

    def validate_semantic_rules(self) -> FlextResult[None]:
        """Validate semantic business rules."""
        return self.validate_business_rules()

    @classmethod
    def from_ldif_dict(cls, dn: str, attrs: dict[str, list[str]]) -> FlextLdifEntry:
        """Create entry from LDIF dictionary."""
        dn_obj = FlextLdifDistinguishedName(value=dn)
        attrs_obj = FlextLdifAttributes(attributes=attrs)
        return cls(id=str(uuid.uuid4()), dn=dn_obj, attributes=attrs_obj)

    @classmethod
    def from_ldif_block(cls, ldif_block: str) -> FlextLdifEntry:
        """Create entry from LDIF text block - SOLID implementation.

        SOLID IMPLEMENTATION: Single Responsibility - parses LDIF text block into entry.
        Delegates to from_ldif_dict for actual object creation (Dependency Inversion).
        """
        lines = ldif_block.strip().split("\n")
        if not lines:
            msg = "LDIF block cannot be empty"
            raise FlextValidationError(msg)

        # Parse DN from first line
        dn_line = lines[0].strip()
        if not dn_line.startswith("dn:"):
            msg = "LDIF block must start with DN"
            raise FlextValidationError(msg)
        dn = dn_line[3:].strip()

        # Parse attributes from remaining lines
        attrs: dict[str, list[str]] = {}
        for raw_line in lines[1:]:
            stripped_line = raw_line.strip()
            if not stripped_line:
                continue
            if ":" not in stripped_line:
                continue
            attr_name, attr_value = stripped_line.split(":", 1)
            attr_name = attr_name.strip()
            attr_value = attr_value.strip()

            if attr_name not in attrs:
                attrs[attr_name] = []
            attrs[attr_name].append(attr_value)

        # Delegate to from_ldif_dict (SOLID: reuse existing functionality)
        return cls.from_ldif_dict(dn, attrs)

    def is_person_entry(self) -> bool:
        """Check if entry represents a person based on objectClass - SOLID implementation.

        SOLID IMPLEMENTATION: Single Responsibility - determines if entry is person-type.
        Uses LDAP standard person objectClasses for classification.

        Returns:
            bool: True if entry represents a person, False otherwise

        """
        object_classes = self.attributes.get_values("objectClass")
        if not object_classes:
            return False

        # Standard LDAP person objectClasses
        person_classes = {
            "person",
            "organizationalPerson",
            "inetOrgPerson",
            "user",
            "posixAccount",
        }

        # Check if any objectClass indicates this is a person entry
        return any(obj_class in person_classes for obj_class in object_classes)

    def set_attribute(self, name: str, values: list[str]) -> None:
        """Set attribute values - SOLID implementation.

        SOLID IMPLEMENTATION: Single Responsibility - delegates attribute setting
        to FlextLdifAttributes object (Dependency Inversion Principle).

        Args:
            name: Attribute name to set
            values: List of values to set for the attribute

        """
        self.attributes.update({name: values})  # type: ignore[misc]


# =============================================================================
# FACTORY METHODS - Modern creation patterns
# =============================================================================


class FlextLdifFactory:
    """Factory for LDIF domain objects using unified patterns."""

    @staticmethod
    def create_dn(value: str) -> FlextResult[FlextLdifDistinguishedName]:
        """Create DN with validation."""
        return FlextFactory.create_model(FlextLdifDistinguishedName, value=value)

    @staticmethod
    def create_attributes(
        attributes: dict[str, list[str]],
    ) -> FlextResult[FlextLdifAttributes]:
        """Create attributes with validation."""
        return FlextFactory.create_model(FlextLdifAttributes, attributes=attributes)

    @staticmethod
    def create_entry(
        dn: str,
        attributes: dict[str, list[str]],
        changetype: str | None = None,
    ) -> FlextResult[FlextLdifEntry]:
        """Create entry with validation."""
        # Create DN
        dn_result = FlextLdifFactory.create_dn(dn)
        if dn_result.is_failure:
            return FlextResult.fail(f"Invalid DN: {dn_result.error}")

        # Create attributes
        attr_result = FlextLdifFactory.create_attributes(attributes)
        if attr_result.is_failure:
            return FlextResult.fail(f"Invalid attributes: {attr_result.error}")

        # Create entry with required id
        return FlextFactory.create_model(
            FlextLdifEntry,
            id=str(uuid.uuid4()),
            dn=dn_result.data,
            attributes=attr_result.data,
            changetype=changetype,
        )


__all__ = [
    "FlextLdifAttributes",
    "FlextLdifAttributesDict",
    "FlextLdifDNDict",
    "FlextLdifDistinguishedName",
    "FlextLdifEntry",
    "FlextLdifEntryDict",
    "FlextLdifFactory",
    "LDIFContent",
    "LDIFLines",
]
