"""FLEXT-LDIF Domain Models - Unified LDIF Processing Models.

ARCHITECTURAL CONSOLIDATION: This module consolidates ALL LDIF domain models from
multiple duplicate sources into ONE centralized domain layer following enterprise patterns.

ELIMINATED DUPLICATION:
✅ models.py + ldif_models.py + domain_models.py → ONE unified models.py
✅ Complete flext-core foundation integration - ZERO local duplication
✅ Clean Architecture + DDD principles throughout
✅ Railway-oriented programming with FlextResult pattern

Domain Objects:
    - FlextLdifDistinguishedName: RFC 4514 compliant DN value object
    - FlextLdifAttributes: Immutable attribute collection with business rules
    - FlextLdifEntry: Rich domain entity with complete business logic
    - FlextLdifFactory: Factory patterns with validation using flext-core

Enterprise Architecture:
- Domain-Driven Design: Rich domain models with business logic
- Value Object Pattern: Immutable domain values (DN, Attributes)
- Entity Pattern: FlextLdifEntry with identity and behavior
- Factory Pattern: Object creation through FlextFactory delegation
- Type Safety: Python 3.13+ with comprehensive type annotations
- Error Handling: FlextResult pattern for railway-oriented programming

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

import hashlib
import uuid
from typing import NotRequired, TypedDict, cast

# FOUNDATION: Complete flext-core integration - NO duplication
from flext_core import (
    FlextEntity,
    FlextFactory,
    FlextResult,
    FlextValidationError,
    FlextValue,
)

# ✅ CORRECT - Import from flext-ldap root API to eliminate DN validation duplication
from flext_ldap import (
    flext_ldap_validate_attribute_name,
    flext_ldap_validate_dn,
)

# NOTE: flext_ldap_normalize_dn should be in root API but currently in utils
from flext_ldap.utils import flext_ldap_normalize_dn
from pydantic import Field, field_validator

# Import consolidated constants (NO DUPLICATION)
from .constants import (
    LDAP_DN_ATTRIBUTES,
    LDAP_GROUP_CLASSES,
    LDAP_PERSON_CLASSES,
    MIN_DN_COMPONENTS,
)

# Enterprise semantic types using flext-core foundation
type LDIFContent = str | bytes
type LDIFLines = list[str]
type LDAPObjectClass = str
type AttributeName = str
type AttributeValue = str

# =============================================================================
# TYPEDDICT DEFINITIONS - Type-safe interfaces
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
# DOMAIN VALUE OBJECTS - Using FlextValue from flext-core
# =============================================================================


class FlextLdifDistinguishedName(FlextValue):
    """Distinguished Name value object with RFC 4514 compliance."""

    value: str = Field(...)

    @field_validator("value")
    @classmethod
    def validate_dn(cls, v: str) -> str:
        """Validate and normalize DN format using flext-ldap root API.

        ✅ CORRECT ARCHITECTURE: Delegates to flext-ldap root API.
        ZERO duplication - uses existing flext-ldap validation and normalization.
        """
        if not v or not isinstance(v, str) or not v.strip():
            error_msg = "DN must be a non-empty string"
            raise FlextValidationError(error_msg)

        # ✅ DELEGATE to flext-ldap root API - NO local validation logic
        if not flext_ldap_validate_dn(v.strip()):
            error_msg = "DN must contain at least one attribute=value pair"
            raise FlextValidationError(error_msg)

        # ✅ DELEGATE to flext-ldap root API - NO local normalization logic
        return flext_ldap_normalize_dn(v.strip())

    # ✅ ELIMINATED DUPLICATION: DN normalization now delegates to flext-ldap root API
    # The _normalize_dn and _normalize_dn_component methods were removed because
    # they duplicated functionality available in flext_ldap_normalize_dn

    def __str__(self) -> str:
        """String representation returns the DN value."""
        return self.value

    def __eq__(self, other: object) -> bool:
        """Enable equality comparison with strings."""
        if isinstance(other, str):
            return self.value == other
        if isinstance(other, FlextLdifDistinguishedName):
            return self.value == other.value
        return super().__eq__(other)

    def __hash__(self) -> int:
        """Enable hashing based on the DN value."""
        return hash(self.value)

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

    def is_child_of(self, parent_dn: FlextLdifDistinguishedName) -> bool:
        """Check if this DN is a child of the parent DN."""
        parent_value = parent_dn.value.lower()
        child_value = self.value.lower()
        return child_value.endswith(f",{parent_value}") and len(child_value) > len(parent_value)


class FlextLdifAttributes(FlextValue):
    """LDIF attribute collection value object."""

    attributes: dict[str, list[str]] = Field(default_factory=dict)

    @field_validator("attributes")
    @classmethod
    def normalize_dn_attributes(cls, v: dict[str, list[str]]) -> dict[str, list[str]]:
        """Normalize DN-valued attributes using enterprise patterns."""
        return {
            attr_name: cls._normalize_attribute_values(attr_name, attr_values)
            for attr_name, attr_values in v.items()
        }

    @classmethod
    def _normalize_attribute_values(
        cls,
        attr_name: AttributeName,
        attr_values: list[AttributeValue],
    ) -> list[AttributeValue]:
        """Normalize attribute values based on semantic type."""
        if attr_name.lower() not in LDAP_DN_ATTRIBUTES:
            return attr_values

        # ✅ DELEGATE DN normalization to flext-ldap root API - NO local duplication
        normalized_values = []
        for value in attr_values:
            try:
                # ✅ Use flext-ldap root API instead of local methods
                normalized_value = flext_ldap_normalize_dn(value)
                normalized_values.append(normalized_value)
            except Exception:
                normalized_values.append(value)

        return normalized_values

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate attribute business rules using flext-ldap root API.

        ✅ CORRECT ARCHITECTURE: Delegates to flext-ldap for attribute validation.
        ZERO duplication - uses existing flext-ldap validation functionality.
        """
        for attr_name in self.attributes:
            if not attr_name or not attr_name.strip():
                return FlextResult.fail("Attribute name cannot be empty or whitespace-only")

            # ✅ DELEGATE to flext-ldap root API - NO local validation logic
            if not flext_ldap_validate_attribute_name(attr_name):
                return FlextResult.fail(f"Invalid LDAP attribute name format: {attr_name}")

        return FlextResult.ok(None)

    def get_values(self, name: str) -> list[str]:
        """Get attribute values by name."""
        return self.attributes.get(name, [])

    def has_attribute(self, name: str) -> bool:
        """Check if attribute exists."""
        return name in self.attributes

    def get_object_classes(self) -> list[str]:
        """Get objectClass values (case-insensitive)."""
        for attr_name in self.attributes:
            if attr_name.lower() == "objectclass":
                return self.attributes[attr_name]
        return []

    def get_single_value(self, name: str) -> str | None:
        """Get single value for attribute."""
        values = self.get_values(name)
        return values[0] if values else None

    def is_empty(self) -> bool:
        """Check if attributes collection is empty."""
        return len(self.attributes) == 0

    def __hash__(self) -> int:
        """Custom hash implementation."""
        hashable_attrs = {
            key: tuple(sorted(value_list))
            for key, value_list in self.attributes.items()
        }
        return hash(tuple(sorted(hashable_attrs.items())))

    def __eq__(self, other: object) -> bool:
        """Enable equality comparison."""
        if isinstance(other, dict):
            return self.attributes == other
        if isinstance(other, FlextLdifAttributes):
            return self.attributes == other.attributes
        return super().__eq__(other)


# =============================================================================
# DOMAIN ENTITIES - Using FlextEntity from flext-core
# =============================================================================

class FlextLdifEntry(FlextEntity):
    """LDIF entry entity with business logic."""

    dn: FlextLdifDistinguishedName = Field(...)
    attributes: FlextLdifAttributes = Field(default_factory=FlextLdifAttributes)
    changetype: str | None = Field(default=None)

    @classmethod
    def from_ldif_dict(cls, dn: str, attributes: dict[str, list[str]]) -> FlextLdifEntry:
        """Create LDIF entry from DN and attributes dict (legacy compatibility)."""
        # Validate inputs directly - same logic as FlextLdifFactory.create_entry
        if not dn or not isinstance(dn, str) or not dn.strip():
            msg = "DN must be a non-empty string"
            raise ValueError(msg)

        try:
            dn_obj = FlextLdifDistinguishedName(value=dn)
            attrs_obj = FlextLdifAttributes(attributes=attributes)
            # Generate deterministic ID like model_validate does
            import hashlib
            content_hash = hashlib.sha256(f"{dn}{attributes}".encode()).hexdigest()
            entry_id = f"{content_hash[:8]}-{content_hash[8:12]}-{content_hash[12:16]}-{content_hash[16:20]}-{content_hash[20:32]}"
            return cls(id=entry_id, dn=dn_obj, attributes=attrs_obj)
        except (ValueError, FlextValidationError) as e:
            raise ValueError(str(e)) from e

    @classmethod
    def model_validate(cls, obj: dict[str, object] | object, **_kwargs: object) -> FlextLdifEntry:
        """Backwards-compatible validation."""
        if isinstance(obj, dict):
            obj_copy = dict(obj)
            if "id" not in obj_copy:
                # Deterministic ID based on DN and attributes
                dn_str = str(obj_copy.get("dn", ""))
                attrs_str = str(obj_copy.get("attributes", {}))
                content_hash = hashlib.sha256(f"{dn_str}{attrs_str}".encode()).hexdigest()
                uuid_str = f"{content_hash[:8]}-{content_hash[8:12]}-{content_hash[12:16]}-{content_hash[16:20]}-{content_hash[20:32]}"
                obj_copy["id"] = uuid_str

            # Convert string DN to object
            if isinstance(obj_copy.get("dn"), str):
                try:
                    obj_copy["dn"] = FlextLdifDistinguishedName(value=cast("str", obj_copy["dn"]))
                except (ValueError, FlextValidationError) as e:
                    if "DN must be a non-empty string" in str(e):
                        msg = "DN must be a non-empty string"
                        raise ValueError(msg) from e
                    raise

            # Convert dict attributes to object
            if isinstance(obj_copy.get("attributes"), dict):
                obj_copy["attributes"] = FlextLdifAttributes(
                    attributes=cast("dict[str, list[str]]", obj_copy["attributes"]),
                )

            return super().model_validate(obj_copy)
        return super().model_validate(obj)

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate entry business rules."""
        if not self.dn.value:
            return FlextResult.fail("Entry must have a DN")

        attr_validation = self.attributes.validate_business_rules()
        if attr_validation.is_failure:
            return FlextResult.fail(f"Invalid attributes: {attr_validation.error}")

        if self.changetype != "delete" and self.attributes.is_empty():
            return FlextResult.fail("LDIF entry must have at least one attribute")

        if self.changetype != "delete" and not self.attributes.has_attribute("objectClass"):
            return FlextResult.fail("Entry must have objectClass attribute")

        return FlextResult.ok(None)

    def has_object_class(self, object_class: str) -> bool:
        """Check if entry has specific objectClass."""
        return object_class in self.attributes.get_object_classes()

    def get_object_classes(self) -> list[str]:
        """Get all objectClass values for this entry."""
        return self.attributes.get_object_classes()

    def get_attribute(self, name: str) -> list[str] | None:
        """Get attribute values by name."""
        values = self.attributes.get_values(name)
        return values or None

    def get_single_attribute(self, name: str) -> str | None:
        """Get single attribute value by name."""
        values = self.attributes.get_values(name)
        return values[0] if values else None

    def has_attribute(self, name: str) -> bool:
        """Check if attribute exists."""
        if not name or not name.strip():
            msg = "Attribute name cannot be empty"
            raise ValueError(msg)
        return self.attributes.has_attribute(name)

    def to_ldif(self) -> str:
        """Convert entry to LDIF string."""
        lines = [f"dn: {self.dn.value}"]

        if self.changetype:
            lines.append(f"changetype: {self.changetype}")

        for attr_name, values in self.attributes.attributes.items():
            lines.extend(f"{attr_name}: {value}" for value in values)

        return "\n".join(lines) + "\n"

    @classmethod
    def from_ldif_block(cls, block: str) -> FlextLdifEntry:
        """Create entry from a minimal LDIF block.

        Enforces:
        - Non-empty block
        - First non-empty line must start with 'dn:'
        - Subsequent lines parsed as 'key: value' pairs; duplicates accumulate
        """
        if not block or not block.strip():
            raise ValueError("LDIF block cannot be empty")

        lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
        if not lines or not lines[0].lower().startswith("dn:"):
            from flext_core.exceptions import FlextValidationError

            raise FlextValidationError("LDIF block must start with DN")

        dn_value = lines[0].split(":", 1)[1].strip()
        attributes: dict[str, list[str]] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip()
            attributes.setdefault(key, []).append(val)

        return cls(
            dn=FlextLdifDistinguishedName(value=dn_value),
            attributes=FlextLdifAttributes(attributes=attributes),
        )

    def is_person_entry(self) -> bool:
        """Check if entry represents a person."""
        return self._has_object_class_in_set(LDAP_PERSON_CLASSES)

    def is_group_entry(self) -> bool:
        """Check if entry represents a group."""
        return self._has_object_class_in_set(LDAP_GROUP_CLASSES)

    def _has_object_class_in_set(self, class_set: frozenset[LDAPObjectClass]) -> bool:
        """Centralized object class checking logic."""
        object_classes = self.get_object_classes()
        return bool(object_classes) and any(
            obj_class.lower() in {cls.lower() for cls in class_set}
            for obj_class in object_classes
        )

    def is_valid_entry(self) -> bool:
        """Check if entry passes semantic validation rules."""
        validation_result = self.validate_business_rules()
        return validation_result.success


# =============================================================================
# FACTORY METHODS - Using FlextFactory from flext-core
# =============================================================================

class FlextLdifFactory:
    """Factory for LDIF domain objects using unified patterns."""

    @staticmethod
    def create_dn(value: str) -> FlextResult[FlextLdifDistinguishedName]:
        """Create DN with validation."""
        return FlextFactory.create_model(FlextLdifDistinguishedName, value=value)

    @staticmethod
    def create_attributes(attributes: dict[str, list[str]]) -> FlextResult[FlextLdifAttributes]:
        """Create attributes with validation."""
        return FlextFactory.create_model(FlextLdifAttributes, attributes=attributes)

    @staticmethod
    def create_entry(
        dn: str,
        attributes: dict[str, list[str]],
        changetype: str | None = None,
    ) -> FlextResult[FlextLdifEntry]:
        """Create entry with validation."""
        dn_result = FlextLdifFactory.create_dn(dn)
        if dn_result.is_failure:
            return FlextResult.fail(f"Invalid DN: {dn_result.error}")

        attr_result = FlextLdifFactory.create_attributes(attributes)
        if attr_result.is_failure:
            return FlextResult.fail(f"Invalid attributes: {attr_result.error}")

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
