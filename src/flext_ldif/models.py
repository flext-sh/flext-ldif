"""FlextLdif models and value objects using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import NewType

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import FlextResult, FlextValueObject
from pydantic import Field, field_validator

# Type aliases for LDIF-specific concepts
LDIFContent = NewType("LDIFContent", str)
LDIFLines = NewType("LDIFLines", list[str])


class FlextLdifDistinguishedName(FlextValueObject):
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

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate DN domain rules (required by FlextValueObject)."""
        # Validation is done in field_validator, so just check final state
        if not self.value or "=" not in self.value:
            return FlextResult.fail("DN must contain at least one attribute=value pair")
        return FlextResult.ok(None)


class FlextLdifAttributes(FlextValueObject):
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

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate attributes domain rules (required by FlextValueObject)."""
        # Validate attribute names
        for attr_name in self.attributes:
            if not attr_name.strip():
                return FlextResult.fail(f"Invalid attribute name: {attr_name}")
        return FlextResult.ok(None)


class FlextLdifEntry(FlextValueObject):
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
            List of attribute values if found, None otherwise

        """
        values = self.attributes.get_values(name)
        return values or None

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
        return False  # Model entries are not change operations

    def is_add_operation(self) -> bool:
        """Check if this is an add operation."""
        return False  # Model entries are not change operations

    def is_delete_operation(self) -> bool:
        """Check if this is a delete operation."""
        return False  # Model entries are not change operations

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

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate LDIF entry domain rules."""
        # Validate DN is not empty
        if not self.dn or not self.dn.value:
            return FlextResult.fail("LDIF entry must have a valid DN")

        # Validate at least one attribute exists
        if not self.attributes or not self.attributes.attributes:
            return FlextResult.fail("LDIF entry must have at least one attribute")

        return FlextResult.ok(None)

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
        return cls(
            dn=FlextLdifDistinguishedName.model_validate({"value": dn}),
            attributes=FlextLdifAttributes.model_validate({"attributes": attributes}),
        )

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
    "FlextLdifDistinguishedName",
    # Core models and value objects
    "FlextLdifEntry",
    # Type aliases
    "LDIFContent",
    "LDIFLines",
]
