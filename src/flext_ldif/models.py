"""FlextLdif models using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Any

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import FlextValueObject
from pydantic import Field, field_validator

from .domain.values import FlextLdifAttributes, FlextLdifDistinguishedName


class FlextLdifEntry(FlextValueObject):
    """LDIF entry model using flext-core patterns."""

    dn: FlextLdifDistinguishedName = Field(..., description="Distinguished Name")
    attributes: FlextLdifAttributes = Field(
        default_factory=lambda: FlextLdifAttributes.model_validate({"attributes": {}}),
        description="LDIF attributes dictionary",
    )

    @field_validator("dn", mode="before")
    @classmethod
    def validate_dn(cls, v: Any) -> FlextLdifDistinguishedName:
        """Convert string DN to FlextLdifDistinguishedName object."""
        if isinstance(v, str):
            return FlextLdifDistinguishedName.model_validate({"value": v})
        if isinstance(v, FlextLdifDistinguishedName):
            return v
        msg = f"Invalid DN type: {type(v)}"
        raise ValueError(msg)

    @field_validator("attributes", mode="before")
    @classmethod
    def validate_attributes(cls, v: Any) -> FlextLdifAttributes:
        """Convert dict attributes to FlextLdifAttributes object."""
        if isinstance(v, dict):
            return FlextLdifAttributes.model_validate({"attributes": v})
        if isinstance(v, FlextLdifAttributes):
            return v
        msg = f"Invalid attributes type: {type(v)}"
        raise ValueError(msg)

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

    def validate_domain_rules(self) -> None:
        """Validate LDIF entry domain rules."""
        # Validate DN is not empty
        if not self.dn or not self.dn.value:
            msg = "LDIF entry must have a valid DN"
            raise ValueError(msg)

        # Validate at least one attribute exists
        if not self.attributes or not self.attributes.attributes:
            msg = "LDIF entry must have at least one attribute"
            raise ValueError(msg)

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


__all__ = [
    "FlextLdifEntry",
]
