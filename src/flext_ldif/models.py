"""LDIF models using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Any

from flext_core import DomainValueObject
from pydantic import Field, field_validator

from .domain.values import DistinguishedName, LDIFAttributes


class LDIFEntry(DomainValueObject):
    """LDIF entry model using flext-core patterns."""

    dn: DistinguishedName = Field(..., description="Distinguished Name")
    attributes: LDIFAttributes = Field(
        default_factory=lambda: LDIFAttributes(attributes={}),
        description="LDIF attributes dictionary",
    )

    @field_validator("dn", mode="before")
    @classmethod
    def validate_dn(cls, v: Any) -> DistinguishedName:
        """Convert string DN to DistinguishedName object."""
        if isinstance(v, str):
            return DistinguishedName(value=v)
        if isinstance(v, DistinguishedName):
            return v
        msg = f"Invalid DN type: {type(v)}"
        raise ValueError(msg)

    @field_validator("attributes", mode="before")
    @classmethod
    def validate_attributes(cls, v: Any) -> LDIFAttributes:
        """Convert dict attributes to LDIFAttributes object."""
        if isinstance(v, dict):
            return LDIFAttributes(attributes=v)
        if isinstance(v, LDIFAttributes):
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
        object.__setattr__(self, "attributes", LDIFAttributes(attributes=new_attrs))

    def has_attribute(self, name: str) -> bool:
        """Check if LDIF entry has a specific attribute.

        Args:
            name: The attribute name to check

        Returns:
            True if attribute exists, False otherwise

        """
        return self.attributes.has_attribute(name)

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

    @classmethod
    def from_ldif_block(cls, ldif_block: str) -> LDIFEntry:
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
            dn=DistinguishedName(value=dn),
            attributes=LDIFAttributes(attributes=attributes),
        )


__all__ = [
    "LDIFEntry",
]
