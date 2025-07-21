"""LDIF models using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import DomainValueObject, Field

from .types import DistinguishedName, LDIFAttributes


class LDIFEntry(DomainValueObject):
    """LDIF entry model using flext-core patterns."""

    dn: DistinguishedName = Field(..., description="Distinguished Name")
    attributes: LDIFAttributes = Field(
        default_factory=lambda: LDIFAttributes({}),
        description="LDIF attributes dictionary",
    )

    def get_attribute(self, name: str) -> list[str] | None:
        """Get LDIF attribute values by name.

        Args:
            name: The attribute name to retrieve

        Returns:
            List of attribute values if found, None otherwise

        """
        return self.attributes.get(name)

    def set_attribute(self, name: str, values: list[str]) -> None:
        """Set an attribute with the given name and values."""
        new_attrs = dict(self.attributes)
        new_attrs[name] = values
        # Use property setter instead of direct assignment
        object.__setattr__(self, "attributes", LDIFAttributes(new_attrs))

    def has_attribute(self, name: str) -> bool:
        """Check if LDIF entry has a specific attribute.

        Args:
            name: The attribute name to check

        Returns:
            True if attribute exists, False otherwise

        """
        return name in self.attributes

    def get_single_attribute(self, name: str) -> str | None:
        """Get single value from an LDIF attribute.

        Args:
            name: The attribute name to retrieve

        Returns:
            First attribute value if found, None otherwise

        """
        values = self.get_attribute(name)
        return values[0] if values else None

    def to_ldif(self) -> str:
        """Convert entry to LDIF string format.

        Returns:
            LDIF string representation of the entry

        """
        lines = [f"dn: {self.dn}"]

        for attr_name, attr_values in self.attributes.items():
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
            dn=DistinguishedName(dn),
            attributes=LDIFAttributes(attributes),
        )


__all__ = [
    "LDIFEntry",
]
