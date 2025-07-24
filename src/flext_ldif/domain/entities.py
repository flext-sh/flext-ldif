"""FlextLdif Domain Entities - Business Objects with Identity.

🏗️ CLEAN ARCHITECTURE: Domain Entities
Built on flext-core foundation patterns.

Entities represent business objects with unique identity in the FlextLdif domain.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import FlextEntity
from pydantic import Field

if TYPE_CHECKING:
    from flext_ldif.domain.values import FlextLdifAttributes, FlextLdifDistinguishedName


class FlextLdifEntry(FlextEntity):
    """FlextLdif Entry Entity.

    Represents a single LDIF entry with distinguished name and attributes.
    """

    dn: FlextLdifDistinguishedName = Field(..., description="Distinguished name")
    attributes: FlextLdifAttributes = Field(..., description="LDIF attributes")
    change_type: str | None = Field(None, description="Optional change type")

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

    def has_attribute(self, name: str) -> bool:
        """Check if entry has attribute.

        Args:
            name: Attribute name

        Returns:
            True if attribute exists

        """
        return self.attributes.has_attribute(name)

    def is_modify_operation(self) -> bool:
        """Check if this is a modify operation."""
        return self.change_type == "modify"

    def is_add_operation(self) -> bool:
        """Check if this is an add operation."""
        return self.change_type == "add"

    def is_delete_operation(self) -> bool:
        """Check if this is a delete operation."""
        return self.change_type == "delete"

    def validate_domain_rules(self) -> None:
        """Validate domain business rules for LDIF entry.

        Validates:
        - DN is valid and non-empty
        - Required attributes exist based on object classes
        - Attribute values comply with LDIF standards

        Raises:
            ValueError: If domain rules are violated

        """
        # Validate DN exists and is valid
        if not self.dn or not self.dn.value:
            raise ValueError("LDIF entry must have a valid distinguished name")

        # Validate DN domain rules
        self.dn.validate_domain_rules()

        # Validate attributes domain rules
        self.attributes.validate_domain_rules()

        # Validate object class requirements
        object_classes = self.get_object_classes()
        if not object_classes:
            raise ValueError("LDIF entry must have at least one objectClass")

        # For standard LDIF entries (not change operations), validate required attributes
        if not self.change_type:
            # Standard entry - ensure it has meaningful attributes beyond objectClass
            non_object_class_attrs = [
                name for name in self.attributes.get_attribute_names()
                if name.lower() != "objectclass"
            ]
            if not non_object_class_attrs:
                raise ValueError("LDIF entry must have attributes beyond objectClass")


class FlextLdifRecord(FlextEntity):
    """FlextLdif Record Entity.

    Represents a collection of FlextLdif entries with metadata.
    """

    entries: list[FlextLdifEntry] = Field(
        default_factory=list, description="LDIF entries",
    )
    ldif_version: int = Field(default=1, description="LDIF version")
    encoding: str = Field(default="utf-8", description="Character encoding")

    def get_entry_count(self) -> int:
        """Get number of entries in record."""
        return len(self.entries)

    def get_entries_by_object_class(self, object_class: str) -> list[FlextLdifEntry]:
        """Get entries filtered by object class.

        Args:
            object_class: Object class to filter by

        Returns:
            List of matching entries

        """
        return [entry for entry in self.entries if entry.has_object_class(object_class)]

    def find_entry_by_dn(self, dn: str) -> FlextLdifEntry | None:
        """Find entry by distinguished name.

        Args:
            dn: Distinguished name to search for

        Returns:
            FlextLdif entry if found, None otherwise

        """
        for entry in self.entries:
            if str(entry.dn) == dn:
                return entry
        return None

    def validate_domain_rules(self) -> None:
        """Validate domain business rules for LDIF record.

        Validates:
        - LDIF version is valid (>= 1)
        - Encoding is supported
        - All entries in the record are valid
        - No duplicate DN entries

        Raises:
            ValueError: If domain rules are violated

        """
        # Validate LDIF version
        if self.ldif_version < 1:
            raise ValueError("LDIF version must be >= 1")

        # Validate encoding
        import codecs
        try:
            codecs.lookup(self.encoding)
        except LookupError as e:
            raise ValueError(f"Unsupported encoding: {self.encoding}") from e

        # Track DNs to check for duplicates
        seen_dns: set[str] = set()

        # Validate all entries
        for i, entry in enumerate(self.entries):
            try:
                # Validate each entry's domain rules
                entry.validate_domain_rules()

                # Check for duplicate DNs
                dn_str = str(entry.dn)
                if dn_str in seen_dns:
                    raise ValueError(f"Duplicate DN found: {dn_str}")
                seen_dns.add(dn_str)

            except Exception as e:
                raise ValueError(f"Entry {i} validation failed: {e}") from e

        # Additional business rule: For non-empty records, ensure we have meaningful content
        if self.entries:
            # Check if we have at least one entry with actual data (beyond just objectClass)
            has_meaningful_entries = any(
                len([name for name in entry.attributes.get_attribute_names()
                    if name.lower() != "objectclass"]) > 0
                for entry in self.entries
            )
            if not has_meaningful_entries:
                raise ValueError("LDIF record must contain entries with meaningful attributes beyond objectClass")


__all__ = [
    "FlextLdifEntry",
    "FlextLdifRecord",
]
