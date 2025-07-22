"""LDIF Domain Entities - Business Objects with Identity.

🏗️ CLEAN ARCHITECTURE: Domain Entities
Built on flext-core foundation patterns.

Entities represent business objects with unique identity in the LDIF domain.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import DomainEntity

if TYPE_CHECKING:
    from flext_ldif.domain.values import DistinguishedName, LDIFAttributes


class LDIFEntry(DomainEntity):
    """LDIF Entry Entity.

    Represents a single LDIF entry with distinguished name and attributes.
    """

    dn: DistinguishedName
    attributes: LDIFAttributes
    change_type: str | None = None

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

    def get_single_attribute(self, name: str) -> str | None:
        """Get single attribute value.

        Args:
            name: Attribute name

        Returns:
            First attribute value or None

        """
        return self.attributes.get_single_value(name)

    def get_attribute_values(self, name: str) -> list[str]:
        """Get all values for an attribute.

        Args:
            name: Attribute name

        Returns:
            List of attribute values

        """
        return self.attributes.get_values(name)

    def has_attribute(self, name: str) -> bool:
        """Check if entry has specific attribute.

        Args:
            name: Attribute name

        Returns:
            True if attribute exists

        """
        return self.attributes.has_attribute(name)

    def is_add_operation(self) -> bool:
        """Check if this is an add operation.

        Returns:
            True if this is an add operation

        """
        return self.change_type is None or self.change_type == "add"

    def is_modify_operation(self) -> bool:
        """Check if this is a modify operation.

        Returns:
            True if this is a modify operation

        """
        return self.change_type == "modify"

    def is_delete_operation(self) -> bool:
        """Check if this is a delete operation.

        Returns:
            True if this is a delete operation

        """
        return self.change_type == "delete"

    def validate_required_attributes(self) -> bool:
        """Validate that required attributes are present.

        Returns:
            True if all required attributes are present

        """
        # Every entry must have a DN
        if not self.dn or not str(self.dn):
            return False

        # Every entry must have at least one object class
        return bool(self.get_object_classes())


class LDIFRecord(DomainEntity):
    """LDIF Record Entity.

    Represents a complete LDIF record that may contain multiple entries
    or change operations.
    """

    entries: list[LDIFEntry]
    version: int = 1

    def get_entry_count(self) -> int:
        """Get number of entries in record.

        Returns:
            Number of entries

        """
        return len(self.entries)

    def get_dns(self) -> list[DistinguishedName]:
        """Get all distinguished names in record.

        Returns:
            List of distinguished names

        """
        return [entry.dn for entry in self.entries]

    def has_duplicate_dns(self) -> bool:
        """Check if record has duplicate DNs.

        Returns:
            True if there are duplicate DNs

        """
        dns = [str(dn) for dn in self.get_dns()]
        return len(dns) != len(set(dns))

    def get_entries_by_operation(self, operation: str) -> list[LDIFEntry]:
        """Get entries by operation type.

        Args:
            operation: Operation type (add, modify, delete)

        Returns:
            List of entries with specified operation

        """
        return [
            entry
            for entry in self.entries
            if (operation == "add" and entry.is_add_operation())
            or (operation == "modify" and entry.is_modify_operation())
            or (operation == "delete" and entry.is_delete_operation())
        ]

    def validate_record(self) -> bool:
        """Validate entire record.

        Returns:
            True if record is valid

        """
        # Must have at least one entry
        if not self.entries:
            return False

        # All entries must be valid
        for entry in self.entries:
            if not entry.validate_required_attributes():
                return False

        # No duplicate DNs allowed
        return not self.has_duplicate_dns()
