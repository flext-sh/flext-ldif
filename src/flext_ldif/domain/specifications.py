"""LDIF Domain Specifications - Business Rules.

🏗️ CLEAN ARCHITECTURE: Domain Specifications
Built on flext-core foundation patterns.

Specifications encapsulate business rules that can be combined and reused.
"""

from __future__ import annotations

from flext_core import SpecificationPattern

from flext_ldif.domain.entities import LDIFEntry


class LDIFEntrySpecification(SpecificationPattern[LDIFEntry]):
    """Base specification for LDIF entries."""

    def is_satisfied_by(self, entry: LDIFEntry) -> bool:
        """Check if entry satisfies the specification.

        Args:
            entry: LDIF entry to check

        Returns:
            True if entry satisfies specification

        """
        return bool(entry.dn and entry.attributes)


class ValidLDIFSpecification(LDIFEntrySpecification):
    """Specification for valid LDIF entries."""

    def is_satisfied_by(self, entry: LDIFEntry) -> bool:
        """Check if entry is valid.

        Args:
            entry: LDIF entry to validate

        Returns:
            True if entry is valid

        """
        if not super().is_satisfied_by(entry):
            return False

        # Must have at least one object class
        object_classes = entry.get_object_classes()
        if not object_classes:
            return False

        # DN must be properly formatted
        dn_str = str(entry.dn)
        return not (not dn_str or "=" not in dn_str)


class PersonLDIFSpecification(LDIFEntrySpecification):
    """Specification for person-type LDIF entries."""

    def is_satisfied_by(self, entry: LDIFEntry) -> bool:
        """Check if entry represents a person.

        Args:
            entry: LDIF entry to check

        Returns:
            True if entry is a person

        """
        if not super().is_satisfied_by(entry):
            return False

        # Check for person-related object classes
        person_classes = {
            "person",
            "organizationalPerson",
            "inetOrgPerson",
            "user",
            "posixAccount",
        }
        object_classes = set(entry.get_object_classes())

        return bool(person_classes & object_classes)


class GroupLDIFSpecification(LDIFEntrySpecification):
    """Specification for group-type LDIF entries."""

    def is_satisfied_by(self, entry: LDIFEntry) -> bool:
        """Check if entry represents a group.

        Args:
            entry: LDIF entry to check

        Returns:
            True if entry is a group

        """
        if not super().is_satisfied_by(entry):
            return False

        # Check for group-related object classes
        group_classes = {
            "group",
            "groupOfNames",
            "groupOfUniqueNames",
            "posixGroup",
            "organizationalRole",
        }
        object_classes = set(entry.get_object_classes())

        return bool(group_classes & object_classes)


class OrganizationalUnitSpecification(LDIFEntrySpecification):
    """Specification for organizational unit LDIF entries."""

    def is_satisfied_by(self, entry: LDIFEntry) -> bool:
        """Check if entry represents an organizational unit.

        Args:
            entry: LDIF entry to check

        Returns:
            True if entry is an OU

        """
        if not super().is_satisfied_by(entry):
            return False

        # Check for OU object class
        object_classes = entry.get_object_classes()
        return "organizationalUnit" in object_classes


class ModifyOperationSpecification(LDIFEntrySpecification):
    """Specification for modify operation entries."""

    def is_satisfied_by(self, entry: LDIFEntry) -> bool:
        """Check if entry is a modify operation.

        Args:
            entry: LDIF entry to check

        Returns:
            True if entry is a modify operation

        """
        return entry.is_modify_operation()


class AddOperationSpecification(LDIFEntrySpecification):
    """Specification for add operation entries."""

    def is_satisfied_by(self, entry: LDIFEntry) -> bool:
        """Check if entry is an add operation.

        Args:
            entry: LDIF entry to check

        Returns:
            True if entry is an add operation

        """
        return entry.is_add_operation()


class DeleteOperationSpecification(LDIFEntrySpecification):
    """Specification for delete operation entries."""

    def is_satisfied_by(self, entry: LDIFEntry) -> bool:
        """Check if entry is a delete operation.

        Args:
            entry: LDIF entry to check

        Returns:
            True if entry is a delete operation

        """
        return entry.is_delete_operation()


class RequiredAttributesSpecification(LDIFEntrySpecification):
    """Specification for entries with required attributes."""

    def __init__(self, required_attributes: list[str]) -> None:
        """Initialize with required attributes.

        Args:
            required_attributes: List of required attribute names

        """
        self.required_attributes = required_attributes

    def is_satisfied_by(self, entry: LDIFEntry) -> bool:
        """Check if entry has all required attributes.

        Args:
            entry: LDIF entry to check

        Returns:
            True if entry has all required attributes

        """
        if not super().is_satisfied_by(entry):
            return False

        for attr_name in self.required_attributes:
            if not entry.has_attribute(attr_name):
                return False

        return True


class DNPatternSpecification(SpecificationPattern[str]):
    """Specification for DN pattern matching."""

    def __init__(self, pattern: str) -> None:
        """Initialize with DN pattern.

        Args:
            pattern: DN pattern to match (supports wildcards)

        """
        self.pattern = pattern.lower()

    def is_satisfied_by(self, dn: str) -> bool:
        """Check if DN matches pattern.

        Args:
            dn: Distinguished name to check

        Returns:
            True if DN matches pattern

        """
        dn_lower = dn.lower()

        # Simple pattern matching - can be enhanced
        if "*" in self.pattern:
            # Remove * and check if remaining parts are in DN
            pattern_parts = self.pattern.replace("*", "").split(",")
            return all(
                part.strip() in dn_lower for part in pattern_parts if part.strip()
            )
        # Exact suffix match
        return dn_lower.endswith(self.pattern)


class AttributeValueSpecification(SpecificationPattern[LDIFEntry]):
    """Specification for entries with specific attribute values."""

    def __init__(self, attribute_name: str, expected_value: str) -> None:
        """Initialize with attribute criteria.

        Args:
            attribute_name: Name of attribute to check
            expected_value: Expected attribute value

        """
        self.attribute_name = attribute_name
        self.expected_value = expected_value

    def is_satisfied_by(self, entry: LDIFEntry) -> bool:
        """Check if entry has expected attribute value.

        Args:
            entry: LDIF entry to check

        Returns:
            True if entry has expected attribute value

        """
        values = entry.get_attribute_values(self.attribute_name)
        return self.expected_value in values
