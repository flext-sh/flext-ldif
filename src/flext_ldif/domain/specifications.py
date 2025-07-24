"""FlextLdif Domain Specifications - Business Rules.

🏗️ CLEAN ARCHITECTURE: Domain Specifications
Built on flext-core foundation patterns.

Specifications encapsulate business rules that can be combined and reused.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import FlextValidationResult, FlextValidator

from flext_ldif.models import FlextLdifEntry

SpecificationPattern = FlextValidator


class FlextLdifEntrySpecification(SpecificationPattern[FlextLdifEntry]):
    """Base specification for FlextLdif entries."""

    def validate_business_rules(self, entry: FlextLdifEntry) -> FlextValidationResult:
        """Validate business rules for entry.

        Args:
            entry: FlextLdif entry to validate

        Returns:
            FlextValidationResult with validation outcome

        """
        if self.is_satisfied_by(entry):
            return FlextValidationResult.success(["Entry satisfies specification"])
        return FlextValidationResult.failure(["Entry does not satisfy specification"])

    def is_satisfied_by(self, entry: FlextLdifEntry) -> bool:
        """Check if entry satisfies the specification.

        Args:
            entry: FlextLdif entry to check

        Returns:
            True if entry satisfies specification

        """
        return bool(entry.dn and entry.attributes and not entry.attributes.is_empty())


class FlextLdifValidSpecification(FlextLdifEntrySpecification):
    """Specification for valid FlextLdif entries."""

    def is_satisfied_by(self, entry: FlextLdifEntry) -> bool:
        """Check if entry is valid.

        Args:
            entry: FlextLdif entry to validate

        Returns:
            True if entry is valid

        """
        if not super().is_satisfied_by(entry):
            return False

        # Must have at least objectClass attribute
        if not entry.has_attribute("objectClass"):
            return False

        # DN must be properly formatted
        dn_str = str(entry.dn)
        return not (not dn_str or "=" not in dn_str)


class FlextLdifPersonSpecification(FlextLdifEntrySpecification):
    """Specification for person-type FlextLdif entries."""

    def is_satisfied_by(self, entry: FlextLdifEntry) -> bool:
        """Check if entry represents a person.

        Args:
            entry: FlextLdif entry to check

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
        object_classes_attr = entry.get_attribute("objectClass")
        if not object_classes_attr:
            return False

        object_classes = set(object_classes_attr)
        return bool(person_classes & object_classes)


class FlextLdifGroupSpecification(FlextLdifEntrySpecification):
    """Specification for group-type FlextLdif entries."""

    def is_satisfied_by(self, entry: FlextLdifEntry) -> bool:
        """Check if entry represents a group.

        Args:
            entry: FlextLdif entry to check

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
        object_classes_attr = entry.get_attribute("objectClass")
        if not object_classes_attr:
            return False

        object_classes = set(object_classes_attr)
        return bool(group_classes & object_classes)


class FlextLdifOrganizationalUnitSpecification(FlextLdifEntrySpecification):
    """Specification for organizational unit FlextLdif entries."""

    def is_satisfied_by(self, entry: FlextLdifEntry) -> bool:
        """Check if entry represents an organizational unit.

        Args:
            entry: FlextLdif entry to check

        Returns:
            True if entry is an organizational unit

        """
        if not super().is_satisfied_by(entry):
            return False

        # Check for OU-related object classes
        ou_classes = {
            "organizationalUnit",
            "organizationalRole",
            "dcObject",
            "domain",
        }
        object_classes_attr = entry.get_attribute("objectClass")
        if not object_classes_attr:
            return False

        object_classes = set(object_classes_attr)
        return bool(ou_classes & object_classes)


class FlextLdifChangeRecordSpecification(FlextLdifEntrySpecification):
    """Specification for LDIF change record entries."""

    def is_satisfied_by(self, entry: FlextLdifEntry) -> bool:
        """Check if entry is a change record.

        Args:
            entry: FlextLdif entry to check

        Returns:
            True if entry is a change record

        """
        if not super().is_satisfied_by(entry):
            return False

        # Check for changetype attribute
        changetype = entry.get_attribute("changetype")
        if not changetype:
            return False

        # Valid change types
        valid_change_types = {"add", "modify", "delete", "modrdn"}
        return changetype[0] in valid_change_types


__all__ = [
    "FlextLdifChangeRecordSpecification",
    "FlextLdifEntrySpecification",
    "FlextLdifGroupSpecification",
    "FlextLdifOrganizationalUnitSpecification",
    "FlextLdifPersonSpecification",
    "FlextLdifValidSpecification",
]
