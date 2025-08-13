"""FLEXT-LDIF Validation Utilities - Using FLEXT-LDAP Root API.

✅ CORRECT ARCHITECTURE: This module uses flext-ldap root APIs for all LDAP validation.
   ZERO duplication - leverages existing flext-ldap functionality.

This module provides LDIF-specific validation utilities by delegating to
flext-ldap for all DN and attribute validation operations.

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from functools import lru_cache
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif.models import FlextLdifEntry

ValidatorFunc = Callable[[str], bool]


@lru_cache(maxsize=1)
def _get_ldap_validators() -> tuple[ValidatorFunc, ValidatorFunc]:
    """Import real validators from flext-ldap (canonical requirement)."""
    utils_mod = importlib.import_module("flext_ldap.utils")
    return (
        utils_mod.flext_ldap_validate_attribute_name,
        utils_mod.flext_ldap_validate_dn,
    )


class LdifValidator:
    """LDIF validation utility class using flext-ldap root APIs."""

    # Object class sets for entry type validation
    PERSON_CLASSES: ClassVar[set[str]] = {
        "person",
        "organizationalPerson",
        "inetOrgPerson",
        "user",
        "posixAccount",
    }

    OU_CLASSES: ClassVar[set[str]] = {
        "organizationalUnit",
        "top",
    }

    GROUP_CLASSES: ClassVar[set[str]] = {
        "group",
        "groupOfNames",
        "groupOfUniqueNames",
        "posixGroup",
        "groupOfMembers",
    }

    @classmethod
    def validate_dn(cls, dn_value: str) -> FlextResult[bool]:
        """Validate Distinguished Name format using flext-ldap root API.

        ✅ CORRECT ARCHITECTURE: Delegates to flext-ldap root API.
        ZERO duplication - uses existing flext-ldap validation functionality.

        Args:
            dn_value: DN string to validate

        Returns:
            FlextResult[bool] indicating validation success

        """
        if not dn_value or not dn_value.strip():
            return FlextResult.fail("DN cannot be empty")

        # ✅ DELEGATE to flext-ldap root API - NO local validation logic
        _attr_validator, dn_validator = _get_ldap_validators()
        is_valid = bool(dn_validator(dn_value.strip()))
        if not is_valid:
            return FlextResult.fail(f"Invalid DN format: {dn_value}")

        return FlextResult.ok(data=True)

    @classmethod
    def validate_attribute_name(cls, attr_name: str) -> FlextResult[bool]:
        """Validate LDAP attribute name format using flext-ldap root API.

        ✅ CORRECT ARCHITECTURE: Delegates to flext-ldap root API.
        ZERO duplication - uses existing flext-ldap validation functionality.

        Args:
            attr_name: Attribute name to validate

        Returns:
            FlextResult[bool] indicating validation success

        """
        if not attr_name or not attr_name.strip():
            return FlextResult.fail("Attribute name cannot be empty")

        # ✅ DELEGATE to flext-ldap root API - NO local validation logic
        attr_validator, _dn_validator = _get_ldap_validators()
        is_valid = bool(attr_validator(attr_name))
        if not is_valid:
            return FlextResult.fail(f"Invalid attribute name format: {attr_name}")

        return FlextResult.ok(data=True)

    @classmethod
    def validate_required_objectclass(cls, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate that entry has required objectClass attribute.

        Args:
            entry: LDIF entry to validate

        Returns:
            FlextResult[bool] indicating validation success

        """
        if not entry.has_attribute("objectClass"):
            return FlextResult.fail("Entry missing required objectClass attribute")

        return FlextResult.ok(data=True)

    @classmethod
    def validate_entry_completeness(cls, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate that entry has minimum required components.

        Args:
            entry: LDIF entry to validate

        Returns:
            FlextResult[bool] indicating validation success

        """
        # Check DN
        if not entry.dn or not entry.dn.value:
            return FlextResult.fail("LDIF entry must have a valid DN")

        dn_validation = cls.validate_dn(entry.dn.value)
        if not dn_validation.success:
            return dn_validation

        # Check objectClass
        objectclass_validation = cls.validate_required_objectclass(entry)
        if not objectclass_validation.success:
            return objectclass_validation

        return FlextResult.ok(data=True)

    @classmethod
    def validate_entry_type(
        cls,
        entry: FlextLdifEntry,
        expected_classes: set[str],
    ) -> FlextResult[bool]:
        """Validate entry type based on objectClass values.

        Args:
            entry: LDIF entry to validate
            expected_classes: Set of expected objectClass values

        Returns:
            FlextResult[bool] indicating validation success

        """
        # First validate basic completeness
        completeness_result = cls.validate_entry_completeness(entry)
        if not completeness_result.success:
            return completeness_result

        # Get objectClass values
        object_classes_attr = entry.get_attribute("objectClass")
        if not object_classes_attr:
            return FlextResult.fail("Entry missing objectClass for type validation")

        object_classes = set(object_classes_attr)

        # Check if entry has any of the expected classes
        if not (expected_classes & object_classes):
            return FlextResult.fail(
                f"Entry does not match expected type. "
                f"Expected: {expected_classes}, Found: {object_classes}",
            )

        return FlextResult.ok(data=True)

    @classmethod
    def is_person_entry(cls, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Check if entry is a person entry.

        Args:
            entry: LDIF entry to check

        Returns:
            FlextResult[bool] indicating if entry is person type

        """
        return cls.validate_entry_type(entry, cls.PERSON_CLASSES)

    @classmethod
    def is_ou_entry(cls, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Check if entry is an organizational unit entry.

        Args:
            entry: LDIF entry to check

        Returns:
            FlextResult[bool] indicating if entry is OU type

        """
        return cls.validate_entry_type(entry, cls.OU_CLASSES)

    @classmethod
    def is_group_entry(cls, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Check if entry is a group entry.

        Args:
            entry: LDIF entry to check

        Returns:
            FlextResult[bool] indicating if entry is group type

        """
        return cls.validate_entry_type(entry, cls.GROUP_CLASSES)


class LdifSchemaValidator:
    """Schema validation utility class for LDIF entries."""

    @classmethod
    def validate_required_attributes(
        cls,
        entry: FlextLdifEntry,
        required_attrs: list[str],
    ) -> FlextResult[bool]:
        """Validate that entry has all required attributes.

        Args:
            entry: LDIF entry to validate
            required_attrs: List of required attribute names

        Returns:
            FlextResult[bool] indicating validation success

        """
        missing_attrs = [
            attr_name
            for attr_name in required_attrs
            if not entry.has_attribute(attr_name)
        ]

        if missing_attrs:
            return FlextResult.fail(
                f"Entry missing required attributes: {', '.join(missing_attrs)}",
            )

        return FlextResult.ok(data=True)

    @classmethod
    def validate_person_schema(cls, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate person entry schema requirements.

        Args:
            entry: LDIF entry to validate

        Returns:
            FlextResult[bool] indicating validation success

        """
        # Check if it's a person entry first
        person_check = LdifValidator.is_person_entry(entry)
        if not person_check.success:
            return person_check

        # Validate required attributes for person entries
        required_attrs = ["cn", "sn"]  # Common Name and Surname
        return cls.validate_required_attributes(entry, required_attrs)

    @classmethod
    def validate_ou_schema(cls, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate organizational unit entry schema requirements.

        Args:
            entry: LDIF entry to validate

        Returns:
            FlextResult[bool] indicating validation success

        """
        # Check if it's an OU entry first
        ou_check = LdifValidator.is_ou_entry(entry)
        if not ou_check.success:
            return ou_check

        # Validate required attributes for OU entries
        required_attrs = ["ou"]  # Organizational Unit name
        return cls.validate_required_attributes(entry, required_attrs)


# ========================================================================
# ADDITIONAL VALIDATION FUNCTIONS (Compatibility)
# ========================================================================


def validate_attribute_format(attr_name: str, attr_value: str) -> FlextResult[bool]:
    """Validate attribute name and value format."""
    # Validate attribute name
    name_result = LdifValidator.validate_attribute_name(attr_name)
    if not name_result.success:
        return name_result

    # Basic value validation
    if not attr_value.strip():
        return FlextResult.fail(f"Empty attribute value not allowed for {attr_name}")

    return FlextResult.ok(data=True)


def validate_dn_format(dn_value: str) -> FlextResult[bool]:
    """Validate DN format - delegates to LdifValidator."""
    return LdifValidator.validate_dn(dn_value)


def validate_ldif_structure(entry: object) -> FlextResult[bool]:
    """Validate LDIF entry structure - delegates to LdifValidator."""
    if not isinstance(entry, FlextLdifEntry):
        return FlextResult.fail("Entry must be FlextLdifEntry instance")

    return LdifValidator.validate_entry_completeness(entry)
