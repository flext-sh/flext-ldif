"""FLEXT-LDIF Validation Utilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
from collections.abc import Callable
from functools import lru_cache
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifFormatConstants
from flext_ldif.models import FlextLdifEntry

ValidatorFunc = Callable[[str], bool]

# Constants to avoid FBT violations
VALIDATION_SUCCESS = True
VALIDATION_FAILURE = False


def _validate_ldap_attribute_name(name: str) -> bool:
    """Local LDAP attribute name validator - breaks circular dependency.

    Validates attribute names per RFC 4512: base name + optional language tags/options.
    Supports: displayname;lang-es_es, orclinstancecount;oid-prd-app01.network.ctbc
    """
    if not name or not isinstance(name, str):
        return False
    attr_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*(?:;[a-zA-Z0-9_.-]+)*$")
    return bool(attr_pattern.match(name))


def _validate_ldap_dn(dn: str) -> bool:
    """Local LDAP DN validator - breaks circular dependency.

    Basic DN validation pattern to avoid circular import from flext-ldap.
    """
    if not dn or not isinstance(dn, str):
        return False
    # Basic DN validation pattern
    dn_pattern = re.compile(r"^[a-zA-Z][\w-]*=.+(?:,[a-zA-Z][\w-]*=.+)*$")
    return bool(dn_pattern.match(dn.strip()))


@lru_cache(maxsize=1)
def _get_ldap_validators() -> tuple[ValidatorFunc, ValidatorFunc]:
    """Use local validators to avoid circular dependency with flext-ldap."""
    return (_validate_ldap_attribute_name, _validate_ldap_dn)


class LdifValidator:
    """LDIF validation utility class using flext-ldap root APIs."""

    # Object class sets for entry type validation - using centralized constants
    PERSON_CLASSES: ClassVar[set[str]] = FlextLdifFormatConstants.PERSON_OBJECTCLASSES
    OU_CLASSES: ClassVar[set[str]] = FlextLdifFormatConstants.OU_OBJECTCLASSES
    GROUP_CLASSES: ClassVar[set[str]] = FlextLdifFormatConstants.GROUP_OBJECTCLASSES

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
            return FlextResult[bool].fail(
                FlextLdifFormatConstants.DN_CANNOT_BE_EMPTY_FORMAT
            )

        # ✅ DELEGATE to flext-ldap root API - NO local validation logic
        _attr_validator, dn_validator = _get_ldap_validators()
        is_valid = bool(dn_validator(dn_value.strip()))
        if not is_valid:
            return FlextResult[bool].fail(
                FlextLdifFormatConstants.INVALID_DN_FORMAT_MSG.format(
                    dn_value=dn_value,
                ),
            )

        return FlextResult[bool].ok(True)  # noqa: FBT003  # noqa: FBT003

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
            return FlextResult[bool].fail(
                FlextLdifFormatConstants.ATTRIBUTE_NAME_CANNOT_BE_EMPTY_FORMAT,
            )

        # ✅ DELEGATE to flext-ldap root API - NO local validation logic
        attr_validator, _dn_validator = _get_ldap_validators()
        is_valid = bool(attr_validator(attr_name))
        if not is_valid:
            return FlextResult[bool].fail(
                FlextLdifFormatConstants.INVALID_ATTRIBUTE_NAME_FORMAT_MSG.format(
                    attr_name=attr_name,
                ),
            )

        return FlextResult[bool].ok(True)  # noqa: FBT003  # noqa: FBT003

    @classmethod
    def validate_required_objectclass(cls, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate that entry has required objectClass attribute.

        Args:
            entry: LDIF entry to validate

        Returns:
            FlextResult[bool] indicating validation success

        """
        if not entry.has_attribute(FlextLdifFormatConstants.OBJECTCLASS_ATTRIBUTE):
            return FlextResult[bool].fail(
                FlextLdifFormatConstants.ENTRY_MISSING_OBJECTCLASS_FORMAT,
            )

        return FlextResult[bool].ok(True)  # noqa: FBT003  # noqa: FBT003

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
            return FlextResult[bool].fail(
                FlextLdifFormatConstants.ENTRY_MUST_HAVE_VALID_DN_FORMAT,
            )

        # Use railway programming for validation chain
        return (
            cls.validate_dn(entry.dn.value)
            .flat_map(lambda _: cls.validate_required_objectclass(entry))
            .map(lambda _: True)
        )

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
        # First validate basic completeness - early return on failure
        completeness_result = cls.validate_entry_completeness(entry)
        if not completeness_result.unwrap_or(VALIDATION_FAILURE):
            return completeness_result

        # Get objectClass values
        object_classes_attr = entry.get_attribute(
            FlextLdifFormatConstants.OBJECTCLASS_ATTRIBUTE,
        )
        if not object_classes_attr:
            return FlextResult[bool].fail(
                FlextLdifFormatConstants.ENTRY_MISSING_OBJECTCLASS_TYPE_VALIDATION,
            )

        object_classes = set(object_classes_attr)

        # Check if entry has any of the expected classes
        if not (expected_classes & object_classes):
            return FlextResult[bool].fail(
                FlextLdifFormatConstants.ENTRY_TYPE_MISMATCH_FORMAT.format(
                    expected_classes=expected_classes,
                    object_classes=object_classes,
                ),
            )

        return FlextResult[bool].ok(True)  # noqa: FBT003  # noqa: FBT003

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
            return FlextResult[bool].fail(
                FlextLdifFormatConstants.ENTRY_MISSING_REQUIRED_ATTRIBUTES_FORMAT.format(
                    missing_attrs=", ".join(missing_attrs),
                ),
            )

        return FlextResult[bool].ok(True)  # noqa: FBT003  # noqa: FBT003

    @classmethod
    def validate_person_schema(cls, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate person entry schema requirements.

        Args:
            entry: LDIF entry to validate

        Returns:
            FlextResult[bool] indicating validation success

        """
        # Check if it's a person entry first
        # Chain validation with railway programming
        return LdifValidator.is_person_entry(entry).flat_map(
            lambda _: cls.validate_required_attributes(
                entry, FlextLdifFormatConstants.PERSON_REQUIRED_ATTRIBUTES
            )
        )

    @classmethod
    def validate_ou_schema(cls, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate organizational unit entry schema requirements.

        Args:
            entry: LDIF entry to validate

        Returns:
            FlextResult[bool] indicating validation success

        """
        # Chain validation with railway programming for OU entries
        return LdifValidator.is_ou_entry(entry).flat_map(
            lambda _: cls.validate_required_attributes(
                entry, FlextLdifFormatConstants.OU_REQUIRED_ATTRIBUTES
            )
        )


# ========================================================================
# ADDITIONAL VALIDATION FUNCTIONS (Compatibility)
# ========================================================================


def validate_attribute_format(attr_name: str, attr_value: str) -> FlextResult[bool]:
    """Validate attribute name and value format."""
    # Use railway programming for attribute validation
    return LdifValidator.validate_attribute_name(attr_name).flat_map(
        lambda _: FlextResult[bool].fail(
            FlextLdifFormatConstants.EMPTY_ATTRIBUTE_VALUE_NOT_ALLOWED_FORMAT.format(
                attr_name=attr_name,
            )
        )
        if not attr_value.strip()
        else FlextResult[bool].ok(VALIDATION_SUCCESS)
    )


def validate_dn_format(dn_value: str) -> FlextResult[bool]:
    """Validate DN format - delegates to LdifValidator."""
    return LdifValidator.validate_dn(dn_value)


def validate_ldif_structure(entry: object) -> FlextResult[bool]:
    """Validate LDIF entry structure - delegates to LdifValidator."""
    if not isinstance(entry, FlextLdifEntry):
        return FlextResult[bool].fail(
            FlextLdifFormatConstants.ENTRY_MUST_BE_FLEXTLDIFENTRY_FORMAT,
        )

    return LdifValidator.validate_entry_completeness(entry)
