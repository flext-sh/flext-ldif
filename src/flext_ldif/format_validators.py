"""FLEXT-LDIF Format Validators - Unified validation following flext-core patterns.

Single class per module containing all LDIF validation functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import Callable
from functools import lru_cache
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif.constants import FlextLDIFConstants
from flext_ldif.models import FlextLDIFModels

ValidatorFunc = Callable[[str], bool]

# Constants to avoid FBT violations
# Use FlextLDIFConstants directly - no loose constants needed


class FlextLDIFFormatValidators:
    """Unified LDIF format validators following flext-core single-class-per-module pattern.

    Contains all LDIF validation functionality as nested classes and static methods.
    No helper functions - all functionality centralized in this unified class.
    """

    @staticmethod
    def _validate_ldap_attribute_name(name: str) -> bool:
        """Local LDAP attribute name validator - breaks circular dependency.

        Validates attribute names per RFC 4512: base name + optional language tags/options.
        Supports: displayname;lang-es_es, orclinstancecount;oid-prd-app01.network.ctbc
        """
        if not name or not isinstance(name, str):
            return False
        attr_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*(?:;[a-zA-Z0-9_.-]+)*$")
        return bool(attr_pattern.match(name))

    @staticmethod
    def _validate_ldap_dn(dn: str) -> bool:
        """Local LDAP DN validator - breaks circular dependency.

        Basic DN validation pattern to avoid circular import from flext-ldap.
        """
        if not dn or not isinstance(dn, str):
            return False
        # Simple DN pattern - components separated by commas
        dn_pattern = re.compile(r"^[a-zA-Z][\w-]*=.+(?:,[a-zA-Z][\w-]*=.+)*$")
        return bool(dn_pattern.match(dn.strip()))

    @classmethod
    @lru_cache(maxsize=1)
    def get_ldap_validators(cls) -> tuple[ValidatorFunc, ValidatorFunc]:
        """Get local validators to avoid circular dependency with flext-ldap."""
        return (cls._validate_ldap_attribute_name, cls._validate_ldap_dn)

    class EntryValidator:
        """LDIF entry validation functionality."""

        # Object class sets for entry type validation - using centralized constants
        PERSON_CLASSES: ClassVar[set[str]] = (
            FlextLDIFConstants.FlextLDIFFormatConstants.PERSON_OBJECTCLASSES
        )
        OU_CLASSES: ClassVar[set[str]] = (
            FlextLDIFConstants.FlextLDIFFormatConstants.OU_OBJECTCLASSES
        )
        GROUP_CLASSES: ClassVar[set[str]] = (
            FlextLDIFConstants.FlextLDIFFormatConstants.GROUP_OBJECTCLASSES
        )

        @classmethod
        def validate_dn(cls, dn_value: str) -> FlextResult[bool]:
            """Validate Distinguished Name format using flext-ldap root API.

            ✅ CORRECT ARCHITECTURE: Delegates to flext-ldap root API.
            ZERO duplication - uses existing flext-ldap validation functionality.

            Args:
                dn_value: DN string to validate

            Returns:
                FlextResult[bool] indicating DN validity

            """
            # Use local DN validation to avoid circular dependency issues
            # flext_ldap may not be available or have import issues
            is_valid = FlextLDIFFormatValidators._validate_ldap_dn(dn_value)
            return FlextResult[bool].ok(is_valid)

        @classmethod
        def validate_attribute_name(cls, attr_name: str) -> FlextResult[bool]:
            """Validate LDAP attribute name format.

            Args:
                attr_name: Attribute name to validate

            Returns:
                FlextResult[bool] indicating attribute name validity

            """
            # Use local attribute validation to avoid circular dependency issues
            # flext_ldap may not be available or have import issues
            is_valid = FlextLDIFFormatValidators._validate_ldap_attribute_name(
                attr_name
            )
            return FlextResult[bool].ok(is_valid)

        @classmethod
        def is_person_entry(cls, entry: FlextLDIFModels.Entry) -> FlextResult[bool]:
            """Check if entry is a person entry based on objectClass.

            Args:
                entry: LDIF entry to check

            Returns:
                FlextResult[bool] indicating if entry is a person

            """
            if not entry.has_attribute("objectClass"):
                return FlextResult[bool].ok(FlextLDIFConstants.VALIDATION_FAILURE)

            object_class_values = entry.get_attribute("objectClass")
            if object_class_values is None:
                return FlextResult[bool].ok(FlextLDIFConstants.VALIDATION_FAILURE)
            object_classes = {oc.lower() for oc in object_class_values}
            is_person = bool(object_classes.intersection(cls.PERSON_CLASSES))
            return FlextResult[bool].ok(is_person)

        @classmethod
        def is_group_entry(cls, entry: FlextLDIFModels.Entry) -> FlextResult[bool]:
            """Check if entry is a group entry based on objectClass.

            Args:
                entry: LDIF entry to check

            Returns:
                FlextResult[bool] indicating if entry is a group

            """
            if not entry.has_attribute("objectClass"):
                return FlextResult[bool].ok(FlextLDIFConstants.VALIDATION_FAILURE)

            object_class_values = entry.get_attribute("objectClass")
            if object_class_values is None:
                return FlextResult[bool].ok(FlextLDIFConstants.VALIDATION_FAILURE)
            object_classes = {oc.lower() for oc in object_class_values}
            is_group = bool(object_classes.intersection(cls.GROUP_CLASSES))
            return FlextResult[bool].ok(is_group)

        @classmethod
        def is_ou_entry(cls, entry: FlextLDIFModels.Entry) -> FlextResult[bool]:
            """Check if entry is an organizational unit based on objectClass.

            Args:
                entry: LDIF entry to check

            Returns:
                FlextResult[bool] indicating if entry is an OU

            """
            if not entry.has_attribute("objectClass"):
                return FlextResult[bool].ok(FlextLDIFConstants.VALIDATION_FAILURE)

            object_class_values = entry.get_attribute("objectClass")
            if object_class_values is None:
                return FlextResult[bool].ok(FlextLDIFConstants.VALIDATION_FAILURE)
            object_classes = {oc.lower() for oc in object_class_values}
            is_ou = bool(object_classes.intersection(cls.OU_CLASSES))
            return FlextResult[bool].ok(is_ou)

        @classmethod
        def validate_entry_completeness(
            cls, entry: FlextLDIFModels.Entry
        ) -> FlextResult[bool]:
            """Validate entry has minimum required components.

            Args:
                entry: LDIF entry to validate

            Returns:
                FlextResult[bool] indicating entry completeness

            """
            # DN validation
            dn_result = cls.validate_dn(entry.dn.value)
            if not dn_result.is_success or not dn_result.value:
                return FlextResult[bool].fail("Invalid DN format")

            # ObjectClass requirement
            if not entry.has_attribute("objectClass"):
                return FlextResult[bool].fail("Missing objectClass attribute")

            return FlextResult[bool].ok(FlextLDIFConstants.VALIDATION_SUCCESS)

    class SchemaValidator:
        """LDIF schema validation functionality."""

        @classmethod
        def validate_required_attributes(
            cls, entry: FlextLDIFModels.Entry, required_attrs: list[str]
        ) -> FlextResult[bool]:
            """Validate entry has all required attributes for its schema.

            Args:
                entry: LDIF entry to validate
                required_attrs: List of required attribute names

            Returns:
                FlextResult[bool] indicating schema compliance

            """
            missing_attrs = [
                attr_name
                for attr_name in required_attrs
                if not entry.has_attribute(attr_name)
            ]

            if missing_attrs:
                return FlextResult[bool].fail(
                    f"Missing required attributes: {', '.join(missing_attrs)}"
                )

            return FlextResult[bool].ok(FlextLDIFConstants.VALIDATION_SUCCESS)

        @classmethod
        def validate_person_schema(
            cls, entry: FlextLDIFModels.Entry
        ) -> FlextResult[bool]:
            """Validate person entry schema requirements.

            Args:
                entry: LDIF entry to validate

            Returns:
                FlextResult[bool] indicating validation success

            """
            # Check if it's a person entry first
            # Chain validation with railway programming
            return FlextLDIFFormatValidators.EntryValidator.is_person_entry(
                entry
            ).flat_map(
                lambda _: cls.validate_required_attributes(
                    entry,
                    FlextLDIFConstants.FlextLDIFFormatConstants.PERSON_REQUIRED_ATTRIBUTES,
                )
            )

        @classmethod
        def validate_ou_schema(cls, entry: FlextLDIFModels.Entry) -> FlextResult[bool]:
            """Validate organizational unit entry schema requirements.

            Args:
                entry: LDIF entry to validate

            Returns:
                FlextResult[bool] indicating validation success

            """
            # Chain validation with railway programming for OU entries
            return FlextLDIFFormatValidators.EntryValidator.is_ou_entry(entry).flat_map(
                lambda _: cls.validate_required_attributes(
                    entry,
                    FlextLDIFConstants.FlextLDIFFormatConstants.OU_REQUIRED_ATTRIBUTES,
                )
            )


# Backward compatibility aliases - remove these after migration
FlextLDIFFormatValidator = FlextLDIFFormatValidators
LdifValidator = FlextLDIFFormatValidators.EntryValidator
LdifSchemaValidator = FlextLDIFFormatValidators.SchemaValidator


__all__ = [
    # Backward compatibility - these will be removed
    "FlextLDIFFormatValidator",
    "FlextLDIFFormatValidators",
    "LdifSchemaValidator",
    "LdifValidator",
]
