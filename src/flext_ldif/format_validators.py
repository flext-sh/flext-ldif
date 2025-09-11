"""FLEXT-LDIF Format Validators - Direct flext-core usage.

Minimal LDIF-specific validator extensions using flext-core directly.
No duplication of existing functionality - only domain-specific additions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from flext_core import FlextConstants, FlextResult, FlextValidations

from flext_ldif.constants import FlextLDIFConstants
from flext_ldif.models import FlextLDIFModels

# Type aliases for Python 3.13+ generic syntax
if TYPE_CHECKING:
    type FlextResultBool = FlextResult[bool]
else:
    FlextResultBool = FlextResult


class FlextLDIFFormatValidators(FlextValidations.Domain.BaseValidator):
    """LDIF Format Validators using flext-core BaseValidator directly.

    Provides LDIF-specific validation methods while using flext-core
    validation infrastructure directly. No duplication of base functionality.
    """

    _cached_validators: tuple[Callable[[str], bool], Callable[[str], bool]] | None = (
        None
    )

    def __init__(self) -> None:
        """Initialize LDIF validators using flext-core BaseValidator."""
        super().__init__()

    def validate_entry(self, entry: FlextLDIFModels.Entry) -> FlextResultBool:
        """Validate complete LDIF entry using flext-core validation."""
        try:
            # Use entry's own validation method
            validation_result = entry.validate_business_rules()
            if validation_result.is_failure:
                return FlextResult[bool].fail(validation_result.error or "Validation failed")
            return FlextResult[bool].ok(data=True)
        except Exception as e:
            return FlextResult[bool].fail(f"Entry validation error: {e}")

    def validate_attribute_name_format(self, name: str) -> FlextResultBool:
        """Validate LDAP attribute name format using flext-core."""
        return (
            FlextValidations.Core.TypeValidators.validate_string_non_empty(name)
            .flat_map(
                lambda _: FlextValidations.Core.validate_pattern_match(
                    name,
                    r"^[a-zA-Z][a-zA-Z0-9-]*(?:;[a-zA-Z0-9-]+(?:[-_.][a-zA-Z0-9-]+)*)*$",
                )
            )
            .map(lambda _: True)
        )

    def validate_dn_format(self, dn: str, *, strict: bool = True) -> FlextResultBool:
        """Validate LDAP DN format using flext-core pattern matching."""
        if dn == "" and not strict:
            return FlextResult[bool].ok(data=True)
        if dn == "":
            return FlextResult[bool].fail("Empty DN is invalid in strict mode")
        pattern_result = FlextValidations.Core.validate_pattern_match(
            dn, FlextConstants.LDAP.DN_PATTERN
        )
        if pattern_result.is_failure:
            return FlextResult[bool].fail(
                f"Invalid DN format: '{dn}' does not match LDAP DN pattern"
            )
        return FlextResult[bool].ok(data=True)

    def validate_object_class_format(self, object_class: str) -> FlextResultBool:
        """Validate objectClass value format using flext-core."""
        return (
            FlextValidations.Core.TypeValidators.validate_string_non_empty(object_class)
            .flat_map(
                lambda _: FlextValidations.Core.validate_pattern_match(
                    object_class.strip(),
                    r"^[a-zA-Z][a-zA-Z0-9]*$",
                )
            )
            .map(lambda _: True)
        )

    def validate_dn(self, dn_value: str, *, strict: bool = True) -> FlextResultBool:
        """Alias to validate_dn_format for API compatibility."""
        return self.validate_dn_format(dn_value, strict=strict)

    def validate_attribute_name(self, attr_name: str) -> FlextResultBool:
        """Alias to validate_attribute_name_format for API compatibility."""
        return self.validate_attribute_name_format(attr_name)

    def is_person_entry(self, entry: FlextLDIFModels.Entry) -> FlextResultBool:
        """Check if entry is a person entry based on objectClass."""
        object_classes = entry.get_attribute("objectClass") or []
        # Convert both to lowercase for case-insensitive comparison
        object_classes_lower = {oc.lower() for oc in object_classes}
        person_classes_lower = {
            oc.lower() for oc in FlextLDIFConstants.PERSON_OBJECTCLASSES
        }

        return FlextResult[bool].ok(
            bool(object_classes_lower.intersection(person_classes_lower))
        )

    def is_group_entry(self, entry: FlextLDIFModels.Entry) -> FlextResultBool:
        """Check if entry is a group entry based on objectClass."""
        object_classes = entry.get_attribute("objectClass") or []
        # Convert both to lowercase for case-insensitive comparison
        object_classes_lower = {oc.lower() for oc in object_classes}
        group_classes_lower = {
            oc.lower() for oc in FlextLDIFConstants.GROUP_OBJECTCLASSES
        }

        return FlextResult[bool].ok(
            bool(object_classes_lower.intersection(group_classes_lower))
        )

    def is_ou_entry(self, entry: FlextLDIFModels.Entry) -> FlextResultBool:
        """Check if entry is an organizational unit based on objectClass."""
        object_classes = entry.get_attribute("objectClass") or []
        # Convert both to lowercase for case-insensitive comparison
        object_classes_lower = {oc.lower() for oc in object_classes}
        organizational_classes_lower = {
            oc.lower() for oc in FlextLDIFConstants.ORGANIZATIONAL_OBJECTCLASSES
        }

        return FlextResult[bool].ok(
            bool(object_classes_lower.intersection(organizational_classes_lower))
        )

    def validate_required_objectclass(
        self, entry: FlextLDIFModels.Entry
    ) -> FlextResultBool:
        """Validate objectClass using flext-core list validation."""
        object_class_values = entry.get_attribute("objectClass") or []

        # Use appropriate flext-core validation for list
        validation_result = FlextValidations.Core.TypeValidators.validate_list(
            object_class_values
        )
        if validation_result.is_failure:
            return FlextResult[bool].fail(
                f"ObjectClass validation failed: {validation_result.error}"
            )

        # Check if list is not empty (required objectClass)
        if not object_class_values:
            return FlextResult[bool].fail("ObjectClass is required but missing")

        return FlextResult[bool].ok(data=True)

    def validate_entry_completeness(
        self, entry: FlextLDIFModels.Entry
    ) -> FlextResultBool:
        """Validate entry completeness using basic LDIF validation."""
        # Basic completeness validation for LDIF entries
        if not entry or not entry.dn or not entry.dn.value:
            return FlextResult[bool].fail("Entry must have a valid DN")

        # Check if entry has attributes
        if not entry.attributes or not entry.attributes.data:
            return FlextResult[bool].fail("Entry must have attributes")

        # Check for objectClass (required in LDIF)
        object_classes = entry.get_attribute("objectClass")
        if not object_classes:
            return FlextResult[bool].fail("Entry must have objectClass attribute")

        return FlextResult[bool].ok(data=True)

    def validate_entry_type(
        self, entry: FlextLDIFModels.Entry, expected_types: set[str]
    ) -> FlextResultBool:
        """Validate entry type using flext-core list validation."""
        object_class_values = entry.get_attribute("objectClass") or []

        # First validate the list structure
        list_validation = FlextValidations.Core.TypeValidators.validate_list(
            object_class_values
        )
        if list_validation.is_failure:
            return list_validation.map(lambda _: False)

        # Check if there's intersection with expected types
        has_expected_type = bool(
            {oc.lower() for oc in object_class_values}.intersection(
                {oc.lower() for oc in expected_types}
            )
        )

        if has_expected_type:
            return FlextResult[bool].ok(data=True)
        return FlextResult[bool].fail("Entry does not have expected objectClass types")

    def validate_required_attributes(
        self, entry: FlextLDIFModels.Entry, required_attrs: list[str]
    ) -> FlextResultBool:
        """Validate required attributes for LDIF entry."""
        missing_attrs = []

        for attr in required_attrs:
            value = entry.get_attribute(attr)
            if value is None or (isinstance(value, list) and len(value) == 0):
                missing_attrs.append(attr)

        if missing_attrs:
            missing_str = ", ".join(missing_attrs)
            return FlextResult[bool].fail(f"Required attributes missing: {missing_str}")

        return FlextResult[bool].ok(data=True)

    def validate_person_schema(self, entry: FlextLDIFModels.Entry) -> FlextResultBool:
        """Validate person entry schema requirements."""
        return (
            self.is_person_entry(entry)
            .flat_map(
                lambda is_person: FlextResult[bool].ok(data=True)
                if is_person
                else FlextResult[bool].fail("Entry is not a person entry")
            )
            .flat_map(
                lambda _: self.validate_required_attributes(
                    entry, list(FlextLDIFConstants.LDIF.REQUIRED_PERSON_ATTRIBUTES)
                )
            )
        )

    def validate_ou_schema(self, entry: FlextLDIFModels.Entry) -> FlextResultBool:
        """Validate organizational unit entry schema requirements."""
        return (
            self.is_ou_entry(entry)
            .flat_map(
                lambda is_ou: FlextResult[bool].ok(data=True)
                if is_ou
                else FlextResult[bool].fail("Entry is not an organizational unit")
            )
            .flat_map(
                lambda _: self.validate_required_attributes(
                    entry, list(FlextLDIFConstants.LDIF.REQUIRED_ORGUNIT_ATTRIBUTES)
                )
            )
        )

    def validate_group_schema(self, entry: FlextLDIFModels.Entry) -> FlextResultBool:
        """Validate group entry schema requirements."""
        return (
            self.is_group_entry(entry)
            .flat_map(
                lambda is_group: FlextResult[bool].ok(data=True)
                if is_group
                else FlextResult[bool].fail("Entry is not a group entry")
            )
            .flat_map(
                lambda _: self.validate_required_attributes(
                    entry, ["cn", "objectClass"]
                )
            )
        )

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules using flext-core directly."""
        entity_data: dict[str, object] = {
            "id": "format_validators",
            "type": "ldif_validators",
        }
        return (
            FlextValidations.Domain.EntityValidator()
            .validate_entity_constraints(entity_data)
            .map(lambda _: None)
        )

    @classmethod
    def get_ldap_validators(cls) -> tuple[Callable[[str], bool], Callable[[str], bool]]:
        """Get LDAP validators using flext-core - simple alias for test compatibility."""
        if cls._cached_validators is None:

            def attr_validator(name: str) -> bool:
                result = FlextValidations.Core.TypeValidators.validate_string_non_empty(
                    name
                )
                if result.is_failure:
                    return False
                pattern_result = FlextValidations.Core.validate_pattern_match(
                    name,
                    r"^[a-zA-Z][a-zA-Z0-9-]*(?:;[a-zA-Z0-9-]+(?:[-_.][a-zA-Z0-9-]+)*)*$",
                )
                return pattern_result.is_success

            def dn_validator(dn: str) -> bool:
                return cls._validate_ldap_dn(dn)

            cls._cached_validators = (attr_validator, dn_validator)
        return cls._cached_validators

    @classmethod
    def _validate_ldap_attribute_name(cls, attr_name: str) -> bool:
        """Private validator for LDAP attribute names - simple alias for test compatibility."""
        result = FlextValidations.Core.TypeValidators.validate_string_non_empty(
            attr_name
        )
        if result.is_failure:
            return False

        pattern_result = FlextValidations.Core.validate_pattern_match(
            attr_name,
            r"^[a-zA-Z][a-zA-Z0-9-]*(?:;[a-zA-Z0-9-]+(?:[-_.][a-zA-Z0-9-]+)*)*$",
        )
        return pattern_result.is_success

    @classmethod
    def _validate_ldap_dn(cls, dn: str) -> bool:
        """Private validator for LDAP DN - simple alias for test compatibility."""
        if dn == "":
            return False
        pattern_result = FlextValidations.Core.validate_pattern_match(
            dn, FlextConstants.LDAP.DN_PATTERN
        )
        return pattern_result.is_success


# Backward compatibility aliases (deprecated - use FlextLDIFFormatValidators directly)
FlextLDIFFormatValidator = FlextLDIFFormatValidators


# Simple aliases for test compatibility - use main FlextLDIFFormatValidators directly
class LdifValidator:
    """Simple validator using flext-core directly."""

    @staticmethod
    def validate_attribute_name(attr_name: str) -> FlextResult[bool]:
        """Validate attribute name using flext-core."""
        return FlextLDIFFormatValidators().validate_attribute_name_format(attr_name)

    @staticmethod
    def validate_dn(dn_value: str) -> FlextResult[bool]:
        """Validate DN using flext-core pattern matching."""
        return FlextLDIFFormatValidators().validate_dn_format(dn_value)

    @staticmethod
    def validate_entry_type(
        entry: FlextLDIFModels.Entry, object_classes: set[str]
    ) -> FlextResult[bool]:
        """Validate entry type using flext-core - simple alias for test compatibility."""
        return FlextLDIFFormatValidators().validate_entry_type(entry, object_classes)

    @staticmethod
    def is_person_entry(entry: FlextLDIFModels.Entry) -> FlextResult[bool]:
        """Check if entry is a person entry - simple alias for test compatibility."""
        return FlextLDIFFormatValidators().is_person_entry(entry)

    @staticmethod
    def is_group_entry(entry: FlextLDIFModels.Entry) -> FlextResult[bool]:
        """Check if entry is a group entry - simple alias for test compatibility."""
        return FlextLDIFFormatValidators().is_group_entry(entry)

    @staticmethod
    def is_ou_entry(entry: FlextLDIFModels.Entry) -> FlextResult[bool]:
        """Check if entry is an OU entry - simple alias for test compatibility."""
        return FlextLDIFFormatValidators().is_ou_entry(entry)

    @staticmethod
    def validate_required_objectclass(
        entry: FlextLDIFModels.Entry,
    ) -> FlextResult[bool]:
        """Validate required objectClass - simple alias for test compatibility."""
        return FlextLDIFFormatValidators().validate_required_objectclass(entry)

    @staticmethod
    def validate_entry_completeness(entry: FlextLDIFModels.Entry) -> FlextResult[bool]:
        """Validate entry completeness - simple alias for test compatibility."""
        return FlextLDIFFormatValidators().validate_entry_completeness(entry)


class LdifSchemaValidator:
    """Schema validator using flext-core directly."""

    @staticmethod
    def validate_object_class(
        entry: FlextLDIFModels.Entry, object_classes: list[str]
    ) -> FlextResult[bool]:
        """Validate objectClass using flext-core list validation."""
        return FlextLDIFFormatValidators().validate_entry_type(
            entry, set(object_classes)
        )

    @staticmethod
    def validate_required_attributes(
        entry: FlextLDIFModels.Entry, required_attrs: list[str]
    ) -> FlextResult[bool]:
        """Validate required attributes using flext-core business rules."""
        return FlextLDIFFormatValidators().validate_required_attributes(
            entry, required_attrs
        )

    @staticmethod
    def validate_person_schema(entry: FlextLDIFModels.Entry) -> FlextResult[bool]:
        """Validate person schema using flext-core user validation."""
        return FlextLDIFFormatValidators().validate_person_schema(entry)

    @staticmethod
    def validate_ou_schema(entry: FlextLDIFModels.Entry) -> FlextResult[bool]:
        """Validate OU schema."""
        return FlextLDIFFormatValidators().validate_ou_schema(entry)


# Export unified validator system
__all__ = [
    "FlextLDIFFormatValidator",
    "FlextLDIFFormatValidators",
    "LdifSchemaValidator",
    "LdifValidator",
]
