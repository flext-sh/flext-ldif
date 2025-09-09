"""FLEXT-LDIF Unified Format Validators Module.

Enterprise-grade LDIF validation with unified class architecture,
advanced Python 3.13 patterns, and comprehensive validation rules.
All validators organized as nested classes following SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import Callable
from functools import lru_cache
from typing import TYPE_CHECKING, Final

from flext_core import FlextModels, FlextResult

from flext_ldif.constants import FlextLDIFConstants
from flext_ldif.models import FlextLDIFModels

# Type aliases for Python 3.13+ generic syntax
if TYPE_CHECKING:
    type ValidatorFunc = Callable[[str], bool]
    type FlextResultBool = FlextResult[bool]
else:
    ValidatorFunc = Callable
    FlextResultBool = FlextResult


class FlextLDIFFormatValidators(FlextModels.AggregateRoot):
    """Unified LDIF Format Validators.

    Enterprise-grade LDIF validation system with nested validator classes
    following unified architecture. Provides comprehensive validation
    for LDIF entries, DNs, attributes, and schema compliance.
    """

    def __init__(self, **data: object) -> None:
        """Initialize unified validators."""
        # Set default id if not provided for Pydantic AggregateRoot
        if "id" not in data:
            data["id"] = "flext-ldif-format-validators"
        super().__init__(**data)

        # Cache compiled patterns for performance FIRST
        self._compiled_patterns = self._compile_patterns()

        # Initialize nested validator instances AFTER patterns
        self._entry_validator = self.EntryValidator(self)
        self._schema_validator = self.SchemaValidator(self)
        self._pattern_validator = self.PatternValidator(self)

    def _compile_patterns(self) -> dict[str, re.Pattern[str]]:
        """Compile regex patterns for efficient validation."""
        return {
            "attribute_name": re.compile(
                r"^[a-zA-Z][a-zA-Z0-9-]*(?:;[a-zA-Z0-9_.-]+)*$"
            ),
            "dn_component": re.compile(r"^[a-zA-Z][\w-]*=.+(?:,[a-zA-Z][\w-]*=.+)*$"),
            "object_class": re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*$"),
            "ldif_line": re.compile(r"^[a-zA-Z][\w-]*\s*:[:< ]?\s*.+$"),
        }

    class PatternValidator:
        """Nested pattern validation utilities."""

        def __init__(self, validators_instance: FlextLDIFFormatValidators) -> None:
            """Initialize with parent validators reference."""
            self._validators = validators_instance
            self._patterns = validators_instance._compiled_patterns

        def validate_attribute_name_format(self, name: str) -> FlextResultBool:
            """Validate LDAP attribute name format per RFC 4512.

            Supports: displayName, displayName;lang-es_ES, orclInstanceCount;oid-prd-app01

            Args:
                name: Attribute name to validate

            Returns:
                FlextResult containing validation status

            """
            if not name or not isinstance(name, str):
                return FlextResult[bool].fail(
                    "Attribute name cannot be empty or non-string"
                )

            name = name.strip()
            if not name:
                return FlextResult[bool].fail(
                    "Attribute name cannot be empty after stripping"
                )

            if self._patterns["attribute_name"].match(name):
                return FlextResult[bool].ok(data=True)
            return FlextResult[bool].fail(f"Invalid attribute name format: {name}")

        def validate_dn_format(self, dn: str, *, strict: bool = True) -> FlextResultBool:
            """Validate LDAP DN format with optional strict mode.

            Args:
                dn: Distinguished name to validate
                strict: Whether to apply strict RFC compliance

            Returns:
                FlextResult containing validation status

            """
            if not dn or not isinstance(dn, str):
                return FlextResult[bool].fail("DN cannot be empty or non-string")

            dn = dn.strip()
            if not dn:
                return FlextResult[bool].fail("DN cannot be empty after stripping")

            # Empty DN is valid in LDAP (root DSE)
            if dn == "":
                return FlextResult[bool].ok(data=True)

            if strict:
                # Strict validation with proper component structure
                components = [comp.strip() for comp in dn.split(",")]
                for i, component in enumerate(components):
                    if not component or "=" not in component:
                        return FlextResult[bool].fail(
                            f"Invalid DN component at position {i}: '{component}'"
                        )
                    # Validate each component format
                    attr_name, _, attr_value = component.partition("=")
                    if not attr_name.strip() or not attr_value.strip():
                        return FlextResult[bool].fail(
                            f"Invalid DN component format at position {i}: '{component}'"
                        )

            # Basic pattern matching
            if self._patterns["dn_component"].match(dn):
                return FlextResult[bool].ok(data=True)
            return FlextResult[bool].fail(f"Invalid DN format: {dn}")

        def validate_object_class_format(self, object_class: str) -> FlextResultBool:
            """Validate objectClass value format.

            Args:
                object_class: ObjectClass value to validate

            Returns:
                FlextResult containing validation status

            """
            if not object_class or not isinstance(object_class, str):
                return FlextResult[bool].fail(
                    "ObjectClass cannot be empty or non-string"
                )

            oc = object_class.strip().lower()
            if not oc:
                return FlextResult[bool].fail(
                    "ObjectClass cannot be empty after stripping"
                )

            if self._patterns["object_class"].match(oc):
                return FlextResult[bool].ok(data=True)
            return FlextResult[bool].fail(f"Invalid objectClass format: {object_class}")

    @classmethod
    @lru_cache(maxsize=128)
    def get_cached_validators(cls) -> tuple[ValidatorFunc, ValidatorFunc]:
        """Get cached validator functions for performance."""
        instance = cls()
        return (
            lambda name: instance._pattern_validator.validate_attribute_name_format(
                name
            ).is_success,
            lambda dn: instance._pattern_validator.validate_dn_format(dn).is_success,
        )

    class EntryValidator:
        """Nested LDIF entry validation functionality."""

        # Object class sets using flext-core SOURCE OF TRUTH (immutable)
        PERSON_CLASSES: Final[set[str]] = FlextLDIFConstants.PERSON_OBJECTCLASSES
        OU_CLASSES: Final[set[str]] = FlextLDIFConstants.ORGANIZATIONAL_OBJECTCLASSES
        GROUP_CLASSES: Final[set[str]] = FlextLDIFConstants.GROUP_OBJECTCLASSES

        def __init__(self, validators_instance: FlextLDIFFormatValidators) -> None:
            """Initialize with parent validators reference."""
            self._validators = validators_instance

        def validate_dn(self, dn_value: str, *, strict: bool = True) -> FlextResultBool:
            """Validate Distinguished Name format with comprehensive rules.

            Args:
                dn_value: DN string to validate
                strict: Whether to apply strict RFC compliance

            Returns:
                FlextResult indicating DN validity

            """
            return self._validators._pattern_validator.validate_dn_format(
                dn_value, strict=strict
            )

        def validate_attribute_name(self, attr_name: str) -> FlextResultBool:
            """Validate LDAP attribute name format.

            Args:
                attr_name: Attribute name to validate

            Returns:
                FlextResult indicating attribute name validity

            """
            return self._validators._pattern_validator.validate_attribute_name_format(
                attr_name
            )

        def is_person_entry(self, entry: FlextLDIFModels.Entry) -> FlextResultBool:
            """Check if entry is a person entry based on objectClass.

            Args:
                entry: LDIF entry to check

            Returns:
                FlextResult indicating if entry is a person

            """
            if not entry.has_attribute("objectClass"):
                return FlextResult[bool].ok(data=False)

            object_class_values = entry.get_attribute("objectClass")
            if not object_class_values:
                return FlextResult[bool].ok(data=False)

            object_classes = {oc.lower() for oc in object_class_values}
            is_person = bool(object_classes.intersection(self.PERSON_CLASSES))
            return FlextResult[bool].ok(is_person)

        def is_group_entry(self, entry: FlextLDIFModels.Entry) -> FlextResultBool:
            """Check if entry is a group entry based on objectClass.

            Args:
                entry: LDIF entry to check

            Returns:
                FlextResult indicating if entry is a group

            """
            if not entry.has_attribute("objectClass"):
                return FlextResult[bool].ok(data=False)

            object_class_values = entry.get_attribute("objectClass")
            if not object_class_values:
                return FlextResult[bool].ok(data=False)

            object_classes = {oc.lower() for oc in object_class_values}
            is_group = bool(object_classes.intersection(self.GROUP_CLASSES))
            return FlextResult[bool].ok(is_group)

        def is_ou_entry(self, entry: FlextLDIFModels.Entry) -> FlextResultBool:
            """Check if entry is an organizational unit based on objectClass.

            Args:
                entry: LDIF entry to check

            Returns:
                FlextResult indicating if entry is an OU

            """
            if not entry.has_attribute("objectClass"):
                return FlextResult[bool].ok(data=False)

            object_class_values = entry.get_attribute("objectClass")
            if not object_class_values:
                return FlextResult[bool].ok(data=False)

            object_classes = {oc.lower() for oc in object_class_values}
            is_ou = bool(object_classes.intersection(self.OU_CLASSES))
            return FlextResult[bool].ok(is_ou)

        def validate_required_objectclass(
            self, entry: FlextLDIFModels.Entry
        ) -> FlextResultBool:
            """Validate that entry has required objectClass attribute.

            Args:
                entry: LDIF entry to validate

            Returns:
                FlextResult indicating if objectClass is present

            """
            if not entry.has_attribute("objectClass"):
                return FlextResult[bool].fail("Entry missing required objectClass")

            object_class_values = entry.get_attribute("objectClass")
            if not object_class_values:
                return FlextResult[bool].fail("Entry has empty objectClass values")

            return FlextResult[bool].ok(data=True)

        def validate_entry_completeness(
            self, entry: FlextLDIFModels.Entry
        ) -> FlextResultBool:
            """Validate entry has minimum required components.

            Args:
                entry: LDIF entry to validate

            Returns:
                FlextResult indicating entry completeness

            """
            # DN validation using pattern validator
            dn_result = self.validate_dn(entry.dn.value)
            if not dn_result.is_success:
                return FlextResult[bool].fail(f"Invalid DN: {dn_result.error}")

            # ObjectClass requirement
            objectclass_result = self.validate_required_objectclass(entry)
            if not objectclass_result.is_success:
                return FlextResult[bool].fail(
                    f"ObjectClass validation failed: {objectclass_result.error}"
                )

            return FlextResult[bool].ok(data=True)

        def validate_entry_type(
            self, entry: FlextLDIFModels.Entry, expected_types: set[str]
        ) -> FlextResultBool:
            """Validate entry matches expected object class types.

            Args:
                entry: LDIF entry to validate
                expected_types: Set of expected objectClass values

            Returns:
                FlextResult indicating if entry matches expected types

            """
            if not expected_types:
                return FlextResult[bool].fail("Expected types cannot be empty")

            if not entry.has_attribute("objectClass"):
                return FlextResult[bool].fail("Missing objectClass attribute")

            object_class_values = entry.get_attribute("objectClass")
            if not object_class_values:
                return FlextResult[bool].fail("objectClass attribute has no values")

            entry_types = {oc.lower() for oc in object_class_values}
            expected_types_lower = {oc.lower() for oc in expected_types}

            if entry_types.intersection(expected_types_lower):
                return FlextResult[bool].ok(data=True)
            return FlextResult[bool].fail(
                f"Entry types {entry_types} do not match expected types {expected_types_lower}"
            )

    class SchemaValidator:
        """Nested LDIF schema validation functionality."""

        def __init__(self, validators_instance: FlextLDIFFormatValidators) -> None:
            """Initialize with parent validators reference."""
            self._validators = validators_instance

        def validate_required_attributes(
            self,
            entry: FlextLDIFModels.Entry,
            required_attrs: list[str],
        ) -> FlextResultBool:
            """Validate entry has all required attributes for its schema.

            Args:
                entry: LDIF entry to validate
                required_attrs: List of required attribute names

            Returns:
                FlextResult indicating schema compliance

            """
            if not required_attrs:
                return FlextResult[bool].ok(data=True)  # No requirements

            missing_attrs = [
                attr_name
                for attr_name in required_attrs
                if not entry.has_attribute(attr_name)
            ]

            if missing_attrs:
                return FlextResult[bool].fail(
                    f"Missing required attributes: {', '.join(missing_attrs)}"
                )

            return FlextResult[bool].ok(data=True)

        def validate_person_schema(
            self, entry: FlextLDIFModels.Entry
        ) -> FlextResultBool:
            """Validate person entry schema requirements.

            Args:
                entry: LDIF entry to validate

            Returns:
                FlextResult indicating validation success

            """
            # Chain validation with railway programming
            return (
                self._validators._entry_validator.is_person_entry(entry)
                .flat_map(
                    lambda is_person: FlextResult[bool].ok(data=True)
                    if is_person
                    else FlextResult[bool].fail("Entry is not a person entry")
                )
                .flat_map(
                    lambda _: self.validate_required_attributes(
                        entry,
                        FlextLDIFConstants.LDIF.REQUIRED_PERSON_ATTRIBUTES,
                    )
                )
            )

        def validate_ou_schema(self, entry: FlextLDIFModels.Entry) -> FlextResultBool:
            """Validate organizational unit entry schema requirements.

            Args:
                entry: LDIF entry to validate

            Returns:
                FlextResult indicating validation success

            """
            # Chain validation with railway programming for OU entries
            return (
                self._validators._entry_validator.is_ou_entry(entry)
                .flat_map(
                    lambda is_ou: FlextResult[bool].ok(data=True)
                    if is_ou
                    else FlextResult[bool].fail("Entry is not an organizational unit")
                )
                .flat_map(
                    lambda _: self.validate_required_attributes(
                        entry,
                        FlextLDIFConstants.LDIF.REQUIRED_ORGUNIT_ATTRIBUTES,
                    )
                )
            )

        def validate_group_schema(
            self, entry: FlextLDIFModels.Entry
        ) -> FlextResultBool:
            """Validate group entry schema requirements.

            Args:
                entry: LDIF entry to validate

            Returns:
                FlextResult indicating validation success

            """
            return (
                self._validators._entry_validator.is_group_entry(entry)
                .flat_map(
                    lambda is_group: FlextResult[bool].ok(data=True)
                    if is_group
                    else FlextResult[bool].fail("Entry is not a group entry")
                )
                .flat_map(
                    lambda _:
                    # Groups typically require cn and objectClass
                    self.validate_required_attributes(entry, ["cn", "objectClass"])
                )
            )

    # Public access methods for nested validators
    def get_entry_validator(self) -> EntryValidator:
        """Get entry validator instance."""
        return self._entry_validator

    def get_schema_validator(self) -> SchemaValidator:
        """Get schema validator instance."""
        return self._schema_validator

    def get_pattern_validator(self) -> PatternValidator:
        """Get pattern validator instance."""
        return self._pattern_validator

    def get_ldap_validators(self) -> tuple[EntryValidator, SchemaValidator, PatternValidator]:
        """Simple alias for LDAP validators - test compatibility."""
        return (self._entry_validator, self._schema_validator, self._pattern_validator)

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate format validators business rules."""
        try:
            # LDIF format validators specific validation rules
            if not hasattr(self, "_entry_validator"):
                return FlextResult[None].fail("Entry validator not properly initialized")

            if not hasattr(self, "_schema_validator"):
                return FlextResult[None].fail("Schema validator not properly initialized")

            if not hasattr(self, "_pattern_validator"):
                return FlextResult[None].fail("Pattern validator not properly initialized")

            # All validators business rules passed
            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Format validators validation failed: {e}")

    # Legacy class methods for backwards compatibility (deprecated)
    @classmethod
    def validate_dn_legacy(cls, dn_value: str) -> FlextResultBool:
        """Legacy DN validation method (deprecated - use instance method)."""
        instance = cls()
        return instance._entry_validator.validate_dn(dn_value)

    @classmethod
    def validate_attribute_name_legacy(cls, attr_name: str) -> FlextResultBool:
        """Legacy attribute name validation (deprecated - use instance method)."""
        instance = cls()
        return instance._entry_validator.validate_attribute_name(attr_name)

    @staticmethod
    def _validate_ldap_dn(dn_value: str) -> bool:
        """Legacy alias for DN validation - test compatibility."""
        validator = FlextLDIFFormatValidators()
        result = validator.get_entry_validator().validate_dn(dn_value, strict=True)
        return result.is_success and result.data


# Backward compatibility aliases (deprecated - use FlextLDIFFormatValidators directly)
FlextLDIFFormatValidator = FlextLDIFFormatValidators


# Aliases simples para compatibilidade de testes - métodos estáticos
class LdifValidator:
    """Alias simples para compatibilidade de testes com métodos estáticos."""

    @staticmethod
    def validate_attribute_name(attr_name: str) -> FlextResult[bool]:
        """Validate LDAP attribute name."""
        validator = FlextLDIFFormatValidators()
        return validator.get_entry_validator().validate_attribute_name(attr_name)

    @staticmethod
    def validate_dn(dn_value: str) -> FlextResult[bool]:
        """Validate DN format."""
        validator = FlextLDIFFormatValidators()
        return validator.get_entry_validator().validate_dn(dn_value)



class LdifSchemaValidator:
    """Alias simples para schema validator."""

    @staticmethod
    def validate_object_class(entry: FlextLDIFModels.Entry, object_classes: list[str]) -> FlextResult[bool]:
        """Validate object class requirements."""
        validator = FlextLDIFFormatValidators()
        return validator.get_schema_validator().validate_object_class(entry, object_classes)

    @staticmethod
    def validate_required_attributes(entry: FlextLDIFModels.Entry, required_attrs: list[str]) -> FlextResult[bool]:
        """Validate required attributes."""
        validator = FlextLDIFFormatValidators()
        return validator.get_schema_validator().validate_required_attributes(entry, required_attrs)

    @staticmethod
    def validate_person_schema(entry: FlextLDIFModels.Entry) -> FlextResult[bool]:
        """Validate person schema."""
        validator = FlextLDIFFormatValidators()
        return validator.validate_person_entry(entry)

    @staticmethod
    def validate_ou_schema(entry: FlextLDIFModels.Entry) -> FlextResult[bool]:
        """Validate OU schema."""
        validator = FlextLDIFFormatValidators()
        return validator.validate_ou_entry(entry)


# Export unified validator system
__all__ = [
    # Backward compatibility (deprecated)
    "FlextLDIFFormatValidator",
    "FlextLDIFFormatValidators",
    "LdifSchemaValidator",
    # Aliases para testes
    "LdifValidator",
]
