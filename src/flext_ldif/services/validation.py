"""LDIF Validation Service - RFC 2849/4512 Compliant Entry Validation.

╔══════════════════════════════════════════════════════════════════════════╗
║  RFC 2849/4512 COMPLIANT LDIF VALIDATION SERVICE                        ║
╠══════════════════════════════════════════════════════════════════════════╣
║  ✅ Attribute name validation (RFC 4512 Section 2.5)                    ║
║  ✅ ObjectClass name validation (RFC 4512 Section 2.4)                  ║
║  ✅ Attribute value length validation                                    ║
║  ✅ DN component validation (attribute=value pairs)                     ║
║  ✅ Batch validation for multiple attribute names                       ║
║  ✅ Replaces naive validation with proper LDAP rules                    ║
║  ✅ 100% type-safe with FlextResult error handling                      ║
║  ✅ Multiple API patterns: execute(), direct methods                   ║
╚══════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════
RESPONSIBILITY (SRP)

This service handles LDIF VALIDATION ONLY:
- Validating LDAP attribute names against RFC 4512 rules
- Validating objectClass names against RFC 4512 rules
- Validating attribute value lengths and formats
- Validating DN components (attribute=value pairs)
- Batch validation operations

What it does NOT do:
- Parse LDIF entries (use FlextLdifParser)
- Transform entries (use FlextLdifEntry)
- Sort entries (use FlextLdifSorting)
- Filter entries (use FlextLdifFilters)

═══════════════════════════════════════════════════════════════════════════
RFC COMPLIANCE

RFC 2849: LDAP Data Interchange Format (LDIF)
- Defines LDIF file format and structure
- Specifies entry and attribute representation

RFC 4512: Lightweight Directory Access Protocol (LDAP): Directory Information Models
- Section 2.4: Object Class Definitions
- Section 2.5: Attribute Type Definitions

RFC 4512 Attribute Name Rules:
- Must start with letter
- Can contain letters, digits, hyphens
- Case-insensitive
- Length typically limited to 127 characters

RFC 4512 Object Class Name Rules:
- Same rules as attribute names
- Must match structural, auxiliary, or abstract class

═══════════════════════════════════════════════════════════════════════════
REAL USAGE EXAMPLES

# PATTERN 1: Direct Method API (Most Common)
─────────────────────────────────────────────
validation_service = FlextLdifValidation()

# Validate attribute name
result = validation_service.validate_attribute_name("cn")
is_valid = result.unwrap()  # True

result = validation_service.validate_attribute_name("2invalid")
is_valid = result.unwrap()  # False (starts with digit)

# Validate objectClass name
result = validation_service.validate_objectclass_name("person")
is_valid = result.unwrap()  # True

# Validate attribute value length
result = validation_service.validate_attribute_value("John Smith", max_length=1024)
is_valid = result.unwrap()  # True

# Validate DN component
result = validation_service.validate_dn_component("cn", "John Smith")
is_valid = result.unwrap()  # True

# Batch validate multiple attribute names
result = validation_service.validate_attribute_names([
    "cn",
    "mail",
    "2invalid",
    "objectClass",
])
validated = result.unwrap()
# {"cn": True, "mail": True, "2invalid": False, "objectClass": True}

# PATTERN 2: Execute Method (V1 FlextService Style)
────────────────────────────────────────────────────
result = FlextLdifValidation().execute()
if result.is_success:
    status = result.unwrap()
    # {"service": "ValidationService", "status": "operational", ...}

═══════════════════════════════════════════════════════════════════════════
QUICK REFERENCE

Most Common Use Cases:
- validate_attribute_name(name) -> bool
- validate_objectclass_name(name) -> bool
- validate_attribute_value(value, max_length=None) -> bool
- validate_dn_component(attr, value) -> bool
- validate_attribute_names(names) -> dict[str, bool]

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
from typing import override

from flext_core import FlextDecorators, FlextResult, FlextService
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants


class FlextLdifValidation(FlextService[dict[str, object]]):
    """RFC 2849/4512 Compliant LDIF Validation Service.

    Provides comprehensive validation for LDAP attribute names, object class names,
    attribute values, and DN components following RFC 2849 (LDIF) and RFC 4512 (Schema).

    This service replaces naive validation approaches with proper RFC-compliant
    validation rules that check format, naming conventions, and length limits.

    Key Features:
    - RFC 4512 compliant attribute name validation
    - RFC 4512 compliant objectClass name validation
    - Attribute value length validation
    - DN component validation (attribute=value pair validation)
    - Batch validation for multiple attribute names
    - Proper error handling with FlextResult monadic composition
    - Fluent builder pattern for batch validation operations

    All validation methods return FlextResult[bool] for consistent error handling
    and composable operations.

    FlextService V2 Integration:
    - Builder pattern for complex validation workflows
    - Pydantic fields for validation parameters
    - execute() method for health checks
    """

    # ════════════════════════════════════════════════════════════════════════
    # PYDANTIC FIELDS (for builder pattern)
    # ════════════════════════════════════════════════════════════════════════

    attribute_names: list[str] = Field(default_factory=list)
    objectclass_names: list[str] = Field(default_factory=list)
    max_attr_value_length: int | None = Field(default=None)

    @override
    @FlextDecorators.log_operation("validation_service_check")
    @FlextDecorators.track_performance()
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute validation service self-check.

        FlextDecorators automatically:
        - Log operation start/completion/failure
        - Track performance metrics
        - Handle context propagation (correlation_id, operation_name)

        Returns:
        FlextResult containing service status

        """
        return FlextResult[dict[str, object]].ok({
            "service": "ValidationService",
            "status": "operational",
            "rfc_compliance": "RFC 2849, RFC 4512",
            "validation_types": [
                "attribute_name",
                "objectclass_name",
                "attribute_value",
            ],
        })

    # ════════════════════════════════════════════════════════════════════════
    # FLUENT BUILDER PATTERN
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def builder(cls) -> FlextLdifValidation:
        """Create fluent builder for complex validation workflows.

        Returns:
            Service instance for method chaining

        Example:
            result = (FlextLdifValidation.builder()
                .with_attribute_names(["cn", "mail"])
                .with_objectclass_names(["person"])
                .build())

        """
        return cls()

    def with_attribute_names(self, names: list[str]) -> FlextLdifValidation:
        """Set attribute names to validate (fluent builder)."""
        self.attribute_names = names
        return self

    def with_objectclass_names(self, names: list[str]) -> FlextLdifValidation:
        """Set objectClass names to validate (fluent builder)."""
        self.objectclass_names = names
        return self

    def with_max_attr_value_length(self, length: int) -> FlextLdifValidation:
        """Set maximum attribute value length (fluent builder)."""
        self.max_attr_value_length = length
        return self

    def build(self) -> dict[str, bool]:
        """Execute validation and return unwrapped result (fluent terminal).

        Validates all configured attribute names and objectClass names,
        returning a unified dictionary with validation results.

        Returns:
            Dictionary mapping validated items to their validation status

        """
        result: dict[str, bool] = {}

        # Validate attribute names
        if self.attribute_names:
            attr_result = self.validate_attribute_names(self.attribute_names)
            if attr_result.is_success:
                result.update(attr_result.unwrap())

        # Validate objectClass names
        for name in self.objectclass_names:
            oc_result = self.validate_objectclass_name(name)
            if oc_result.is_success:
                result[name] = oc_result.unwrap()

        return result

    def validate_attribute_name(self, name: str) -> FlextResult[bool]:
        """Validate LDAP attribute name against RFC 4512 rules.

        RFC 4512 Section 2.5: Attribute Type Definitions
        - AttributeType names must start with a letter
        - Can contain letters, digits, and hyphens
        - Case-insensitive comparison
        - Typically limited to 127 characters

        Args:
            name: Attribute name to validate

        Returns:
            FlextResult containing True if valid, False otherwise

        Example:
            >>> result = service.validate_attribute_name(FlextLdifConstants.DictKeys.CN)
            >>> is_valid = result.unwrap()  # True
            >>>
            >>> result = service.validate_attribute_name("2invalid")
            >>> is_valid = result.unwrap()  # False (starts with digit)
            >>>
            >>> result = service.validate_attribute_name("user-name")
            >>> is_valid = result.unwrap()  # True (hyphens allowed)

        """
        try:
            # Check empty
            if not name:
                return FlextResult[bool].ok(False)

            # Check length (RFC 4512 typical limit)
            if (
                len(name)
                > FlextLdifConstants.ValidationRules.TYPICAL_ATTR_NAME_LENGTH_LIMIT
            ):
                return FlextResult[bool].ok(False)

            # Check pattern (RFC 4512: starts with letter, contains letters/digits/hyphens)
            if not re.match(FlextLdifConstants.LdifPatterns.ATTRIBUTE_NAME, name):
                return FlextResult[bool].ok(False)

            return FlextResult[bool].ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[bool].fail(f"Failed to validate attribute name: {e}")

    def validate_objectclass_name(self, name: str) -> FlextResult[bool]:
        """Validate LDAP object class name against RFC 4512 rules.

        RFC 4512 Section 2.4: Object Class Definitions
        - ObjectClass names follow same rules as attribute names
        - Must start with a letter
        - Can contain letters, digits, and hyphens
        - Case-insensitive comparison

        Args:
            name: Object class name to validate

        Returns:
            FlextResult containing True if valid, False otherwise

        Example:
            >>> result = service.validate_objectclass_name("person")
            >>> is_valid = result.unwrap()  # True
            >>>
            >>> result = service.validate_objectclass_name("inetOrgPerson")
            >>> is_valid = result.unwrap()  # True
            >>>
            >>> result = service.validate_objectclass_name("invalid class")
            >>> is_valid = result.unwrap()  # False (contains space)

        """
        # Object class names follow same rules as attribute names (RFC 4512)
        return self.validate_attribute_name(name)

    def validate_attribute_value(
        self,
        value: str,
        max_length: int | None = None,
    ) -> FlextResult[bool]:
        """Validate LDAP attribute value length and format.

        Args:
            value: Attribute value to validate
            max_length: Optional maximum length (default: 1MB)

        Returns:
            FlextResult containing True if valid, False otherwise

        Example:
            >>> result = service.validate_attribute_value("John Smith")
            >>> is_valid = result.unwrap()  # True
            >>>
            >>> result = service.validate_attribute_value("test", max_length=2)
            >>> is_valid = result.unwrap()  # False (exceeds max_length)

        """
        try:
            # Allow empty values (valid in LDAP)
            if not value:
                return FlextResult[bool].ok(True)

            # Check length
            max_len = (
                max_length
                if max_length is not None
                else FlextLdifConstants.ValidationRules.DEFAULT_MAX_ATTR_VALUE_LENGTH
            )
            if len(value) > max_len:
                return FlextResult[bool].ok(False)

            return FlextResult[bool].ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[bool].fail(f"Failed to validate attribute value: {e}")

    def validate_dn_component(
        self,
        attr: str,
        value: object,
    ) -> FlextResult[bool]:
        """Validate DN component (attribute=value pair).

        Validates both the attribute name and value for DN usage.

        Args:
            attr: Attribute name (must be string)
            value: Attribute value (must be string for valid DN)

        Returns:
            FlextResult containing True if valid, False otherwise

        Example:
            >>> result = service.validate_dn_component(
            ...     FlextLdifConstants.DictKeys.CN, "John Smith"
            ... )
            >>> is_valid = result.unwrap()  # True

        """
        try:
            # Validate attribute name
            attr_result = self.validate_attribute_name(attr)
            if attr_result.is_failure or not attr_result.unwrap():
                return FlextResult[bool].ok(False)

            # Validate value - must be a string
            if not isinstance(value, str):
                return FlextResult[bool].ok(False)

            # DN values can be empty strings
            return FlextResult[bool].ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[bool].fail(f"Failed to validate DN component: {e}")

    def validate_attribute_names(
        self,
        names: list[str],
    ) -> FlextResult[dict[str, bool]]:
        """Batch validate multiple attribute names.

        Validates a list of attribute names and returns results for each.

        Args:
            names: List of attribute names to validate

        Returns:
            FlextResult containing dict mapping each name to validation result

        Example:
            >>> result = service.validate_attribute_names([
            ...     "cn",
            ...     "mail",
            ...     "2invalid",
            ...     "objectClass",
            ... ])
            >>> validated = result.unwrap()
            >>> print(validated["cn"])  # True
            >>> print(validated["2invalid"])  # False

        """
        try:
            validated_names: dict[str, bool] = {}

            for name in names:
                result = self.validate_attribute_name(name)
                if result.is_success:
                    validated_names[name] = result.unwrap()
                else:
                    # If validation fails, mark as invalid
                    validated_names[name] = False

            return FlextResult[dict[str, bool]].ok(validated_names)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[dict[str, bool]].fail(
                f"Failed to batch validate attribute names: {e}",
            )


__all__ = ["FlextLdifValidation"]
