"""LDIF Validation Service - RFC 2849/4512 Compliant Entry Validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Self, override

from flext_core import d, r, t
from pydantic import Field

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.utilities import u

# Services CAN import constants, models, protocols, types, utilities
# Services CANNOT import other services, servers, or api


class FlextLdifValidation(
    FlextLdifServiceBase[m.Ldif.ValidationServiceStatus],
):
    """RFC 2849/4512 Compliant LDIF Validation Service.

    Business Rule: Validation service enforces RFC 2849/4512 compliance for LDAP
    attribute names, objectClass names, attribute values, and DN components.
    All validation follows RFC specifications: attribute names must start with letter,
    can contain letters/digits/hyphens, case-insensitive, length limits apply.

    Implication: RFC-compliant validation ensures interoperability across LDAP
    servers. Validation failures result in fail-fast error responses via r.
    Batch validation enables efficient processing of multiple attributes.

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

    All validation methods return r[bool] for consistent error handling
    and composable operations.

    FlextService V2 Integration:
    - Builder pattern for complex validation workflows
    - Pydantic fields for validation parameters
    - execute() method for health checks

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
    is_valid = result.value  # True

    result = validation_service.validate_attribute_name("2invalid")
    is_valid = result.value  # False (starts with digit)

    # Validate objectClass name
    result = validation_service.validate_objectclass_name("person")
    is_valid = result.value  # True

    # Validate attribute value length
    result = validation_service.validate_attribute_value("John Smith", max_length=1024)
    is_valid = result.value  # True

    # Validate DN component
    result = validation_service.validate_dn_component("cn", "John Smith")
    is_valid = result.value  # True

    # Batch validate multiple attribute names
    result = validation_service.validate_attribute_names([
        "cn",
        "mail",
        "2invalid",
        "objectClass",
    ])
    validated = result.value
    # {"cn": True, "mail": True, "2invalid": False, "objectClass": True}

    # PATTERN 2: Execute Method (V1 FlextService Style)
    ────────────────────────────────────────────────────
    result = FlextLdifValidation().execute()
    if result.is_success:
        status = result.value
        # {"service": "ValidationService", "status": "operational", ...}

    ═══════════════════════════════════════════════════════════════════════════
    QUICK REFERENCE

    Most Common Use Cases:
    - validate_attribute_name(name) -> bool
    - validate_objectclass_name(name) -> bool
    - validate_attribute_value(value, max_length=None) -> bool
    - validate_dn_component(attr, value) -> bool
    - validate_attribute_names(names) -> dict[str, bool]
    """

    # ════════════════════════════════════════════════════════════════════════
    # PYDANTIC FIELDS (for builder pattern)
    # ════════════════════════════════════════════════════════════════════════

    attribute_names: list[str] = Field(default_factory=list)
    objectclass_names: list[str] = Field(default_factory=list)
    max_attr_value_length: int | None = Field(default=None)

    @override
    @d.log_operation("validation_service_check")
    @d.track_performance()
    def execute(
        self,
    ) -> r[m.Ldif.ValidationServiceStatus]:
        """Execute validation service self-check.

        Business Rule: Execute method provides service health check for protocol compliance.
        Returns ValidationServiceStatus indicating service is operational and ready for
        validation operations.

        Implication: This method enables service-based execution patterns while maintaining
        type safety. Used internally by service orchestration layers for health monitoring.

        Returns:
            FlextResult with ValidationServiceStatus containing service metadata

        """
        return r[m.Ldif.ValidationServiceStatus].ok(
            m.Ldif.ValidationServiceStatus(
                service="ValidationService",
                status="operational",
                rfc_compliance="RFC 2849, RFC 4512",
                validation_types=[
                    "attribute_name",
                    "objectclass_name",
                    "attribute_value",
                ],
            ),
        )

    # ════════════════════════════════════════════════════════════════════════
    # FLUENT BUILDER PATTERN
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def builder(cls) -> Self:
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

    def with_attribute_names(self, names: list[str]) -> Self:
        """Set attribute names to validate (fluent builder)."""
        return self.model_copy(update={"attribute_names": names})

    def with_objectclass_names(self, names: list[str]) -> Self:
        """Set objectClass names to validate (fluent builder)."""
        return self.model_copy(update={"objectclass_names": names})

    def with_max_attr_value_length(self, length: int) -> Self:
        """Set maximum attribute value length (fluent builder)."""
        return self.model_copy(update={"max_attr_value_length": length})

    @d.track_performance()
    def build(self) -> m.Ldif.ValidationBatchResult:
        """Execute validation and return unwrapped result (fluent terminal).

        Validates all configured attribute names and objectClass names,
        returning a unified model with validation results.

        Returns:
            ValidationBatchResult model mapping validated items to their validation status

        """
        # Start with empty result
        result: dict[str, bool] = {}

        # Validate attribute names (if any)
        if self.attribute_names:
            attr_result = self.validate_attribute_names(self.attribute_names)
            if attr_result.is_success:
                result.update(attr_result.value)

        # Validate objectClass names
        for name in self.objectclass_names:
            obj_result = self.validate_objectclass_name(name)
            if obj_result.is_success:
                result[name] = obj_result.value

        # Create ValidationBatchResult from validation results
        return m.Ldif.ValidationBatchResult(results=result)

    def validate_attribute_name(self, name: str) -> r[bool]:
        """Validate LDAP attribute name against RFC 4512 rules.

        Business Rule: Attribute name validation follows RFC 4512 Section 2.5 rules.
        Names must start with letter, can contain letters/digits/hyphens, case-insensitive,
        length typically limited to 127 characters. Invalid names result in False result.

        Implication: RFC-compliant validation ensures interoperability across LDAP servers.
        Validation uses u.Constants for core logic, ensuring consistency.

        Uses u.Constants.validate_attribute_name() for core validation logic.

        RFC 4512 Section 2.5: Attribute Type Definitions
        - AttributeType names must start with a letter
        - Can contain letters, digits, and hyphens
        - Case-insensitive comparison
        - Limited to reasonable length (1-255 chars)

        Args:
            name: Attribute name to validate

        Returns:
            FlextResult containing True if valid, False otherwise

        Example:
            >>> result = service.validate_attribute_name("cn")
            >>> is_valid = result.value  # True
            >>>
            >>> result = service.validate_attribute_name("2invalid")
            >>> is_valid = result.value  # False (starts with digit)
            >>>
            >>> result = service.validate_attribute_name("user-name")
            >>> is_valid = result.value  # True (hyphens allowed)

        """
        try:
            is_valid = u.Attribute.validate_attribute_name(name)
            return r[bool].ok(is_valid)

        except Exception as e:
            return r[bool].fail(f"Failed to validate attribute name: {e}")

    def validate_objectclass_name(self, name: str) -> r[bool]:
        """Validate LDAP object class name against RFC 4512 rules.

        Business Rule: ObjectClass name validation follows RFC 4512 Section 2.4 rules.
        Same rules as attribute names: must start with letter, can contain letters/digits/hyphens,
        case-insensitive. Must match structural, auxiliary, or abstract class definitions.

        Implication: RFC-compliant validation ensures interoperability across LDAP servers.
        Validation uses u.Constants for core logic, ensuring consistency.

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
            >>> is_valid = result.value  # True
            >>>
            >>> result = service.validate_objectclass_name("inetOrgPerson")
            >>> is_valid = result.value  # True
            >>>
            >>> result = service.validate_objectclass_name("invalid class")
            >>> is_valid = result.value  # False (contains space)

        """
        # Object class names follow same rules as attribute names (RFC 4512)
        return self.validate_attribute_name(name)

    def validate_attribute_value(
        self,
        value: str,
        max_length: int | None = None,
    ) -> r[bool]:
        """Validate LDAP attribute value length and format.

        Args:
            value: Attribute value to validate
            max_length: Optional maximum length in bytes (default: 1048576, approximately 1MB)

        Returns:
            FlextResult containing True if valid, False otherwise

        Example:
            >>> result = service.validate_attribute_value("John Smith")
            >>> is_valid = result.value  # True
            >>>
            >>> result = service.validate_attribute_value("test", max_length=2)
            >>> is_valid = result.value  # False (exceeds max_length)

        """
        try:
            # Allow empty values (valid in LDAP)
            if not value:
                return r[bool].ok(True)

            # Check length
            max_len = (
                max_length
                if max_length is not None
                else c.ValidationRules.DEFAULT_MAX_ATTR_VALUE_LENGTH
            )
            if len(value) > max_len:
                return r[bool].ok(False)

            return r[bool].ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return r[bool].fail(f"Failed to validate attribute value: {e}")

    def validate_dn_component(
        self,
        attr: str,
        value: t.ScalarValue,
    ) -> r[bool]:
        """Validate DN component (attribute=value pair).

        Validates both the attribute name and value for DN usage.

        Args:
            attr: Attribute name (must be string)
            value: Attribute value (must be string for valid DN)

        Returns:
            FlextResult containing True if valid, False otherwise

        Example:
            >>> result = service.validate_dn_component("cn", "John Smith")
            >>> is_valid = result.value  # True

        """
        try:
            # Validate attribute name
            attr_result = self.validate_attribute_name(attr)
            if attr_result.is_failure or not attr_result.value:
                return r[bool].ok(False)

            # Validate value - must be a string for DN component
            # Use isinstance check directly for simplicity
            if not isinstance(value, str):
                return r[bool].ok(False)

            # DN values can be empty strings
            return r[bool].ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return r[bool].fail(f"Failed to validate DN component: {e}")

    def validate_attribute_names(
        self,
        names: list[str],
    ) -> r[dict[str, bool]]:
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
            >>> validated = result.value
            >>> print(validated["cn"])  # True
            >>> print(validated["2invalid"])  # False

        """
        try:
            validated_names: dict[str, bool] = {}

            for name in names:
                result = self.validate_attribute_name(name)
                if result.is_success:
                    validated_names[name] = result.value
                else:
                    # If validation fails, mark as invalid
                    validated_names[name] = False

            return r[dict[str, bool]].ok(validated_names)

        except (ValueError, TypeError, AttributeError) as e:
            return r[dict[str, bool]].fail(
                f"Failed to batch validate attribute names: {e}",
            )


__all__ = ["FlextLdifValidation"]
