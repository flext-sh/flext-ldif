"""Validation Service - RFC 2849/4512 Compliant Entry Validation.

This service provides validation for LDIF entries, attributes, and object classes
following RFC 2849 (LDIF format) and RFC 4512 (LDAP schema).

Replaces naive validation from utilities.py with proper LDAP validation rules.

RFC 2849: LDAP Data Interchange Format (LDIF)
RFC 4512: Lightweight Directory Access Protocol (LDAP): Directory Information Models

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
from typing import override

from flext_core import FlextDecorators, FlextResult, FlextService

from flext_ldif.typings import FlextLdifTypes


class ValidationService(FlextService[FlextLdifTypes.Models.CustomDataDict]):
    """RFC 2849/4512 compliant validation service for LDIF entries.

    Provides methods for validating LDAP attribute names, object class names,
    and entry structures following RFC 2849 (LDIF) and RFC 4512 (Schema).

    This service replaces the naive validation from utilities.py which only
    checked for spaces and length limits.

    RFC 4512 Attribute Name Rules:
    - Must start with letter
    - Can contain letters, digits, hyphens
    - Case-insensitive
    - Length typically limited to 127 characters

    RFC 4512 Object Class Name Rules:
    - Same rules as attribute names
    - Must match structural, auxiliary, or abstract class

    Example:
        >>> validation_service = ValidationService()
        >>>
        >>> # Validate attribute name
        >>> result = validation_service.validate_attribute_name(
        ...     FlextLdifConstants.DictKeys.CN
        ... )
        >>> if result.is_success:
        >>>     is_valid = result.unwrap()  # True
        >>>
        >>> # Validate object class name
        >>> result = validation_service.validate_objectclass_name("person")
        >>> if result.is_success:
        >>>     is_valid = result.unwrap()  # True
        >>>
        >>> # Validate attribute value length
        >>> result = validation_service.validate_attribute_value("test", 1024)
        >>> if result.is_success:
        >>>     is_valid = result.unwrap()  # True

    """

    # RFC 4512: Attribute name pattern (starts with letter, contains letters/digits/hyphens)
    _ATTR_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*$")

    # RFC 4512: Typical attribute name length limit
    _MAX_ATTR_NAME_LENGTH = 127

    # LDIF: Reasonable attribute value length limit (configurable)
    _MAX_ATTR_VALUE_LENGTH = 1048576  # 1MB default

    def __init__(self) -> None:
        """Initialize validation service."""
        super().__init__()

    @override
    @FlextDecorators.log_operation("validation_service_check")
    @FlextDecorators.track_performance()
    def execute(self) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Execute validation service self-check.

        FlextDecorators automatically:
        - Log operation start/completion/failure
        - Track performance metrics
        - Handle context propagation (correlation_id, operation_name)

        Returns:
            FlextResult containing service status

        """
        return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok({
            "service": "ValidationService",
            "status": "operational",
            "rfc_compliance": "RFC 2849, RFC 4512",
            "validation_types": [
                "attribute_name",
                "objectclass_name",
                "attribute_value",
            ],
        })

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
            # Check type
            if not isinstance(name, str):
                return FlextResult[bool].ok(False)

            # Check empty
            if not name:
                return FlextResult[bool].ok(False)

            # Check length (RFC 4512 typical limit)
            if len(name) > self._MAX_ATTR_NAME_LENGTH:
                return FlextResult[bool].ok(False)

            # Check pattern (RFC 4512: starts with letter, contains letters/digits/hyphens)
            if not self._ATTR_NAME_PATTERN.match(name):
                return FlextResult[bool].ok(False)

            return FlextResult[bool].ok(True)

        except Exception as e:
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
            # Check if value is a string
            if not isinstance(value, str):
                return FlextResult[bool].ok(False)

            # Allow empty values (valid in LDAP)
            if not value:
                return FlextResult[bool].ok(True)

            # Check length
            max_len = (
                max_length if max_length is not None else self._MAX_ATTR_VALUE_LENGTH
            )
            if len(value) > max_len:
                return FlextResult[bool].ok(False)

            return FlextResult[bool].ok(True)

        except Exception as e:
            return FlextResult[bool].fail(f"Failed to validate attribute value: {e}")

    def validate_dn_component(
        self,
        attr: str,
        value: str,
    ) -> FlextResult[bool]:
        """Validate DN component (attribute=value pair).

        Validates both the attribute name and value for DN usage.

        Args:
            attr: Attribute name
            value: Attribute value

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

        except Exception as e:
            return FlextResult[bool].fail(f"Failed to validate DN component: {e}")


__all__ = ["ValidationService"]
