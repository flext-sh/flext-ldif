"""FLEXT LDIF Mixins - Single unified class following FLEXT standards.

Common validation and factory patterns for LDIF operations.
Single FlextLdifMixins class with nested mixin subclasses following FLEXT pattern.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TypeVar

from flext_core import FlextMixins, FlextResult
from flext_ldif.constants import FlextLdifConstants

T = TypeVar("T")


class FlextLdifMixins(FlextMixins):
    """Single unified LDIF mixins class following FLEXT standards.

    Contains all mixin subclasses for LDIF domain operations.
    Follows FLEXT pattern: one class per module with nested subclasses.
    Extends FlextMixins with LDIF-specific functionality.
    """

    # =========================================================================
    # VALIDATION MIXIN - Common validation utilities
    # =========================================================================

    class ValidationMixin:
        """Mixin providing common validation utilities for LDIF classes.

        Contains reusable validation methods to eliminate duplication
        across config and models classes.
        """

        @staticmethod
        def validate_string_not_empty(value: str | None, field_name: str) -> str:
            """Validate that a string is not empty.

            Args:
                value: String value to validate (can be None)
                field_name: Name of the field for error messages

            Returns:
                str: Trimmed string value

            Raises:
                ValueError: If string is None, empty or whitespace only

            """
            if value is None or not value or not value.strip():
                msg = f"{field_name} cannot be empty"
                raise ValueError(msg)
            return value.strip()

        @staticmethod
        def validate_encoding(value: str) -> str:
            """Validate encoding is supported.

            Args:
                value: Encoding string to validate

            Returns:
                str: The validated encoding string

            Raises:
                ValueError: If the encoding is not supported

            """
            try:
                test_bytes = "test".encode(value)
                test_bytes.decode(value)
            except (UnicodeError, LookupError) as e:
                msg = f"Unsupported encoding: {value}"
                raise ValueError(msg) from e
            return value

        @staticmethod
        def validate_dn_format(value: str) -> str:
            """Validate DN format and characters.

            Args:
                value: DN string to validate

            Returns:
                str: Validated DN string

            Raises:
                ValueError: If DN format is invalid

            """
            if not value.strip():
                raise ValueError(FlextLdifConstants.ErrorMessages.DN_EMPTY_ERROR)

            # Basic DN format validation - must contain = character
            if "=" not in value:
                raise ValueError(
                    FlextLdifConstants.ErrorMessages.DN_INVALID_FORMAT_ERROR
                )

            # Check for invalid characters (excluding "@" for email support and "{}" for OpenLDAP config)
            invalid_chars = {
                "#",
                "$",
                "%",
                "^",
                "&",
                "*",
                "(",
                ")",
                "[",
                "]",
                "|",
                "\\",
                "/",
                "?",
                "<",
                ">",
            }
            if any(char in value for char in invalid_chars):
                raise ValueError(
                    FlextLdifConstants.ErrorMessages.DN_INVALID_CHARS_ERROR
                )

            return value.strip()

        @staticmethod
        def validate_url_format(value: str) -> str:
            """Basic URL format validation.

            Args:
                value: URL string to validate

            Returns:
                str: Validated URL string

            Raises:
                ValueError: If URL format is invalid

            """
            if not value.strip():
                msg = "URL cannot be empty"
                raise ValueError(msg)

            # Basic URL validation - must start with protocol
            valid_protocols = ("http://", "https://", "ldap://", "ldaps://")
            if not value.startswith(valid_protocols):
                msg = "URL must start with valid protocol"
                raise ValueError(msg)

            return value.strip()

        @staticmethod
        def validate_attribute_name(attr_name: str) -> str:
            """Validate attribute name.

            Args:
                attr_name: Attribute name to validate

            Returns:
                str: Validated attribute name

            Raises:
                ValueError: If attribute name is invalid

            """
            if not attr_name or not attr_name.strip():
                raise ValueError(FlextLdifConstants.ErrorMessages.ATTRIBUTE_NAME_ERROR)
            return attr_name.strip()

        @staticmethod
        def validate_attribute_values(attr_values: list[str]) -> list[str]:
            """Validate attribute values.

            Args:
                attr_values: List of attribute values to validate

            Returns:
                list[str]: Validated attribute values

            Raises:
                TypeError: If attribute values are invalid

            """
            if not attr_values:  # Allow empty lists
                return attr_values

            return attr_values

    # =========================================================================
    # BUSINESS RULES MIXIN - Common business rule validation patterns
    # =========================================================================

    class BusinessRulesMixin:
        """Mixin providing common business rule validation patterns.

        Contains reusable business rule validation methods.
        """

        @staticmethod
        def validate_minimum_entries(
            current_entries: int, minimum_required: int, context: str = "entries"
        ) -> FlextResult[None]:
            """Validate minimum number of entries.

            Args:
                current_entries: Current number of entries
                minimum_required: Minimum required entries
                context: Context for error message

            Returns:
                FlextResult[None]: Validation result

            """
            if current_entries < minimum_required:
                msg = f"Too few {context} for production use (minimum: {minimum_required})"
                return FlextResult[None].fail(msg, error_code="MINIMUM_ENTRIES_ERROR")
            return FlextResult[None].ok(None)

        @staticmethod
        def validate_resource_limits(
            current_value: int, maximum_allowed: int, resource_name: str
        ) -> FlextResult[None]:
            """Validate resource limits.

            Args:
                current_value: Current resource value
                maximum_allowed: Maximum allowed value
                resource_name: Name of the resource for error message

            Returns:
                FlextResult[None]: Validation result

            """
            if current_value > maximum_allowed:
                msg = f"{resource_name} exceeds maximum limit ({maximum_allowed})"
                return FlextResult[None].fail(msg, error_code="RESOURCE_LIMIT_ERROR")
            return FlextResult[None].ok(None)

        @staticmethod
        def validate_parallel_configuration_consistency(
            *, parallel_enabled: bool, worker_count: int, min_workers: int
        ) -> FlextResult[None]:
            """Validate parallel processing configuration consistency.

            Args:
                parallel_enabled: Whether parallel processing is enabled
                worker_count: Number of workers configured
                min_workers: Minimum workers required for parallel processing

            Returns:
                FlextResult[None]: Validation result

            """
            if parallel_enabled and worker_count < min_workers:
                msg = f"Parallel processing requires at least {min_workers} workers"
                return FlextResult[None].fail(msg, error_code="PARALLEL_CONFIG_ERROR")
            return FlextResult[None].ok(None)


__all__ = [
    "FlextLdifMixins",
]
