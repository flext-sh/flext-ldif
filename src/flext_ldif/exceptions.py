"""LDIF exceptions using flext-core DRY patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

Domain-specific exceptions using factory pattern to eliminate duplication.
"""

from __future__ import annotations

from flext_core import get_logger
from flext_core.exceptions import (
    FlextProcessingError,
    FlextValidationError,
    create_module_exception_classes,
)

logger = get_logger(__name__)

# Create all standard exception classes using factory pattern - eliminates duplication
ldif_exceptions = create_module_exception_classes("flext_ldif")

# Import generated classes for clean usage
FlextLdifError = ldif_exceptions["FlextLdifError"]
FlextLdifValidationError = ldif_exceptions["FlextLdifValidationError"]
FlextLdifConfigurationError = ldif_exceptions["FlextLdifConfigurationError"]
FlextLdifConnectionError = ldif_exceptions["FlextLdifConnectionError"]
FlextLdifProcessingError = ldif_exceptions["FlextLdifProcessingError"]
FlextLdifAuthenticationError = ldif_exceptions["FlextLdifAuthenticationError"]
FlextLdifTimeoutError = ldif_exceptions["FlextLdifTimeoutError"]


class FlextLdifParseError(FlextProcessingError):
    """Exception raised when LDIF parsing fails."""

    def __init__(
        self,
        message: str = "LDIF parsing failed",
        line_number: int | None = None,
        entry_dn: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize LDIF parse error with context."""
        logger.debug("Creating FlextLdifParseError: %s", message)
        logger.trace("Parse error details - line: %s, DN: %s", line_number, entry_dn)

        context = kwargs.copy()
        if line_number is not None:
            context["line_number"] = line_number
        if entry_dn is not None:
            context["entry_dn"] = entry_dn

        logger.trace("Parse error context: %s", context)
        super().__init__(f"LDIF parse: {message}", **context)
        logger.debug("FlextLdifParseError created successfully")


class FlextLdifValidationError(FlextValidationError):
    """Exception raised when LDIF validation fails."""

    def __init__(
        self,
        message: str = "LDIF validation failed",
        attribute_name: str | None = None,
        attribute_value: object = None,
        entry_dn: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize LDIF validation error with context."""
        validation_details: dict[str, object] = {}
        if attribute_name is not None:
            validation_details["field"] = attribute_name
        if attribute_value is not None:
            validation_details["value"] = attribute_value

        context = kwargs.copy()
        if entry_dn is not None:
            context["entry_dn"] = entry_dn

        super().__init__(
            f"LDIF validation: {message}",
            validation_details=validation_details,
            context=context,
        )


class FlextLdifEntryError(FlextLdifError):
    """Exception raised for LDIF entry operations."""

    def __init__(
        self,
        message: str = "LDIF entry error",
        entry_dn: str | None = None,
        operation: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize LDIF entry error with context."""
        context = kwargs.copy()
        if entry_dn is not None:
            context["entry_dn"] = entry_dn
        if operation is not None:
            context["operation"] = operation

        super().__init__(f"LDIF entry: {message}", **context)


__all__ = [
    "FlextLdifEntryError",
    "FlextLdifError",
    "FlextLdifParseError",
    "FlextLdifValidationError",
]
