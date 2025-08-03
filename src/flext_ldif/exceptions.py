"""FLEXT-LDIF Domain Exceptions

This module defines domain-specific exceptions for LDIF processing operations,
implementing a comprehensive exception hierarchy using flext-core exception
patterns with factory-based generation for consistency and maintainability.

The exception hierarchy provides structured error reporting with proper context,
error codes, and integration with FlextResult patterns for railway-oriented
programming throughout the LDIF processing pipeline.

Key Components:
    - FlextLdifError: Base exception for all LDIF-related errors
    - FlextLdifValidationError: Business rule and data validation failures
    - FlextLdifParseError: LDIF format parsing and syntax errors
    - FlextLdifEntryError: Entry-specific validation and processing errors
    - Specialized exceptions: Configuration, connection, timeout, and authentication errors

Architecture:
    Part of Domain Layer in Clean Architecture, these exceptions represent
    domain-specific error conditions and business rule violations without
    dependencies on external concerns or infrastructure implementation details.

Exception Hierarchy:
    - FlextLdifError (base)
      ├── FlextLdifValidationError (business rule violations)
      ├── FlextLdifParseError (LDIF format errors)
      ├── FlextLdifEntryError (entry-specific errors)
      ├── FlextLdifConfigurationError (configuration validation)
      ├── FlextLdifProcessingError (processing pipeline errors)
      ├── FlextLdifConnectionError (external service connectivity)
      ├── FlextLdifAuthenticationError (authentication failures)
      └── FlextLdifTimeoutError (operation timeout errors)

Example:
    Structured exception handling with context information:
    
    >>> from flext_ldif.exceptions import FlextLdifValidationError, FlextLdifParseError
    >>> from flext_core import FlextResult
    >>> 
    >>> def validate_entry(entry):
    ...     try:
    ...         if not entry.dn.value:
    ...             raise FlextLdifValidationError(
    ...                 "DN cannot be empty",
    ...                 context={"entry_id": entry.id},
    ...                 error_code="EMPTY_DN"
    ...             )
    ...         return FlextResult.ok(entry)
    ...     except FlextLdifValidationError as e:
    ...         return FlextResult.fail(str(e))

Integration:
    - Built on flext-core exception factory patterns for consistency
    - Integrates with FlextResult for railway-oriented error handling
    - Provides structured error reporting with context and error codes
    - Supports observability integration with error tracking and metrics

Author: FLEXT Development Team
Version: 0.9.0
License: MIT

"""

from __future__ import annotations

from flext_core import get_logger
from flext_core.exceptions import (
    FlextProcessingError,
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


class FlextLdifEntryError(FlextProcessingError):
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
