"""FLEXT-LDIF Domain Exceptions.

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
    ...                 error_code="EMPTY_DN",
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
    """Enterprise-grade exception for LDIF parsing failures with comprehensive context and error reporting.

    This exception provides detailed error information for LDIF format parsing failures,
    including line number tracking, entry context, and comprehensive error reporting
    for enterprise environments with structured logging and observability integration.

    The exception supports detailed context information to aid in troubleshooting
    and debugging LDIF format issues with precise error location and comprehensive
    error reporting for enterprise log aggregation systems.

    Example:
        >>> from flext_ldif.exceptions import FlextLdifParseError
        >>>
        >>> try:
        ...     # LDIF parsing operation
        ...     pass
        ... except Exception as e:
        ...     raise FlextLdifParseError(
        ...         "Invalid DN format in LDIF entry",
        ...         line_number=42,
        ...         entry_dn="cn=invalid entry,dc=example,dc=com",
        ...         error_code="INVALID_DN_FORMAT",
        ...     ) from e

    """

    def __init__(
        self,
        message: str = "LDIF parsing failed",
        line_number: int | None = None,
        entry_dn: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize LDIF parse error with enterprise-grade context and comprehensive logging.

        Creates a comprehensive LDIF parsing error with detailed context information,
        structured logging, and enterprise-grade error reporting for troubleshooting.

        Args:
            message: Human-readable error description
            line_number: Optional line number where parsing failed
            entry_dn: Optional DN of the entry being parsed when error occurred
            **kwargs: Additional context information for error reporting

        """
        # REFACTORING: Enhanced error creation logging with comprehensive context
        logger.debug(
            "Creating FlextLdifParseError with comprehensive context",
            error_message=message,
            parse_line_number=line_number,
            parse_entry_dn=entry_dn,
        )
        logger.trace("Parse error additional context: %s", kwargs)

        # REFACTORING: Enhanced context building with validation and error handling
        context = kwargs.copy()

        # Add line number context with validation
        if line_number is not None:
            if isinstance(line_number, int) and line_number > 0:
                context["line_number"] = line_number
                logger.trace("Added line number to error context: %d", line_number)
            else:
                logger.warning(
                    "Invalid line_number provided to FlextLdifParseError: %s",
                    line_number,
                )

        # Add entry DN context with validation
        if entry_dn is not None:
            if isinstance(entry_dn, str) and entry_dn.strip():
                context["entry_dn"] = entry_dn.strip()
                logger.trace("Added entry DN to error context: %s", entry_dn)
            else:
                logger.warning(
                    "Invalid entry_dn provided to FlextLdifParseError: %s",
                    entry_dn,
                )

        # REFACTORING: Enhanced error message formatting with context integration
        enhanced_message = f"LDIF parsing failed: {message}"
        if line_number is not None:
            enhanced_message += f" (line {line_number})"
        if entry_dn is not None:
            enhanced_message += f" (entry: {entry_dn})"

        logger.trace("Enhanced error message: %s", enhanced_message)
        logger.trace("Complete error context: %s", context)

        # REFACTORING: Enhanced parent initialization with error handling
        try:
            super().__init__(enhanced_message, **context)
            logger.debug(
                "FlextLdifParseError created successfully",
                error_message=enhanced_message,
                context_keys=list(context.keys()),
            )
        except (TypeError, ValueError) as e:
            logger.exception("Failed to create FlextLdifParseError")
            # Fallback to basic initialization
            super().__init__(f"LDIF parse: {message}")
            logger.warning(
                "FlextLdifParseError created with fallback initialization due to: %s",
                e,
            )


class FlextLdifEntryError(FlextProcessingError):
    """Enterprise-grade exception for LDIF entry operations with comprehensive context and detailed error reporting.

    This exception provides detailed error information for LDIF entry processing failures,
    including entry identification, operation context, and comprehensive error reporting
    for enterprise environments with structured logging and observability integration.

    The exception supports detailed context information to aid in troubleshooting
    entry-specific processing issues with precise error identification and comprehensive
    error reporting for enterprise log aggregation systems.

    Example:
        >>> from flext_ldif.exceptions import FlextLdifEntryError
        >>>
        >>> try:
        ...     # LDIF entry processing operation
        ...     pass
        ... except Exception as e:
        ...     raise FlextLdifEntryError(
        ...         "Entry validation failed due to missing required attribute",
        ...         entry_dn="cn=user,ou=people,dc=example,dc=com",
        ...         operation="validate_required_attributes",
        ...         error_code="MISSING_REQUIRED_ATTR",
        ...         missing_attribute="objectClass",
        ...     ) from e

    """

    def __init__(
        self,
        message: str = "LDIF entry error",
        entry_dn: str | None = None,
        operation: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize LDIF entry error with enterprise-grade context and comprehensive logging.

        Creates a comprehensive LDIF entry processing error with detailed context information,
        structured logging, and enterprise-grade error reporting for troubleshooting.

        Args:
            message: Human-readable error description
            entry_dn: Optional DN of the entry being processed when error occurred
            operation: Optional operation name that was being performed
            **kwargs: Additional context information for error reporting

        """
        # REFACTORING: Enhanced error creation logging with comprehensive context
        logger.debug(
            "Creating FlextLdifEntryError with comprehensive context",
            error_message=message,
            entry_entry_dn=entry_dn,
            entry_operation=operation,
        )
        logger.trace("Entry error additional context: %s", kwargs)

        # REFACTORING: Enhanced context building with validation and error handling
        context = kwargs.copy()

        # Add entry DN context with validation
        if entry_dn is not None:
            if isinstance(entry_dn, str) and entry_dn.strip():
                context["entry_dn"] = entry_dn.strip()
                logger.trace("Added entry DN to error context: %s", entry_dn)
            else:
                logger.warning(
                    "Invalid entry_dn provided to FlextLdifEntryError: %s",
                    entry_dn,
                )

        # Add operation context with validation
        if operation is not None:
            if isinstance(operation, str) and operation.strip():
                context["operation"] = operation.strip()
                logger.trace("Added operation to error context: %s", operation)
            else:
                logger.warning(
                    "Invalid operation provided to FlextLdifEntryError: %s",
                    operation,
                )

        # REFACTORING: Enhanced error message formatting with context integration
        enhanced_message = f"LDIF entry processing failed: {message}"
        if entry_dn is not None:
            enhanced_message += f" (entry: {entry_dn})"
        if operation is not None:
            enhanced_message += f" (operation: {operation})"

        logger.trace("Enhanced error message: %s", enhanced_message)
        logger.trace("Complete error context: %s", context)

        # REFACTORING: Enhanced parent initialization with error handling
        try:
            super().__init__(enhanced_message, **context)
            logger.debug(
                "FlextLdifEntryError created successfully",
                error_message=enhanced_message,
                context_keys=list(context.keys()),
            )
        except (TypeError, ValueError) as e:
            logger.exception("Failed to create FlextLdifEntryError")
            # Fallback to basic initialization
            super().__init__(f"LDIF entry: {message}")
            logger.warning(
                "FlextLdifEntryError created with fallback initialization due to: %s",
                e,
            )


__all__: list[str] = [
    "FlextLdifEntryError",
    "FlextLdifError",
    "FlextLdifParseError",
    "FlextLdifValidationError",
]
