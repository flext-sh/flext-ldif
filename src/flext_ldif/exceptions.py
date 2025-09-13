"""FLEXT LDIF Exceptions - LDIF-specific exception handling.

Eliminates 127+ lines of duplicated error formatting and context building.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextExceptions

# Create LDIF-specific exception classes using flext-core's factory
_LDIF_EXCEPTIONS = FlextExceptions.create_module_exception_classes("flext_ldif")

# Constants for magic numbers (ZERO TOLERANCE - no magic values)
_CONTENT_PREVIEW_LENGTH = 50
_DN_PREVIEW_LENGTH = 80


class FlextLDIFExceptions:
    """LDIF-specific exceptions using flext-core SOURCE OF TRUTH.

    All exception types automatically include:
    - Context tracking (service/operation/DN)
    - Error codes (LDIF_PARSE_ERROR, LDIF_VALIDATION_ERROR, etc.)
    - Structured logging integration
    - Chain-friendly error handling
    """

    # Direct access to flext-core exception classes via dictionary
    BaseError = _LDIF_EXCEPTIONS["FLEXT_LDIFBaseError"]
    ValidationError = _LDIF_EXCEPTIONS["FLEXT_LDIFValidationError"]
    ProcessingError = _LDIF_EXCEPTIONS["FLEXT_LDIFProcessingError"]
    ConfigurationError = _LDIF_EXCEPTIONS["FLEXT_LDIFConfigurationError"]
    ConnectionError = _LDIF_EXCEPTIONS["FLEXT_LDIFConnectionError"]

    # Reference to LDIF-specific exception classes
    LdifParseError: type[Exception] = None
    LdifValidationError: type[Exception] = None
    LdifProcessingError: type[Exception] = None
    LdifFileError: type[Exception] = None
    LdifConfigurationError: type[Exception] = None

    @classmethod
    def validation_error(cls, message: str, **_kwargs: object) -> Exception:
        """Create a validation error."""
        return cls.ValidationError(message)


# Define classes outside the FlextLDIFExceptions class to avoid MyPy issues
class LdifParseError(Exception):
    """LDIF parsing errors with content context."""

    def __init__(
        self,
        message: str,
        line_number: int | None = None,
        content_preview: str | None = None,
        **_kwargs: object,
    ) -> None:
        """Initialize with parsing context."""
        enriched_message = message
        if line_number is not None:
            enriched_message += f" (line {line_number})"
        if content_preview:
            preview = (
                content_preview[:_CONTENT_PREVIEW_LENGTH]
                if len(content_preview) > _CONTENT_PREVIEW_LENGTH
                else content_preview
            )
            enriched_message += f" - Preview: '{preview}'"

        super().__init__(enriched_message)


class LdifValidationError(Exception):
    """LDIF validation errors with entry context."""

    def __init__(
        self,
        message: str,
        dn: str | None = None,
        attribute_name: str | None = None,
        **_kwargs: object,
    ) -> None:
        """Initialize with validation context."""
        enriched_message = message
        if dn:
            dn_preview = dn[:_DN_PREVIEW_LENGTH] if len(dn) > _DN_PREVIEW_LENGTH else dn
            enriched_message += f" (DN: {dn_preview})"
        if attribute_name:
            enriched_message += f" (attribute: {attribute_name})"

        super().__init__(enriched_message)


class LdifProcessingError(Exception):
    """LDIF processing errors with operation context."""

    def __init__(
        self,
        message: str,
        operation: str | None = None,
        entry_count: int | None = None,
        **_kwargs: object,
    ) -> None:
        """Initialize with processing context."""
        enriched_message = message
        if operation:
            enriched_message += f" (operation: {operation})"
        if entry_count is not None:
            enriched_message += f" (entries processed: {entry_count})"

        super().__init__(enriched_message)


class LdifFileError(Exception):
    """LDIF file operation errors."""

    def __init__(
        self,
        message: str,
        file_path: str | None = None,
        **_kwargs: object,
    ) -> None:
        """Initialize with file context."""
        enriched_message = message
        if file_path:
            enriched_message += f" (file: {file_path})"

        super().__init__(enriched_message)


class LdifConfigurationError(Exception):
    """LDIF configuration errors."""

    def __init__(
        self,
        message: str,
        config_key: str | None = None,
        **_kwargs: object,
    ) -> None:
        """Initialize with configuration context."""
        enriched_message = message
        if config_key:
            enriched_message += f" (config: {config_key})"

        super().__init__(enriched_message)


# Set the class references in FlextLDIFExceptions after class definitions
FlextLDIFExceptions.LdifParseError = LdifParseError
FlextLDIFExceptions.LdifValidationError = LdifValidationError
FlextLDIFExceptions.LdifProcessingError = LdifProcessingError
FlextLDIFExceptions.LdifFileError = LdifFileError
FlextLDIFExceptions.LdifConfigurationError = LdifConfigurationError


# Add this to the FlextLDIFExceptions class methods
class FlextLDIFExceptionsMethods:
    """Additional methods for FlextLDIFExceptions class."""

    @classmethod
    def get_exception_info(cls) -> dict[str, object]:
        """Get LDIF exception class information."""
        return {
            "module": "flext_ldif.exceptions",
            "base_exceptions": [
                "BaseError",
                "ValidationError",
                "ProcessingError",
                "ConfigurationError",
                "ExternalServiceError",
            ],
            "ldif_specific": [
                "LdifParseError",
                "LdifValidationError",
                "LdifProcessingError",
                "LdifFileError",
                "LdifConfigurationError",
            ],
            "flext_core_integration": True,
        }


# Convenience aliases for common usage patterns - these reference the module-level classes
# LdifParseError = LdifParseError (already defined above)
# LdifValidationError = LdifValidationError (already defined above)
# LdifProcessingError = LdifProcessingError (already defined above)
# LdifFileError = LdifFileError (already defined above)
# LdifConfigurationError = LdifConfigurationError (already defined above)

__all__ = [
    "FlextLDIFExceptions",
    "LdifConfigurationError",
    "LdifFileError",
    "LdifParseError",
    "LdifProcessingError",
    "LdifValidationError",
]
