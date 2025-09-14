"""FLEXT LDIF Exceptions - LDIF-specific exception handling using flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextExceptions

# Constants for magic numbers (ZERO TOLERANCE - no magic values)
_CONTENT_PREVIEW_LENGTH = 50
_DN_PREVIEW_LENGTH = 80
_ATTRIBUTE_TRUNCATION_THRESHOLD = 3


class FlextLDIFExceptions(FlextExceptions):
    """LDIF-specific exceptions inheriting from flext-core FlextExceptions."""

    @classmethod
    def validation_error(cls, message: str, **_kwargs: object) -> LdifValidationError:
        """Create a validation error."""
        # Enrich message with context from kwargs
        dn = _kwargs.get("entry_dn") or _kwargs.get("dn")
        attribute_name = _kwargs.get("attribute_name")

        error = LdifValidationError(
            message,
            dn=dn if isinstance(dn, str) else None,
            attribute_name=attribute_name if isinstance(attribute_name, str) else None,
        )

        # Add validation_details if validation_rule is provided
        validation_rule = _kwargs.get("validation_rule")
        if validation_rule:
            error.validation_details = {"rule": validation_rule}

        return error

    @classmethod
    def parse_error(cls, message: str, **_kwargs: object) -> LdifParseError:
        """Create a parse error."""
        # Handle both 'line' and 'line_number' parameters
        line_number = _kwargs.get("line_number") or _kwargs.get("line")
        content_preview = _kwargs.get("content_preview") or _kwargs.get("content")
        column = _kwargs.get("column")
        return LdifParseError(
            message,
            line_number=line_number if isinstance(line_number, int) else None,
            content_preview=content_preview
            if isinstance(content_preview, str)
            else None,
            column=column if isinstance(column, int) else None,
        )

    @classmethod
    def processing_error(cls, message: str, **_kwargs: object) -> LdifProcessingError:
        """Create a processing error."""
        operation = _kwargs.get("operation")
        entry_count = _kwargs.get("entry_count")
        return LdifProcessingError(
            message,
            operation=operation if isinstance(operation, str) else None,
            entry_count=entry_count if isinstance(entry_count, int) else None,
        )

    @classmethod
    def file_error(cls, message: str, **_kwargs: object) -> LdifFileError:
        """Create a file error."""
        file_path = _kwargs.get("file_path")
        return LdifFileError(
            message, file_path=file_path if isinstance(file_path, str) else None
        )

    @classmethod
    def configuration_error(
        cls, message: str, **_kwargs: object
    ) -> LdifConfigurationError:
        """Create a configuration error."""
        config_key = _kwargs.get("config_key")
        return LdifConfigurationError(
            message, config_key=config_key if isinstance(config_key, str) else None
        )

    @classmethod
    def connection_error(
        cls, message: str, **_kwargs: object
    ) -> FlextLDIFConnectionError:
        """Create a connection error."""
        return FlextLDIFConnectionError(message)

    @classmethod
    def timeout_error(cls, message: str, **_kwargs: object) -> FlextLDIFTimeoutError:
        """Create a timeout error."""
        return FlextLDIFTimeoutError(message)

    @classmethod
    def authentication_error(
        cls, message: str, **_kwargs: object
    ) -> FlextLDIFAuthenticationError:
        """Create an authentication error."""
        return FlextLDIFAuthenticationError(message)

    @classmethod
    def error(cls, message: str, **_kwargs: object) -> FlextLDIFError:
        """Create a generic error."""
        return FlextLDIFError(message)

    @classmethod
    def entry_error(cls, message: str, **_kwargs: object) -> LdifValidationError:
        """Create an entry error."""
        # Handle both 'dn' and 'entry_dn' parameters
        dn = _kwargs.get("dn") or _kwargs.get("entry_dn")
        attribute_name = _kwargs.get("attribute_name")

        # Handle entry_data parameter
        entry_data = _kwargs.get("entry_data")
        if entry_data and isinstance(entry_data, dict):
            # Format attributes list with truncation
            attributes = list(entry_data.keys())
            if attributes:
                if len(attributes) > _ATTRIBUTE_TRUNCATION_THRESHOLD:
                    # Show first few attributes and count of remaining
                    shown_attrs = attributes[:_ATTRIBUTE_TRUNCATION_THRESHOLD]
                    remaining_count = len(attributes) - _ATTRIBUTE_TRUNCATION_THRESHOLD
                    attribute_name = (
                        f"[{', '.join(shown_attrs)} (+{remaining_count} more)]"
                    )
                else:
                    attribute_name = f"[{', '.join(attributes)}]"

        return LdifValidationError(
            message,
            dn=dn if isinstance(dn, str) else None,
            attribute_name=attribute_name if isinstance(attribute_name, str) else None,
        )

    @classmethod
    def parse_error_alias(cls, message: str, **_kwargs: object) -> LdifParseError:
        """Create a parse error alias."""
        # Handle both 'line' and 'line_number' parameters
        line_number = _kwargs.get("line_number") or _kwargs.get("line")
        content_preview = _kwargs.get("content_preview") or _kwargs.get("content")
        column = _kwargs.get("column")
        return LdifParseError(
            message,
            line_number=line_number if isinstance(line_number, int) else None,
            content_preview=content_preview
            if isinstance(content_preview, str)
            else None,
            column=column if isinstance(column, int) else None,
        )


# Legacy exception classes for backward compatibility
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
        self.operation = "ldif_parsing"
        enriched_message = message
        if line_number is not None:
            enriched_message += f" (line {line_number}"
            # Handle column if provided in kwargs
            column = _kwargs.get("column")
            if column is not None:
                enriched_message += f", column {column}"
            enriched_message += ")"
        if content_preview and content_preview.strip():
            preview = (
                content_preview[:_CONTENT_PREVIEW_LENGTH]
                if len(content_preview) > _CONTENT_PREVIEW_LENGTH
                else content_preview
            )
            enriched_message += f" - Content: {preview}"
            if len(content_preview) > _CONTENT_PREVIEW_LENGTH:
                enriched_message += "..."

        # Store the enriched message in self.message for compatibility
        self.message = enriched_message
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
        self.operation = "ldif_entry_processing"
        self.validation_details: dict[str, object] = {}  # Add validation_details attribute
        enriched_message = message
        if dn:
            dn_preview = dn[:_DN_PREVIEW_LENGTH] if len(dn) > _DN_PREVIEW_LENGTH else dn
            enriched_message += f" (DN: {dn_preview})"
        if attribute_name:
            enriched_message += f" (Attributes: {attribute_name})"

        # Store the enriched message in self.message for compatibility
        self.message = enriched_message
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
        self.message = message
        self.operation = operation or "ldif_processing"
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
        self.operation = "ldif_file_operation"
        enriched_message = message
        if file_path:
            enriched_message += f" (file: {file_path})"

        # Store the enriched message in self.message for compatibility
        self.message = enriched_message
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
        self.message = message
        self.operation = "ldif_configuration"
        enriched_message = message
        if config_key:
            enriched_message += f" (config: {config_key})"

        super().__init__(enriched_message)


# Additional exception classes for test compatibility
class FlextLDIFError(LdifProcessingError):
    """Base LDIF error for test compatibility."""

    def __init__(self, message: str, **_kwargs: object) -> None:
        """Initialize with context for test compatibility."""
        operation = _kwargs.get("operation")
        entry_count = _kwargs.get("entry_count")
        super().__init__(
            message,
            operation=operation if isinstance(operation, str) else None,
            entry_count=entry_count if isinstance(entry_count, int) else None,
        )
        self.context = _kwargs


class FlextLDIFParseError(LdifParseError):
    """LDIF parse error for test compatibility."""


class FlextLDIFValidationError(LdifValidationError):
    """LDIF validation error for test compatibility."""


class FlextLDIFProcessingError(LdifProcessingError):
    """LDIF processing error for test compatibility."""


class FlextLDIFFileError(LdifFileError):
    """LDIF file error for test compatibility."""


class FlextLDIFConfigurationError(LdifConfigurationError):
    """LDIF configuration error for test compatibility."""


class FlextLDIFConnectionError(Exception):
    """LDIF connection error for test compatibility."""

    def __init__(self, message: str, **_kwargs: object) -> None:
        """Initialize with message for test compatibility."""
        self.message = message
        self.operation = "ldif_connection"
        super().__init__(message)


class FlextLDIFTimeoutError(Exception):
    """LDIF timeout error for test compatibility."""

    def __init__(self, message: str, **_kwargs: object) -> None:
        """Initialize with message for test compatibility."""
        self.message = message
        self.operation = "ldif_timeout"
        super().__init__(message)


class FlextLDIFAuthenticationError(Exception):
    """LDIF authentication error for test compatibility."""

    def __init__(self, message: str, **_kwargs: object) -> None:
        """Initialize with message for test compatibility."""
        self.message = message
        self.operation = "ldif_authentication"
        super().__init__(message)


class FlextLDIFErrorCodes:
    """LDIF error codes for test compatibility."""

    PARSE_ERROR = "LDIF_PARSE_ERROR"
    VALIDATION_ERROR = "LDIF_VALIDATION_ERROR"
    PROCESSING_ERROR = "LDIF_PROCESSING_ERROR"
    FILE_ERROR = "LDIF_FILE_ERROR"
    CONFIGURATION_ERROR = "LDIF_CONFIGURATION_ERROR"
    CONNECTION_ERROR = "LDIF_CONNECTION_ERROR"
    TIMEOUT_ERROR = "LDIF_TIMEOUT_ERROR"
    AUTHENTICATION_ERROR = "LDIF_AUTHENTICATION_ERROR"


__all__ = [
    "FlextLDIFAuthenticationError",
    "FlextLDIFConfigurationError",
    "FlextLDIFConnectionError",
    "FlextLDIFError",
    "FlextLDIFErrorCodes",
    "FlextLDIFExceptions",
    "FlextLDIFFileError",
    "FlextLDIFParseError",
    "FlextLDIFProcessingError",
    "FlextLDIFTimeoutError",
    "FlextLDIFValidationError",
    "LdifConfigurationError",
    "LdifFileError",
    "LdifParseError",
    "LdifProcessingError",
    "LdifValidationError",
]
