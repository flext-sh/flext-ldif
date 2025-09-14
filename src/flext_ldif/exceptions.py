"""FLEXT LDIF Exceptions - LDIF-specific exception handling using flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextExceptions

# Constants for magic numbers (ZERO TOLERANCE - no magic values)
_CONTENT_PREVIEW_LENGTH = 50
_DN_PREVIEW_LENGTH = 80


class FlextLDIFExceptions(FlextExceptions):
    """LDIF-specific exceptions inheriting from flext-core FlextExceptions."""

    @classmethod
    def validation_error(cls, message: str, **_kwargs: object) -> Exception:
        """Create a validation error."""
        return cls.ValidationError(message)

    @classmethod
    def parse_error(cls, message: str, **_kwargs: object) -> Exception:
        """Create a parse error."""
        line_number = _kwargs.get("line_number")
        content_preview = _kwargs.get("content_preview")
        return LdifParseError(message, line_number=line_number, content_preview=content_preview)

    @classmethod
    def processing_error(cls, message: str, **_kwargs: object) -> Exception:
        """Create a processing error."""
        operation = _kwargs.get("operation")
        entry_count = _kwargs.get("entry_count")
        return LdifProcessingError(message, operation=operation, entry_count=entry_count)

    @classmethod
    def file_error(cls, message: str, **_kwargs: object) -> Exception:
        """Create a file error."""
        file_path = _kwargs.get("file_path")
        return LdifFileError(message, file_path=file_path)

    @classmethod
    def configuration_error(cls, message: str, **_kwargs: object) -> Exception:
        """Create a configuration error."""
        config_key = _kwargs.get("config_key")
        return LdifConfigurationError(message, config_key=config_key)

    @classmethod
    def connection_error(cls, message: str, **_kwargs: object) -> Exception:
        """Create a connection error."""
        return cls.ConnectionError(message)

    @classmethod
    def timeout_error(cls, message: str, **_kwargs: object) -> Exception:
        """Create a timeout error."""
        return cls.TimeoutError(message)

    @classmethod
    def authentication_error(cls, message: str, **_kwargs: object) -> Exception:
        """Create an authentication error."""
        return cls.AuthenticationError(message)

    @classmethod
    def error(cls, message: str, **_kwargs: object) -> Exception:
        """Create a generic error."""
        return cls.BaseError(message)

    @classmethod
    def entry_error(cls, message: str, **_kwargs: object) -> Exception:
        """Create an entry error."""
        dn = _kwargs.get("dn")
        attribute_name = _kwargs.get("attribute_name")
        return LdifValidationError(message, dn=dn, attribute_name=attribute_name)

    @classmethod
    def parse_error_alias(cls, message: str, **_kwargs: object) -> Exception:
        """Create a parse error alias."""
        line_number = _kwargs.get("line_number")
        content_preview = _kwargs.get("content_preview")
        return LdifParseError(message, line_number=line_number, content_preview=content_preview)


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


# Additional exception classes for test compatibility
class FlextLDIFError(LdifProcessingError):
    """Base LDIF error for test compatibility."""



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



class FlextLDIFTimeoutError(Exception):
    """LDIF timeout error for test compatibility."""



class FlextLDIFAuthenticationError(Exception):
    """LDIF authentication error for test compatibility."""



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
