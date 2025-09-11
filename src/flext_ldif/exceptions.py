"""FLEXT-LDIF Exceptions - Direct flext-core usage.

Minimal LDIF-specific exception extensions using flext-core directly.
No duplication of existing functionality - only domain-specific additions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextExceptions

# Constants for error message formatting
_CONTENT_PREVIEW_LENGTH = 50
_MAX_ATTRIBUTES_DISPLAY = 3


class FlextLDIFExceptions(FlextExceptions):
    """LDIF Exceptions using flext-core FlextExceptions directly.

    Provides LDIF-specific exception methods while using flext-core
    exception infrastructure directly. No duplication of base functionality.
    """

    # LDIF-specific error codes - minimal additions
    LDIF_PARSE_ERROR = "LDIF_PARSE_ERROR"
    LDIF_ENTRY_ERROR = "LDIF_ENTRY_ERROR"

    @classmethod
    def parse_error(
        cls,
        message: str,
        *,
        line: int | None = None,
        column: int | None = None,
        content: str | None = None,
    ) -> FlextExceptions.BaseError:
        """Create LDIF parse error using flext-core directly."""
        # Build enhanced error message with location context
        enhanced_message = message
        if line is not None:
            enhanced_message += f" (line {line}"
            if column is not None:
                enhanced_message += f", column {column}"
            enhanced_message += ")"
        if content is not None and len(content.strip()) > 0:
            enhanced_message += f" - Content: {content[:_CONTENT_PREVIEW_LENGTH]}{'...' if len(content) > _CONTENT_PREVIEW_LENGTH else ''}"

        return cls.ProcessingError(enhanced_message, operation="ldif_parsing")

    @classmethod
    def entry_error(
        cls,
        message: str,
        *,
        dn: str | None = None,
        entry_dn: str | None = None,
        entry_data: dict[str, object] | None = None,
    ) -> FlextExceptions.BaseError:
        """Create LDIF entry error using flext-core directly."""
        # Support both dn and entry_dn parameter names for test compatibility
        actual_dn = dn or entry_dn

        # Build enhanced message with DN and entry data context
        enhanced_message = message
        if actual_dn:
            enhanced_message += f" (DN: {actual_dn})"
        if entry_data:
            # Add entry data summary for debugging context
            attrs = list(entry_data.keys())[
                :_MAX_ATTRIBUTES_DISPLAY
            ]  # Show first few attributes
            attr_summary = ", ".join(attrs)
            if len(entry_data) > _MAX_ATTRIBUTES_DISPLAY:
                attr_summary += f" (+{len(entry_data) - _MAX_ATTRIBUTES_DISPLAY} more)"
            enhanced_message += f" - Attributes: [{attr_summary}]"

        # Use ProcessingError with enhanced message
        return cls.ProcessingError(enhanced_message, operation="ldif_entry_processing")

    @classmethod
    def validation_error(
        cls,
        message: str,
        *,
        entry_dn: str | None = None,
        validation_rule: str | None = None,
    ) -> FlextLDIFValidationError:
        """Create LDIF validation error using flext-core directly."""
        # Build enhanced message with DN context
        enhanced_message = message
        if entry_dn:
            enhanced_message += f" (DN: {entry_dn})"

        # Build validation details with rule context
        validation_details = validation_rule or "ldif_validation"

        context: dict[str, object] = {
            "field": "ldif_entry",
            "validation_details": validation_details,
        }
        if entry_dn:
            context["entry_dn"] = entry_dn

        return FlextLDIFValidationError(enhanced_message, context=context)

    @classmethod
    def processing_error(
        cls, message: str, *, operation: str | None = None
    ) -> FlextLDIFProcessingError:
        """Create LDIF processing error with proper code."""
        context: dict[str, object] = {}
        if operation:
            context["operation"] = operation
        return FlextLDIFProcessingError(message, context=context)

    @classmethod
    def timeout_error(
        cls, message: str, *, timeout_duration: float | None = None
    ) -> FlextLDIFTimeoutError:
        """Create LDIF timeout error with proper code."""
        context: dict[str, object] = {}
        if timeout_duration:
            context["timeout_duration"] = timeout_duration
        return FlextLDIFTimeoutError(message, context=context)

    @classmethod
    def error(cls, message: str) -> FlextExceptions.BaseError:
        """Create general error using flext-core directly."""
        return cls.BaseError(message)

    @classmethod
    def connection_error(cls, message: str) -> FlextExceptions.BaseError:
        """Create connection error using flext-core directly."""
        return cls.ConnectionError(message)

    @classmethod
    def file_error(
        cls, message: str, *, file_path: str | None = None, operation: str | None = None
    ) -> FlextExceptions.BaseError:
        """Create file error using flext-core directly - use OperationError since no FileError."""
        # Build enhanced message with file path context
        enhanced_message = message
        if file_path:
            enhanced_message += f" (file: {file_path})"
        return cls.OperationError(enhanced_message, operation=operation)

    @classmethod
    def configuration_error(
        cls, message: str = "LDIF configuration error"
    ) -> FlextExceptions.BaseError:
        """Create configuration error using flext-core directly."""
        return cls.ConfigurationError(message)

    @classmethod
    def authentication_error(cls, message: str) -> FlextExceptions.BaseError:
        """Create authentication error using flext-core directly."""
        return cls.AuthenticationError(message)

    @classmethod
    def builder(cls) -> FlextLDIFExceptionBuilder:
        """Create exception builder for fluent API."""
        return FlextLDIFExceptionBuilder()

    @classmethod
    def parse_error_alias(
        cls, message: str, *, line: int | None = None, column: int | None = None
    ) -> FlextLDIFParseError:
        """Create parse error - simple alias for test compatibility."""
        # Build enhanced error message with location context
        enhanced_message = message
        if line is not None:
            enhanced_message += f" (line {line}"
            if column is not None:
                enhanced_message += f", column {column}"
            enhanced_message += ")"

        context: dict[str, object] = {}
        if line is not None:
            context["line"] = line
        if column is not None:
            context["column"] = column
        return FlextLDIFParseError(enhanced_message, context=context)


# Simple aliases for test compatibility - use flext-core SOURCE OF TRUTH directly
class _ErrorCode:
    """Simple error code with value attribute for test compatibility."""

    def __init__(self, value: str) -> None:
        self.value = value


class FlextLDIFErrorCodes:
    """Simple error codes using flext-core directly."""

    LDIF_PARSE_ERROR = _ErrorCode(FlextLDIFExceptions.LDIF_PARSE_ERROR)
    LDIF_ENTRY_ERROR = _ErrorCode(FlextLDIFExceptions.LDIF_ENTRY_ERROR)

    # Additional error codes for test compatibility
    LDIF_ERROR = _ErrorCode("LDIF_ERROR")
    LDIF_VALIDATION_ERROR = _ErrorCode("LDIF_VALIDATION_ERROR")
    LDIF_CONFIGURATION_ERROR = _ErrorCode("LDIF_CONFIGURATION_ERROR")
    LDIF_PROCESSING_ERROR = _ErrorCode("LDIF_PROCESSING_ERROR")
    LDIF_CONNECTION_ERROR = _ErrorCode("LDIF_CONNECTION_ERROR")
    LDIF_AUTHENTICATION_ERROR = _ErrorCode("LDIF_AUTHENTICATION_ERROR")
    LDIF_TIMEOUT_ERROR = _ErrorCode("LDIF_TIMEOUT_ERROR")


# Exception builder for fluent API
class FlextLDIFExceptionBuilder:
    """Fluent builder for LDIF exceptions."""

    def __init__(self) -> None:
        """Initialize exception builder with empty state."""
        self._message = ""
        self._code: object | None = None
        self._context: dict[str, object] = {}

    def message(self, message: str) -> FlextLDIFExceptionBuilder:
        """Set exception message."""
        self._message = message
        return self

    def code(self, code: object) -> FlextLDIFExceptionBuilder:
        """Set exception code."""
        self._code = code
        return self

    def context(self, context: dict[str, object]) -> FlextLDIFExceptionBuilder:
        """Set exception context."""
        self._context.update(context)
        return self

    def location(
        self, *, line: int | None = None, column: int | None = None
    ) -> FlextLDIFExceptionBuilder:
        """Set location information."""
        if line is not None:
            self._context["line"] = line
        if column is not None:
            self._context["column"] = column
        return self

    def dn(self, dn: str) -> FlextLDIFExceptionBuilder:
        """Set DN information."""
        self._context["dn"] = dn
        return self

    def attribute(self, attribute: str) -> FlextLDIFExceptionBuilder:
        """Set attribute information."""
        self._context["attribute"] = attribute
        return self

    def entry_index(self, index: int) -> FlextLDIFExceptionBuilder:
        """Set entry index."""
        self._context["entry_index"] = index
        return self

    def entry_data(self, data: dict[str, object]) -> FlextLDIFExceptionBuilder:
        """Set entry data."""
        self._context["entry_data"] = data
        return self

    def validation_rule(self, rule: str) -> FlextLDIFExceptionBuilder:
        """Set validation rule."""
        self._context["validation_rule"] = rule
        return self

    def file_path(self, path: str) -> FlextLDIFExceptionBuilder:
        """Set file path."""
        self._context["file_path"] = path
        return self

    def operation(self, operation: str) -> FlextLDIFExceptionBuilder:
        """Set operation."""
        self._context["operation"] = operation
        return self

    def build(self) -> FlextLDIFError:
        """Build the exception."""
        return FlextLDIFError(self._message, context=self._context)


# Simple exception aliases for test compatibility - delegate to flext-core
class FlextLDIFError(Exception):
    """Base LDIF error - simple alias with context support."""

    def __init__(
        self,
        message: str,
        *,
        context: dict[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize LDIF error with message and context."""
        super().__init__(message)
        self.context = context or {}
        for key, value in kwargs.items():
            setattr(self, key, value)

    @property
    def code(self) -> str:
        """Get error code - should be overridden by subclasses."""
        return "LDIF_ERROR"


class FlextLDIFParseError(FlextLDIFError):
    """Parse error - simple alias."""

    def __init__(
        self,
        message: str,
        *,
        context: dict[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize parse error with message and context."""
        super().__init__(message, context=context, **kwargs)
        self.message = message
        self.operation = "ldif_parsing"


class FlextLDIFValidationError(FlextLDIFError):
    """Validation error - simple alias."""

    def __init__(
        self,
        message: str,
        *,
        context: dict[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize validation error with message and context."""
        super().__init__(message, context=context, **kwargs)
        self.message = message
        self.operation = "ldif_validation"
        self.validation_details = (
            context.get("validation_details", "ldif_validation")
            if context
            else "ldif_validation"
        )


class FlextLDIFConnectionError(FlextLDIFError):
    """Connection error - simple alias."""


class FlextLDIFFileError(FlextLDIFError):
    """File error - simple alias."""


class FlextLDIFProcessingError(FlextLDIFError):
    """Processing error - simple alias."""

    def __init__(
        self,
        message: str,
        *,
        context: dict[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize processing error with message and context."""
        super().__init__(message, context=context, **kwargs)
        self.message = message
        self.operation = "ldif_processing"

    @property
    def code(self) -> str:
        """Get processing error code."""
        return "LDIF_PROCESSING_ERROR"


class FlextLDIFTimeoutError(FlextLDIFError):
    """Timeout error - simple alias."""

    def __init__(
        self,
        message: str,
        *,
        context: dict[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize timeout error with message and context."""
        super().__init__(message, context=context, **kwargs)
        self.message = message
        self.operation = "ldif_timeout"

    @property
    def code(self) -> str:
        """Get timeout error code."""
        return "LDIF_TIMEOUT_ERROR"


class FlextLDIFAuthenticationError(FlextLDIFError):
    """Authentication error - simple alias."""


# Export unified exception system
__all__ = [
    "FlextLDIFAuthenticationError",
    "FlextLDIFConnectionError",
    "FlextLDIFError",
    "FlextLDIFErrorCodes",
    "FlextLDIFExceptionBuilder",
    "FlextLDIFExceptions",
    "FlextLDIFFileError",
    "FlextLDIFParseError",
    "FlextLDIFProcessingError",
    "FlextLDIFTimeoutError",
    "FlextLDIFValidationError",
]
