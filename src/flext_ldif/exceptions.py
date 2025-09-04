"""FLEXT-LDIF Exceptions - Advanced Builder Pattern with Zero Duplication.

Ultra-consolidated exception system using Builder Pattern, Pydantic validation,
and functional composition to eliminate 127+ lines of duplicated code.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum

from flext_core import FlextExceptions
from pydantic import BaseModel, Field


class FlextLDIFErrorCodes(StrEnum):
    """Error codes for LDIF operations with string enum."""

    LDIF_ERROR = "LDIF_ERROR"
    LDIF_VALIDATION_ERROR = "LDIF_VALIDATION_ERROR"
    LDIF_PARSE_ERROR = "LDIF_PARSE_ERROR"
    LDIF_ENTRY_ERROR = "LDIF_ENTRY_ERROR"
    LDIF_CONFIGURATION_ERROR = "LDIF_CONFIGURATION_ERROR"
    LDIF_PROCESSING_ERROR = "LDIF_PROCESSING_ERROR"
    LDIF_CONNECTION_ERROR = "LDIF_CONNECTION_ERROR"
    LDIF_AUTHENTICATION_ERROR = "LDIF_AUTHENTICATION_ERROR"
    LDIF_TIMEOUT_ERROR = "LDIF_TIMEOUT_ERROR"
    LDIF_FILE_ERROR = "LDIF_FILE_ERROR"


class ExceptionSpec(BaseModel):
    """Exception specification model using Pydantic for validation."""

    message: str = Field(min_length=1)
    error_code: FlextLDIFErrorCodes = Field(default=FlextLDIFErrorCodes.LDIF_ERROR)
    context: dict[str, object] = Field(default_factory=dict)
    line_number: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    dn: str | None = Field(default=None, min_length=1)
    attribute_name: str | None = Field(default=None, min_length=1)
    entry_index: int | None = Field(default=None, ge=0)
    validation_rule: str | None = Field(default=None, min_length=1)
    file_path: str | None = Field(default=None, min_length=1)
    operation: str | None = Field(default=None, min_length=1)


class ExceptionBuilder:
    """Fluent builder for LDIF exceptions with method chaining."""

    def __init__(self) -> None:
        self._spec = ExceptionSpec(message="LDIF operation failed")

    def message(self, msg: str) -> ExceptionBuilder:
        """Set exception message."""
        self._spec.message = msg
        return self

    def code(self, code: FlextLDIFErrorCodes) -> ExceptionBuilder:
        """Set error code."""
        self._spec.error_code = code
        return self

    def context(self, ctx: dict[str, object]) -> ExceptionBuilder:
        """Set context dictionary."""
        self._spec.context.update(ctx)
        return self

    def location(
        self, line: int | None = None, column: int | None = None
    ) -> ExceptionBuilder:
        """Set location information."""
        if line is not None:
            self._spec.line_number = line
        if column is not None:
            self._spec.column = column
        return self

    def dn(self, dn: str) -> ExceptionBuilder:
        """Set distinguished name context."""
        self._spec.dn = dn
        return self

    def attribute(self, attr_name: str) -> ExceptionBuilder:
        """Set attribute name context."""
        self._spec.attribute_name = attr_name
        return self

    def entry_index(self, index: int) -> ExceptionBuilder:
        """Set entry index context."""
        self._spec.entry_index = index
        return self

    def validation_rule(self, rule: str) -> ExceptionBuilder:
        """Set validation rule context."""
        self._spec.validation_rule = rule
        return self

    def file_path(self, path: str) -> ExceptionBuilder:
        """Set file path context."""
        self._spec.file_path = path
        return self

    def operation(self, op: str) -> ExceptionBuilder:
        """Set operation context."""
        self._spec.operation = op
        return self

    def build(self) -> FlextExceptions.BaseError:
        """Build the exception with all specifications."""
        # Auto-populate context from spec fields
        context = dict(self._spec.context)

        for field_name in [
            "line_number",
            "column",
            "dn",
            "attribute_name",
            "entry_index",
            "validation_rule",
            "file_path",
            "operation",
        ]:
            value = getattr(self._spec, field_name)
            if value is not None:
                context[field_name] = value

        return FlextExceptions.BaseError(
            message=self._spec.message,
            code=self._spec.error_code.value,
            context=context or None,
        )


class FlextLDIFExceptions:
    """Zero-duplication LDIF exception system using Builder Pattern.

    Eliminates 127+ lines of duplicated code by using functional composition
    and the Builder pattern. All exceptions are created through pre-configured
    builders that eliminate constructor parameter duplication.
    """

    # Base exception types
    Error = FlextExceptions.BaseError
    ValidationError = FlextExceptions.ValidationError

    @staticmethod
    def builder() -> ExceptionBuilder:
        """Create new exception builder."""
        return ExceptionBuilder()

    @staticmethod
    def parse_error(
        message: str = "LDIF parsing failed",
        line: int | None = None,
        column: int | None = None,
    ) -> FlextExceptions.BaseError:
        """Create parse error with location."""
        return (
            ExceptionBuilder()
            .message(message)
            .code(FlextLDIFErrorCodes.LDIF_PARSE_ERROR)
            .location(line, column)
            .build()
        )

    @staticmethod
    def entry_error(
        message: str = "LDIF entry error",
        dn: str | None = None,
        entry_index: int | None = None,
    ) -> FlextExceptions.BaseError:
        """Create entry error with DN and index."""
        builder = (
            ExceptionBuilder()
            .message(message)
            .code(FlextLDIFErrorCodes.LDIF_ENTRY_ERROR)
        )
        if dn:
            builder = builder.dn(dn)
        if entry_index is not None:
            builder = builder.entry_index(entry_index)
        return builder.build()

    @staticmethod
    def validation_error(
        message: str = "LDIF validation failed",
        dn: str | None = None,
        rule: str | None = None,
    ) -> FlextExceptions.BaseError:
        """Create validation error with DN and rule."""
        builder = (
            ExceptionBuilder()
            .message(message)
            .code(FlextLDIFErrorCodes.LDIF_VALIDATION_ERROR)
        )
        if dn:
            builder = builder.dn(dn)
        if rule:
            builder = builder.validation_rule(rule)
        return builder.build()

    @staticmethod
    def connection_error(
        message: str = "LDIF connection failed",
    ) -> FlextExceptions.BaseError:
        """Create connection error."""
        return (
            ExceptionBuilder()
            .message(message)
            .code(FlextLDIFErrorCodes.LDIF_CONNECTION_ERROR)
            .build()
        )

    @staticmethod
    def file_error(
        message: str = "LDIF file operation failed",
        file_path: str | None = None,
        operation: str | None = None,
    ) -> FlextExceptions.BaseError:
        """Create file error with path and operation."""
        builder = (
            ExceptionBuilder()
            .message(message)
            .code(FlextLDIFErrorCodes.LDIF_FILE_ERROR)
        )
        if file_path:
            builder = builder.file_path(file_path)
        if operation:
            builder = builder.operation(operation)
        return builder.build()

    @staticmethod
    def configuration_error(
        message: str = "LDIF configuration error",
    ) -> FlextExceptions.BaseError:
        """Create configuration error."""
        return (
            ExceptionBuilder()
            .message(message)
            .code(FlextLDIFErrorCodes.LDIF_CONFIGURATION_ERROR)
            .build()
        )

    @staticmethod
    def processing_error(
        message: str = "LDIF processing failed", operation: str | None = None
    ) -> FlextExceptions.BaseError:
        """Create processing error with operation."""
        builder = (
            ExceptionBuilder()
            .message(message)
            .code(FlextLDIFErrorCodes.LDIF_PROCESSING_ERROR)
        )
        if operation:
            builder = builder.operation(operation)
        return builder.build()

    @staticmethod
    def authentication_error(
        message: str = "LDIF authentication failed",
    ) -> FlextExceptions.BaseError:
        """Create authentication error."""
        return (
            ExceptionBuilder()
            .message(message)
            .code(FlextLDIFErrorCodes.LDIF_AUTHENTICATION_ERROR)
            .build()
        )

    @staticmethod
    def timeout_error(
        message: str = "LDIF operation timed out", operation: str | None = None
    ) -> FlextExceptions.BaseError:
        """Create timeout error."""
        builder = (
            ExceptionBuilder()
            .message(message)
            .code(FlextLDIFErrorCodes.LDIF_TIMEOUT_ERROR)
        )
        if operation:
            builder = builder.operation(operation)
        return builder.build()

    # Compatibility aliases for existing code
    ParseError = staticmethod(
        lambda msg="LDIF parsing failed", **kwargs: FlextLDIFExceptions.parse_error(
            msg, **kwargs
        )
    )
    EntryError = staticmethod(
        lambda msg="LDIF entry error", **kwargs: FlextLDIFExceptions.entry_error(
            msg, **kwargs
        )
    )
    LdifConnectionError = staticmethod(
        lambda msg="LDIF connection failed": FlextLDIFExceptions.connection_error(msg)
    )
    LdifFileError = staticmethod(
        lambda msg="LDIF file operation failed",
        **kwargs: FlextLDIFExceptions.file_error(msg, **kwargs)
    )
    LdifValidationError = staticmethod(
        lambda msg="LDIF validation failed",
        **kwargs: FlextLDIFExceptions.validation_error(msg, **kwargs)
    )


# Export only the main class
__all__ = ["ExceptionBuilder", "FlextLDIFErrorCodes", "FlextLDIFExceptions"]
