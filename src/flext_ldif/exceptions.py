"""LDIF Exception Hierarchy - Modern Pydantic v2 Patterns.

This module provides LDIF-specific exceptions using modern patterns from flext-core.
All exceptions follow the FlextErrorMixin pattern with keyword-only arguments and
modern Python 3.13 type aliases for comprehensive error handling in LDIF operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum

from flext_core import FlextError


class FlextLdifErrorCodes(Enum):
    """Error codes for LDIF domain operations."""

    LDIF_ERROR = "LDIF_ERROR"
    LDIF_VALIDATION_ERROR = "LDIF_VALIDATION_ERROR"
    LDIF_PARSE_ERROR = "LDIF_PARSE_ERROR"
    LDIF_ENTRY_ERROR = "LDIF_ENTRY_ERROR"
    LDIF_CONFIGURATION_ERROR = "LDIF_CONFIGURATION_ERROR"
    LDIF_PROCESSING_ERROR = "LDIF_PROCESSING_ERROR"
    LDIF_CONNECTION_ERROR = "LDIF_CONNECTION_ERROR"
    LDIF_AUTHENTICATION_ERROR = "LDIF_AUTHENTICATION_ERROR"
    LDIF_TIMEOUT_ERROR = "LDIF_TIMEOUT_ERROR"


# Base LDIF exception hierarchy using FlextError pattern
class FlextLdifError(FlextError):
    """Base LDIF error."""

    def __init__(
        self,
        message: str = "LDIF operation failed",
        *,
        error_code: str | None = None,
        context: Mapping[str, object] | None = None,
        cause: Exception | None = None,
    ) -> None:
        """Initialize LDIF error with proper defaults."""
        super().__init__(
            message,
            error_code=error_code or FlextLdifErrorCodes.LDIF_ERROR.value,
            context=dict(context) if context else None,
            cause=cause,
        )


class FlextLdifValidationError(FlextLdifError):
    """LDIF validation error."""

    def __init__(
        self,
        message: str = "LDIF validation failed",
        *,
        error_code: str | None = None,
        context: Mapping[str, object] | None = None,
        cause: Exception | None = None,
    ) -> None:
        """Initialize LDIF validation error."""
        super().__init__(
            message,
            error_code=error_code or FlextLdifErrorCodes.LDIF_VALIDATION_ERROR.value,
            context=dict(context) if context else None,
            cause=cause,
        )


class FlextLdifParseError(FlextLdifError):
    """LDIF parsing error."""

    def __init__(
        self,
        message: str = "LDIF parsing failed",
        *,
        error_code: str | None = None,
        context: Mapping[str, object] | None = None,
        cause: Exception | None = None,
    ) -> None:
        """Initialize LDIF parse error."""
        super().__init__(
            message,
            error_code=error_code or FlextLdifErrorCodes.LDIF_PARSE_ERROR.value,
            context=dict(context) if context else None,
            cause=cause,
        )


class FlextLdifEntryError(FlextLdifValidationError):
    """LDIF entry processing error."""

    def __init__(
        self,
        message: str = "LDIF entry processing failed",
        *,
        error_code: str | None = None,
        context: Mapping[str, object] | None = None,
        cause: Exception | None = None,
    ) -> None:
        """Initialize LDIF entry error."""
        super().__init__(
            message,
            error_code=error_code or FlextLdifErrorCodes.LDIF_ENTRY_ERROR.value,
            context=dict(context) if context else None,
            cause=cause,
        )


class FlextLdifConfigurationError(FlextLdifError):
    """LDIF configuration error."""

    def __init__(
        self,
        message: str = "LDIF configuration failed",
        *,
        error_code: str | None = None,
        context: Mapping[str, object] | None = None,
        cause: Exception | None = None,
    ) -> None:
        """Initialize LDIF configuration error."""
        super().__init__(
            message,
            error_code=error_code or FlextLdifErrorCodes.LDIF_CONFIGURATION_ERROR.value,
            context=dict(context) if context else None,
            cause=cause,
        )


class FlextLdifProcessingError(FlextLdifError):
    """LDIF processing error."""

    def __init__(
        self,
        message: str = "LDIF processing failed",
        *,
        error_code: str | None = None,
        context: Mapping[str, object] | None = None,
        cause: Exception | None = None,
    ) -> None:
        """Initialize LDIF processing error."""
        super().__init__(
            message,
            error_code=error_code or FlextLdifErrorCodes.LDIF_PROCESSING_ERROR.value,
            context=dict(context) if context else None,
            cause=cause,
        )


class FlextLdifConnectionError(FlextLdifError):
    """LDIF connection error."""

    def __init__(
        self,
        message: str = "LDIF connection failed",
        *,
        error_code: str | None = None,
        context: Mapping[str, object] | None = None,
        cause: Exception | None = None,
    ) -> None:
        """Initialize LDIF connection error."""
        super().__init__(
            message,
            error_code=error_code or FlextLdifErrorCodes.LDIF_CONNECTION_ERROR.value,
            context=dict(context) if context else None,
            cause=cause,
        )


class FlextLdifAuthenticationError(FlextLdifError):
    """LDIF authentication error."""

    def __init__(
        self,
        message: str = "LDIF authentication failed",
        *,
        error_code: str | None = None,
        context: Mapping[str, object] | None = None,
        cause: Exception | None = None,
    ) -> None:
        """Initialize LDIF authentication error."""
        super().__init__(
            message,
            error_code=error_code
            or FlextLdifErrorCodes.LDIF_AUTHENTICATION_ERROR.value,
            context=dict(context) if context else None,
            cause=cause,
        )


class FlextLdifTimeoutError(FlextLdifError):
    """LDIF timeout error."""

    def __init__(
        self,
        message: str = "LDIF operation timed out",
        *,
        error_code: str | None = None,
        context: Mapping[str, object] | None = None,
        cause: Exception | None = None,
    ) -> None:
        """Initialize LDIF timeout error."""
        super().__init__(
            message,
            error_code=error_code or FlextLdifErrorCodes.LDIF_TIMEOUT_ERROR.value,
            context=dict(context) if context else None,
            cause=cause,
        )


# Domain-specific exceptions for LDIF business logic
# Using modern FlextErrorMixin pattern with context support


class FlextLdifFileError(FlextLdifError):
    """LDIF file operation errors with file context."""

    def __init__(
        self,
        message: str,
        *,
        file_path: str | None = None,
        line_number: int | None = None,
        operation: str | None = None,
        encoding: str | None = None,
        code: FlextLdifErrorCodes | None = FlextLdifErrorCodes.LDIF_ERROR,
        context: Mapping[str, object] | None = None,
    ) -> None:
        """Initialize LDIF file error with file context."""
        context_dict: dict[str, object] = dict(context) if context else {}
        if file_path is not None:
            context_dict["file_path"] = file_path
        if line_number is not None:
            context_dict["line_number"] = line_number
        if operation is not None:
            context_dict["operation"] = operation
        if encoding is not None:
            context_dict["encoding"] = encoding

        super().__init__(
            message,
            error_code=code.value if code else "UNKNOWN_ERROR",
            context=context_dict,
        )


class FlextLdifEntryValidationError(FlextLdifEntryError):
    """LDIF entry validation errors with entry context."""

    def __init__(
        self,
        message: str,
        *,
        dn: str | None = None,
        attribute_name: str | None = None,
        attribute_value: str | None = None,
        entry_index: int | None = None,
        validation_rule: str | None = None,
        code: FlextLdifErrorCodes | None = FlextLdifErrorCodes.LDIF_ENTRY_ERROR,
        context: Mapping[str, object] | None = None,
    ) -> None:
        """Initialize LDIF entry validation error with entry context."""
        context_dict: dict[str, object] = dict(context) if context else {}
        if dn is not None:
            context_dict["dn"] = dn
        if attribute_name is not None:
            context_dict["attribute_name"] = attribute_name
        if attribute_value is not None:
            # Truncate long attribute values for safety
            max_value_length = 100
            truncated_value = (
                attribute_value[:max_value_length] + "..."
                if len(attribute_value) > max_value_length
                else attribute_value
            )
            context_dict["attribute_value"] = truncated_value
        if entry_index is not None:
            context_dict["entry_index"] = entry_index
        if validation_rule is not None:
            context_dict["validation_rule"] = validation_rule

        super().__init__(
            message,
            error_code=code.value if code else "UNKNOWN_ERROR",
            context=context_dict,
        )


__all__: list[str] = [
    "FlextLdifAuthenticationError",
    "FlextLdifConfigurationError",
    "FlextLdifConnectionError",
    "FlextLdifEntryError",
    "FlextLdifEntryValidationError",
    "FlextLdifError",
    "FlextLdifErrorCodes",
    "FlextLdifFileError",
    "FlextLdifParseError",
    "FlextLdifProcessingError",
    "FlextLdifTimeoutError",
    "FlextLdifValidationError",
]
