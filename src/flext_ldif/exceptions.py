"""FLEXT LDIF Exceptions - Exception handling using flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextExceptions, FlextResult
from flext_ldif.constants import FlextLdifConstants


class FlextLdifExceptions:
    """LDIF exceptions using FlextExceptions - eliminates duplication while providing domain-specific context."""

    # Import universal exceptions from flext-core (single source of truth)

    # =========================================================================
    # DIRECT ALIASES TO FlextExceptions - Consistent with flext-ldap pattern
    # =========================================================================

    # Base exception types from FlextExceptions
    Error = FlextExceptions.BaseError
    ValidationError = FlextExceptions.ValidationError
    ConfigurationError = FlextExceptions.ConfigurationError
    ProcessingError = FlextExceptions.ProcessingError
    ConnectionError = FlextExceptions.ConnectionError
    TimeoutError = FlextExceptions.TimeoutError
    AuthenticationError = FlextExceptions.AuthenticationError
    TypeError = FlextExceptions.TypeError

    # LDIF-specific exceptions extending FlextExceptions patterns
    ParseError = FlextExceptions.ProcessingError  # LDIF parsing is processing
    FileError = FlextExceptions.OperationError  # File operations
    EntryError = FlextExceptions.ValidationError  # Entry validation

    # =========================================================================
    # FLEXT RESULT INTEGRATION - Combining exceptions with FlextResult pattern
    # =========================================================================

    @classmethod
    def validation_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create validation error with context that returns FlextResult.

        Returns:
            FlextResult[None]: Failure result with enriched error message

        """
        # Enrich message with LDIF-specific context
        dn = context.get("entry_dn") or context.get("dn")
        attribute_name = context.get("attribute_name")
        validation_rule = context.get("validation_rule")

        enriched_message = message
        if dn and isinstance(dn, str):
            enriched_message += f" (DN: {dn})"
        if attribute_name and isinstance(attribute_name, str):
            enriched_message += f" (Attribute: {attribute_name})"
        if validation_rule and isinstance(validation_rule, str):
            enriched_message += f" (Rule: {validation_rule})"

        # Use flext-core exception with LDIF domain prefix
        error_code = f"LDIF_{FlextExceptions.ErrorCodes.VALIDATION_ERROR}"
        return FlextResult[None].fail(enriched_message, error_code=error_code)

    @classmethod
    def parse_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create parse error with line/column context.

        Returns:
            FlextResult[None]: Failure result with enriched error message

        """
        line_number = context.get("line_number") or context.get("line")
        column = context.get("column")
        content_preview = context.get("content_preview") or context.get("content")

        enriched_message = message

        # Add line/column information
        if line_number is not None:
            if isinstance(line_number, int) and line_number > 0:
                enriched_message += f" (line {line_number}"
            elif isinstance(line_number, str) and line_number.isdigit():
                enriched_message += f" (line {int(line_number)}"
            else:
                enriched_message += " (line unknown"

            if column is not None:
                if isinstance(column, int) and column > 0:
                    enriched_message += f", column {column}"
                elif isinstance(column, str) and column.isdigit():
                    enriched_message += f", column {int(column)}"

            enriched_message += ")"

        # Add content preview
        if content_preview and str(content_preview).strip():
            content_str = str(content_preview)
            preview = (
                content_str[: FlextLdifConstants.Formatting.CONTENT_PREVIEW_LENGTH]
                if len(content_str)
                > FlextLdifConstants.Formatting.CONTENT_PREVIEW_LENGTH
                else content_str
            )
            enriched_message += f" - Content: {preview}"
            if len(content_str) > FlextLdifConstants.Formatting.CONTENT_PREVIEW_LENGTH:
                enriched_message += "..."

        error_code = f"LDIF_{FlextExceptions.ErrorCodes.PROCESSING_ERROR}"
        return FlextResult[None].fail(enriched_message, error_code=error_code)

    @classmethod
    def processing_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create processing error with operation context.

        Returns:
            FlextResult[None]: Failure result with enriched error message

        """
        operation = context.get("operation")
        entry_count = context.get("entry_count")

        enriched_message = message

        if operation and isinstance(operation, str):
            enriched_message += f" (Operation: {operation})"

        if entry_count is not None:
            if isinstance(entry_count, int) and entry_count >= 0:
                enriched_message += f" (Entries: {entry_count})"
            elif isinstance(entry_count, str) and entry_count.isdigit():
                enriched_message += f" (Entries: {int(entry_count)})"

        error_code = f"LDIF_{FlextExceptions.ErrorCodes.PROCESSING_ERROR}"
        return FlextResult[None].fail(enriched_message, error_code=error_code)

    @classmethod
    def file_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create file error with path context.

        Returns:
            FlextResult[None]: Failure result with enriched error message

        """
        file_path = context.get("file_path")

        enriched_message = message
        if file_path:
            enriched_message += f" (File: {file_path!s})"

        error_code = f"LDIF_{FlextExceptions.ErrorCodes.OPERATION_ERROR}"
        return FlextResult[None].fail(enriched_message, error_code=error_code)

    @classmethod
    def configuration_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create configuration error with config key context.

        Returns:
            FlextResult[None]: Failure result with enriched error message

        """
        config_key = context.get("config_key")

        enriched_message = message
        if config_key:
            enriched_message += f" (Config: {config_key!s})"

        error_code = f"LDIF_{FlextExceptions.ErrorCodes.CONFIGURATION_ERROR}"
        return FlextResult[None].fail(enriched_message, error_code=error_code)

    @classmethod
    def connection_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create connection error.

        Returns:
            FlextResult[None]: Failure result with enriched error message

        """
        # Use context for enriching connection error details
        host = context.get("host")
        port = context.get("port")

        enriched_message = f"LDIF Connection Error: {message}"
        if host:
            enriched_message += f" (Host: {host})"
        if port:
            enriched_message += f" (Port: {port})"

        error_code = f"LDIF_{FlextExceptions.ErrorCodes.CONNECTION_ERROR}"
        return FlextResult[None].fail(enriched_message, error_code=error_code)

    @classmethod
    def timeout_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create timeout error.

        Returns:
            FlextResult[None]: Failure result with enriched error message

        """
        # Use context for enriching timeout error details
        operation = context.get("operation")
        timeout_seconds = context.get("timeout_seconds")

        enriched_message = f"LDIF Timeout Error: {message}"
        if operation:
            enriched_message += f" (Operation: {operation})"
        if timeout_seconds:
            enriched_message += f" (Timeout: {timeout_seconds}s)"

        error_code = f"LDIF_{FlextExceptions.ErrorCodes.TIMEOUT_ERROR}"
        return FlextResult[None].fail(enriched_message, error_code=error_code)

    @classmethod
    def authentication_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create authentication error.

        Returns:
            FlextResult[None]: Failure result with enriched error message

        """
        # Use context for enriching authentication error details
        username = context.get("username")
        auth_method = context.get("auth_method")

        enriched_message = f"LDIF Authentication Error: {message}"
        if username:
            enriched_message += f" (User: {username})"
        if auth_method:
            enriched_message += f" (Method: {auth_method})"

        error_code = f"LDIF_{FlextExceptions.ErrorCodes.AUTHENTICATION_ERROR}"
        return FlextResult[None].fail(enriched_message, error_code=error_code)

    @classmethod
    def error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create generic LDIF error.

        Returns:
            FlextResult[None]: Failure result with enriched error message

        """
        # Use context for enriching generic error details
        error_type = context.get("error_type")
        component = context.get("component")

        enriched_message = f"LDIF Error: {message}"
        if error_type:
            enriched_message += f" (Type: {error_type})"
        if component:
            enriched_message += f" (Component: {component})"

        error_code = f"LDIF_{FlextExceptions.ErrorCodes.GENERIC_ERROR}"
        return FlextResult[None].fail(enriched_message, error_code=error_code)

    @classmethod
    def entry_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create entry error with DN and attribute context.

        Returns:
            FlextResult[None]: Failure result with enriched error message

        """
        dn = context.get("dn") or context.get("entry_dn")
        attribute_name = context.get("attribute_name")
        entry_data = context.get("entry_data")

        enriched_message = message
        if dn:
            enriched_message += f" (DN: {dn!s})"

        if entry_data:
            if isinstance(entry_data, dict):
                attributes: list[str] = list(entry_data.keys())
                if attributes:
                    if (
                        len(attributes)
                        > FlextLdifConstants.Formatting.MAX_ATTRIBUTES_DISPLAY
                    ):
                        shown_attrs: list[str] = attributes[
                            : FlextLdifConstants.Formatting.MAX_ATTRIBUTES_DISPLAY
                        ]
                        remaining_count = (
                            len(attributes)
                            - FlextLdifConstants.Formatting.MAX_ATTRIBUTES_DISPLAY
                        )
                        enriched_message += f" (Attributes: {', '.join(shown_attrs)} +{remaining_count} more)"
                    else:
                        enriched_message += f" (Attributes: {', '.join(attributes)})"
            else:
                enriched_message += " (Entry data: non-mapping type)"
        elif attribute_name:
            enriched_message += f" (Attribute: {attribute_name!s})"

        error_code = f"LDIF_{FlextExceptions.ErrorCodes.VALIDATION_ERROR}"
        return FlextResult[None].fail(enriched_message, error_code=error_code)

    @classmethod
    def create(
        cls, message: str, error_type: str | None = None, **context: object
    ) -> FlextResult[None]:
        """Create error with specific type.

        Returns:
            FlextResult[None]: Failure result with enriched error message

        """
        if error_type == "ValidationError":
            return cls.validation_error(message, **context)
        if error_type == "ParseError":
            return cls.parse_error(message, **context)
        if error_type == "ProcessingError":
            return cls.processing_error(message, **context)
        if error_type == "FileError":
            return cls.file_error(message, **context)
        if error_type == "ConfigurationError":
            return cls.configuration_error(message, **context)
        if error_type == "ConnectionError":
            return cls.connection_error(message, **context)
        if error_type == "TimeoutError":
            return cls.timeout_error(message, **context)
        if error_type == "AuthenticationError":
            return cls.authentication_error(message, **context)
        return cls.error(message, **context)


__all__ = [
    "FlextLdifExceptions",
]
