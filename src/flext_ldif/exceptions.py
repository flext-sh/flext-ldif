"""FLEXT LDIF Exceptions - Minimal compatibility layer using flext-core directly.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult

# Constants for magic numbers (ZERO TOLERANCE - no magic values)
_CONTENT_PREVIEW_LENGTH = 50
_DN_PREVIEW_LENGTH = 80
_ATTRIBUTE_TRUNCATION_THRESHOLD = 3
_MAX_ATTRIBUTES_DISPLAY = 5


class FlextLDIFExceptions:
    """Unified LDIF exception handling following FLEXT patterns.

    Single responsibility: All LDIF exception creation and management.
    Eliminates all legacy compatibility layers and aliases.
    """

    class _ErrorTypes:
        """Nested class for error type constants."""

        PARSE = "ldif_parse"
        VALIDATION = "ldif_validation"
        PROCESSING = "ldif_processing"
        FILE = "ldif_file"
        CONFIGURATION = "ldif_configuration"
        CONNECTION = "ldif_connection"
        TIMEOUT = "ldif_timeout"
        AUTHENTICATION = "ldif_authentication"
        GENERIC = "ldif_error"

    # Exception classes for backward compatibility
    class ValidationError(Exception):
        """ValidationError for test compatibility."""

    @classmethod
    def validation_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create validation error with context."""
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

        return FlextResult[None].fail(enriched_message)

    @classmethod
    def parse_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create parse error with line/column context."""
        line_number = context.get("line_number") or context.get("line")
        column = context.get("column")
        content_preview = context.get("content_preview") or context.get("content")

        enriched_message = message
        if line_number and isinstance(line_number, int):
            enriched_message += f" (line {line_number}"
            if column and isinstance(column, int):
                enriched_message += f", column {column}"
            enriched_message += ")"
        if content_preview and isinstance(content_preview, str) and content_preview.strip():
            preview = (
                content_preview[:_CONTENT_PREVIEW_LENGTH]
                if len(content_preview) > _CONTENT_PREVIEW_LENGTH
                else content_preview
            )
            enriched_message += f" - Content: {preview}"
            if len(content_preview) > _CONTENT_PREVIEW_LENGTH:
                enriched_message += "..."

        return FlextResult[None].fail(enriched_message)

    @classmethod
    def parse_error_alias(cls, message: str, **context: object) -> FlextResult[None]:
        """Create parse error alias for compatibility."""
        return cls.parse_error(message, **context)

    @classmethod
    def processing_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create processing error with operation context."""
        operation = context.get("operation")
        entry_count = context.get("entry_count")

        enriched_message = message
        if operation and isinstance(operation, str):
            enriched_message += f" (Operation: {operation})"
        if entry_count and isinstance(entry_count, int):
            enriched_message += f" (Entries: {entry_count})"

        return FlextResult[None].fail(enriched_message)

    @classmethod
    def file_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create file error with path context."""
        file_path = context.get("file_path")

        enriched_message = message
        if file_path and isinstance(file_path, str):
            enriched_message += f" (File: {file_path})"

        return FlextResult[None].fail(enriched_message)

    @classmethod
    def configuration_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create configuration error with config key context."""
        config_key = context.get("config_key")

        enriched_message = message
        if config_key and isinstance(config_key, str):
            enriched_message += f" (Config: {config_key})"

        return FlextResult[None].fail(enriched_message)

    @classmethod
    def connection_error(cls, message: str) -> FlextResult[None]:
        """Create connection error."""
        return FlextResult[None].fail(f"LDIF Connection Error: {message}")

    @classmethod
    def timeout_error(cls, message: str) -> FlextResult[None]:
        """Create timeout error."""
        return FlextResult[None].fail(f"LDIF Timeout Error: {message}")

    @classmethod
    def authentication_error(cls, message: str) -> FlextResult[None]:
        """Create authentication error."""
        return FlextResult[None].fail(f"LDIF Authentication Error: {message}")

    @classmethod
    def error(cls, message: str) -> FlextResult[None]:
        """Create generic LDIF error."""
        return FlextResult[None].fail(f"LDIF Error: {message}")

    @classmethod
    def entry_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create entry error with DN and attribute context."""
        dn = context.get("dn") or context.get("entry_dn")
        attribute_name = context.get("attribute_name")
        entry_data = context.get("entry_data")

        enriched_message = message
        if dn and isinstance(dn, str):
            enriched_message += f" (DN: {dn})"
        if entry_data and isinstance(entry_data, dict):
            attributes = list(entry_data.keys())
            if attributes:
                if len(attributes) > _MAX_ATTRIBUTES_DISPLAY:
                    shown_attrs = attributes[:_MAX_ATTRIBUTES_DISPLAY]
                    remaining_count = len(attributes) - _MAX_ATTRIBUTES_DISPLAY
                    enriched_message += f" (Attributes: {', '.join(shown_attrs)} +{remaining_count} more)"
                else:
                    enriched_message += f" (Attributes: {', '.join(attributes)})"
        elif attribute_name and isinstance(attribute_name, str):
            enriched_message += f" (Attribute: {attribute_name})"

        return FlextResult[None].fail(enriched_message)

    @classmethod
    def create(cls, message: str, error_type: str | None = None) -> FlextResult[None]:
        """Create error with specific type for backward compatibility."""
        if error_type == "ValidationError":
            return cls.validation_error(message)
        return cls.error(message)


# Convenience exception classes for examples and tests compatibility
class FlextLDIFError(Exception):
    """Generic LDIF error for examples compatibility."""


class FlextLDIFParseError(Exception):
    """LDIF parse error for examples compatibility."""


class FlextLDIFValidationError(Exception):
    """LDIF validation error for examples compatibility."""


__all__ = [
    "FlextLDIFError",
    "FlextLDIFExceptions",
    "FlextLDIFParseError",
    "FlextLDIFValidationError",
]
