"""FLEXT LDIF Exceptions - Exception handling using flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from flext_core import FlextResult

# Constants for magic numbers (ZERO TOLERANCE - no magic values)
_CONTENT_PREVIEW_LENGTH = 50
_DN_PREVIEW_LENGTH = 80
_ATTRIBUTE_TRUNCATION_THRESHOLD = 3
_MAX_ATTRIBUTES_DISPLAY = 5


class FlextLdifExceptions:
    """Unified LDIF exception handling following FLEXT patterns.

    Single responsibility: All LDIF exception creation and management.
    Uses FlextResult for consistent error handling.
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

    @classmethod
    def validation_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create validation error with context."""
        dn = context.get("entry_dn") or context.get("dn")
        attribute_name = context.get("attribute_name")
        validation_rule = context.get("validation_rule")

        enriched_message = message
        # Use str() conversion only for string values to maintain expected behavior
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
        # Use duck typing instead of isinstance checks
        if line_number is not None:
            try:
                line_num = (
                    int(line_number) if isinstance(line_number, (int, str)) else 0
                )
                enriched_message += f" (line {line_num}"
                if column is not None:
                    try:
                        col_num = int(column) if isinstance(column, (int, str)) else 0
                        enriched_message += f", column {col_num}"
                    except (ValueError, TypeError):
                        pass
                enriched_message += ")"
            except (ValueError, TypeError):
                pass

        if content_preview and str(content_preview).strip():
            content_str = str(content_preview)
            preview = (
                content_str[:_CONTENT_PREVIEW_LENGTH]
                if len(content_str) > _CONTENT_PREVIEW_LENGTH
                else content_str
            )
            enriched_message += f" - Content: {preview}"
            if len(content_str) > _CONTENT_PREVIEW_LENGTH:
                enriched_message += "..."

        return FlextResult[None].fail(enriched_message)

    @classmethod
    def processing_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create processing error with operation context."""
        operation = context.get("operation")
        entry_count = context.get("entry_count")

        enriched_message = message
        # Use str() conversion only for string values to maintain expected behavior
        if operation and isinstance(operation, str):
            enriched_message += f" (Operation: {operation})"
        if entry_count is not None:
            try:
                count = int(entry_count) if isinstance(entry_count, (int, str)) else 0
                enriched_message += f" (Entries: {count})"
            except (ValueError, TypeError):
                pass

        return FlextResult[None].fail(enriched_message)

    @classmethod
    def file_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create file error with path context."""
        file_path = context.get("file_path")

        enriched_message = message
        # Use str() conversion instead of isinstance check
        if file_path:
            enriched_message += f" (File: {file_path!s})"

        return FlextResult[None].fail(enriched_message)

    @classmethod
    def configuration_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create configuration error with config key context."""
        config_key = context.get("config_key")

        enriched_message = message
        # Use str() conversion instead of isinstance check
        if config_key:
            enriched_message += f" (Config: {config_key!s})"

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
        # Use str() conversion instead of isinstance check
        if dn:
            enriched_message += f" (DN: {dn!s})"
        if entry_data:
            # Prefer explicit Mapping check for static typing safety
            if isinstance(entry_data, Mapping):
                attributes = list(entry_data.keys())
                if attributes:
                    if len(attributes) > _MAX_ATTRIBUTES_DISPLAY:
                        shown_attrs = attributes[:_MAX_ATTRIBUTES_DISPLAY]
                        remaining_count = len(attributes) - _MAX_ATTRIBUTES_DISPLAY
                        enriched_message += f" (Attributes: {', '.join(shown_attrs)} +{remaining_count} more)"
                    else:
                        enriched_message += f" (Attributes: {', '.join(attributes)})"
            else:
                # Fallback: try duck-typing but swallow attribute errors
                try:
                    if hasattr(entry_data, "keys") and callable(
                        getattr(entry_data, "keys")
                    ):
                        # Cast to dict-like type after validation for type safety
                        dict_like_data = cast("dict[str, object]", entry_data)
                        attributes = list(dict_like_data.keys())
                        if attributes:
                            if len(attributes) > _MAX_ATTRIBUTES_DISPLAY:
                                shown_attrs = attributes[:_MAX_ATTRIBUTES_DISPLAY]
                                remaining_count = (
                                    len(attributes) - _MAX_ATTRIBUTES_DISPLAY
                                )
                                enriched_message += f" (Attributes: {', '.join(shown_attrs)} +{remaining_count} more)"
                            else:
                                enriched_message += (
                                    f" (Attributes: {', '.join(attributes)})"
                                )
                except AttributeError:
                    # Not a mapping and no keys callable — ignore
                    pass
        elif attribute_name:
            enriched_message += f" (Attribute: {attribute_name!s})"

        return FlextResult[None].fail(enriched_message)

    @classmethod
    def create(cls, message: str, error_type: str | None = None) -> FlextResult[None]:
        """Create error with specific type."""
        if error_type == "ValidationError":
            return cls.validation_error(message)
        return cls.error(message)


__all__ = [
    "FlextLdifExceptions",
]
