"""FLEXT LDIF Exceptions - Exception handling using flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult
from flext_ldif.constants import FlextLdifConstants


class FlextLdifExceptions:
    """Unified LDIF exception handling following FLEXT patterns.

    Single responsibility: All LDIF exception creation and management.
    Uses FlextResult for consistent error handling.
    """

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
        """Create parse error with line/column context.

        Args:
            message: Base error message
            **context: Additional context including line_number, column, content_preview

        Returns:
            FlextResult containing enriched error message

        """
        line_number = context.get("line_number") or context.get("line")
        column = context.get("column")
        content_preview = context.get("content_preview") or context.get("content")

        enriched_message = message

        # Handle line number with explicit validation
        if line_number is not None:
            if isinstance(line_number, int) and line_number > 0:
                enriched_message += f" (line {line_number}"
            elif isinstance(line_number, str) and line_number.isdigit():
                enriched_message += f" (line {int(line_number)}"
            else:
                enriched_message += " (line unknown"

            # Handle column with explicit validation
            if column is not None:
                if isinstance(column, int) and column > 0:
                    enriched_message += f", column {column}"
                elif isinstance(column, str) and column.isdigit():
                    enriched_message += f", column {int(column)}"

            enriched_message += ")"

        # Handle content preview with explicit validation
        if content_preview and str(content_preview).strip():
            content_str = str(content_preview)
            preview = (
                content_str[: FlextLdifConstants.CONTENT_PREVIEW_LENGTH]
                if len(content_str) > FlextLdifConstants.CONTENT_PREVIEW_LENGTH
                else content_str
            )
            enriched_message += f" - Content: {preview}"
            if len(content_str) > FlextLdifConstants.CONTENT_PREVIEW_LENGTH:
                enriched_message += "..."

        return FlextResult[None].fail(enriched_message)

    @classmethod
    def processing_error(cls, message: str, **context: object) -> FlextResult[None]:
        """Create processing error with operation context.

        Args:
            message: Base error message
            **context: Additional context including operation, entry_count

        Returns:
            FlextResult containing enriched error message

        """
        operation = context.get("operation")
        entry_count = context.get("entry_count")

        enriched_message = message

        # Handle operation with explicit validation
        if operation and isinstance(operation, str):
            enriched_message += f" (Operation: {operation})"

        # Handle entry count with explicit validation
        if entry_count is not None:
            if isinstance(entry_count, int) and entry_count >= 0:
                enriched_message += f" (Entries: {entry_count})"
            elif isinstance(entry_count, str) and entry_count.isdigit():
                enriched_message += f" (Entries: {int(entry_count)})"

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
            # Use dict type check for mappings - no collections.abc import needed
            if isinstance(entry_data, dict):
                attributes = list(entry_data.keys())
                if attributes:
                    if len(attributes) > FlextLdifConstants.MAX_ATTRIBUTES_DISPLAY:
                        shown_attrs = attributes[
                            : FlextLdifConstants.MAX_ATTRIBUTES_DISPLAY
                        ]
                        remaining_count = (
                            len(attributes) - FlextLdifConstants.MAX_ATTRIBUTES_DISPLAY
                        )
                        enriched_message += f" (Attributes: {', '.join(shown_attrs)} +{remaining_count} more)"
                    else:
                        enriched_message += f" (Attributes: {', '.join(attributes)})"
            else:
                # Use explicit type checking - no fallback mechanisms
                enriched_message += " (Entry data: non-mapping type)"
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
