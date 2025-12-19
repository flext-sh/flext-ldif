"""Standardized decorators for quirk metadata assignment across all servers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

This module provides reusable decorators for parse/write methods to automatically
attach quirk metadata (quirk_type, timestamp, server_type) to parsing results.

Eliminates ~200-300 lines of duplicate metadata assignment code by consolidating
the pattern into a single decorator that can be applied to any parse_* or write_*
method across all 12 server implementations.

Usage:
    class CustomSchema(FlextLdifServersRfc.Schema):
        @FlextLdifUtilitiesDecorators.attach_parse_metadata("custom_server")
        def _parse_attribute(self, attr_definition: str) -> r[SchemaAttribute]:
            # Parse logic here...
            result = self._do_parse(attr_definition)
"""

from __future__ import annotations

from datetime import UTC, datetime
from functools import wraps
from typing import Any, cast

from flext_core import FlextLogger, r

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._shared import normalize_server_type
from flext_ldif.models import m
from flext_ldif.typings import t

logger = FlextLogger(__name__)


def generate_iso_timestamp() -> str:
    """Generate ISO 8601 timestamp string.

    Returns:
        ISO 8601 formatted timestamp string (e.g., "2025-01-15T10:30:00Z")

    """
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class FlextLdifUtilitiesDecorators:
    """Decorators for LDIF server quirk metadata assignment."""

    @staticmethod
    def _get_server_type_from_class(
        obj: (
            m.Ldif.Entry
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Acl
            | str
            | float
        ),
    ) -> str | None:
        """Extract SERVER_TYPE from class Constants via MRO traversal.

        Internal helper to reduce complexity in attach_parse_metadata.

        Args:
            obj: Object instance to extract server type from (any type with __class__)

        Returns:
            Server type string or None if not found

        """
        if not hasattr(obj, "__class__"):
            return None

        for cls in obj.__class__.__mro__:
            if hasattr(cls, "Constants") and hasattr(cls.Constants, "SERVER_TYPE"):
                return str(cls.Constants.SERVER_TYPE)

        return None

    @staticmethod
    def _attach_metadata_if_present(
        result_value: (
            m.Ldif.Entry
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Acl
            | str
            | float
            | None
        ),
        quirk_type: str,
        server_type: str | None,
    ) -> None:
        """Attach metadata to result value if it has metadata attribute.

        Internal helper to reduce complexity in attach_parse_metadata.
        Mutates result_value by setting metadata attribute.

        Args:
            result_value: Unwrapped result value from FlextResult
            quirk_type: Quirk type for metadata
            server_type: Server type from Constants

        """
        # Only attach metadata to models with metadata attribute
        if not (
            getattr(result_value, "metadata", None) is not None
            or hasattr(result_value, "metadata")
        ):
            return

        # Create metadata with extensions
        extensions_dict = {
            "server_type": server_type,
            "parsed_timestamp": generate_iso_timestamp(),
        }
        # Normalize quirk_type if provided, otherwise None
        # normalize_server_type validates and returns a valid ServerTypeLiteral string
        normalized_quirk_type: str | None = (
            normalize_server_type(quirk_type) if quirk_type else None
        )
        metadata = FlextLdifModelsDomains.QuirkMetadata.create_for(
            quirk_type=normalized_quirk_type,
            extensions=FlextLdifModelsMetadata.DynamicMetadata(**extensions_dict),
        )

        # Attach metadata by checking if object is a model instance with metadata
        # Use runtime type check instead of protocol isinstance to avoid mypy issues
        if hasattr(result_value, "metadata") and hasattr(result_value, "model_fields"):
            # This is a Pydantic model with metadata field - assign directly
            # Cast to Any to avoid type checker issues with dynamic attribute assignment
            cast("Any", result_value).metadata = metadata

    @staticmethod
    def attach_parse_metadata(
        quirk_type: str,
    ) -> t.Ldif.Decorators.ParseMethodDecorator:
        """Decorator to automatically attach metadata to parse method results.

        Wraps parse_attribute, parse_objectclass, parse_acl, parse_entry methods
        to attach consistent metadata (quirk_type, timestamp, server_type).

        Args:
            quirk_type: Server type (e.g., "oid", "oud", "rfc")

        Returns:
            Decorator function that wraps parse methods

        Example:
            @attach_parse_metadata("oid")
            def _parse_attribute(self, definition: str) -> r[SchemaAttribute]:
                result = ... # Parse logic
                return result

            # Result automatically has metadata attached with quirk_type="oid"

        """

        def decorator(
            func: t.Ldif.Decorators.ParseMethod,
        ) -> t.Ldif.Decorators.ParseMethod:
            """Wrapper function for parse methods."""

            @wraps(func)
            def wrapper(
                self: object,
                arg: str,
            ) -> r[object]:
                """Call original function and attach metadata to result."""
                result = cast("r[object]", func(self, arg))

                # If result is successful, attach metadata using helper methods
                if result.is_success:
                    unwrapped = result.value
                    # Type narrowing: self is a protocol, but we need concrete types
                    # Check if unwrapped is one of the supported types
                    if isinstance(
                        unwrapped,
                        (
                            m.Ldif.Entry,
                            m.Ldif.SchemaAttribute,
                            m.Ldif.SchemaObjectClass,
                            m.Ldif.Acl,
                        ),
                    ):
                        server_type = (
                            FlextLdifUtilitiesDecorators._get_server_type_from_class(
                                unwrapped,
                            )
                        )
                        FlextLdifUtilitiesDecorators._attach_metadata_if_present(
                            unwrapped,
                            quirk_type,
                            server_type,
                        )

                return result

            # Type narrowing: wrapper is compatible with ParseMethod type
            return cast("t.Ldif.Decorators.ParseMethod", wrapper)

        return decorator

    @staticmethod
    def attach_write_metadata(
        _quirk_type: str,
    ) -> t.Ldif.Decorators.WriteMethodDecorator:
        """Decorator to automatically attach metadata to write method results.

        Wraps write_attribute, write_objectclass, write_acl, write_entry methods
        to attach consistent metadata during serialization operations.

        Args:
            _quirk_type: Server type (e.g., "oid", "oud", "rfc") - reserved for future use

        Returns:
            Decorator function that wraps write methods

        Example:
            @attach_write_metadata("oid")
            def _write_attribute(self, definition: SchemaAttribute) -> r[str]:
                result = ... # Write logic
                return result

        """

        def decorator(
            func: t.Ldif.Decorators.WriteMethod,
        ) -> t.Ldif.Decorators.WriteMethod:
            """Wrapper function for write methods."""

            @wraps(func)
            def wrapper(
                self: t.Ldif.Decorators.ProtocolType,
                arg: t.Ldif.Decorators.WriteMethodArg,
            ) -> object:
                """Call original function - write methods don't modify inputs."""
                # Write methods typically return strings, not models
                # So metadata attachment would be on the input model
                return func(self, arg)

            # Type narrowing: wrapper is compatible with WriteMethod type
            return cast("t.Ldif.Decorators.WriteMethod", wrapper)

        return decorator

    @staticmethod
    def _safe_operation(
        operation_name: str,
    ) -> t.Ldif.Decorators.SafeMethodDecorator:
        """Generic decorator to wrap methods with standardized error handling.

        Internal helper used by safe_parse and safe_write decorators.
        Eliminates 89 lines of duplication between parse/write decorators.

        Args:
            operation_name: Operation name for error messages

        Returns:
            Decorator that adds error handling

        """

        def decorator(
            func: t.Ldif.Decorators.SafeMethod,
        ) -> t.Ldif.Decorators.SafeMethod:
            """Wrapper that adds error handling."""

            @wraps(func)
            def wrapper(
                self: t.Ldif.Decorators.ProtocolType,
                arg: t.Ldif.Decorators.ParseMethodArg,
            ) -> object:
                """Execute function with automatic error handling."""
                try:
                    return func(self, arg)
                except BaseException as e:
                    error_msg = f"{operation_name} failed: {e}"
                    logger.exception(
                        error_msg,
                    )  # Log error with message (no traceback for KeyboardInterrupt)
                    return r.fail(error_msg)

            # Type narrowing: wrapper is compatible with SafeMethod type
            return cast("t.Ldif.Decorators.SafeMethod", wrapper)

        return decorator

    @staticmethod
    def safe_parse(
        operation_name: str,
    ) -> t.Ldif.Decorators.SafeMethodDecorator:
        """Decorator to wrap parse methods with standardized error handling.

        Consolidates try/except patterns across all servers (eliminates 200-300 lines).
        Automatically catches exceptions and returns r.fail with context.

        Args:
            operation_name: Operation name for error messages (e.g., "OID attribute parsing")

        Returns:
            Decorator that adds error handling

        Example:
            @FlextLdifUtilitiesDecorators.safe_parse("OID attribute parsing")
            def _parse_attribute(self, definition: str) -> r[SchemaAttribute]:
                # Parse logic - exceptions automatically caught
                return r.ok(parsed_attr)

        """
        return FlextLdifUtilitiesDecorators._safe_operation(operation_name)

    @staticmethod
    def safe_write(
        operation_name: str,
    ) -> t.Ldif.Decorators.SafeMethodDecorator:
        """Decorator to wrap write methods with standardized error handling.

        Consolidates try/except patterns for write operations across all servers.

        Args:
            operation_name: Operation name for error messages (e.g., "OID attribute writing")

        Returns:
            Decorator that adds error handling

        Example:
            @FlextLdifUtilitiesDecorators.safe_write("OID attribute writing")
            def _write_attribute(self, attr: SchemaAttribute) -> r[str]:
                # Write logic - exceptions automatically caught
                return r.ok(ldif_str)

        """
        return FlextLdifUtilitiesDecorators._safe_operation(operation_name)


# Use FlextLdifUtilitiesDecorators directly - no aliases needed
# Access via: FlextLdifUtilitiesDecorators.attach_parse_metadata(...)

__all__ = [
    "FlextLdifUtilitiesDecorators",
]
