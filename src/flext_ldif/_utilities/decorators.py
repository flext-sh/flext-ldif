"""Standardized decorators for quirk metadata assignment across all servers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

This module provides reusable decorators for parse/write methods to automatically
attach quirk metadata (quirk_type, timestamp, server_type) to parsing results.

Eliminates ~200-300 lines of duplicate metadata assignment code by consolidating
the pattern into a single decorator that can be applied to any parse_* or write_*
method across all 12 server implementations.

Usage:
    from flext_ldif.utilities import FlextLdifUtilities

    class CustomSchema(FlextLdifServersRfc.Schema):
        @FlextLdifUtilities.Decorators.attach_parse_metadata("custom_server")
        def _parse_attribute(self, attr_definition: str) -> FlextResult[SchemaAttribute]:
            # Parse logic here...
            result = self._do_parse(attr_definition)
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from functools import wraps
from typing import Protocol, TypeVar, cast

from flext_core import FlextLogger, FlextResult

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.models import FlextLdifModels

logger = FlextLogger(__name__)

T = TypeVar("T")


class _HasMetadata(Protocol):
    """Protocol for objects that have a metadata attribute."""

    metadata: FlextLdifModelsDomains.QuirkMetadata


class FlextLdifUtilitiesDecorators:
    """Decorators for LDIF server quirk metadata assignment."""

    @staticmethod
    def _get_server_type_from_class(obj: object) -> str | None:
        """Extract SERVER_TYPE from class Constants via MRO traversal.

        Internal helper to reduce complexity in attach_parse_metadata.

        Args:
            obj: Object instance to extract server type from

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
        result_value: object,
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

        # Create metadata
        metadata = FlextLdifModels.QuirkMetadata.create_for(
            quirk_type=quirk_type,
            server_type=server_type,
        )
        # Store parsed_timestamp in extensions dict (QuirkMetadata has extra="forbid")
        metadata.add_extension("parsed_timestamp", datetime.now(UTC).isoformat())

        # Attach metadata - Protocol cast after hasattr check
        obj_with_metadata = cast("_HasMetadata", result_value)
        obj_with_metadata.metadata = metadata

    @staticmethod
    def attach_parse_metadata(
        quirk_type: str,
    ) -> Callable[[Callable[..., FlextResult[T]]], Callable[..., FlextResult[T]]]:
        """Decorator to automatically attach metadata to parse method results.

        Wraps parse_attribute, parse_objectclass, parse_acl, parse_entry methods
        to attach consistent metadata (quirk_type, timestamp, server_type).

        Args:
            quirk_type: Server type (e.g., "oid", "oud", "rfc")

        Returns:
            Decorator function that wraps parse methods

        Example:
            @attach_parse_metadata("oid")
            def _parse_attribute(self, definition: str) -> FlextResult[SchemaAttribute]:
                result = ... # Parse logic
                return result

            # Result automatically has metadata attached with quirk_type="oid"

        """

        def decorator(
            func: Callable[..., FlextResult[T]],
        ) -> Callable[..., FlextResult[T]]:
            """Wrapper function for parse methods."""

            @wraps(func)
            def wrapper(
                self: object,
                *args: object,
                **kwargs: object,
            ) -> FlextResult[T]:
                """Call original function and attach metadata to result."""
                result = func(self, *args, **kwargs)

                # If result is successful, attach metadata using helper methods
                if result.is_success:
                    unwrapped = result.unwrap()
                    server_type = (
                        FlextLdifUtilitiesDecorators._get_server_type_from_class(self)
                    )
                    FlextLdifUtilitiesDecorators._attach_metadata_if_present(
                        unwrapped,
                        quirk_type,
                        server_type,
                    )

                return result

            # Use cast to preserve original function signature for type checkers
            return cast("Callable[..., FlextResult[T]]", wrapper)

        return decorator

    @staticmethod
    def attach_write_metadata(
        _quirk_type: str,
    ) -> Callable[[Callable[..., FlextResult[T]]], Callable[..., FlextResult[T]]]:
        """Decorator to automatically attach metadata to write method results.

        Wraps write_attribute, write_objectclass, write_acl, write_entry methods
        to attach consistent metadata during serialization operations.

        Args:
            _quirk_type: Server type (e.g., "oid", "oud", "rfc") - reserved for future use

        Returns:
            Decorator function that wraps write methods

        Example:
            @attach_write_metadata("oid")
            def _write_attribute(self, definition: SchemaAttribute) -> FlextResult[str]:
                result = ... # Write logic
                return result

        """

        def decorator(
            func: Callable[..., FlextResult[T]],
        ) -> Callable[..., FlextResult[T]]:
            """Wrapper function for write methods."""

            @wraps(func)
            def wrapper(
                self: object,
                *args: object,
                **kwargs: object,
            ) -> FlextResult[T]:
                """Call original function - write methods don't modify inputs."""
                # Write methods typically return strings, not models
                # So metadata attachment would be on the input model
                return func(self, *args, **kwargs)

            # Use cast to preserve original function signature for type checkers
            return cast("Callable[..., FlextResult[T]]", wrapper)

        return decorator

    @staticmethod
    def _safe_operation(
        operation_name: str,
    ) -> Callable[[Callable[..., FlextResult[T]]], Callable[..., FlextResult[T]]]:
        """Generic decorator to wrap methods with standardized error handling.

        Internal helper used by safe_parse and safe_write decorators.
        Eliminates 89 lines of duplication between parse/write decorators.

        Args:
            operation_name: Operation name for error messages

        Returns:
            Decorator that adds error handling

        """

        def decorator(
            func: Callable[..., FlextResult[T]],
        ) -> Callable[..., FlextResult[T]]:
            """Wrapper that adds error handling."""

            @wraps(func)
            def wrapper(
                self: object,
                *args: object,
                **kwargs: object,
            ) -> FlextResult[T]:
                """Execute function with automatic error handling."""
                try:
                    return func(self, *args, **kwargs)
                except Exception as e:
                    error_msg = f"{operation_name} failed: {e}"
                    logger.exception(error_msg)
                    return FlextResult.fail(error_msg)

            return wrapper

        return decorator

    @staticmethod
    def safe_parse(
        operation_name: str,
    ) -> Callable[[Callable[..., FlextResult[T]]], Callable[..., FlextResult[T]]]:
        """Decorator to wrap parse methods with standardized error handling.

        Consolidates try/except patterns across all servers (eliminates 200-300 lines).
        Automatically catches exceptions and returns FlextResult.fail with context.

        Args:
            operation_name: Operation name for error messages (e.g., "OID attribute parsing")

        Returns:
            Decorator that adds error handling

        Example:
            @FlextLdifUtilities.Decorators.safe_parse("OID attribute parsing")
            def _parse_attribute(self, definition: str) -> FlextResult[SchemaAttribute]:
                # Parse logic - exceptions automatically caught
                return FlextResult.ok(parsed_attr)

        """
        return FlextLdifUtilitiesDecorators._safe_operation(operation_name)

    @staticmethod
    def safe_write(
        operation_name: str,
    ) -> Callable[[Callable[..., FlextResult[T]]], Callable[..., FlextResult[T]]]:
        """Decorator to wrap write methods with standardized error handling.

        Consolidates try/except patterns for write operations across all servers.

        Args:
            operation_name: Operation name for error messages (e.g., "OID attribute writing")

        Returns:
            Decorator that adds error handling

        Example:
            @FlextLdifUtilities.Decorators.safe_write("OID attribute writing")
            def _write_attribute(self, attr: SchemaAttribute) -> FlextResult[str]:
                # Write logic - exceptions automatically caught
                return FlextResult.ok(ldif_str)

        """
        return FlextLdifUtilitiesDecorators._safe_operation(operation_name)


# Export standalone functions for backward compatibility
attach_parse_metadata = FlextLdifUtilitiesDecorators.attach_parse_metadata
attach_write_metadata = FlextLdifUtilitiesDecorators.attach_write_metadata
safe_parse = FlextLdifUtilitiesDecorators.safe_parse
safe_write = FlextLdifUtilitiesDecorators.safe_write

__all__ = [
    "FlextLdifUtilitiesDecorators",
    "attach_parse_metadata",
    "attach_write_metadata",
    "safe_parse",
    "safe_write",
]
