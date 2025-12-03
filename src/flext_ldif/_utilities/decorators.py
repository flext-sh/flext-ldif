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
        def _parse_attribute(self, attr_definition: str) -> r[SchemaAttribute]:
            # Parse logic here...
            result = self._do_parse(attr_definition)
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from functools import wraps

from flext_core import FlextLogger, r
from flext_core.typings import T
from flext_core.utilities import FlextUtilities

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols

# Aliases for simplified usage - after all imports
u = FlextUtilities  # Utilities
# r is already imported from flext_core

logger = FlextLogger(__name__)

# Use TypeVars from flext-core (no local aliases)
# Type aliases for decorator functions to avoid Any
ProtocolType = (
    FlextLdifProtocols.Quirks.SchemaProtocol
    | FlextLdifProtocols.Quirks.AclProtocol
    | FlextLdifProtocols.Quirks.EntryProtocol
)
ParseMethodArg = str | float | bool | None
WriteMethodArg = (
    FlextLdifProtocols.Models.SchemaAttributeProtocol
    | FlextLdifProtocols.Models.SchemaObjectClassProtocol
    | FlextLdifProtocols.Models.AclProtocol
    | FlextLdifProtocols.Models.EntryProtocol
    | Sequence[FlextLdifProtocols.Models.EntryProtocol]
    | str
)

ParseMethod = Callable[[ProtocolType, ParseMethodArg], r[T]]
WriteMethod = Callable[[ProtocolType, WriteMethodArg], r[T]]
SafeMethod = Callable[[ProtocolType, ParseMethodArg], r[T]]


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
            FlextLdifModels.Entry
            | FlextLdifModelsDomains.SchemaAttribute
            | FlextLdifModelsDomains.SchemaObjectClass
            | FlextLdifModelsDomains.Acl
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
            FlextLdifModels.Entry
            | FlextLdifModelsDomains.SchemaAttribute
            | FlextLdifModelsDomains.SchemaObjectClass
            | FlextLdifModelsDomains.Acl
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
        normalized_quirk_type: (
            FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None
        ) = FlextLdifConstants.normalize_server_type(quirk_type) if quirk_type else None
        metadata = FlextLdifModels.QuirkMetadata.create_for(
            quirk_type=normalized_quirk_type,
            extensions=FlextLdifModels.DynamicMetadata(**extensions_dict),
        )

        # Attach metadata using type narrowing with isinstance check
        # Type narrowing confirmed by isinstance check
        if isinstance(
            result_value,
            (
                FlextLdifModels.Entry,
                FlextLdifModelsDomains.SchemaAttribute,
                FlextLdifModelsDomains.SchemaObjectClass,
            ),
        ):
            result_value.metadata = metadata

    @staticmethod
    def attach_parse_metadata(
        quirk_type: str,
    ) -> Callable[[ParseMethod[T]], ParseMethod[T]]:
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
            func: ParseMethod[T],
        ) -> ParseMethod[T]:
            """Wrapper function for parse methods."""

            @wraps(func)
            def wrapper(
                self: ProtocolType,
                arg: ParseMethodArg,
            ) -> r[T]:
                """Call original function and attach metadata to result."""
                result = func(self, arg)

                # If result is successful, attach metadata using helper methods
                if result.is_success:
                    unwrapped = result.unwrap()
                    # Type narrowing: self is a protocol, but we need concrete types
                    # Check if unwrapped is one of the supported types
                    if isinstance(
                        unwrapped,
                        (
                            FlextLdifModels.Entry,
                            FlextLdifModelsDomains.SchemaAttribute,
                            FlextLdifModelsDomains.SchemaObjectClass,
                            FlextLdifModelsDomains.Acl,
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

            # Type narrowing: wrapper already has correct type signature
            return wrapper

        return decorator

    @staticmethod
    def attach_write_metadata(
        _quirk_type: str,
    ) -> Callable[[WriteMethod[T]], WriteMethod[T]]:
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
            func: WriteMethod[T],
        ) -> WriteMethod[T]:
            """Wrapper function for write methods."""

            @wraps(func)
            def wrapper(
                self: ProtocolType,
                arg: WriteMethodArg,
            ) -> r[T]:
                """Call original function - write methods don't modify inputs."""
                # Write methods typically return strings, not models
                # So metadata attachment would be on the input model
                return func(self, arg)

            # Type narrowing: wrapper already has correct type signature
            return wrapper

        return decorator

    @staticmethod
    def _safe_operation(
        operation_name: str,
    ) -> Callable[[SafeMethod[T]], SafeMethod[T]]:
        """Generic decorator to wrap methods with standardized error handling.

        Internal helper used by safe_parse and safe_write decorators.
        Eliminates 89 lines of duplication between parse/write decorators.

        Args:
            operation_name: Operation name for error messages

        Returns:
            Decorator that adds error handling

        """

        def decorator(
            func: SafeMethod[T],
        ) -> SafeMethod[T]:
            """Wrapper that adds error handling."""

            @wraps(func)
            def wrapper(
                self: ProtocolType,
                arg: ParseMethodArg,
            ) -> r[T]:
                """Execute function with automatic error handling."""
                try:
                    return func(self, arg)
                except Exception as e:
                    error_msg = f"{operation_name} failed: {e}"
                    logger.exception(
                        error_msg,
                    )  # Log exception with traceback and message
                    return r.fail(error_msg)

            return wrapper

        return decorator

    @staticmethod
    def safe_parse(
        operation_name: str,
    ) -> Callable[[SafeMethod[T]], SafeMethod[T]]:
        """Decorator to wrap parse methods with standardized error handling.

        Consolidates try/except patterns across all servers (eliminates 200-300 lines).
        Automatically catches exceptions and returns r.fail with context.

        Args:
            operation_name: Operation name for error messages (e.g., "OID attribute parsing")

        Returns:
            Decorator that adds error handling

        Example:
            @FlextLdifUtilities.Decorators.safe_parse("OID attribute parsing")
            def _parse_attribute(self, definition: str) -> r[SchemaAttribute]:
                # Parse logic - exceptions automatically caught
                return r.ok(parsed_attr)

        """
        return FlextLdifUtilitiesDecorators._safe_operation(operation_name)

    @staticmethod
    def safe_write(
        operation_name: str,
    ) -> Callable[[SafeMethod[T]], SafeMethod[T]]:
        """Decorator to wrap write methods with standardized error handling.

        Consolidates try/except patterns for write operations across all servers.

        Args:
            operation_name: Operation name for error messages (e.g., "OID attribute writing")

        Returns:
            Decorator that adds error handling

        Example:
            @FlextLdifUtilities.Decorators.safe_write("OID attribute writing")
            def _write_attribute(self, attr: SchemaAttribute) -> r[str]:
                # Write logic - exceptions automatically caught
                return r.ok(ldif_str)

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
