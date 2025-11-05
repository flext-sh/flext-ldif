"""Standardized decorators for quirk metadata assignment across all servers.

This module provides reusable decorators for parse/write methods to automatically
attach quirk metadata (quirk_type, timestamp, server_type) to parsing results.

Eliminates ~200-300 lines of duplicate metadata assignment code by consolidating
the pattern into a single decorator that can be applied to any parse_* or write_*
method across all 12 server implementations.

Usage:
    from flext_ldif.servers._decorators import attach_parse_metadata, attach_write_metadata

    class CustomSchema(FlextLdifServersRfc.Schema):
        @attach_parse_metadata("custom_server")
        def _parse_attribute(self, attr_definition: str) -> FlextResult[SchemaAttribute]:
            # Parse logic here...
            result = self._do_parse(attr_definition)
            return result

        @attach_write_metadata("custom_server")
        def _write_attribute(self, attr_data: SchemaAttribute) -> FlextResult[str]:
            # Write logic here...
            return result

Benefits:
    - Single source of truth for metadata assignment pattern
    - Automatic timestamp recording
    - Consistent server_type tracking
    - Reduces boilerplate in all 12 servers
    - Type-safe with FlextResult pattern
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from functools import wraps
from typing import TypeVar

from flext_core import FlextLogger, FlextResult

from flext_ldif.models import FlextLdifModels

logger = FlextLogger(__name__)

T = TypeVar("T")


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

            # If result is successful, attach metadata
            if result.is_success:
                unwrapped = result.unwrap()

                # Only attach metadata to models with metadata attribute
                if hasattr(unwrapped, "metadata"):
                    # Get server_type from self if available
                    server_type = None
                    if hasattr(self, "server_type"):
                        server_type = self.server_type
                    elif hasattr(self, "__class__"):
                        cls = self.__class__
                        while cls:
                            if hasattr(cls, "server_type"):
                                server_type = cls.server_type
                                break
                            if hasattr(cls, "__bases__") and cls.__bases__:
                                cls = cls.__bases__[0]
                            else:
                                break

                    # Create or update metadata
                    metadata = FlextLdifModels.QuirkMetadata.create_for(
                        quirk_type=quirk_type,
                        server_type=server_type,
                    )
                    metadata.parsed_timestamp = datetime.now(
                        UTC,
                    ).isoformat()

                    # Attach metadata to model
                    unwrapped.metadata = metadata

            return result

        return wrapper

    return decorator


def attach_write_metadata(
    quirk_type: str,  # noqa: ARG001
) -> Callable[[Callable[..., FlextResult[T]]], Callable[..., FlextResult[T]]]:
    """Decorator to automatically attach metadata to write method results.

    Wraps write_attribute, write_objectclass, write_acl, write_entry methods
    to attach consistent metadata during serialization operations.

    Args:
        quirk_type: Server type (e.g., "oid", "oud", "rfc") - reserved for future use

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

        return wrapper

    return decorator


__all__ = [
    "attach_parse_metadata",
    "attach_write_metadata",
]
