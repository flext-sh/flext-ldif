"""Standardized decorators for quirk metadata assignment across all servers."""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from functools import wraps
from typing import TypeGuard

from flext_core import FlextLogger, FlextResult

from flext_ldif import FlextLdifShared, m, t
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata

logger = FlextLogger(__name__)


def _has_metadata_attribute(obj: t.ContainerValue) -> TypeGuard[t.ContainerValue]:
    """Type guard to check if object has metadata attribute."""
    return hasattr(obj, "metadata")


class FlextLdifUtilitiesDecorators:
    """Decorators for LDIF server quirk metadata assignment."""

    @staticmethod
    def _attach_metadata_if_present(
        result_value: t.ContainerValue | None, quirk_type: str, server_type: str | None
    ) -> None:
        """Attach metadata to result value if it has metadata attribute."""
        if result_value is None or not _has_metadata_attribute(result_value):
            return
        extensions_dict = {
            "server_type": server_type,
            "parsed_timestamp": datetime.now(UTC).replace(microsecond=0).isoformat(),
        }
        normalized_quirk_type: str | None = (
            FlextLdifShared.normalize_server_type(quirk_type) if quirk_type else None
        )
        metadata = FlextLdifModelsDomains.QuirkMetadata.create_for(
            quirk_type=normalized_quirk_type,
            extensions=FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                extensions_dict
            ),
        )
        try:
            result_value.metadata = metadata
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            logger.debug("Failed to attach metadata", error=str(e))

    @staticmethod
    def _get_server_type_from_class(obj: t.ContainerValue) -> str | None:
        """Extract SERVER_TYPE from class Constants via MRO traversal."""
        if not getattr(obj, "__class__", None) is not None:
            return None
        for cls in obj.__class__.__mro__:
            constants_obj = getattr(cls, "Constants", None)
            if (
                constants_obj is not None
                and getattr(constants_obj, "SERVER_TYPE", None) is not None
            ):
                return str(constants_obj.SERVER_TYPE)
        return None

    @staticmethod
    def _safe_operation(operation_name: str) -> t.Ldif.Decorators.ParseMethodDecorator:
        """Generic decorator to wrap methods with standardized error handling."""

        def decorator(
            func: t.Ldif.Decorators.ParseMethod,
        ) -> t.Ldif.Decorators.ParseMethod:

            @wraps(func)
            def wrapper(
                self: t.ContainerValue, arg: t.Ldif.Decorators.ParseMethodArg
            ) -> t.Ldif.Decorators.ParseMethodReturn:
                try:
                    return func(self, arg)
                except (
                    ValueError,
                    KeyError,
                    AttributeError,
                    UnicodeDecodeError,
                    struct.error,
                ) as e:
                    error_msg = f"{operation_name} failed: {e}"
                    logger.exception(error_msg, operation_name=operation_name)
                    return FlextResult.fail(error_msg)

            return wrapper

        return decorator

    @staticmethod
    def attach_parse_metadata(
        quirk_type: str,
    ) -> t.Ldif.Decorators.ParseMethodDecorator:
        """Decorator to automatically attach metadata to parse method results."""

        def decorator(
            func: t.Ldif.Decorators.ParseMethod,
        ) -> t.Ldif.Decorators.ParseMethod:
            """Wrapper function for parse methods."""

            @wraps(func)
            def wrapper(
                self: t.ContainerValue, arg: str
            ) -> t.Ldif.Decorators.ParseMethodReturn:
                """Call original function and attach metadata to result."""
                result = func(self, arg)
                if result.is_success:
                    unwrapped = result.value
                    if issubclass(
                        unwrapped.__class__,
                        (
                            m.Ldif.Entry,
                            m.Ldif.SchemaAttribute,
                            m.Ldif.SchemaObjectClass,
                            m.Ldif.Acl,
                        ),
                    ):
                        server_type = (
                            FlextLdifUtilitiesDecorators._get_server_type_from_class(
                                unwrapped
                            )
                        )
                        FlextLdifUtilitiesDecorators._attach_metadata_if_present(
                            unwrapped, quirk_type, server_type
                        )
                return result

            return wrapper

        return decorator

    @staticmethod
    def attach_write_metadata(
        _quirk_type: str,
    ) -> t.Ldif.Decorators.WriteMethodDecorator:
        """Decorator to automatically attach metadata to write method results."""

        def decorator(
            func: t.Ldif.Decorators.WriteMethod,
        ) -> t.Ldif.Decorators.WriteMethod:

            @wraps(func)
            def wrapper(
                self: t.ContainerValue, arg: t.Ldif.Decorators.WriteMethodArg
            ) -> t.Ldif.Decorators.WriteMethodReturn:
                return func(self, arg)

            return wrapper

        return decorator

    @staticmethod
    def safe_parse(operation_name: str) -> t.Ldif.Decorators.ParseMethodDecorator:
        """Decorator to wrap parse methods with standardized error handling."""
        return FlextLdifUtilitiesDecorators._safe_operation(operation_name)

    @staticmethod
    def safe_write(operation_name: str) -> t.Ldif.Decorators.WriteMethodDecorator:
        """Decorator to wrap write methods with standardized error handling."""

        def decorator(
            func: t.Ldif.Decorators.WriteMethod,
        ) -> t.Ldif.Decorators.WriteMethod:

            @wraps(func)
            def wrapper(
                self: t.ContainerValue, arg: t.Ldif.Decorators.WriteMethodArg
            ) -> t.Ldif.Decorators.WriteMethodReturn:
                try:
                    return func(self, arg)
                except (
                    ValueError,
                    KeyError,
                    AttributeError,
                    UnicodeDecodeError,
                    struct.error,
                ) as e:
                    error_msg = f"{operation_name} failed: {e}"
                    logger.exception(error_msg, operation_name=operation_name)
                    return FlextResult.fail(error_msg)

            return wrapper

        return decorator


__all__ = ["FlextLdifUtilitiesDecorators"]
