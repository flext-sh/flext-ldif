"""Standardized decorators for quirk metadata assignment across all servers."""

from __future__ import annotations

import struct
from collections.abc import Callable, MutableMapping
from datetime import UTC, datetime
from functools import wraps
from typing import TypeIs, TypeVar

from flext_core import FlextLogger, r

from flext_ldif import (
    FlextLdifModelsDomains,
    FlextLdifModelsMetadata,
    FlextLdifShared,
    m,
    t,
)

logger = FlextLogger(__name__)

_TDecoratorArg = TypeVar(
    "_TDecoratorArg",
    t.Ldif.ParseMethodArg,
    t.Ldif.WriteMethodArg,
)
_TDecoratorReturn = TypeVar(
    "_TDecoratorReturn",
    t.Ldif.ParseMethodReturn,
    t.Ldif.WriteMethodReturn,
)


class FlextLdifUtilitiesDecorators:
    """Decorators for LDIF server quirk metadata assignment."""

    @staticmethod
    def _is_metadata_attachable(
        obj: t.NormalizedValue,
    ) -> TypeIs[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
        """Type guard to check if t.NormalizedValue supports metadata attachment."""
        return isinstance(
            obj,
            (
                m.Ldif.Entry,
                m.Ldif.SchemaAttribute,
                m.Ldif.SchemaObjectClass,
                m.Ldif.Acl,
            ),
        )

    @staticmethod
    def _attach_metadata_if_present(
        result_value: t.NormalizedValue | None,
        quirk_type: str,
        server_type: str | None,
    ) -> None:
        """Attach metadata to result value if it has metadata attribute."""
        if (
            result_value is None
            or not FlextLdifUtilitiesDecorators._is_metadata_attachable(result_value)
        ):
            return
        extensions_dict_raw: MutableMapping[str, str | None] = {
            "server_type": server_type,
            "parsed_timestamp": datetime.now(UTC).replace(microsecond=0).isoformat(),
        }
        extensions_dict: t.MutableContainerMapping = {
            key: value
            for key, value in extensions_dict_raw.items()
            if value is not None
        }
        normalized_quirk_type: str | None = (
            FlextLdifShared.normalize_server_type(quirk_type) if quirk_type else None
        )
        metadata = FlextLdifModelsDomains.QuirkMetadata.create_for(
            quirk_type=normalized_quirk_type,
            extensions=FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                extensions_dict,
            ),
        )
        try:
            setattr(result_value, "metadata", metadata)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            logger.debug("Failed to attach metadata: %s", e)

    @staticmethod
    def _get_server_type_from_class(obj: t.NormalizedValue) -> str | None:
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
    def _safe_operation(operation_name: str) -> t.Ldif.ParseMethodDecorator:
        """Generic decorator to wrap methods with standardized error handling."""

        def decorator(
            func: t.Ldif.ParseMethod,
        ) -> t.Ldif.ParseMethod:

            @wraps(func)
            def wrapper(
                self: t.NormalizedValue,
                arg: t.Ldif.ParseMethodArg,
            ) -> t.Ldif.ParseMethodReturn:
                def _parse_error(message: str) -> t.Ldif.ParseMethodReturn:
                    return r[t.Scalar | list[str] | None].fail(message)

                return FlextLdifUtilitiesDecorators._execute_safe_operation(
                    operation_name=operation_name,
                    func=func,
                    self_obj=self,
                    arg=arg,
                    on_error=_parse_error,
                )

            return wrapper

        return decorator

    @staticmethod
    def attach_parse_metadata(
        quirk_type: str,
    ) -> t.Ldif.ParseMethodDecorator:
        """Decorator to automatically attach metadata to parse method results."""

        def decorator(
            func: t.Ldif.ParseMethod,
        ) -> t.Ldif.ParseMethod:
            """Wrapper function for parse methods."""

            @wraps(func)
            def wrapper(
                self: t.NormalizedValue,
                arg: str,
            ) -> t.Ldif.ParseMethodReturn:
                """Call original function and attach metadata to result."""
                result = func(self, arg)
                if result.is_success:
                    unwrapped = result.value
                    if FlextLdifUtilitiesDecorators._is_metadata_attachable(unwrapped):
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

            return wrapper

        return decorator

    @staticmethod
    def attach_write_metadata(
        _quirk_type: str,
    ) -> t.Ldif.WriteMethodDecorator:
        """Decorator to automatically attach metadata to write method results."""

        def decorator(
            func: t.Ldif.WriteMethod,
        ) -> t.Ldif.WriteMethod:

            @wraps(func)
            def wrapper(
                self: t.NormalizedValue,
                arg: t.Ldif.WriteMethodArg,
            ) -> t.Ldif.WriteMethodReturn:
                return func(self, arg)

            return wrapper

        return decorator

    @staticmethod
    def safe_parse(operation_name: str) -> t.Ldif.ParseMethodDecorator:
        """Decorator to wrap parse methods with standardized error handling."""
        return FlextLdifUtilitiesDecorators._safe_operation(operation_name)

    @staticmethod
    def safe_write(operation_name: str) -> t.Ldif.WriteMethodDecorator:
        """Decorator to wrap write methods with standardized error handling."""

        def decorator(
            func: t.Ldif.WriteMethod,
        ) -> t.Ldif.WriteMethod:

            @wraps(func)
            def wrapper(
                self: t.NormalizedValue,
                arg: t.Ldif.WriteMethodArg,
            ) -> t.Ldif.WriteMethodReturn:
                def _write_error(message: str) -> t.Ldif.WriteMethodReturn:
                    return r[t.Scalar | list[str] | None].fail(message)

                return FlextLdifUtilitiesDecorators._execute_safe_operation(
                    operation_name=operation_name,
                    func=func,
                    self_obj=self,
                    arg=arg,
                    on_error=_write_error,
                )

            return wrapper

        return decorator

    @staticmethod
    def _execute_safe_operation(
        operation_name: str,
        func: Callable[[t.NormalizedValue, _TDecoratorArg], _TDecoratorReturn],
        self_obj: t.NormalizedValue,
        arg: _TDecoratorArg,
        on_error: Callable[[str], _TDecoratorReturn],
    ) -> _TDecoratorReturn:
        try:
            return func(self_obj, arg)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            error_msg = f"{operation_name} failed: {e}"
            logger.exception(error_msg, operation_name=operation_name)
            return on_error(error_msg)


__all__ = ["FlextLdifUtilitiesDecorators"]
