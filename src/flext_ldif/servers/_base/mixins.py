"""Base server mixins for LDIF server implementations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldif import c, p, r, t, u

if TYPE_CHECKING:
    from collections.abc import Callable


class FlextLdifServerMethodsMixin:
    """Common server methods shared by schema, ACL, and entry servers."""

    @staticmethod
    def parse_operation_kwarg(kwargs: t.JsonMapping) -> p.Result[str]:
        """Validate the raw ``operation`` kwarg as a string.

        Args:
            kwargs: Keyword mapping carrying the operation value.

        Returns:
            Result carrying the operation string, or a failure.

        """
        try:
            operation_raw = u.str_adapter().validate_python(kwargs.get("operation"))
        except c.ValidationError as exc:
            return r[str].fail(str(exc), exception=exc)
        return r[str].ok(operation_raw)

    @staticmethod
    def project_processor_fields[T](
        fields: t.MappingKV[str, T],
        processor_keys: frozenset[str],
        *,
        force_dispatch: bool = False,
    ) -> t.JsonDict | None:
        """Validate fields outside the processor key set for builder dispatch.

        Non-processor field values are coerced through the JSON-value adapter;
        the caller is responsible for supplying JSON-compatible values.

        Args:
            fields: Fields passed to the callable processor.
            processor_keys: Keys the local processor consumes itself.
            force_dispatch: Whether the builder path is forced.

        Returns:
            Validated non-processor fields, or None when the local processor
            branch should run.

        """
        if not (force_dispatch or any(key not in processor_keys for key in fields)):
            return None
        return {
            key: u.json_value_adapter().validate_python(value)
            for key, value in fields.items()
            if key not in processor_keys
        }

    @staticmethod
    def resolve_parent_server_from_instance(
        instance: FlextLdifServerMethodsMixin,
    ) -> p.Ldif.ServerServer | None:
        """Resolve the nested parent server of the given server instance.

        Args:
            instance: Server instance to probe for a parent.

        Returns:
            The parent server bundle, or None when absent or top-level.

        """
        parent: p.Ldif.ServerServer | None = getattr(
            instance,
            "parent_server",
            None,
        )
        if parent is not None and getattr(parent, "parent_server", None) is not None:
            return parent
        return None

    @staticmethod
    def resolve_priority_from_parent(parent: p.Ldif.ServerServer | None) -> int:
        """Resolve priority from the parent server Constants class.

        Args:
            parent: Parent server bundle, or None.

        Returns:
            The declared priority, or the default 100.

        """
        if parent is None:
            return 100
        constants_attr = getattr(parent, "Constants", None)
        if constants_attr is None:
            return 100
        priority_raw = getattr(constants_attr, "PRIORITY", 100)
        if isinstance(priority_raw, int):
            return priority_raw
        return 100

    @staticmethod
    def resolve_server_type_from_utilities(server_class: type) -> c.Ldif.ServerTypes:
        """Infer the server type from the utilities namespace.

        Args:
            server_class: Server class to resolve the type for.

        Returns:
            The resolved server type.

        """
        resolved: c.Ldif.ServerTypes = u.Ldif.resolve_parent_server_type(server_class)
        return resolved

    def _get_parent_server_safe(self) -> p.Ldif.ServerServer | None:
        """Return the effective parent server of this instance.

        Returns:
            The parent server bundle, or None when absent or top-level.

        """
        return FlextLdifServerMethodsMixin.resolve_parent_server_from_instance(self)

    def _get_priority(self) -> int:
        """Return this server's priority from the parent Constants class.

        Returns:
            The declared priority, or the default 100.

        """
        return FlextLdifServerMethodsMixin.resolve_priority_from_parent(
            self._get_parent_server_safe(),
        )

    def _get_server_type(self) -> c.Ldif.ServerTypes:
        """Resolve the server type for the current server class.

        Returns:
            The resolved server type.

        """
        return FlextLdifServerMethodsMixin.resolve_server_type_from_utilities(
            type(self)
        )

    @staticmethod
    def _narrow_operation(operation: t.JsonValue | None) -> str | None:
        """Restrict the operation value to a string or None.

        Args:
            operation: Raw operation value.

        Returns:
            The operation string, or None for any other value.

        """
        return operation if isinstance(operation, str) else None

    @classmethod
    def builder_fields_or_none[T](
        cls,
        fields: t.MappingKV[str, T],
        processor_keys: frozenset[str],
        server: p.Ldif.ServerRegistry | None,
        settings: p.Ldif.Settings | None,
    ) -> t.JsonDict | None:
        """Return builder dispatch fields or None to skip dispatch."""
        return cls.project_processor_fields(
            fields,
            processor_keys,
            force_dispatch=server is not None or settings is not None,
        )

    @classmethod
    def dispatch_builder[T, V](
        cls,
        builder: Callable[..., T],
        fields: t.MappingKV[str, V],
        processor_keys: frozenset[str],
        server: p.Ldif.ServerRegistry | None,
        settings: p.Ldif.Settings | None,
    ) -> T | None:
        """Clone through ``builder`` when builder fields or bindings are present.

        Args:
            builder: Builder callable that reconstructs the processor.
            fields: Fields passed to the callable processor.
            processor_keys: Keys the local processor consumes itself.
            server: Optional server registry binding.
            settings: Optional settings binding.

        Returns:
            The built processor, or None when the local processor branch
            should run.

        """
        builder_fields = cls.builder_fields_or_none(
            fields,
            processor_keys,
            server,
            settings,
        )
        if builder_fields is None:
            return None
        return builder(server=server, settings=settings, **builder_fields)


__all__: list[str] = ["FlextLdifServerMethodsMixin"]
