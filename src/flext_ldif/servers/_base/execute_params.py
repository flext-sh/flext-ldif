"""Base server execute-parameter extraction and registry registration.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldif import c, m, p, t, u

if TYPE_CHECKING:
    from collections.abc import Callable

    from flext_ldif.servers.base import FlextLdifServersBase


class FlextLdifServersBaseExecuteParamsMixin:
    """Extract validated execute parameters and auto-register server instances."""

    @classmethod
    def _extract_execute_params(
        cls,
        kwargs: t.MutableMappingKV[
            str,
            str | int | bool | t.MutableSequenceOf[m.Ldif.Entry],
        ],
    ) -> tuple[str | None, t.MutableSequenceOf[m.Ldif.Entry] | None, str | None]:
        """Extract type-safe execution parameters from kwargs.

        Returns:
            The resulting ``tuple[str | None, t.MutableSequenceOf[m.Ldif.Entry] | None,
                str | None]``.
        """
        return (
            cls._extract_ldif_text(kwargs),
            cls._extract_entries(kwargs),
            cls._extract_operation(kwargs),
        )

    @staticmethod
    def _register_in_registry(
        server_instance: p.Ldif.SchemaServer | FlextLdifServersBase,
        registry: p.Ldif.ServerRegistry | t.JsonValue,
    ) -> None:
        """Register a server instance in the registry."""
        register_func = _validate_registry(registry)
        _perform_registration(register_func, server_instance)

    @staticmethod
    def _extract_entries(
        kwargs: t.MutableMappingKV[
            str,
            str | int | bool | t.MutableSequenceOf[m.Ldif.Entry],
        ],
    ) -> t.MutableSequenceOf[m.Ldif.Entry] | None:
        """Extract and validate entries parameter.

        Returns:
            The resulting ``t.MutableSequenceOf[m.Ldif.Entry] | None``.

        Raises:
            TypeError: If Expected t.MutableSequenceOf[Entry | None] for entries, got.
        """
        if "entries" not in kwargs:
            return None
        raw = kwargs["entries"]
        if not raw:
            return []
        try:
            entries: t.MutableSequenceOf[m.Ldif.Entry] = u.Ldif.as_entries(raw)
        except c.EXC_VALIDATION_TYPE as exc:
            msg = (
                f"Expected t.MutableSequenceOf[Entry | None] for entries, "
                f"got {type(raw)}"
            )
            raise TypeError(msg) from exc
        else:
            return entries

    @staticmethod
    def _extract_ldif_text(
        kwargs: t.MutableMappingKV[
            str,
            str | int | bool | t.MutableSequenceOf[m.Ldif.Entry],
        ],
    ) -> str | None:
        """Extract and validate ldif_text parameter.

        Returns:
            The resulting ``str | None``.

        Raises:
            TypeError: If Expected str | None for ldif_text, got.
        """
        if "ldif_text" not in kwargs:
            return None
        match kwargs.get("ldif_text"):
            case None:
                return None
            case str() as raw_text:
                return raw_text
            case raw:
                msg = f"Expected str | None for ldif_text, got {type(raw)}"
                raise TypeError(msg)

    @staticmethod
    def _extract_operation(
        kwargs: t.MutableMappingKV[
            str,
            str | int | bool | t.MutableSequenceOf[m.Ldif.Entry],
        ],
    ) -> str | None:
        """Extract and validate operation parameter.

        Returns:
            The resulting ``str | None``.

        Raises:
            TypeError: If Expected 'parse' | 'write' | None for operation, got.
            ValueError: If Expected 'parse' | 'write' | None for operation, got.
        """
        if "operation" not in kwargs:
            return None
        match kwargs.get("operation"):
            case None:
                return None
            case "parse":
                return "parse"
            case "write":
                return "write"
            case str() as raw_operation:
                msg = (
                    f"Expected 'parse' | 'write' | None for operation, "
                    f"got {raw_operation}"
                )
                raise ValueError(msg)
            case raw:
                msg = (
                    f"Expected 'parse' | 'write' | None for operation, got {type(raw)}"
                )
                raise TypeError(msg)


def _validate_registry(
    registry_obj: p.Ldif.ServerRegistry | t.JsonValue,
) -> Callable[[str, p.Ldif.SchemaServer | t.JsonValue], None] | None:
    """Validate registry has a register_server method.

    Returns:
        The resulting ``Callable[[str, p.Ldif.SchemaServer | t.JsonValue],
            None] | None``.
    """
    method = getattr(registry_obj, "register_server", None)
    if method is None or not callable(method):
        return None
    captured = method

    def typed_register(
        server_type: str,
        server: p.Ldif.SchemaServer | t.JsonValue,
    ) -> None:
        _ = captured(server_type, server)

    return typed_register


def _perform_registration(
    register_func: Callable[[str, p.Ldif.SchemaServer | t.JsonValue], None] | None,
    instance: p.Ldif.SchemaServer,
) -> None:
    """Execute registration if the instance exposes the required methods."""
    if register_func is None:
        return
    required_methods = ("parse", "write")
    if all(
        callable(getattr(instance, method, None))
        for method in required_methods
    ):
        register_func("auto", instance)


__all__: list[str] = ["FlextLdifServersBaseExecuteParamsMixin"]
