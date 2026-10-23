"""Base server execute-parameter extraction.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, m, t, u


class FlextLdifServersBaseExecuteParamsMixin:
    """Extract validated execute parameters without registry side effects."""

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
        if c.ContextScope.OPERATION not in kwargs:
            return None
        match kwargs.get(c.ContextScope.OPERATION):
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


__all__: list[str] = ["FlextLdifServersBaseExecuteParamsMixin"]
