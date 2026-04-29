"""LDIF-specific collection/merge/DSL utilities for FLEXT-LDIF."""

from __future__ import annotations

from collections.abc import (
    Callable,
    MutableSequence,
)

from flext_ldif import t


class FlextLdifUtilitiesCollectionLdif:
    """LDIF-specific collection, merge, and DSL methods."""

    @staticmethod
    def find(
        items: t.JsonList,
        *,
        predicate: Callable[..., bool],
    ) -> t.JsonValue | None:
        """Find first item matching predicate."""
        for elem in items:
            if predicate(elem):
                return elem
        return None

    @classmethod
    def normalize_ldif(
        cls,
        value: str | MutableSequence[str] | tuple[str, ...] | set[str] | frozenset[str],
        other: str
        | MutableSequence[str]
        | tuple[str, ...]
        | set[str]
        | frozenset[str]
        | None = None,
        *,
        case: str = "lower",
    ) -> str | MutableSequence[str] | set[str] | bool:
        """Normalize for LDIF comparison (mnemonic: nz)."""

        def normalize_single(v: str) -> str:
            if case == "lower":
                return v.lower()
            if case == "upper":
                return v.upper()
            return v

        if other is not None:
            match (value, other):
                case [str() as value_str, str() as other_str]:
                    return normalize_single(value_str) == normalize_single(
                        other_str,
                    )
                case _:
                    pass
        match value:
            case str() as value_str:
                return normalize_single(value_str)
            case list() | tuple() as seq_value:
                return [normalize_single(v) for v in seq_value]
            case set() | frozenset() as set_value:
                return {normalize_single(v) for v in set_value}
            case _:
                return [normalize_single(v) for v in value]

    nz = normalize_ldif


__all__: list[str] = ["FlextLdifUtilitiesCollectionLdif"]
