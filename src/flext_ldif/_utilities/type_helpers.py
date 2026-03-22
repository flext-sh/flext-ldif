"""Type Helpers - Type utilities to break circular dependencies.

Single class per module: all helpers in FlextLdifTypeHelpers.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TypeIs

from flext_core import u

from flext_ldif import m, t


class FlextLdifTypeHelpers:
    """Type guards and helpers for LDIF (single class per module)."""

    @staticmethod
    def is_entry_sequence(
        obj: t.NormalizedValue,
    ) -> TypeIs[Sequence[m.Ldif.Entry]]:
        """Check if t.NormalizedValue is a Sequence but not a string, bytes, or dict (for Entry sequences)."""
        return isinstance(obj, Sequence) and (
            not isinstance(obj, str | bytes) and not u.is_dict_like(obj)
        )

    @staticmethod
    def is_mapping_of_scalars(
        obj: t.NormalizedValue,
    ) -> TypeIs[Mapping[str, t.Scalar | None]]:
        """Check if t.NormalizedValue is a Mapping of scalar values (for simple dicts)."""
        if not isinstance(obj, Mapping):
            return False
        return all(isinstance(v, t.Primitives | None) for v in obj.values())

    @staticmethod
    def is_mapping_type(
        obj: t.NormalizedValue,
    ) -> TypeIs[Mapping[str, t.NormalizedValue]]:
        """Check if t.NormalizedValue is a Mapping but not a string (for dict-like objects)."""
        return isinstance(obj, Mapping) and (not isinstance(obj, str | bytes))

    @staticmethod
    def is_sequence_of_scalars(
        obj: t.NormalizedValue,
    ) -> TypeIs[Sequence[t.Scalar | None]]:
        """Check if t.NormalizedValue is a Sequence of scalar values (for simple sequences)."""
        if (
            not isinstance(obj, Sequence)
            or isinstance(obj, str | bytes)
            or u.is_dict_like(obj)
        ):
            return False
        return all(isinstance(item, t.Primitives | None) for item in obj)


__all__ = ["FlextLdifTypeHelpers"]
