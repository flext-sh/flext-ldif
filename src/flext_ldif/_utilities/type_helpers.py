"""Type Helpers - Type utilities to break circular dependencies.

Single class per module: all helpers in FlextLdifTypeHelpers.
"""

from __future__ import annotations

from collections.abc import Mapping as ABCMapping, Sequence as ABCSequence
from typing import TypeGuard

from flext_ldif import m, t


class FlextLdifTypeHelpers:
    """Type guards and helpers for LDIF (single class per module)."""

    @staticmethod
    def is_entry_sequence(
        obj: t.GeneralValueType,
    ) -> TypeGuard[ABCSequence[m.Ldif.Entry]]:
        """Check if object is a Sequence but not a string, bytes, or dict (for Entry sequences)."""
        return isinstance(obj, ABCSequence) and not isinstance(obj, str | bytes | dict)

    @staticmethod
    def is_mapping_type(
        obj: t.GeneralValueType,
    ) -> TypeGuard[ABCMapping[str, t.ConfigMapValue]]:
        """Check if object is a Mapping but not a string (for dict-like objects)."""
        return isinstance(obj, ABCMapping) and not isinstance(obj, str | bytes)

    @staticmethod
    def is_sequence_of_scalars(
        obj: t.GeneralValueType,
    ) -> TypeGuard[ABCSequence[str | int | float | bool | None]]:
        """Check if object is a Sequence of scalar values (for simple sequences)."""
        if not isinstance(obj, ABCSequence) or isinstance(obj, str | bytes | dict):
            return False
        return all(isinstance(item, str | int | float | bool | None) for item in obj)

    @staticmethod
    def is_mapping_of_scalars(
        obj: t.GeneralValueType,
    ) -> TypeGuard[ABCMapping[str, str | int | float | bool | None]]:
        """Check if object is a Mapping of scalar values (for simple dicts)."""
        if not isinstance(obj, ABCMapping):
            return False
        return all(isinstance(v, str | int | float | bool | None) for v in obj.values())


__all__ = ["FlextLdifTypeHelpers"]
