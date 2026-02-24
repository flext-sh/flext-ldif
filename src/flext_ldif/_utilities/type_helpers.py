"""Type Helpers - Type utilities to break circular dependencies.

Single class per module: all helpers in FlextLdifTypeHelpers.
"""

from __future__ import annotations

from collections.abc import Mapping as ABCMapping, Sequence as ABCSequence
from typing import TypeGuard


class FlextLdifTypeHelpers:
    """Type guards and helpers for LDIF (single class per module)."""

    @staticmethod
    def is_entry_sequence(obj: object) -> TypeGuard[ABCSequence[object]]:
        """Check if object is a Sequence but not a string, bytes, or dict (for Entry sequences)."""
        return issubclass(obj.__class__, ABCSequence) and not issubclass(
            obj.__class__, (str, bytes, dict)
        )

    @staticmethod
    def is_mapping_type(obj: object) -> TypeGuard[ABCMapping[str, object]]:
        """Check if object is a Mapping but not a string (for dict-like objects)."""
        return issubclass(obj.__class__, ABCMapping) and not issubclass(
            obj.__class__, (str, bytes)
        )

    @staticmethod
    def is_sequence_of_scalars(
        obj: object,
    ) -> TypeGuard[ABCSequence[str | int | float | bool | None]]:
        """Check if object is a Sequence of scalar values (for simple sequences)."""
        if not issubclass(obj.__class__, ABCSequence) or issubclass(
            obj.__class__, (str, bytes, dict)
        ):
            return False
        return all(
            issubclass(item.__class__, (str, int, float, bool, type(None)))
            for item in obj
        )

    @staticmethod
    def is_mapping_of_scalars(
        obj: object,
    ) -> TypeGuard[ABCMapping[str, str | int | float | bool | None]]:
        """Check if object is a Mapping of scalar values (for simple dicts)."""
        if not issubclass(obj.__class__, ABCMapping):
            return False
        return all(
            issubclass(v.__class__, (str, int, float, bool, type(None)))
            for v in obj.values()
        )


__all__ = ["FlextLdifTypeHelpers"]
