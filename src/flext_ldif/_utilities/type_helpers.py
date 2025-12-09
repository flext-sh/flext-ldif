"""Type Helpers - Type utilities to break circular dependencies.

Provides type helpers that can be imported without causing circular dependencies.
"""

from __future__ import annotations

from collections.abc import Mapping as ABCMapping, Sequence as ABCSequence
from typing import TypeGuard

# normalize_server_type moved to constants.py to break circular import
# Import it from there: from flext_ldif.constants import normalize_server_type


def is_entry_sequence(obj: object) -> TypeGuard[ABCSequence[object]]:
    """Check if object is a Sequence but not a string, bytes, or dict (for Entry sequences)."""
    return isinstance(obj, ABCSequence) and not isinstance(obj, (str, bytes, dict))


def is_mapping_type(obj: object) -> TypeGuard[ABCMapping[str, object]]:
    """Check if object is a Mapping but not a string (for dict-like objects)."""
    return isinstance(obj, ABCMapping) and not isinstance(obj, (str, bytes))


def is_sequence_of_scalars(
    obj: object,
) -> TypeGuard[ABCSequence[str | int | float | bool | None]]:
    """Check if object is a Sequence of scalar values (for simple sequences)."""
    if not isinstance(obj, ABCSequence) or isinstance(obj, (str, bytes, dict)):
        return False
    # Check if all items are scalars
    return all(isinstance(item, (str, int, float, bool, type(None))) for item in obj)


def is_mapping_of_scalars(
    obj: object,
) -> TypeGuard[ABCMapping[str, str | int | float | bool | None]]:
    """Check if object is a Mapping of scalar values (for simple dicts)."""
    if not isinstance(obj, ABCMapping):
        return False
    # Check if all values are scalars
    return all(isinstance(v, (str, int, float, bool, type(None))) for v in obj.values())
