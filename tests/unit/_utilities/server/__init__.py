# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests for flext_ldif._utilities.server module."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes
    from tests.unit._utilities.server import test_server_utilities
    from tests.unit._utilities.server.test_server_utilities import (
        OidServer,
        OudServer,
        TestFlextLdifUtilitiesServer,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "OidServer": ["tests.unit._utilities.server.test_server_utilities", "OidServer"],
    "OudServer": ["tests.unit._utilities.server.test_server_utilities", "OudServer"],
    "TestFlextLdifUtilitiesServer": [
        "tests.unit._utilities.server.test_server_utilities",
        "TestFlextLdifUtilitiesServer",
    ],
    "test_server_utilities": ["tests.unit._utilities.server.test_server_utilities", ""],
}

__all__ = [
    "OidServer",
    "OudServer",
    "TestFlextLdifUtilitiesServer",
    "test_server_utilities",
]


_LAZY_CACHE: MutableMapping[str, FlextTypes.ModuleExport] = {}


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562).

    A local cache ``_LAZY_CACHE`` persists resolved objects across repeated
    accesses during process lifetime.

    Args:
        name: Attribute name requested by dir()/import.

    Returns:
        Lazy-loaded module export type.

    Raises:
        AttributeError: If attribute not registered.

    """
    if name in _LAZY_CACHE:
        return _LAZY_CACHE[name]

    value = lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)
    _LAZY_CACHE[name] = value
    return value


def __dir__() -> Sequence[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
