# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""LDIF test helpers package - DEPRECATED.

DEPRECATED: Use unified test infrastructure from tests/ root instead.

All test helpers have been consolidated into:
- tests/base.py - FlextLdifTestsServiceBase (unified base class)
- tests/__init__.py - unified imports (t, c, p, m, u, s, tm, tv, tt, tf)
- tests/test_helpers.py - enhanced test helpers (tv, tt, tf, tm)
- tests/conftest.py - pytest fixtures

Old helpers have been renamed to .bak:
- constants.py.bak
- models.py.bak
- protocols.py.bak
- typings.py.bak
- utilities.py.bak

Use these imports instead:
    from tests import t, c, p, m, u, s, tm, tv, tt, tf
    from tests.base import s
    from tests.test_helpers import tm, tv, tt, tf

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes

    from tests.helpers import example_refactoring

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "example_refactoring": ["tests.helpers.example_refactoring", ""],
}

__all__ = [
    "example_refactoring",
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
