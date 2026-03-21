# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Tests for flext_ldif._utilities.oid module."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from .test_oid_utilities import TestFlextLdifUtilitiesOID

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "TestFlextLdifUtilitiesOID": (
        "tests.unit._utilities.oid.test_oid_utilities",
        "TestFlextLdifUtilitiesOID",
    ),
}

__all__ = [
    "TestFlextLdifUtilitiesOID",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
