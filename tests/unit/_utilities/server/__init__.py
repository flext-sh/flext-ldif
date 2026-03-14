# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Tests for flext_ldif._utilities.server module."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from tests.unit._utilities.server.test_server_utilities import (
        OidServer,
        OudServer,
        TestFlextLdifUtilitiesServer,
    )

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "OidServer": ("tests.unit._utilities.server.test_server_utilities", "OidServer"),
    "OudServer": ("tests.unit._utilities.server.test_server_utilities", "OudServer"),
    "TestFlextLdifUtilitiesServer": (
        "tests.unit._utilities.server.test_server_utilities",
        "TestFlextLdifUtilitiesServer",
    ),
}

__all__ = [
    "OidServer",
    "OudServer",
    "TestFlextLdifUtilitiesServer",
]


def __getattr__(name: str) -> t.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
