"""Test support utilities for FLEXT-LDIF testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from ldif_data import LdifSample, LdifTestData
    from real_services import FlextLdifTestFactory
    from test_files import FileManager
    from validators import TestValidators
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FileManager": ("test_files", "FileManager"),
    "FlextLdifTestFactory": ("real_services", "FlextLdifTestFactory"),
    "LdifSample": ("ldif_data", "LdifSample"),
    "LdifTestData": ("ldif_data", "LdifTestData"),
    "TestValidators": ("validators", "TestValidators"),
}
__all__ = [
    "FileManager",
    "FlextLdifTestFactory",
    "LdifSample",
    "LdifTestData",
    "TestValidators",
]


def __getattr__(name: str) -> Any:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
