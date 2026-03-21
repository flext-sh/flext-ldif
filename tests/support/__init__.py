# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Test support utilities for FLEXT-LDIF testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FileManager": ("tests.support.test_files", "FileManager"),
    "FlextLdifTestConftest": (
        "tests.support.conftest_factory",
        "FlextLdifTestConftest",
    ),
    "FlextLdifTestFactory": ("tests.support.real_services", "FlextLdifTestFactory"),
    "LdifSample": ("tests.support.ldif_data", "LdifSample"),
    "LdifTestData": ("tests.support.ldif_data", "LdifTestData"),
    "MockFlextUtilitiesResultHelpers": (
        "tests.support.validators",
        "MockFlextUtilitiesResultHelpers",
    ),
    "MockMatchers": ("tests.support.validators", "MockMatchers"),
    "TestValidators": ("tests.support.validators", "TestValidators"),
    "tk": ("tests.support.conftest_factory", "tk"),
}

__all__ = [
    "FileManager",
    "FlextLdifTestConftest",
    "FlextLdifTestFactory",
    "LdifSample",
    "LdifTestData",
    "MockFlextUtilitiesResultHelpers",
    "MockMatchers",
    "TestValidators",
    "tk",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
