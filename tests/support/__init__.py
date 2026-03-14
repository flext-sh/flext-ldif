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

    from tests.support.conftest_factory import FlextLdifTestConftest, FlextTestsDocker
    from tests.support.ldif_data import LdifSample, LdifTestData
    from tests.support.real_services import FlextLdifTestFactory
    from tests.support.test_files import FileManager
    from tests.support.validators import MockMatchers, MockResultHelpers, TestValidators

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FileManager": ("tests.support.test_files", "FileManager"),
    "FlextLdifTestConftest": (
        "tests.support.conftest_factory",
        "FlextLdifTestConftest",
    ),
    "FlextLdifTestFactory": ("tests.support.real_services", "FlextLdifTestFactory"),
    "FlextTestsDocker": ("tests.support.conftest_factory", "FlextTestsDocker"),
    "LdifSample": ("tests.support.ldif_data", "LdifSample"),
    "LdifTestData": ("tests.support.ldif_data", "LdifTestData"),
    "MockMatchers": ("tests.support.validators", "MockMatchers"),
    "MockResultHelpers": ("tests.support.validators", "MockResultHelpers"),
    "TestValidators": ("tests.support.validators", "TestValidators"),
}

__all__ = [
    "FileManager",
    "FlextLdifTestConftest",
    "FlextLdifTestFactory",
    "FlextTestsDocker",
    "LdifSample",
    "LdifTestData",
    "MockMatchers",
    "MockResultHelpers",
    "TestValidators",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
