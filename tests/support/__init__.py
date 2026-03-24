# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Test support utilities for FLEXT-LDIF testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes

    from tests.support.conftest_factory import FlextLdifTestConftest, tk
    from tests.support.ldif_data import LdifSample, LdifTestData
    from tests.support.real_services import FlextLdifTestServiceFactory
    from tests.support.test_files import FileManager
    from tests.support.validators import (
        MockFlextUtilitiesResultHelpers,
        MockMatchers,
        TestValidators,
    )

_LAZY_IMPORTS: Mapping[str, tuple[str, str]] = {
    "FileManager": ("tests.support.test_files", "FileManager"),
    "FlextLdifTestConftest": (
        "tests.support.conftest_factory",
        "FlextLdifTestConftest",
    ),
    "FlextLdifTestServiceFactory": (
        "tests.support.real_services",
        "FlextLdifTestServiceFactory",
    ),
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
    "FlextLdifTestServiceFactory",
    "LdifSample",
    "LdifTestData",
    "MockFlextUtilitiesResultHelpers",
    "MockMatchers",
    "TestValidators",
    "tk",
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
