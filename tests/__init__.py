"""Tests package for flext-ldif.

Unified test infrastructure providing:
- t: TestsFlextLdifTypes (type definitions and TypeVars)
- c: TestsFlextLdifConstants (test constants organized by domain)
- p: TestsFlextLdifProtocols (test protocol definitions)
- m: TestsFlextLdifModels (test model definitions)
- u: TestsFlextLdifUtilities (test utility functions)
- s: FlextLdifTestsServiceBase (base class for test services with factories)
- tv: FlextTestsValidator (validation helpers)
- tf: FlextTestsFactories (factory helpers)

All test files should import these unified infrastructure components:
    from tests import t, c, p, m, u, s, tv, tf

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from tests.base import FlextLdifTestsServiceBase as s
    from tests.constants import (
        Filters,
        OIDs,
        RfcTestHelpers,
        Syntax,
        TestDeduplicationHelpers,
        TestsFlextLdifConstants,
        TestsFlextLdifConstants as c,
    )
    from tests.models import TestsFlextLdifModels as m
    from tests.protocols import p
    from tests.test_helpers import (
        TestsFlextLdifFixtures as tf,
        TestsFlextLdifMatchers as tm,
        TestsFlextLdifValidators as tv,
    )
    from tests.typings import GenericFieldsDict, TestsFlextLdifTypes as t
    from tests.utilities import TestsFlextLdifUtilities as u

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "Filters": ("tests.constants", "Filters"),
    "GenericFieldsDict": ("tests.typings", "GenericFieldsDict"),
    "OIDs": ("tests.constants", "OIDs"),
    "RfcTestHelpers": ("tests.constants", "RfcTestHelpers"),
    "Syntax": ("tests.constants", "Syntax"),
    "TestDeduplicationHelpers": ("tests.constants", "TestDeduplicationHelpers"),
    "TestsFlextLdifConstants": ("tests.constants", "TestsFlextLdifConstants"),
    "c": ("tests.constants", "TestsFlextLdifConstants"),
    "m": ("tests.models", "TestsFlextLdifModels"),
    "p": ("tests.protocols", "p"),
    "s": ("tests.base", "FlextLdifTestsServiceBase"),
    "t": ("tests.typings", "TestsFlextLdifTypes"),
    "tf": ("tests.test_helpers", "TestsFlextLdifFixtures"),
    "tm": ("tests.test_helpers", "TestsFlextLdifMatchers"),
    "tv": ("tests.test_helpers", "TestsFlextLdifValidators"),
    "u": ("tests.utilities", "TestsFlextLdifUtilities"),
}

__all__ = [
    "Filters",
    "GenericFieldsDict",
    "OIDs",
    "RfcTestHelpers",
    "Syntax",
    "TestDeduplicationHelpers",
    "TestsFlextLdifConstants",
    "c",
    "m",
    "p",
    "s",
    "t",
    "tf",
    "tm",
    "tv",
    "u",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
