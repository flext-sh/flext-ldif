# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Utilities package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from .test_utilities import TestsTestFlextLdifServiceAPIs
    from .test_utilities_comprehensive import TestFlextLdifUtilitiesComprehensive
    from .test_utilities_constants import (
        GetValidValuesType,
        IsValidTestType,
        TestsTestFlextLdifConstants,
        ValidateManyType,
    )
    from .test_utilities_core import (
        TestAclParser,
        TestAttributeFixer,
        TestDnObjectClassMethods,
        TestLdifParser,
        TestObjectClassUtilities,
        TestServerTypes,
        TestsFlextLdifDnOperationsPure,
    )

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "GetValidValuesType": (
        "tests.unit.utilities.test_utilities_constants",
        "GetValidValuesType",
    ),
    "IsValidTestType": (
        "tests.unit.utilities.test_utilities_constants",
        "IsValidTestType",
    ),
    "TestAclParser": ("tests.unit.utilities.test_utilities_core", "TestAclParser"),
    "TestAttributeFixer": (
        "tests.unit.utilities.test_utilities_core",
        "TestAttributeFixer",
    ),
    "TestDnObjectClassMethods": (
        "tests.unit.utilities.test_utilities_core",
        "TestDnObjectClassMethods",
    ),
    "TestFlextLdifUtilitiesComprehensive": (
        "tests.unit.utilities.test_utilities_comprehensive",
        "TestFlextLdifUtilitiesComprehensive",
    ),
    "TestLdifParser": ("tests.unit.utilities.test_utilities_core", "TestLdifParser"),
    "TestObjectClassUtilities": (
        "tests.unit.utilities.test_utilities_core",
        "TestObjectClassUtilities",
    ),
    "TestServerTypes": ("tests.unit.utilities.test_utilities_core", "TestServerTypes"),
    "TestsFlextLdifDnOperationsPure": (
        "tests.unit.utilities.test_utilities_core",
        "TestsFlextLdifDnOperationsPure",
    ),
    "TestsTestFlextLdifConstants": (
        "tests.unit.utilities.test_utilities_constants",
        "TestsTestFlextLdifConstants",
    ),
    "TestsTestFlextLdifServiceAPIs": (
        "tests.unit.utilities.test_utilities",
        "TestsTestFlextLdifServiceAPIs",
    ),
    "ValidateManyType": (
        "tests.unit.utilities.test_utilities_constants",
        "ValidateManyType",
    ),
}

__all__ = [
    "GetValidValuesType",
    "IsValidTestType",
    "TestAclParser",
    "TestAttributeFixer",
    "TestDnObjectClassMethods",
    "TestFlextLdifUtilitiesComprehensive",
    "TestLdifParser",
    "TestObjectClassUtilities",
    "TestServerTypes",
    "TestsFlextLdifDnOperationsPure",
    "TestsTestFlextLdifConstants",
    "TestsTestFlextLdifServiceAPIs",
    "ValidateManyType",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
