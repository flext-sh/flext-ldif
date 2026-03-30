# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Utilities package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests.unit.utilities import (
        test_utilities_comprehensive as test_utilities_comprehensive,
        test_utilities_core as test_utilities_core,
    )
    from tests.unit.utilities.test_utilities_comprehensive import (
        TestFlextLdifUtilitiesComprehensive as TestFlextLdifUtilitiesComprehensive,
    )
    from tests.unit.utilities.test_utilities_core import (
        TestAttributeFixer as TestAttributeFixer,
        TestDnObjectClassMethods as TestDnObjectClassMethods,
        TestLdifParser as TestLdifParser,
        TestObjectClassUtilities as TestObjectClassUtilities,
        TestServerTypes as TestServerTypes,
        TestsFlextLdifDnOperationsPure as TestsFlextLdifDnOperationsPure,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "TestAttributeFixer": [
        "tests.unit.utilities.test_utilities_core",
        "TestAttributeFixer",
    ],
    "TestDnObjectClassMethods": [
        "tests.unit.utilities.test_utilities_core",
        "TestDnObjectClassMethods",
    ],
    "TestFlextLdifUtilitiesComprehensive": [
        "tests.unit.utilities.test_utilities_comprehensive",
        "TestFlextLdifUtilitiesComprehensive",
    ],
    "TestLdifParser": ["tests.unit.utilities.test_utilities_core", "TestLdifParser"],
    "TestObjectClassUtilities": [
        "tests.unit.utilities.test_utilities_core",
        "TestObjectClassUtilities",
    ],
    "TestServerTypes": ["tests.unit.utilities.test_utilities_core", "TestServerTypes"],
    "TestsFlextLdifDnOperationsPure": [
        "tests.unit.utilities.test_utilities_core",
        "TestsFlextLdifDnOperationsPure",
    ],
    "test_utilities_comprehensive": [
        "tests.unit.utilities.test_utilities_comprehensive",
        "",
    ],
    "test_utilities_core": ["tests.unit.utilities.test_utilities_core", ""],
}

_EXPORTS: Sequence[str] = [
    "TestAttributeFixer",
    "TestDnObjectClassMethods",
    "TestFlextLdifUtilitiesComprehensive",
    "TestLdifParser",
    "TestObjectClassUtilities",
    "TestServerTypes",
    "TestsFlextLdifDnOperationsPure",
    "test_utilities_comprehensive",
    "test_utilities_core",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
