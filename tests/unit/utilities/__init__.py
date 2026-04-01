# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Utilities package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes

    from tests.unit.utilities.test_utilities_comprehensive import (
        TestFlextLdifUtilitiesComprehensive,
    )
    from tests.unit.utilities.test_utilities_core import (
        TestAttributeFixer,
        TestDnObjectClassMethods,
        TestLdifParser,
        TestObjectClassUtilities,
        TestServerTypes,
        TestsFlextLdifDnOperationsPure,
    )

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "TestAttributeFixer": "tests.unit.utilities.test_utilities_core",
    "TestDnObjectClassMethods": "tests.unit.utilities.test_utilities_core",
    "TestFlextLdifUtilitiesComprehensive": "tests.unit.utilities.test_utilities_comprehensive",
    "TestLdifParser": "tests.unit.utilities.test_utilities_core",
    "TestObjectClassUtilities": "tests.unit.utilities.test_utilities_core",
    "TestServerTypes": "tests.unit.utilities.test_utilities_core",
    "TestsFlextLdifDnOperationsPure": "tests.unit.utilities.test_utilities_core",
    "test_utilities_comprehensive": "tests.unit.utilities.test_utilities_comprehensive",
    "test_utilities_core": "tests.unit.utilities.test_utilities_core",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
