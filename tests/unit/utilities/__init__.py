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
    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u
    from tests.unit.utilities import test_utilities_comprehensive, test_utilities_core
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

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "TestAttributeFixer": "tests.unit.utilities.test_utilities_core",
    "TestDnObjectClassMethods": "tests.unit.utilities.test_utilities_core",
    "TestFlextLdifUtilitiesComprehensive": "tests.unit.utilities.test_utilities_comprehensive",
    "TestLdifParser": "tests.unit.utilities.test_utilities_core",
    "TestObjectClassUtilities": "tests.unit.utilities.test_utilities_core",
    "TestServerTypes": "tests.unit.utilities.test_utilities_core",
    "TestsFlextLdifDnOperationsPure": "tests.unit.utilities.test_utilities_core",
    "c": ("flext_core.constants", "FlextConstants"),
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "m": ("flext_core.models", "FlextModels"),
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "t": ("flext_core.typings", "FlextTypes"),
    "test_utilities_comprehensive": "tests.unit.utilities.test_utilities_comprehensive",
    "test_utilities_core": "tests.unit.utilities.test_utilities_core",
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
