# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _t.TYPE_CHECKING:
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from tests.base import TestsFlextLdifServiceBase, TestsFlextLdifServiceBase as s
    from tests.constants import TestsFlextLdifConstants, TestsFlextLdifConstants as c
    from tests.models import TestsFlextLdifModels, TestsFlextLdifModels as m
    from tests.protocols import TestsFlextLdifProtocols, TestsFlextLdifProtocols as p
    from tests.typings import (
        GenericFieldsDict,
        TestsFlextLdifTypes,
        TestsFlextLdifTypes as t,
    )
    from tests.utilities import TestsFlextLdifUtilities, TestsFlextLdifUtilities as u
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "tests.e2e",
        "tests.helpers",
        "tests.integration",
        "tests.support",
        "tests.unit",
    ),
    {
        "GenericFieldsDict": ("tests.typings", "GenericFieldsDict"),
        "TestsFlextLdifConstants": ("tests.constants", "TestsFlextLdifConstants"),
        "TestsFlextLdifModels": ("tests.models", "TestsFlextLdifModels"),
        "TestsFlextLdifProtocols": ("tests.protocols", "TestsFlextLdifProtocols"),
        "TestsFlextLdifServiceBase": ("tests.base", "TestsFlextLdifServiceBase"),
        "TestsFlextLdifTypes": ("tests.typings", "TestsFlextLdifTypes"),
        "TestsFlextLdifUtilities": ("tests.utilities", "TestsFlextLdifUtilities"),
        "base": "tests.base",
        "c": ("tests.constants", "TestsFlextLdifConstants"),
        "conftest": "tests.conftest",
        "conftest_shared": "tests.conftest_shared",
        "constants": "tests.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "e2e": "tests.e2e",
        "h": ("flext_core.handlers", "FlextHandlers"),
        "helpers": "tests.helpers",
        "integration": "tests.integration",
        "m": ("tests.models", "TestsFlextLdifModels"),
        "models": "tests.models",
        "p": ("tests.protocols", "TestsFlextLdifProtocols"),
        "protocols": "tests.protocols",
        "r": ("flext_core.result", "FlextResult"),
        "s": ("tests.base", "TestsFlextLdifServiceBase"),
        "support": "tests.support",
        "t": ("tests.typings", "TestsFlextLdifTypes"),
        "test_factory": "tests.test_factory",
        "test_helpers": "tests.test_helpers",
        "typings": "tests.typings",
        "u": ("tests.utilities", "TestsFlextLdifUtilities"),
        "unit": "tests.unit",
        "utilities": "tests.utilities",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)
_ = _LAZY_IMPORTS.pop("cleanup_submodule_namespace", None)
_ = _LAZY_IMPORTS.pop("install_lazy_exports", None)
_ = _LAZY_IMPORTS.pop("lazy_getattr", None)
_ = _LAZY_IMPORTS.pop("logger", None)
_ = _LAZY_IMPORTS.pop("merge_lazy_imports", None)
_ = _LAZY_IMPORTS.pop("output", None)
_ = _LAZY_IMPORTS.pop("output_reporting", None)

__all__ = [
    "GenericFieldsDict",
    "TestsFlextLdifConstants",
    "TestsFlextLdifModels",
    "TestsFlextLdifProtocols",
    "TestsFlextLdifServiceBase",
    "TestsFlextLdifTypes",
    "TestsFlextLdifUtilities",
    "base",
    "c",
    "conftest",
    "conftest_shared",
    "constants",
    "d",
    "e",
    "e2e",
    "h",
    "helpers",
    "integration",
    "m",
    "models",
    "p",
    "protocols",
    "r",
    "s",
    "support",
    "t",
    "test_factory",
    "test_helpers",
    "typings",
    "u",
    "unit",
    "utilities",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
