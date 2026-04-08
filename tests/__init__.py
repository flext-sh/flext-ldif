# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _t.TYPE_CHECKING:
    import tests.base as _tests_base

    base = _tests_base
    import tests.conftest as _tests_conftest
    from tests.base import TestsFlextLdifServiceBase, TestsFlextLdifServiceBase as s

    conftest = _tests_conftest
    import tests.conftest_shared as _tests_conftest_shared

    conftest_shared = _tests_conftest_shared
    import tests.constants as _tests_constants

    constants = _tests_constants
    import tests.e2e as _tests_e2e
    from tests.constants import TestsFlextLdifConstants, TestsFlextLdifConstants as c

    e2e = _tests_e2e
    import tests.helpers as _tests_helpers

    helpers = _tests_helpers
    import tests.integration as _tests_integration

    integration = _tests_integration
    import tests.models as _tests_models

    models = _tests_models
    import tests.protocols as _tests_protocols
    from tests.models import TestsFlextLdifModels, TestsFlextLdifModels as m

    protocols = _tests_protocols
    import tests.support as _tests_support
    from tests.protocols import TestsFlextLdifProtocols, TestsFlextLdifProtocols as p

    support = _tests_support
    import tests.test_factory as _tests_test_factory

    test_factory = _tests_test_factory
    import tests.test_helpers as _tests_test_helpers

    test_helpers = _tests_test_helpers
    import tests.typings as _tests_typings

    typings = _tests_typings
    import tests.unit as _tests_unit
    from tests.typings import (
        GenericFieldsDict,
        TestsFlextLdifTypes,
        TestsFlextLdifTypes as t,
    )

    unit = _tests_unit
    import tests.utilities as _tests_utilities

    utilities = _tests_utilities
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
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
