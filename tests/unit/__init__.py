# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _t.TYPE_CHECKING:
    import tests.unit.constants as _tests_unit_constants

    constants = _tests_unit_constants
    import tests.unit.protocols as _tests_unit_protocols

    protocols = _tests_unit_protocols
    import tests.unit.services as _tests_unit_services

    services = _tests_unit_services
    import tests.unit.test_migration_pipeline as _tests_unit_test_migration_pipeline

    test_migration_pipeline = _tests_unit_test_migration_pipeline
    import tests.unit.test_migration_pipeline_quirks as _tests_unit_test_migration_pipeline_quirks

    test_migration_pipeline_quirks = _tests_unit_test_migration_pipeline_quirks
    import tests.unit.test_typings as _tests_unit_test_typings

    test_typings = _tests_unit_test_typings
    import tests.unit.utilities as _tests_unit_utilities

    utilities = _tests_unit_utilities
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
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "tests.unit.__init__",
        "tests.unit.constants",
        "tests.unit.protocols",
        "tests.unit.services",
        "tests.unit.utilities",
    ),
    {
        "c": ("flext_core.constants", "FlextConstants"),
        "constants": "tests.unit.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "h": ("flext_core.handlers", "FlextHandlers"),
        "m": ("flext_core.models", "FlextModels"),
        "p": ("flext_core.protocols", "FlextProtocols"),
        "protocols": "tests.unit.protocols",
        "r": ("flext_core.result", "FlextResult"),
        "s": ("flext_core.service", "FlextService"),
        "services": "tests.unit.services",
        "t": ("flext_core.typings", "FlextTypes"),
        "test_migration_pipeline": "tests.unit.test_migration_pipeline",
        "test_migration_pipeline_quirks": "tests.unit.test_migration_pipeline_quirks",
        "test_typings": "tests.unit.test_typings",
        "u": ("flext_core.utilities", "FlextUtilities"),
        "utilities": "tests.unit.utilities",
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
    "c",
    "constants",
    "d",
    "e",
    "h",
    "m",
    "p",
    "protocols",
    "r",
    "s",
    "services",
    "t",
    "test_migration_pipeline",
    "test_migration_pipeline_quirks",
    "test_typings",
    "u",
    "utilities",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
