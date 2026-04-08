# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

_LAZY_IMPORTS = merge_lazy_imports(
    (
        "tests.unit.__init__",
        "tests.unit.constants",
        "tests.unit.protocols",
        "tests.unit.services",
        "tests.unit.utilities",
    ),
    {
        "constants": "tests.unit.constants",
        "protocols": "tests.unit.protocols",
        "services": "tests.unit.services",
        "test_migration_pipeline": "tests.unit.test_migration_pipeline",
        "test_migration_pipeline_quirks": "tests.unit.test_migration_pipeline_quirks",
        "test_typings": "tests.unit.test_typings",
        "utilities": "tests.unit.utilities",
    },
)
_ = _LAZY_IMPORTS.pop("cleanup_submodule_namespace", None)
_ = _LAZY_IMPORTS.pop("install_lazy_exports", None)
_ = _LAZY_IMPORTS.pop("lazy_getattr", None)
_ = _LAZY_IMPORTS.pop("logger", None)
_ = _LAZY_IMPORTS.pop("merge_lazy_imports", None)
_ = _LAZY_IMPORTS.pop("output", None)
_ = _LAZY_IMPORTS.pop("output_reporting", None)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
