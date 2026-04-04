# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Init package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import tests.unit.__init__.test_version as _tests_unit___init___test_version

    test_version = _tests_unit___init___test_version
    from tests.unit.__init__.test_version import TestsFlextLdifVersion, version_module
_LAZY_IMPORTS = {
    "TestsFlextLdifVersion": "tests.unit.__init__.test_version",
    "test_version": "tests.unit.__init__.test_version",
    "version_module": "tests.unit.__init__.test_version",
}

__all__ = [
    "TestsFlextLdifVersion",
    "test_version",
    "version_module",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
