# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Init package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports
from tests.unit.__init__.test_version import TestsFlextLdifVersion

if _t.TYPE_CHECKING:
    import tests.unit.__init__.test_version as _tests_unit___init___test_version

    test_version = _tests_unit___init___test_version

    _ = (
        TestsFlextLdifVersion,
        test_version,
    )
_LAZY_IMPORTS = {
    "TestsFlextLdifVersion": "tests.unit.__init__.test_version",
    "test_version": "tests.unit.__init__.test_version",
}

__all__ = [
    "TestsFlextLdifVersion",
    "test_version",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
