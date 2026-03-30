# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Init package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests.unit.__init__ import test_version as test_version
    from tests.unit.__init__.test_version import (
        TestsFlextLdifVersion as TestsFlextLdifVersion,
        version_module as version_module,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "TestsFlextLdifVersion": [
        "tests.unit.__init__.test_version",
        "TestsFlextLdifVersion",
    ],
    "test_version": ["tests.unit.__init__.test_version", ""],
    "version_module": ["tests.unit.__init__.test_version", "version_module"],
}

_EXPORTS: Sequence[str] = [
    "TestsFlextLdifVersion",
    "test_version",
    "version_module",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
