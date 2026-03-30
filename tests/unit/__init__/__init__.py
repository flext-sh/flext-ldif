# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Init package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests.unit.__init__.test_version import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "TestsFlextLdifVersion": "tests.unit.__init__.test_version",
    "test_version": "tests.unit.__init__.test_version",
    "version_module": "tests.unit.__init__.test_version",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
