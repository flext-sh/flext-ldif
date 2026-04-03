# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Init package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_ldif import test_version
    from flext_ldif.test_version import TestsFlextLdifVersion

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "TestsFlextLdifVersion": "flext_ldif.test_version",
    "test_version": "flext_ldif.test_version",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
