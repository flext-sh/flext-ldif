# AUTO-GENERATED FILE — Regenerate with: make gen
"""Utilities package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.tests.unit.utilities.test_utilities_comprehensive import (
        TestsFlextLdifUtilitiesComprehensive as TestsFlextLdifUtilitiesComprehensive,
    )
    from flext_ldif.tests.unit.utilities.test_utilities_core import (
        TestsFlextLdifUtilitiesCore as TestsFlextLdifUtilitiesCore,
    )
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_utilities_comprehensive": ("TestsFlextLdifUtilitiesComprehensive",),
        ".test_utilities_core": ("TestsFlextLdifUtilitiesCore",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
