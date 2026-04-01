# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit tests for services."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes

    from tests.unit.services import test_migration_pipeline, test_quirks_standardization
    from tests.unit.services.test_migration_pipeline import (
        TestsTestFlextLdifMigrationPipeline,
    )
    from tests.unit.services.test_quirks_standardization import (
        TestAliasDiscovery,
        TestQuirksAutoInterchange,
        TestQuirksWithRealLdifFixtures,
        TestsFlextLdifQuirksStandardizedConstants,
    )

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "TestAliasDiscovery": "tests.unit.services.test_quirks_standardization",
    "TestQuirksAutoInterchange": "tests.unit.services.test_quirks_standardization",
    "TestQuirksWithRealLdifFixtures": "tests.unit.services.test_quirks_standardization",
    "TestsFlextLdifQuirksStandardizedConstants": "tests.unit.services.test_quirks_standardization",
    "TestsTestFlextLdifMigrationPipeline": "tests.unit.services.test_migration_pipeline",
    "test_migration_pipeline": "tests.unit.services.test_migration_pipeline",
    "test_quirks_standardization": "tests.unit.services.test_quirks_standardization",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
