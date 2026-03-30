# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit tests for services."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests.unit.services import (
        test_migration_pipeline as test_migration_pipeline,
        test_quirks_standardization as test_quirks_standardization,
    )
    from tests.unit.services.test_migration_pipeline import (
        TestsTestFlextLdifMigrationPipeline as TestsTestFlextLdifMigrationPipeline,
    )
    from tests.unit.services.test_quirks_standardization import (
        TestAliasDiscovery as TestAliasDiscovery,
        TestQuirksAutoInterchange as TestQuirksAutoInterchange,
        TestQuirksWithRealLdifFixtures as TestQuirksWithRealLdifFixtures,
        TestsFlextLdifQuirksStandardizedConstants as TestsFlextLdifQuirksStandardizedConstants,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "TestAliasDiscovery": [
        "tests.unit.services.test_quirks_standardization",
        "TestAliasDiscovery",
    ],
    "TestQuirksAutoInterchange": [
        "tests.unit.services.test_quirks_standardization",
        "TestQuirksAutoInterchange",
    ],
    "TestQuirksWithRealLdifFixtures": [
        "tests.unit.services.test_quirks_standardization",
        "TestQuirksWithRealLdifFixtures",
    ],
    "TestsFlextLdifQuirksStandardizedConstants": [
        "tests.unit.services.test_quirks_standardization",
        "TestsFlextLdifQuirksStandardizedConstants",
    ],
    "TestsTestFlextLdifMigrationPipeline": [
        "tests.unit.services.test_migration_pipeline",
        "TestsTestFlextLdifMigrationPipeline",
    ],
    "test_migration_pipeline": ["tests.unit.services.test_migration_pipeline", ""],
    "test_quirks_standardization": [
        "tests.unit.services.test_quirks_standardization",
        "",
    ],
}

_EXPORTS: Sequence[str] = [
    "TestAliasDiscovery",
    "TestQuirksAutoInterchange",
    "TestQuirksWithRealLdifFixtures",
    "TestsFlextLdifQuirksStandardizedConstants",
    "TestsTestFlextLdifMigrationPipeline",
    "test_migration_pipeline",
    "test_quirks_standardization",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
