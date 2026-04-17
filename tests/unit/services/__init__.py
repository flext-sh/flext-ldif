# AUTO-GENERATED FILE — Regenerate with: make gen
"""Services package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_migration_pipeline": ("TestsTestFlextLdifMigrationPipeline",),
        ".test_quirks_standardization": (
            "TestAliasDiscovery",
            "TestQuirksAutoInterchange",
            "TestQuirksWithRealLdifFixtures",
            "TestsFlextLdifServersStandardizedConstants",
        ),
        "flext_ldif": (
            "c",
            "d",
            "e",
            "h",
            "m",
            "p",
            "r",
            "s",
            "t",
            "u",
            "x",
        ),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
