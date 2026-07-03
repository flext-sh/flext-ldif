# AUTO-GENERATED FILE — Regenerate with: make gen
"""Lazy export map part."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map

TESTS_FLEXT_LDIF_LAZY_IMPORTS_PART_03 = build_lazy_import_map(
    {
        ".base": ("s",),
        ".conftest": ("conftest",),
        ".constants": ("c",),
        ".integration": ("integration",),
        ".integration.test_cross_direction_conversion": (
            "TestsTestFlextLdifCrossDirectionConversion",
        ),
        ".integration.test_zero_data_loss_oid_oud": (
            "TestsFlextLdifZeroDataLossOidOud",
        ),
        ".models": ("m",),
        ".protocols": ("p",),
        ".typings": ("t",),
        ".unit": ("unit",),
        ".unit.servers.test_apache_servers": ("TestsTestFlextLdifApacheServers",),
        ".unit.servers.test_ds389_servers": ("TestsTestFlextLdifDs389Servers",),
        ".unit.servers.test_oid_servers": ("TestsTestFlextLdifOidServers",),
        ".unit.servers.test_relaxed_servers": ("TestsTestFlextLdifRelaxedServers",),
        ".unit.services.test_api_server_registry": (
            "TestsTestFlextLdifApiServerRegistry",
        ),
        ".unit.services.test_migration_pipeline": (
            "TestsTestFlextLdifMigrationPipeline",
        ),
        ".utilities": ("u",),
        "flext_tests": (
            "d",
            "e",
            "h",
            "r",
            "td",
            "tf",
            "tk",
            "tm",
            "tv",
            "x",
        ),
    },
)

__all__: list[str] = ["TESTS_FLEXT_LDIF_LAZY_IMPORTS_PART_03"]
