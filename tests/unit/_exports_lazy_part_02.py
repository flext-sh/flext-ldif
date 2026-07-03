# AUTO-GENERATED FILE — Regenerate with: make gen
"""Lazy export map part."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map

FLEXT_LDIF_TESTS_UNIT_LAZY_IMPORTS_PART_02 = build_lazy_import_map(
    {
        ".fixtures": ("fixtures",),
        ".servers": ("servers",),
        ".servers.test_apache_servers": ("TestsTestFlextLdifApacheServers",),
        ".servers.test_ds389_servers": ("TestsTestFlextLdifDs389Servers",),
        ".servers.test_oid_servers": ("TestsTestFlextLdifOidServers",),
        ".servers.test_relaxed_servers": ("TestsTestFlextLdifRelaxedServers",),
        ".services": ("services",),
        ".services.test_api_server_registry": ("TestsTestFlextLdifApiServerRegistry",),
        ".services.test_migration_pipeline": ("TestsTestFlextLdifMigrationPipeline",),
        ".services.test_validation_service": ("TestsFlextLdifValidationService",),
        ".services.test_writer_service": ("TestsFlextLdifWriterService",),
        ".test_version": ("TestsFlextLdifVersion",),
        ".utilities": ("utilities",),
    },
)

__all__: list[str] = ["FLEXT_LDIF_TESTS_UNIT_LAZY_IMPORTS_PART_02"]
