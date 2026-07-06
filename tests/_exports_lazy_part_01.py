# AUTO-GENERATED FILE — Regenerate with: make gen
"""Lazy export map part."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map

TESTS_FLEXT_LDIF_LAZY_IMPORTS_PART_01 = build_lazy_import_map(
    {
        ".constants": ("TestsFlextLdifConstants",),
        ".integration.test_acl_metadata_preservation": (
            "TestsFlextLdifAclMetadataPreservation",
        ),
        ".integration.test_api_integration": ("TestsFlextLdifApiIntegration",),
        ".integration.test_categorization_real_data": (
            "TestsFlextLdifCategorizationRealData",
        ),
        ".integration.test_config_integration": ("TestsFlextLdifConfigIntegration",),
        ".integration.test_cross_direction_conversion": (
            "TestsFlextLdifCrossDirectionConversion",
        ),
        ".integration.test_cross_server_conversion": (
            "TestsFlextLdifCrossServerConversion",
        ),
        ".integration.test_dn_case_handling": ("TestsFlextLdifDnCaseHandling",),
        ".integration.test_edge_cases": ("TestsFlextLdifEdgeCases",),
        ".integration.test_error_recovery": ("TestsFlextLdifErrorRecovery",),
        ".integration.test_ldif_fixtures_integration": (
            "TestsFlextLdifLdifFixturesIntegration",
        ),
        ".integration.test_minimal_differences_metadata": (
            "TestsFlextLdifMinimalDifferencesMetadata",
        ),
        ".models": ("TestsFlextLdifModels",),
        ".unit.servers.test_apache_servers": ("TestsFlextLdifApacheServers",),
        ".unit.servers.test_ds389_servers": ("TestsFlextLdifDs389Servers",),
        ".unit.servers.test_novell_servers": ("TestsFlextLdifNovellServers",),
        ".unit.servers.test_oid_acl_assemble": ("TestsFlextLdifOidAclAssemble",),
        ".unit.servers.test_oid_acl_convert": ("TestsFlextLdifOidAclConvert",),
        ".unit.servers.test_oid_acl_convert_oud": ("TestsFlextLdifOidAclConvertOud",),
        ".unit.servers.test_oid_acl_endtoend": ("TestsFlextLdifOidAclEndToEnd",),
        ".unit.services.test_acl_service": ("TestsFlextLdifAclService",),
        ".unit.services.test_analysis_service": ("TestsFlextLdifAnalysisService",),
        ".unit.services.test_api_server_registry": ("TestsFlextLdifApiServerRegistry",),
        ".unit.services.test_detector_service": ("TestsFlextLdifDetectorService",),
        ".unit.services.test_entries_service": ("TestsFlextLdifEntries",),
        ".unit.services.test_filters_service": ("TestsFlextLdifFiltersService",),
        ".unit.services.test_migration_pipeline": ("TestsFlextLdifMigrationPipeline",),
        ".unit.test_acl_registry": ("TestsFlextLdifAclRegistry",),
        ".unit.test_api_freeze": ("TestsFlextLdifApiFreeze",),
        ".unit.test_collections_models": ("TestsFlextLdifCollectionsModels",),
        ".unit.test_constants_data_driven": ("TestsFlextLdifConstantsDataDriven",),
        ".unit.test_migration_pipeline_servers": (
            "TestsFlextLdifMigrationPipelineServers",
        ),
    },
)

__all__: list[str] = ["TESTS_FLEXT_LDIF_LAZY_IMPORTS_PART_01"]
