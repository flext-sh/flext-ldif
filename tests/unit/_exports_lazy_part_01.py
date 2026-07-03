# AUTO-GENERATED FILE — Regenerate with: make gen
"""Lazy export map part."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map

FLEXT_LDIF_TESTS_UNIT_LAZY_IMPORTS_PART_01 = build_lazy_import_map(
    {
        ".servers.test_edge_cases": ("TestsFlextLdifEdgeCases",),
        ".servers.test_novell_servers": ("TestsFlextLdifNovellServers",),
        ".servers.test_oid_acl_assemble": (
            "TestsFlextLdifOidAclAssemble",
            "TestsFlextLdifOidAclBuild",
            "TestsFlextLdifOidAclConvertEntryAcls",
            "TestsFlextLdifOidAclConvertValues",
        ),
        ".servers.test_oid_acl_convert": ("TestsFlextLdifOidAclConvertParse",),
        ".servers.test_oid_acl_convert_oud": (
            "TestsFlextLdifOidAclConvertPermissions",
            "TestsFlextLdifOidAclConvertSubject",
            "TestsFlextLdifOidAclConvertTarget",
        ),
        ".servers.test_oid_acl_endtoend": ("TestsFlextLdifOidAclEndToEnd",),
        ".servers.test_schema_transformer": ("TestsFlextLdifSchemaTransformer",),
        ".services.test_acl_service": ("TestsFlextLdifAclService",),
        ".services.test_analysis_service": ("TestsFlextLdifAnalysisService",),
        ".services.test_detector_service": ("TestsFlextLdifDetectorService",),
        ".services.test_entries_service": ("TestsFlextLdifEntriesService",),
        ".services.test_filters_service": ("TestsFlextLdifFiltersService",),
        ".services.test_migration_pipeline": ("TestsFlextLdifProcessingPipeline",),
        ".services.test_parser_service": ("TestsFlextLdifParserService",),
        ".services.test_processing_service": ("TestsFlextLdifProcessingService",),
        ".services.test_servers_standardization": (
            "TestsFlextLdifServersStandardization",
        ),
        ".services.test_statistics_service": ("TestsFlextLdifStatisticsService",),
        ".services.test_transformers_service": ("TestsFlextLdifTransformerService",),
        ".test_acl_registry": ("TestsFlextLdifAclRegistry",),
        ".test_api_freeze": ("TestsFlextLdifApiFreeze",),
        ".test_collections_models": ("TestsFlextLdifCollectionsModels",),
        ".test_constants_data_driven": ("TestsFlextLdifConstantsDataDriven",),
        ".test_migration_pipeline_servers": ("TestsFlextLdifMigrationPipelineServers",),
        ".test_oid_utilities": ("TestsFlextLdifOidUtilities",),
        ".test_parser_utilities": ("TestsFlextLdifParserUtilities",),
        ".utilities.test_utilities_comprehensive": (
            "TestsFlextLdifUtilitiesComprehensive",
        ),
        ".utilities.test_utilities_core": ("TestsFlextLdifUtilitiesCore",),
    },
)

__all__: list[str] = ["FLEXT_LDIF_TESTS_UNIT_LAZY_IMPORTS_PART_01"]
