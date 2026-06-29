# AUTO-GENERATED FILE — Regenerate with: make gen
"""Unit package."""

from __future__ import annotations

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

_LAZY_IMPORTS = merge_lazy_imports(
    (
        ".servers",
        ".services",
        ".utilities",
    ),
    build_lazy_import_map(
        {
            ".fixtures": ("fixtures",),
            ".servers.test_apache_servers": ("TestsTestFlextLdifApacheServers",),
            ".servers.test_ds389_servers": ("TestsTestFlextLdifDs389Servers",),
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
            ".servers.test_oid_servers": ("TestsTestFlextLdifOidServers",),
            ".servers.test_relaxed_servers": ("TestsTestFlextLdifRelaxedServers",),
            ".servers.test_schema_transformer": ("TestsFlextLdifSchemaTransformer",),
            ".services.test_acl_service": ("TestsFlextLdifAclService",),
            ".services.test_analysis_service": ("TestsFlextLdifAnalysisService",),
            ".services.test_api_server_registry": (
                "TestsTestFlextLdifApiServerRegistry",
            ),
            ".services.test_detector_service": ("TestsFlextLdifDetectorService",),
            ".services.test_entries_service": ("TestsFlextLdifEntriesService",),
            ".services.test_filters_service": ("TestsFlextLdifFiltersService",),
            ".services.test_migration_pipeline": (
                "TestsFlextLdifProcessingPipeline",
                "TestsTestFlextLdifMigrationPipeline",
            ),
            ".services.test_parser_service": ("TestsFlextLdifParserService",),
            ".services.test_processing_service": ("TestsFlextLdifProcessingService",),
            ".services.test_servers_standardization": (
                "TestsFlextLdifServersStandardization",
            ),
            ".services.test_statistics_service": ("TestsFlextLdifStatisticsService",),
            ".services.test_transformers_service": (
                "TestsFlextLdifTransformerService",
            ),
            ".services.test_validation_service": ("TestsFlextLdifValidationService",),
            ".services.test_writer_service": ("TestsFlextLdifWriterService",),
            ".test_acl_registry": ("TestsFlextLdifAclRegistry",),
            ".test_api_freeze": ("TestsFlextLdifApiFreeze",),
            ".test_collections_models": ("TestsFlextLdifCollectionsModels",),
            ".test_constants_data_driven": ("TestsFlextLdifConstantsDataDriven",),
            ".test_migration_pipeline_servers": (
                "TestsFlextLdifMigrationPipelineServers",
            ),
            ".test_oid_utilities": ("TestsFlextLdifOidUtilities",),
            ".test_parser_utilities": ("TestsFlextLdifParserUtilities",),
            ".test_version": ("TestsFlextLdifVersion",),
            ".utilities.test_utilities_comprehensive": (
                "TestsFlextLdifUtilitiesComprehensive",
            ),
            ".utilities.test_utilities_core": ("TestsFlextLdifUtilitiesCore",),
            "flext_tests": (
                "c",
                "d",
                "e",
                "h",
                "m",
                "p",
                "r",
                "s",
                "t",
                "td",
                "tf",
                "tk",
                "tm",
                "tv",
                "u",
                "x",
            ),
        },
    ),
    exclude_names=(
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
        "pytest_addoption",
        "pytest_collect_file",
        "pytest_collection_modifyitems",
        "pytest_configure",
        "pytest_runtest_setup",
        "pytest_runtest_teardown",
        "pytest_sessionfinish",
        "pytest_sessionstart",
        "pytest_terminal_summary",
        "pytest_warning_recorded",
    ),
    module_name=__name__,
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
