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
            ".servers.test_apache_quirks": ("TestsTestFlextLdifApacheQuirks",),
            ".servers.test_ds389_quirks": ("TestsTestFlextLdifDs389Quirks",),
            ".servers.test_edge_cases": ("TestsFlextLdifEdgeCases",),
            ".servers.test_novell_quirks": ("TestsFlextLdifNovellQuirks",),
            ".servers.test_oid_quirks": ("TestsTestFlextLdifOidQuirks",),
            ".servers.test_relaxed_quirks": ("TestsTestFlextLdifRelaxedQuirks",),
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
            ".services.test_quirks_standardization": (
                "TestsFlextLdifQuirksStandardization",
            ),
            ".services.test_statistics_service": ("TestsFlextLdifStatisticsService",),
            ".services.test_writer_service": ("TestsFlextLdifWriterService",),
            ".test_acl_registry": ("TestsFlextLdifAclRegistry",),
            ".test_constants_data_driven": ("TestsFlextLdifConstantsDataDriven",),
            ".test_migration_pipeline_quirks": (
                "TestsFlextLdifMigrationPipelineQuirks",
            ),
            ".test_oid_utilities": ("TestsFlextLdifOidUtilities",),
            ".test_parser_utilities": ("TestsFlextLdifParserUtilities",),
            ".test_version": ("TestsFlextLdifVersion",),
            ".utilities.test_utilities_comprehensive": (
                "TestsFlextLdifUtilitiesComprehensive",
            ),
            ".utilities.test_utilities_core": ("TestsFlextLdifUtilitiesCore",),
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
