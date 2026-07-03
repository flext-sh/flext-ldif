# AUTO-GENERATED FILE — Regenerate with: make gen
"""Services package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_acl_service": ("TestsFlextLdifAclService",),
        ".test_analysis_service": ("TestsFlextLdifAnalysisService",),
        ".test_api_server_registry": ("TestsTestFlextLdifApiServerRegistry",),
        ".test_detector_service": ("TestsFlextLdifDetectorService",),
        ".test_entries_service": ("TestsFlextLdifEntriesService",),
        ".test_filters_service": ("TestsFlextLdifFiltersService",),
        ".test_migration_pipeline": (
            "TestsFlextLdifProcessingPipeline",
            "TestsTestFlextLdifMigrationPipeline",
        ),
        ".test_parser_service": ("TestsFlextLdifParserService",),
        ".test_processing_service": ("TestsFlextLdifProcessingService",),
        ".test_servers_standardization": ("TestsFlextLdifServersStandardization",),
        ".test_statistics_service": ("TestsFlextLdifStatisticsService",),
        ".test_transformers_service": ("TestsFlextLdifTransformerService",),
        ".test_validation_service": ("TestsFlextLdifValidationService",),
        ".test_writer_service": ("TestsFlextLdifWriterService",),
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
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
