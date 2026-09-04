# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests.unit.services package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_tests import c, d, e, h, m, p, r, s, t, td, tf, tk, tm, tv, u, x

    from .test_acl_service import TestsFlextLdifAclService
    from .test_analysis_service import TestsFlextLdifAnalysisService
    from .test_api_server_registry import TestsFlextLdifApiServerRegistry
    from .test_detector_service import TestsFlextLdifDetectorService
    from .test_entries_service import TestsFlextLdifEntries
    from .test_filters_service import TestsFlextLdifFiltersService
    from .test_migration_pipeline import TestsFlextLdifMigrationPipeline
    from .test_parser_service import TestsFlextLdifParserService
    from .test_processing_service import TestsFlextLdifProcessingService
    from .test_servers_standardization import TestsFlextLdifServersStandardization
    from .test_statistics_service import TestsFlextLdifStatisticsService
    from .test_transformers_service import TestsFlextLdifTransformersService
    from .test_validation_service import TestsFlextLdifValidationService
    from .test_writer_service import TestsFlextLdifWriterService
__all__: tuple[str, ...] = (
    "TestsFlextLdifAclService",
    "TestsFlextLdifAnalysisService",
    "TestsFlextLdifApiServerRegistry",
    "TestsFlextLdifDetectorService",
    "TestsFlextLdifEntries",
    "TestsFlextLdifFiltersService",
    "TestsFlextLdifMigrationPipeline",
    "TestsFlextLdifParserService",
    "TestsFlextLdifProcessingService",
    "TestsFlextLdifServersStandardization",
    "TestsFlextLdifStatisticsService",
    "TestsFlextLdifTransformersService",
    "TestsFlextLdifValidationService",
    "TestsFlextLdifWriterService",
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
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".test_acl_service": ("TestsFlextLdifAclService",),
            ".test_analysis_service": ("TestsFlextLdifAnalysisService",),
            ".test_api_server_registry": ("TestsFlextLdifApiServerRegistry",),
            ".test_detector_service": ("TestsFlextLdifDetectorService",),
            ".test_entries_service": ("TestsFlextLdifEntries",),
            ".test_filters_service": ("TestsFlextLdifFiltersService",),
            ".test_migration_pipeline": ("TestsFlextLdifMigrationPipeline",),
            ".test_parser_service": ("TestsFlextLdifParserService",),
            ".test_processing_service": ("TestsFlextLdifProcessingService",),
            ".test_servers_standardization": ("TestsFlextLdifServersStandardization",),
            ".test_statistics_service": ("TestsFlextLdifStatisticsService",),
            ".test_transformers_service": ("TestsFlextLdifTransformersService",),
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
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
