# AUTO-GENERATED FILE — Regenerate with: make gen
"""Services package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.tests.unit.services.test_acl_service import (
        TestsFlextLdifAclService as TestsFlextLdifAclService,
    )
    from flext_ldif.tests.unit.services.test_analysis_service import (
        TestsFlextLdifAnalysisService as TestsFlextLdifAnalysisService,
    )
    from flext_ldif.tests.unit.services.test_api_server_registry import (
        TestsTestFlextLdifApiServerRegistry as TestsTestFlextLdifApiServerRegistry,
    )
    from flext_ldif.tests.unit.services.test_detector_service import (
        TestsFlextLdifDetectorService as TestsFlextLdifDetectorService,
    )
    from flext_ldif.tests.unit.services.test_entries_service import (
        TestsFlextLdifEntriesService as TestsFlextLdifEntriesService,
    )
    from flext_ldif.tests.unit.services.test_filters_service import (
        TestsFlextLdifFiltersService as TestsFlextLdifFiltersService,
    )
    from flext_ldif.tests.unit.services.test_migration_pipeline import (
        TestsFlextLdifProcessingPipeline as TestsFlextLdifProcessingPipeline,
        TestsTestFlextLdifMigrationPipeline as TestsTestFlextLdifMigrationPipeline,
    )
    from flext_ldif.tests.unit.services.test_parser_service import (
        TestsFlextLdifParserService as TestsFlextLdifParserService,
    )
    from flext_ldif.tests.unit.services.test_processing_service import (
        TestsFlextLdifProcessingService as TestsFlextLdifProcessingService,
    )
    from flext_ldif.tests.unit.services.test_servers_standardization import (
        TestsFlextLdifServersStandardization as TestsFlextLdifServersStandardization,
    )
    from flext_ldif.tests.unit.services.test_statistics_service import (
        TestsFlextLdifStatisticsService as TestsFlextLdifStatisticsService,
    )
    from flext_ldif.tests.unit.services.test_transformers_service import (
        TestsFlextLdifTransformerService as TestsFlextLdifTransformerService,
    )
    from flext_ldif.tests.unit.services.test_validation_service import (
        TestsFlextLdifValidationService as TestsFlextLdifValidationService,
    )
    from flext_ldif.tests.unit.services.test_writer_service import (
        TestsFlextLdifWriterService as TestsFlextLdifWriterService,
    )
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
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
