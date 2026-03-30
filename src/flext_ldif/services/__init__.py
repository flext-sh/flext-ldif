# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""FLEXT-LDIF Services - Internal Business Logic Layer."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.services import (
        _services as _services,
        acl as acl,
        analysis as analysis,
        categorization as categorization,
        conversion as conversion,
        detector as detector,
        entries as entries,
        filters as filters,
        migration as migration,
        parser as parser,
        pipeline as pipeline,
        processing as processing,
        rfc_validation as rfc_validation,
        server as server,
        statistics as statistics,
        transformers as transformers,
        writer as writer,
    )
    from flext_ldif.services._services import (
        processing_pipeline_service as processing_pipeline_service,
    )
    from flext_ldif.services._services.processing_pipeline_service import (
        FlextLdifProcessingPipelineService as FlextLdifProcessingPipelineService,
    )
    from flext_ldif.services.acl import FlextLdifAcl as FlextLdifAcl
    from flext_ldif.services.analysis import FlextLdifAnalysis as FlextLdifAnalysis
    from flext_ldif.services.categorization import (
        FlextLdifCategorization as FlextLdifCategorization,
    )
    from flext_ldif.services.conversion import (
        FlextLdifConversion as FlextLdifConversion,
    )
    from flext_ldif.services.detector import (
        FlextLdifDetector as FlextLdifDetector,
        FlextLdifDetectorMixin as FlextLdifDetectorMixin,
    )
    from flext_ldif.services.entries import FlextLdifEntries as FlextLdifEntries
    from flext_ldif.services.filters import FlextLdifFilters as FlextLdifFilters
    from flext_ldif.services.migration import (
        FlextLdifMigrationPipeline as FlextLdifMigrationPipeline,
    )
    from flext_ldif.services.parser import (
        FlextLdifParser as FlextLdifParser,
        FlextLdifParserMixin as FlextLdifParserMixin,
    )
    from flext_ldif.services.pipeline import (
        FlextLdifProcessingPipeline as FlextLdifProcessingPipeline,
    )
    from flext_ldif.services.processing import (
        FlextLdifProcessing as FlextLdifProcessing,
    )
    from flext_ldif.services.rfc_validation import (
        FlextLdifValidation as FlextLdifValidation,
    )
    from flext_ldif.services.server import FlextLdifServer as FlextLdifServer
    from flext_ldif.services.statistics import (
        FlextLdifStatistics as FlextLdifStatistics,
    )
    from flext_ldif.services.transformers import (
        FlextLdifTransformer as FlextLdifTransformer,
    )
    from flext_ldif.services.writer import (
        FlextLdifWriter as FlextLdifWriter,
        FlextLdifWriterMixin as FlextLdifWriterMixin,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdifAcl": ["flext_ldif.services.acl", "FlextLdifAcl"],
    "FlextLdifAnalysis": ["flext_ldif.services.analysis", "FlextLdifAnalysis"],
    "FlextLdifCategorization": [
        "flext_ldif.services.categorization",
        "FlextLdifCategorization",
    ],
    "FlextLdifConversion": ["flext_ldif.services.conversion", "FlextLdifConversion"],
    "FlextLdifDetector": ["flext_ldif.services.detector", "FlextLdifDetector"],
    "FlextLdifDetectorMixin": [
        "flext_ldif.services.detector",
        "FlextLdifDetectorMixin",
    ],
    "FlextLdifEntries": ["flext_ldif.services.entries", "FlextLdifEntries"],
    "FlextLdifFilters": ["flext_ldif.services.filters", "FlextLdifFilters"],
    "FlextLdifMigrationPipeline": [
        "flext_ldif.services.migration",
        "FlextLdifMigrationPipeline",
    ],
    "FlextLdifParser": ["flext_ldif.services.parser", "FlextLdifParser"],
    "FlextLdifParserMixin": ["flext_ldif.services.parser", "FlextLdifParserMixin"],
    "FlextLdifProcessing": ["flext_ldif.services.processing", "FlextLdifProcessing"],
    "FlextLdifProcessingPipeline": [
        "flext_ldif.services.pipeline",
        "FlextLdifProcessingPipeline",
    ],
    "FlextLdifProcessingPipelineService": [
        "flext_ldif.services._services.processing_pipeline_service",
        "FlextLdifProcessingPipelineService",
    ],
    "FlextLdifServer": ["flext_ldif.services.server", "FlextLdifServer"],
    "FlextLdifStatistics": ["flext_ldif.services.statistics", "FlextLdifStatistics"],
    "FlextLdifTransformer": [
        "flext_ldif.services.transformers",
        "FlextLdifTransformer",
    ],
    "FlextLdifValidation": [
        "flext_ldif.services.rfc_validation",
        "FlextLdifValidation",
    ],
    "FlextLdifWriter": ["flext_ldif.services.writer", "FlextLdifWriter"],
    "FlextLdifWriterMixin": ["flext_ldif.services.writer", "FlextLdifWriterMixin"],
    "_services": ["flext_ldif.services._services", ""],
    "acl": ["flext_ldif.services.acl", ""],
    "analysis": ["flext_ldif.services.analysis", ""],
    "categorization": ["flext_ldif.services.categorization", ""],
    "conversion": ["flext_ldif.services.conversion", ""],
    "detector": ["flext_ldif.services.detector", ""],
    "entries": ["flext_ldif.services.entries", ""],
    "filters": ["flext_ldif.services.filters", ""],
    "migration": ["flext_ldif.services.migration", ""],
    "parser": ["flext_ldif.services.parser", ""],
    "pipeline": ["flext_ldif.services.pipeline", ""],
    "processing": ["flext_ldif.services.processing", ""],
    "processing_pipeline_service": [
        "flext_ldif.services._services.processing_pipeline_service",
        "",
    ],
    "rfc_validation": ["flext_ldif.services.rfc_validation", ""],
    "server": ["flext_ldif.services.server", ""],
    "statistics": ["flext_ldif.services.statistics", ""],
    "transformers": ["flext_ldif.services.transformers", ""],
    "writer": ["flext_ldif.services.writer", ""],
}

_EXPORTS: Sequence[str] = [
    "FlextLdifAcl",
    "FlextLdifAnalysis",
    "FlextLdifCategorization",
    "FlextLdifConversion",
    "FlextLdifDetector",
    "FlextLdifDetectorMixin",
    "FlextLdifEntries",
    "FlextLdifFilters",
    "FlextLdifMigrationPipeline",
    "FlextLdifParser",
    "FlextLdifParserMixin",
    "FlextLdifProcessing",
    "FlextLdifProcessingPipeline",
    "FlextLdifProcessingPipelineService",
    "FlextLdifServer",
    "FlextLdifStatistics",
    "FlextLdifTransformer",
    "FlextLdifValidation",
    "FlextLdifWriter",
    "FlextLdifWriterMixin",
    "_services",
    "acl",
    "analysis",
    "categorization",
    "conversion",
    "detector",
    "entries",
    "filters",
    "migration",
    "parser",
    "pipeline",
    "processing",
    "processing_pipeline_service",
    "rfc_validation",
    "server",
    "statistics",
    "transformers",
    "writer",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
