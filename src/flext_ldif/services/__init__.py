# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""FLEXT-LDIF Services - Internal Business Logic Layer."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_ldif.services import (
        _services,
        acl,
        analysis,
        categorization,
        conversion,
        detector,
        entries,
        filters,
        migration,
        parser,
        pipeline,
        processing,
        rfc_validation,
        server,
        statistics,
        transformers,
        writer,
    )
    from flext_ldif.services._services import (
        FlextLdifProcessingPipelineService,
        processing_pipeline_service,
    )
    from flext_ldif.services.acl import FlextLdifAcl
    from flext_ldif.services.analysis import FlextLdifAnalysis
    from flext_ldif.services.categorization import FlextLdifCategorization
    from flext_ldif.services.conversion import FlextLdifConversion
    from flext_ldif.services.detector import FlextLdifDetector, FlextLdifDetectorMixin
    from flext_ldif.services.entries import FlextLdifEntries
    from flext_ldif.services.filters import FlextLdifFilters
    from flext_ldif.services.migration import FlextLdifMigrationPipeline
    from flext_ldif.services.parser import FlextLdifParser, FlextLdifParserMixin
    from flext_ldif.services.pipeline import FlextLdifProcessingPipeline
    from flext_ldif.services.processing import FlextLdifProcessing
    from flext_ldif.services.rfc_validation import FlextLdifValidation
    from flext_ldif.services.server import FlextLdifServer
    from flext_ldif.services.statistics import FlextLdifStatistics
    from flext_ldif.services.transformers import FlextLdifTransformer
    from flext_ldif.services.writer import FlextLdifWriter, FlextLdifWriterMixin

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = merge_lazy_imports(
    ("flext_ldif.services._services",),
    {
        "FlextLdifAcl": "flext_ldif.services.acl",
        "FlextLdifAnalysis": "flext_ldif.services.analysis",
        "FlextLdifCategorization": "flext_ldif.services.categorization",
        "FlextLdifConversion": "flext_ldif.services.conversion",
        "FlextLdifDetector": "flext_ldif.services.detector",
        "FlextLdifDetectorMixin": "flext_ldif.services.detector",
        "FlextLdifEntries": "flext_ldif.services.entries",
        "FlextLdifFilters": "flext_ldif.services.filters",
        "FlextLdifMigrationPipeline": "flext_ldif.services.migration",
        "FlextLdifParser": "flext_ldif.services.parser",
        "FlextLdifParserMixin": "flext_ldif.services.parser",
        "FlextLdifProcessing": "flext_ldif.services.processing",
        "FlextLdifProcessingPipeline": "flext_ldif.services.pipeline",
        "FlextLdifServer": "flext_ldif.services.server",
        "FlextLdifStatistics": "flext_ldif.services.statistics",
        "FlextLdifTransformer": "flext_ldif.services.transformers",
        "FlextLdifValidation": "flext_ldif.services.rfc_validation",
        "FlextLdifWriter": "flext_ldif.services.writer",
        "FlextLdifWriterMixin": "flext_ldif.services.writer",
        "_services": "flext_ldif.services._services",
        "acl": "flext_ldif.services.acl",
        "analysis": "flext_ldif.services.analysis",
        "categorization": "flext_ldif.services.categorization",
        "conversion": "flext_ldif.services.conversion",
        "detector": "flext_ldif.services.detector",
        "entries": "flext_ldif.services.entries",
        "filters": "flext_ldif.services.filters",
        "migration": "flext_ldif.services.migration",
        "parser": "flext_ldif.services.parser",
        "pipeline": "flext_ldif.services.pipeline",
        "processing": "flext_ldif.services.processing",
        "rfc_validation": "flext_ldif.services.rfc_validation",
        "server": "flext_ldif.services.server",
        "statistics": "flext_ldif.services.statistics",
        "transformers": "flext_ldif.services.transformers",
        "writer": "flext_ldif.services.writer",
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
