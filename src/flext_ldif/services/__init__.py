# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Services package."""

from __future__ import annotations

import typing as _t

from flext_core.constants import FlextConstants as c
from flext_core.decorators import FlextDecorators as d
from flext_core.exceptions import FlextExceptions as e
from flext_core.handlers import FlextHandlers as h
from flext_core.lazy import install_lazy_exports, merge_lazy_imports
from flext_core.mixins import FlextMixins as x
from flext_core.models import FlextModels as m
from flext_core.protocols import FlextProtocols as p
from flext_core.result import FlextResult as r
from flext_core.service import FlextService as s
from flext_core.typings import FlextTypes as t
from flext_core.utilities import FlextUtilities as u

if _t.TYPE_CHECKING:
    import flext_ldif.services._services as _flext_ldif_services__services

    _services = _flext_ldif_services__services
    import flext_ldif.services._services.processing_pipeline_service as _flext_ldif_services__services_processing_pipeline_service

    processing_pipeline_service = (
        _flext_ldif_services__services_processing_pipeline_service
    )
    import flext_ldif.services.acl as _flext_ldif_services_acl

    acl = _flext_ldif_services_acl
    import flext_ldif.services.analysis as _flext_ldif_services_analysis

    analysis = _flext_ldif_services_analysis
    import flext_ldif.services.categorization as _flext_ldif_services_categorization

    categorization = _flext_ldif_services_categorization
    import flext_ldif.services.conversion as _flext_ldif_services_conversion

    conversion = _flext_ldif_services_conversion
    import flext_ldif.services.detector as _flext_ldif_services_detector

    detector = _flext_ldif_services_detector
    import flext_ldif.services.entries as _flext_ldif_services_entries

    entries = _flext_ldif_services_entries
    import flext_ldif.services.filters as _flext_ldif_services_filters

    filters = _flext_ldif_services_filters
    import flext_ldif.services.migration as _flext_ldif_services_migration

    migration = _flext_ldif_services_migration
    import flext_ldif.services.parser as _flext_ldif_services_parser

    parser = _flext_ldif_services_parser
    import flext_ldif.services.pipeline as _flext_ldif_services_pipeline

    pipeline = _flext_ldif_services_pipeline
    import flext_ldif.services.processing as _flext_ldif_services_processing

    processing = _flext_ldif_services_processing
    import flext_ldif.services.rfc_validation as _flext_ldif_services_rfc_validation

    rfc_validation = _flext_ldif_services_rfc_validation
    import flext_ldif.services.server as _flext_ldif_services_server

    server = _flext_ldif_services_server
    import flext_ldif.services.statistics as _flext_ldif_services_statistics

    statistics = _flext_ldif_services_statistics
    import flext_ldif.services.transformers as _flext_ldif_services_transformers

    transformers = _flext_ldif_services_transformers
    import flext_ldif.services.writer as _flext_ldif_services_writer

    writer = _flext_ldif_services_writer

    _ = (
        FlextLdifAcl,
        FlextLdifAnalysis,
        FlextLdifCategorization,
        FlextLdifConversion,
        FlextLdifDetector,
        FlextLdifDetectorMixin,
        FlextLdifEntries,
        FlextLdifFilters,
        FlextLdifMigrationPipeline,
        FlextLdifParser,
        FlextLdifParserMixin,
        FlextLdifProcessing,
        FlextLdifProcessingPipeline,
        FlextLdifProcessingPipelineService,
        FlextLdifServer,
        FlextLdifStatistics,
        FlextLdifTransformer,
        FlextLdifValidation,
        FlextLdifWriter,
        FlextLdifWriterMixin,
        _services,
        acl,
        analysis,
        c,
        categorization,
        conversion,
        d,
        detector,
        e,
        entries,
        filters,
        h,
        m,
        migration,
        p,
        parser,
        pipeline,
        processing,
        processing_pipeline_service,
        r,
        rfc_validation,
        s,
        server,
        statistics,
        t,
        transformers,
        u,
        writer,
        x,
    )
_LAZY_IMPORTS = merge_lazy_imports(
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
        "c": ("flext_core.constants", "FlextConstants"),
        "categorization": "flext_ldif.services.categorization",
        "conversion": "flext_ldif.services.conversion",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "detector": "flext_ldif.services.detector",
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "entries": "flext_ldif.services.entries",
        "filters": "flext_ldif.services.filters",
        "h": ("flext_core.handlers", "FlextHandlers"),
        "m": ("flext_core.models", "FlextModels"),
        "migration": "flext_ldif.services.migration",
        "p": ("flext_core.protocols", "FlextProtocols"),
        "parser": "flext_ldif.services.parser",
        "pipeline": "flext_ldif.services.pipeline",
        "processing": "flext_ldif.services.processing",
        "r": ("flext_core.result", "FlextResult"),
        "rfc_validation": "flext_ldif.services.rfc_validation",
        "s": ("flext_core.service", "FlextService"),
        "server": "flext_ldif.services.server",
        "statistics": "flext_ldif.services.statistics",
        "t": ("flext_core.typings", "FlextTypes"),
        "transformers": "flext_ldif.services.transformers",
        "u": ("flext_core.utilities", "FlextUtilities"),
        "writer": "flext_ldif.services.writer",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)

__all__ = [
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
    "c",
    "categorization",
    "conversion",
    "d",
    "detector",
    "e",
    "entries",
    "filters",
    "h",
    "m",
    "migration",
    "p",
    "parser",
    "pipeline",
    "processing",
    "processing_pipeline_service",
    "r",
    "rfc_validation",
    "s",
    "server",
    "statistics",
    "t",
    "transformers",
    "u",
    "writer",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
