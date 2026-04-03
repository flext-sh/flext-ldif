# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Services package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u
    from flext_ldif import (
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
        processing_pipeline_service,
        rfc_validation,
        server,
        statistics,
        transformers,
        writer,
    )
    from flext_ldif._services import FlextLdifProcessingPipelineService
    from flext_ldif.acl import FlextLdifAcl
    from flext_ldif.analysis import FlextLdifAnalysis
    from flext_ldif.categorization import FlextLdifCategorization
    from flext_ldif.conversion import FlextLdifConversion
    from flext_ldif.detector import FlextLdifDetector, FlextLdifDetectorMixin
    from flext_ldif.entries import FlextLdifEntries
    from flext_ldif.filters import FlextLdifFilters
    from flext_ldif.migration import FlextLdifMigrationPipeline
    from flext_ldif.parser import FlextLdifParser, FlextLdifParserMixin
    from flext_ldif.pipeline import FlextLdifProcessingPipeline
    from flext_ldif.processing import FlextLdifProcessing
    from flext_ldif.rfc_validation import FlextLdifValidation
    from flext_ldif.server import FlextLdifServer
    from flext_ldif.statistics import FlextLdifStatistics
    from flext_ldif.transformers import FlextLdifTransformer
    from flext_ldif.writer import FlextLdifWriter, FlextLdifWriterMixin

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = merge_lazy_imports(
    ("flext_ldif._services",),
    {
        "FlextLdifAcl": "flext_ldif.acl",
        "FlextLdifAnalysis": "flext_ldif.analysis",
        "FlextLdifCategorization": "flext_ldif.categorization",
        "FlextLdifConversion": "flext_ldif.conversion",
        "FlextLdifDetector": "flext_ldif.detector",
        "FlextLdifDetectorMixin": "flext_ldif.detector",
        "FlextLdifEntries": "flext_ldif.entries",
        "FlextLdifFilters": "flext_ldif.filters",
        "FlextLdifMigrationPipeline": "flext_ldif.migration",
        "FlextLdifParser": "flext_ldif.parser",
        "FlextLdifParserMixin": "flext_ldif.parser",
        "FlextLdifProcessing": "flext_ldif.processing",
        "FlextLdifProcessingPipeline": "flext_ldif.pipeline",
        "FlextLdifServer": "flext_ldif.server",
        "FlextLdifStatistics": "flext_ldif.statistics",
        "FlextLdifTransformer": "flext_ldif.transformers",
        "FlextLdifValidation": "flext_ldif.rfc_validation",
        "FlextLdifWriter": "flext_ldif.writer",
        "FlextLdifWriterMixin": "flext_ldif.writer",
        "_services": "flext_ldif._services",
        "acl": "flext_ldif.acl",
        "analysis": "flext_ldif.analysis",
        "c": ("flext_core.constants", "FlextConstants"),
        "categorization": "flext_ldif.categorization",
        "conversion": "flext_ldif.conversion",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "detector": "flext_ldif.detector",
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "entries": "flext_ldif.entries",
        "filters": "flext_ldif.filters",
        "h": ("flext_core.handlers", "FlextHandlers"),
        "m": ("flext_core.models", "FlextModels"),
        "migration": "flext_ldif.migration",
        "p": ("flext_core.protocols", "FlextProtocols"),
        "parser": "flext_ldif.parser",
        "pipeline": "flext_ldif.pipeline",
        "processing": "flext_ldif.processing",
        "processing_pipeline_service": "flext_ldif.processing_pipeline_service",
        "r": ("flext_core.result", "FlextResult"),
        "rfc_validation": "flext_ldif.rfc_validation",
        "s": ("flext_core.service", "FlextService"),
        "server": "flext_ldif.server",
        "statistics": "flext_ldif.statistics",
        "t": ("flext_core.typings", "FlextTypes"),
        "transformers": "flext_ldif.transformers",
        "u": ("flext_core.utilities", "FlextUtilities"),
        "writer": "flext_ldif.writer",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
