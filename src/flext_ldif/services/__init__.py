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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
