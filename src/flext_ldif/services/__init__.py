# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""FLEXT-LDIF Services - Internal Business Logic Layer."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
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
    from flext_ldif.services._services import processing_pipeline_service
    from flext_ldif.services._services.processing_pipeline_service import (
        FlextLdifProcessingPipelineService,
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


_LAZY_CACHE: MutableMapping[str, FlextTypes.ModuleExport] = {}


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562).

    A local cache ``_LAZY_CACHE`` persists resolved objects across repeated
    accesses during process lifetime.

    Args:
        name: Attribute name requested by dir()/import.

    Returns:
        Lazy-loaded module export type.

    Raises:
        AttributeError: If attribute not registered.

    """
    if name in _LAZY_CACHE:
        return _LAZY_CACHE[name]

    value = lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)
    _LAZY_CACHE[name] = value
    return value


def __dir__() -> Sequence[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
