# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""FLEXT-LDIF Services - Internal Business Logic Layer."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from flext_ldif.services import _services
    from flext_ldif.services._services.processing_pipeline_service import (
        FlextLdifProcessingPipelineService,
        FlextLdifProcessingPipelineService as s,
    )
    from flext_ldif.services.acl import FlextLdifAcl
    from flext_ldif.services.analysis import FlextLdifAnalysis
    from flext_ldif.services.categorization import FlextLdifCategorization
    from flext_ldif.services.conversion import FlextLdifConversion
    from flext_ldif.services.detector import FlextLdifDetector
    from flext_ldif.services.dn import FlextLdifDn
    from flext_ldif.services.entries import FlextLdifEntries
    from flext_ldif.services.filters import FlextLdifFilters
    from flext_ldif.services.migration import FlextLdifMigrationPipeline
    from flext_ldif.services.parser import FlextLdifParser
    from flext_ldif.services.pipeline import ProcessingPipeline
    from flext_ldif.services.processing import FlextLdifProcessing
    from flext_ldif.services.registry import FlextLdifServiceRegistry
    from flext_ldif.services.schema import FlextLdifSchema
    from flext_ldif.services.server import FlextLdifServer
    from flext_ldif.services.sorting import FlextLdifSorting
    from flext_ldif.services.statistics import FlextLdifStatistics
    from flext_ldif.services.syntax import FlextLdifSyntax
    from flext_ldif.services.transformers import ServerTransformer
    from flext_ldif.services.validation import FlextLdifValidation
    from flext_ldif.services.writer import FlextLdifWriter

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdifAcl": ("flext_ldif.services.acl", "FlextLdifAcl"),
    "FlextLdifAnalysis": ("flext_ldif.services.analysis", "FlextLdifAnalysis"),
    "FlextLdifCategorization": (
        "flext_ldif.services.categorization",
        "FlextLdifCategorization",
    ),
    "FlextLdifConversion": ("flext_ldif.services.conversion", "FlextLdifConversion"),
    "FlextLdifDetector": ("flext_ldif.services.detector", "FlextLdifDetector"),
    "FlextLdifDn": ("flext_ldif.services.dn", "FlextLdifDn"),
    "FlextLdifEntries": ("flext_ldif.services.entries", "FlextLdifEntries"),
    "FlextLdifFilters": ("flext_ldif.services.filters", "FlextLdifFilters"),
    "FlextLdifMigrationPipeline": (
        "flext_ldif.services.migration",
        "FlextLdifMigrationPipeline",
    ),
    "FlextLdifParser": ("flext_ldif.services.parser", "FlextLdifParser"),
    "FlextLdifProcessing": ("flext_ldif.services.processing", "FlextLdifProcessing"),
    "FlextLdifProcessingPipelineService": (
        "flext_ldif.services._services.processing_pipeline_service",
        "FlextLdifProcessingPipelineService",
    ),
    "FlextLdifSchema": ("flext_ldif.services.schema", "FlextLdifSchema"),
    "FlextLdifServer": ("flext_ldif.services.server", "FlextLdifServer"),
    "FlextLdifServiceRegistry": (
        "flext_ldif.services.registry",
        "FlextLdifServiceRegistry",
    ),
    "FlextLdifSorting": ("flext_ldif.services.sorting", "FlextLdifSorting"),
    "FlextLdifStatistics": ("flext_ldif.services.statistics", "FlextLdifStatistics"),
    "FlextLdifSyntax": ("flext_ldif.services.syntax", "FlextLdifSyntax"),
    "FlextLdifValidation": ("flext_ldif.services.validation", "FlextLdifValidation"),
    "FlextLdifWriter": ("flext_ldif.services.writer", "FlextLdifWriter"),
    "ProcessingPipeline": ("flext_ldif.services.pipeline", "ProcessingPipeline"),
    "ServerTransformer": ("flext_ldif.services.transformers", "ServerTransformer"),
    "_services": ("flext_ldif.services._services", ""),
    "s": (
        "flext_ldif.services._services.processing_pipeline_service",
        "FlextLdifProcessingPipelineService",
    ),
}

__all__ = [
    "FlextLdifAcl",
    "FlextLdifAnalysis",
    "FlextLdifCategorization",
    "FlextLdifConversion",
    "FlextLdifDetector",
    "FlextLdifDn",
    "FlextLdifEntries",
    "FlextLdifFilters",
    "FlextLdifMigrationPipeline",
    "FlextLdifParser",
    "FlextLdifProcessing",
    "FlextLdifProcessingPipelineService",
    "FlextLdifSchema",
    "FlextLdifServer",
    "FlextLdifServiceRegistry",
    "FlextLdifSorting",
    "FlextLdifStatistics",
    "FlextLdifSyntax",
    "FlextLdifValidation",
    "FlextLdifWriter",
    "ProcessingPipeline",
    "ServerTransformer",
    "_services",
    "s",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
