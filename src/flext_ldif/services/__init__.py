# AUTO-GENERATED FILE — Regenerate with: make gen
"""Services package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.services.acl import FlextLdifAcl
    from flext_ldif.services.analysis import FlextLdifAnalysis
    from flext_ldif.services.categorization import FlextLdifCategorization
    from flext_ldif.services.conversion import FlextLdifConversion
    from flext_ldif.services.conversion_acl import FlextLdifConversionAclMixin
    from flext_ldif.services.conversion_acl_preserve import (
        FlextLdifConversionAclPreserveMixin,
    )
    from flext_ldif.services.conversion_entry import FlextLdifConversionEntryMixin
    from flext_ldif.services.conversion_metadata import FlextLdifConversionMetadataMixin
    from flext_ldif.services.conversion_schema import FlextLdifConversionSchemaMixin
    from flext_ldif.services.conversion_schema_entry import (
        FlextLdifConversionSchemaEntryMixin,
    )
    from flext_ldif.services.conversion_support import FlextLdifConversionSupportMixin
    from flext_ldif.services.detector import FlextLdifDetector
    from flext_ldif.services.entries import FlextLdifEntries
    from flext_ldif.services.filters import FlextLdifFilters
    from flext_ldif.services.migration import FlextLdifMigrationPipeline
    from flext_ldif.services.parser import FlextLdifParser
    from flext_ldif.services.pipeline import FlextLdifProcessingPipeline
    from flext_ldif.services.processing import FlextLdifProcessing
    from flext_ldif.services.server import FlextLdifServer
    from flext_ldif.services.statistics import FlextLdifStatistics
    from flext_ldif.services.transformers import FlextLdifTransformer
    from flext_ldif.services.validation import FlextLdifValidation
    from flext_ldif.services.writer import FlextLdifWriter
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".acl": ("FlextLdifAcl",),
        ".analysis": ("FlextLdifAnalysis",),
        ".categorization": ("FlextLdifCategorization",),
        ".conversion": ("FlextLdifConversion",),
        ".conversion_acl": ("FlextLdifConversionAclMixin",),
        ".conversion_acl_preserve": ("FlextLdifConversionAclPreserveMixin",),
        ".conversion_entry": ("FlextLdifConversionEntryMixin",),
        ".conversion_metadata": ("FlextLdifConversionMetadataMixin",),
        ".conversion_schema": ("FlextLdifConversionSchemaMixin",),
        ".conversion_schema_entry": ("FlextLdifConversionSchemaEntryMixin",),
        ".conversion_support": ("FlextLdifConversionSupportMixin",),
        ".detector": ("FlextLdifDetector",),
        ".entries": ("FlextLdifEntries",),
        ".filters": ("FlextLdifFilters",),
        ".migration": ("FlextLdifMigrationPipeline",),
        ".parser": ("FlextLdifParser",),
        ".pipeline": ("FlextLdifProcessingPipeline",),
        ".processing": ("FlextLdifProcessing",),
        ".server": ("FlextLdifServer",),
        ".statistics": ("FlextLdifStatistics",),
        ".transformers": ("FlextLdifTransformer",),
        ".validation": ("FlextLdifValidation",),
        ".writer": ("FlextLdifWriter",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
