# AUTO-GENERATED FILE — Regenerate with: make gen
"""Services package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.services.acl import FlextLdifAcl as FlextLdifAcl
    from flext_ldif.services.analysis import FlextLdifAnalysis as FlextLdifAnalysis
    from flext_ldif.services.categorization import (
        FlextLdifCategorization as FlextLdifCategorization,
    )
    from flext_ldif.services.conversion import (
        FlextLdifConversion as FlextLdifConversion,
    )
    from flext_ldif.services.conversion_acl import (
        FlextLdifConversionAclMixin as FlextLdifConversionAclMixin,
    )
    from flext_ldif.services.conversion_acl_preserve import (
        FlextLdifConversionAclPreserveMixin as FlextLdifConversionAclPreserveMixin,
    )
    from flext_ldif.services.conversion_entry import (
        FlextLdifConversionEntryMixin as FlextLdifConversionEntryMixin,
    )
    from flext_ldif.services.conversion_metadata import (
        FlextLdifConversionMetadataMixin as FlextLdifConversionMetadataMixin,
    )
    from flext_ldif.services.conversion_schema import (
        FlextLdifConversionSchemaMixin as FlextLdifConversionSchemaMixin,
    )
    from flext_ldif.services.conversion_schema_entry import (
        FlextLdifConversionSchemaEntryMixin as FlextLdifConversionSchemaEntryMixin,
    )
    from flext_ldif.services.conversion_support import (
        FlextLdifConversionSupportMixin as FlextLdifConversionSupportMixin,
    )
    from flext_ldif.services.detector import FlextLdifDetector as FlextLdifDetector
    from flext_ldif.services.entries import FlextLdifEntries as FlextLdifEntries
    from flext_ldif.services.filters import FlextLdifFilters as FlextLdifFilters
    from flext_ldif.services.migration import (
        FlextLdifMigrationPipeline as FlextLdifMigrationPipeline,
    )
    from flext_ldif.services.parser import FlextLdifParser as FlextLdifParser
    from flext_ldif.services.pipeline import (
        FlextLdifProcessingPipeline as FlextLdifProcessingPipeline,
    )
    from flext_ldif.services.processing import (
        FlextLdifProcessing as FlextLdifProcessing,
    )
    from flext_ldif.services.server import FlextLdifServer as FlextLdifServer
    from flext_ldif.services.statistics import (
        FlextLdifStatistics as FlextLdifStatistics,
    )
    from flext_ldif.services.transformers import (
        FlextLdifTransformer as FlextLdifTransformer,
    )
    from flext_ldif.services.validation import (
        FlextLdifValidation as FlextLdifValidation,
    )
    from flext_ldif.services.writer import FlextLdifWriter as FlextLdifWriter
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
