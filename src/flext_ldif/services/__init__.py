# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.services package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .acl import FlextLdifAcl
    from .analysis import FlextLdifAnalysis
    from .categorization import FlextLdifCategorization
    from .conversion import FlextLdifConversion
    from .conversion_acl import FlextLdifConversionAclMixin
    from .conversion_acl_preserve import FlextLdifConversionAclPreserveMixin
    from .conversion_entry import FlextLdifConversionEntryMixin
    from .conversion_metadata import FlextLdifConversionMetadataMixin
    from .conversion_schema import FlextLdifConversionSchemaMixin
    from .conversion_schema_entry import FlextLdifConversionSchemaEntryMixin
    from .conversion_support import FlextLdifConversionSupportMixin
    from .detector import FlextLdifDetector
    from .entries import FlextLdifEntries
    from .filters import FlextLdifFilters
    from .migration import FlextLdifMigrationPipeline
    from .parser import FlextLdifParser
    from .processing import FlextLdifProcessing
    from .server import FlextLdifServer
    from .statistics import FlextLdifStatistics
    from .validation import FlextLdifValidation
    from .writer import FlextLdifWriter
__all__: tuple[str, ...] = (
    "FlextLdifAcl",
    "FlextLdifAnalysis",
    "FlextLdifCategorization",
    "FlextLdifConversion",
    "FlextLdifConversionAclMixin",
    "FlextLdifConversionAclPreserveMixin",
    "FlextLdifConversionEntryMixin",
    "FlextLdifConversionMetadataMixin",
    "FlextLdifConversionSchemaEntryMixin",
    "FlextLdifConversionSchemaMixin",
    "FlextLdifConversionSupportMixin",
    "FlextLdifDetector",
    "FlextLdifEntries",
    "FlextLdifFilters",
    "FlextLdifMigrationPipeline",
    "FlextLdifParser",
    "FlextLdifProcessing",
    "FlextLdifServer",
    "FlextLdifStatistics",
    "FlextLdifValidation",
    "FlextLdifWriter",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
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
            ".processing": ("FlextLdifProcessing",),
            ".server": ("FlextLdifServer",),
            ".statistics": ("FlextLdifStatistics",),
            ".validation": ("FlextLdifValidation",),
            ".writer": ("FlextLdifWriter",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
