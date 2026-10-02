# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.services package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

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
    from flext_ldif.services.processing import FlextLdifProcessing
    from flext_ldif.services.server import FlextLdifServer
    from flext_ldif.services.statistics import FlextLdifStatistics
    from flext_ldif.services.validation import FlextLdifValidation
    from flext_ldif.services.writer import FlextLdifWriter


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
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
