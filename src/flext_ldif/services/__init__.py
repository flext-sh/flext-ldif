# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.services package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.services.acl import FlextLdifAcl
    from flext_ldif.services.analysis import FlextLdifAnalysis
    from flext_ldif.services.categorization import FlextLdifCategorization
    from flext_ldif.services.categorization_filtering import (
        FlextLdifCategorizationFiltering,
    )
    from flext_ldif.services.categorization_rules import FlextLdifCategorizationRules
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
    "FlextLdifCategorizationFiltering",
    "FlextLdifCategorizationRules",
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

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifAcl": ".acl",
        "FlextLdifAnalysis": ".analysis",
        "FlextLdifCategorization": ".categorization",
        "FlextLdifCategorizationFiltering": ".categorization_filtering",
        "FlextLdifCategorizationRules": ".categorization_rules",
        "FlextLdifConversion": ".conversion",
        "FlextLdifConversionAclMixin": ".conversion_acl",
        "FlextLdifConversionAclPreserveMixin": ".conversion_acl_preserve",
        "FlextLdifConversionEntryMixin": ".conversion_entry",
        "FlextLdifConversionMetadataMixin": ".conversion_metadata",
        "FlextLdifConversionSchemaEntryMixin": ".conversion_schema_entry",
        "FlextLdifConversionSchemaMixin": ".conversion_schema",
        "FlextLdifConversionSupportMixin": ".conversion_support",
        "FlextLdifDetector": ".detector",
        "FlextLdifEntries": ".entries",
        "FlextLdifFilters": ".filters",
        "FlextLdifMigrationPipeline": ".migration",
        "FlextLdifParser": ".parser",
        "FlextLdifProcessing": ".processing",
        "FlextLdifServer": ".server",
        "FlextLdifStatistics": ".statistics",
        "FlextLdifValidation": ".validation",
        "FlextLdifWriter": ".writer",
    }),
    public_exports=__all__,
)
