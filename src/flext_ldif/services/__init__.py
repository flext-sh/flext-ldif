# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.services package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.services.acl import FlextLdifAcl
    from flext_ldif.services.analysis import FlextLdifAnalysis
    from flext_ldif.services.categorization import FlextLdifCategorization
    from flext_ldif.services.categorization_filtering import (
        FlextLdifCategorizationFiltering,
    )
    from flext_ldif.services.categorization_rules import FlextLdifCategorizationRules
    from flext_ldif.services.conversion import FlextLdifConversion
    from flext_ldif.services.conversion_acl import FlextLdifConversionAcl
    from flext_ldif.services.conversion_acl_preserve import (
        FlextLdifConversionAclPreserve,
    )
    from flext_ldif.services.conversion_entry import FlextLdifConversionEntry
    from flext_ldif.services.conversion_metadata import FlextLdifConversionMetadata
    from flext_ldif.services.conversion_schema import FlextLdifConversionSchema
    from flext_ldif.services.conversion_schema_entry import (
        FlextLdifConversionSchemaEntry,
    )
    from flext_ldif.services.conversion_support import FlextLdifConversionSupport
    from flext_ldif.services.detector import FlextLdifDetector
    from flext_ldif.services.detector_scoring import FlextLdifDetectorScoring
    from flext_ldif.services.entries import FlextLdifEntries
    from flext_ldif.services.facade import FlextLdifFacade
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


__all__: tuple[str, ...] = (
    "FlextLdifAcl",
    "FlextLdifAnalysis",
    "FlextLdifCategorization",
    "FlextLdifCategorizationFiltering",
    "FlextLdifCategorizationRules",
    "FlextLdifConversion",
    "FlextLdifConversionAcl",
    "FlextLdifConversionAclPreserve",
    "FlextLdifConversionEntry",
    "FlextLdifConversionMetadata",
    "FlextLdifConversionSchema",
    "FlextLdifConversionSchemaEntry",
    "FlextLdifConversionSupport",
    "FlextLdifDetector",
    "FlextLdifDetectorScoring",
    "FlextLdifEntries",
    "FlextLdifFacade",
    "FlextLdifFilters",
    "FlextLdifMigrationPipeline",
    "FlextLdifParser",
    "FlextLdifProcessing",
    "FlextLdifProcessingPipeline",
    "FlextLdifServer",
    "FlextLdifStatistics",
    "FlextLdifTransformer",
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
        "FlextLdifConversionAcl": ".conversion_acl",
        "FlextLdifConversionAclPreserve": ".conversion_acl_preserve",
        "FlextLdifConversionEntry": ".conversion_entry",
        "FlextLdifConversionMetadata": ".conversion_metadata",
        "FlextLdifConversionSchemaEntry": ".conversion_schema_entry",
        "FlextLdifConversionSchema": ".conversion_schema",
        "FlextLdifConversionSupport": ".conversion_support",
        "FlextLdifDetector": ".detector",
        "FlextLdifDetectorScoring": ".detector_scoring",
        "FlextLdifEntries": ".entries",
        "FlextLdifFacade": ".facade",
        "FlextLdifFilters": ".filters",
        "FlextLdifMigrationPipeline": ".migration",
        "FlextLdifParser": ".parser",
        "FlextLdifProcessing": ".processing",
        "FlextLdifProcessingPipeline": ".pipeline",
        "FlextLdifServer": ".server",
        "FlextLdifStatistics": ".statistics",
        "FlextLdifTransformer": ".transformers",
        "FlextLdifValidation": ".validation",
        "FlextLdifWriter": ".writer",
    }),
    public_exports=__all__,
)
