# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""FLEXT-LDIF Services - Internal Business Logic Layer."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

from flext_ldif.services._services import _LAZY_IMPORTS as _CHILD_LAZY_0

if TYPE_CHECKING:
    from flext_ldif.services._services import *
    from flext_ldif.services.acl import *
    from flext_ldif.services.analysis import *
    from flext_ldif.services.categorization import *
    from flext_ldif.services.conversion import *
    from flext_ldif.services.detector import *
    from flext_ldif.services.entries import *
    from flext_ldif.services.filters import *
    from flext_ldif.services.migration import *
    from flext_ldif.services.parser import *
    from flext_ldif.services.pipeline import *
    from flext_ldif.services.processing import *
    from flext_ldif.services.rfc_validation import *
    from flext_ldif.services.server import *
    from flext_ldif.services.statistics import *
    from flext_ldif.services.transformers import *
    from flext_ldif.services.writer import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    **_CHILD_LAZY_0,
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
    "categorization": "flext_ldif.services.categorization",
    "conversion": "flext_ldif.services.conversion",
    "detector": "flext_ldif.services.detector",
    "entries": "flext_ldif.services.entries",
    "filters": "flext_ldif.services.filters",
    "migration": "flext_ldif.services.migration",
    "parser": "flext_ldif.services.parser",
    "pipeline": "flext_ldif.services.pipeline",
    "processing": "flext_ldif.services.processing",
    "rfc_validation": "flext_ldif.services.rfc_validation",
    "server": "flext_ldif.services.server",
    "statistics": "flext_ldif.services.statistics",
    "transformers": "flext_ldif.services.transformers",
    "writer": "flext_ldif.services.writer",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
