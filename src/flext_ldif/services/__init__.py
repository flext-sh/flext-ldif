# AUTO-GENERATED FILE — Regenerate with: make gen
"""Services package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".acl": ("FlextLdifAcl",),
        ".analysis": ("FlextLdifAnalysis",),
        ".categorization": ("FlextLdifCategorization",),
        ".conversion": ("FlextLdifConversion",),
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
