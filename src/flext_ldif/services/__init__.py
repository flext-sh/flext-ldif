# AUTO-GENERATED FILE — Regenerate with: make gen
"""Services package."""

from __future__ import annotations

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

_LAZY_IMPORTS = merge_lazy_imports(
    ("._services",),
    build_lazy_import_map(
        {
            ".acl": ("FlextLdifAcl",),
            ".analysis": ("FlextLdifAnalysis",),
            ".categorization": ("FlextLdifCategorization",),
            ".conversion": ("FlextLdifConversion",),
            ".detector": (
                "FlextLdifDetector",
                "FlextLdifDetectorMixin",
            ),
            ".entries": ("FlextLdifEntries",),
            ".filters": ("FlextLdifFilters",),
            ".migration": ("FlextLdifMigrationPipeline",),
            ".parser": (
                "FlextLdifParser",
                "FlextLdifParserMixin",
            ),
            ".pipeline": ("FlextLdifProcessingPipeline",),
            ".processing": ("FlextLdifProcessing",),
            ".rfc_validation": ("FlextLdifValidation",),
            ".server": ("FlextLdifServer",),
            ".statistics": ("FlextLdifStatistics",),
            ".transformers": ("FlextLdifTransformer",),
            ".writer": (
                "FlextLdifWriter",
                "FlextLdifWriterMixin",
            ),
        },
    ),
    exclude_names=(
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
    ),
    module_name=__name__,
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
