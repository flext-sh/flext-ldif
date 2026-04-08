# AUTO-GENERATED FILE — Regenerate with: make gen
from __future__ import annotations

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

_LAZY_IMPORTS = merge_lazy_imports(
    ("._services",),
    {
        "FlextLdifAcl": ".acl",
        "FlextLdifAnalysis": ".analysis",
        "FlextLdifCategorization": ".categorization",
        "FlextLdifConversion": ".conversion",
        "FlextLdifDetector": ".detector",
        "FlextLdifDetectorMixin": ".detector",
        "FlextLdifEntries": ".entries",
        "FlextLdifFilters": ".filters",
        "FlextLdifMigrationPipeline": ".migration",
        "FlextLdifParser": ".parser",
        "FlextLdifParserMixin": ".parser",
        "FlextLdifProcessing": ".processing",
        "FlextLdifProcessingPipeline": ".pipeline",
        "FlextLdifServer": ".server",
        "FlextLdifStatistics": ".statistics",
        "FlextLdifTransformer": ".transformers",
        "FlextLdifValidation": ".rfc_validation",
        "FlextLdifWriter": ".writer",
        "FlextLdifWriterMixin": ".writer",
    },
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
