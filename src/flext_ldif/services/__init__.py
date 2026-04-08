# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Services package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

_LAZY_IMPORTS = merge_lazy_imports(
    ("flext_ldif.services._services",),
    {
        "FlextLdifAcl": ("flext_ldif.services.acl", "FlextLdifAcl"),
        "FlextLdifAnalysis": ("flext_ldif.services.analysis", "FlextLdifAnalysis"),
        "FlextLdifCategorization": (
            "flext_ldif.services.categorization",
            "FlextLdifCategorization",
        ),
        "FlextLdifConversion": (
            "flext_ldif.services.conversion",
            "FlextLdifConversion",
        ),
        "FlextLdifDetector": ("flext_ldif.services.detector", "FlextLdifDetector"),
        "FlextLdifDetectorMixin": (
            "flext_ldif.services.detector",
            "FlextLdifDetectorMixin",
        ),
        "FlextLdifEntries": ("flext_ldif.services.entries", "FlextLdifEntries"),
        "FlextLdifFilters": ("flext_ldif.services.filters", "FlextLdifFilters"),
        "FlextLdifMigrationPipeline": (
            "flext_ldif.services.migration",
            "FlextLdifMigrationPipeline",
        ),
        "FlextLdifParser": ("flext_ldif.services.parser", "FlextLdifParser"),
        "FlextLdifParserMixin": ("flext_ldif.services.parser", "FlextLdifParserMixin"),
        "FlextLdifProcessing": (
            "flext_ldif.services.processing",
            "FlextLdifProcessing",
        ),
        "FlextLdifProcessingPipeline": (
            "flext_ldif.services.pipeline",
            "FlextLdifProcessingPipeline",
        ),
        "FlextLdifServer": ("flext_ldif.services.server", "FlextLdifServer"),
        "FlextLdifStatistics": (
            "flext_ldif.services.statistics",
            "FlextLdifStatistics",
        ),
        "FlextLdifTransformer": (
            "flext_ldif.services.transformers",
            "FlextLdifTransformer",
        ),
        "FlextLdifValidation": (
            "flext_ldif.services.rfc_validation",
            "FlextLdifValidation",
        ),
        "FlextLdifWriter": ("flext_ldif.services.writer", "FlextLdifWriter"),
        "FlextLdifWriterMixin": ("flext_ldif.services.writer", "FlextLdifWriterMixin"),
        "_services": "flext_ldif.services._services",
        "acl": "flext_ldif.services.acl",
        "analysis": "flext_ldif.services.analysis",
        "c": ("flext_core.constants", "FlextConstants"),
        "categorization": "flext_ldif.services.categorization",
        "conversion": "flext_ldif.services.conversion",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "detector": "flext_ldif.services.detector",
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "entries": "flext_ldif.services.entries",
        "filters": "flext_ldif.services.filters",
        "h": ("flext_core.handlers", "FlextHandlers"),
        "m": ("flext_core.models", "FlextModels"),
        "migration": "flext_ldif.services.migration",
        "p": ("flext_core.protocols", "FlextProtocols"),
        "parser": "flext_ldif.services.parser",
        "pipeline": "flext_ldif.services.pipeline",
        "processing": "flext_ldif.services.processing",
        "r": ("flext_core.result", "FlextResult"),
        "rfc_validation": "flext_ldif.services.rfc_validation",
        "s": ("flext_core.service", "FlextService"),
        "server": "flext_ldif.services.server",
        "statistics": "flext_ldif.services.statistics",
        "t": ("flext_core.typings", "FlextTypes"),
        "transformers": "flext_ldif.services.transformers",
        "u": ("flext_core.utilities", "FlextUtilities"),
        "writer": "flext_ldif.services.writer",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)
_ = _LAZY_IMPORTS.pop("cleanup_submodule_namespace", None)
_ = _LAZY_IMPORTS.pop("install_lazy_exports", None)
_ = _LAZY_IMPORTS.pop("lazy_getattr", None)
_ = _LAZY_IMPORTS.pop("logger", None)
_ = _LAZY_IMPORTS.pop("merge_lazy_imports", None)
_ = _LAZY_IMPORTS.pop("output", None)
_ = _LAZY_IMPORTS.pop("output_reporting", None)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
