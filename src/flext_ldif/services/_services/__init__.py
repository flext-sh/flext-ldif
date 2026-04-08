# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Services package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "FlextLdifProcessingPipelineService": (
        "flext_ldif.services._services.processing_pipeline_service",
        "FlextLdifProcessingPipelineService",
    ),
    "processing_pipeline_service": "flext_ldif.services._services.processing_pipeline_service",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
