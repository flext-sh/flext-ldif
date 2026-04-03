# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Services package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import flext_ldif.services._services.processing_pipeline_service as _flext_ldif_services__services_processing_pipeline_service

    processing_pipeline_service = (
        _flext_ldif_services__services_processing_pipeline_service
    )
    from flext_ldif.services._services.processing_pipeline_service import (
        FlextLdifProcessingPipelineService,
    )
_LAZY_IMPORTS = {
    "FlextLdifProcessingPipelineService": "flext_ldif.services._services.processing_pipeline_service",
    "processing_pipeline_service": "flext_ldif.services._services.processing_pipeline_service",
}

__all__ = [
    "FlextLdifProcessingPipelineService",
    "processing_pipeline_service",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
