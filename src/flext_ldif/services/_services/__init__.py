# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Services package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_ldif import processing_pipeline_service
    from flext_ldif.processing_pipeline_service import (
        FlextLdifProcessingPipelineService,
    )

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FlextLdifProcessingPipelineService": "flext_ldif.processing_pipeline_service",
    "processing_pipeline_service": "flext_ldif.processing_pipeline_service",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
