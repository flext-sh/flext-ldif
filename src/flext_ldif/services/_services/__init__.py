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

    from flext_ldif.services._services.processing_pipeline_service import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "FlextLdifProcessingPipelineService": "flext_ldif.services._services.processing_pipeline_service",
    "processing_pipeline_service": "flext_ldif.services._services.processing_pipeline_service",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
