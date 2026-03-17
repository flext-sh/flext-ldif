"""Result facade exports for flext_ldif."""

from __future__ import annotations

from flext_ldif._models.collections import FlextLdifModelsCollections
from flext_ldif._models.results import FlextLdifModelsResults

DynamicCounts = FlextLdifModelsCollections.DynamicCounts

__all__ = ["DynamicCounts", "FlextLdifModelsResults"]
