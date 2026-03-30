# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Internal module for FlextLdifModels nested classes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._models import (
        base as base,
        collections as collections,
        domain as domain,
        domain_entries as domain_entries,
        events as events,
        metadata as metadata,
        processing as processing,
        results as results,
        settings as settings,
    )
    from flext_ldif._models.base import FlextLdifModelsBases as FlextLdifModelsBases
    from flext_ldif._models.collections import (
        FlextLdifModelsCollections as FlextLdifModelsCollections,
    )
    from flext_ldif._models.domain import (
        FlextLdifModelsDomains as FlextLdifModelsDomains,
    )
    from flext_ldif._models.domain_entries import (
        FlextLdifModelsDomainsEntries as FlextLdifModelsDomainsEntries,
    )
    from flext_ldif._models.events import FlextLdifModelsEvents as FlextLdifModelsEvents
    from flext_ldif._models.metadata import (
        FlextLdifModelsMetadata as FlextLdifModelsMetadata,
    )
    from flext_ldif._models.processing import (
        FlextLdifModelsProcessing as FlextLdifModelsProcessing,
    )
    from flext_ldif._models.results import (
        FlextLdifModelsResults as FlextLdifModelsResults,
    )
    from flext_ldif._models.settings import (
        FlextLdifModelsSettings as FlextLdifModelsSettings,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdifModelsBases": ["flext_ldif._models.base", "FlextLdifModelsBases"],
    "FlextLdifModelsCollections": [
        "flext_ldif._models.collections",
        "FlextLdifModelsCollections",
    ],
    "FlextLdifModelsDomains": ["flext_ldif._models.domain", "FlextLdifModelsDomains"],
    "FlextLdifModelsDomainsEntries": [
        "flext_ldif._models.domain_entries",
        "FlextLdifModelsDomainsEntries",
    ],
    "FlextLdifModelsEvents": ["flext_ldif._models.events", "FlextLdifModelsEvents"],
    "FlextLdifModelsMetadata": [
        "flext_ldif._models.metadata",
        "FlextLdifModelsMetadata",
    ],
    "FlextLdifModelsProcessing": [
        "flext_ldif._models.processing",
        "FlextLdifModelsProcessing",
    ],
    "FlextLdifModelsResults": ["flext_ldif._models.results", "FlextLdifModelsResults"],
    "FlextLdifModelsSettings": [
        "flext_ldif._models.settings",
        "FlextLdifModelsSettings",
    ],
    "base": ["flext_ldif._models.base", ""],
    "collections": ["flext_ldif._models.collections", ""],
    "domain": ["flext_ldif._models.domain", ""],
    "domain_entries": ["flext_ldif._models.domain_entries", ""],
    "events": ["flext_ldif._models.events", ""],
    "metadata": ["flext_ldif._models.metadata", ""],
    "processing": ["flext_ldif._models.processing", ""],
    "results": ["flext_ldif._models.results", ""],
    "settings": ["flext_ldif._models.settings", ""],
}

_EXPORTS: Sequence[str] = [
    "FlextLdifModelsBases",
    "FlextLdifModelsCollections",
    "FlextLdifModelsDomains",
    "FlextLdifModelsDomainsEntries",
    "FlextLdifModelsEvents",
    "FlextLdifModelsMetadata",
    "FlextLdifModelsProcessing",
    "FlextLdifModelsResults",
    "FlextLdifModelsSettings",
    "base",
    "collections",
    "domain",
    "domain_entries",
    "events",
    "metadata",
    "processing",
    "results",
    "settings",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
