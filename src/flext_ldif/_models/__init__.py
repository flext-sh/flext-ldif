# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Models package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import flext_ldif._models.base as _flext_ldif__models_base

    base = _flext_ldif__models_base
    import flext_ldif._models.collections as _flext_ldif__models_collections

    collections = _flext_ldif__models_collections
    import flext_ldif._models.domain as _flext_ldif__models_domain

    domain = _flext_ldif__models_domain
    import flext_ldif._models.domain_entries as _flext_ldif__models_domain_entries

    domain_entries = _flext_ldif__models_domain_entries
    import flext_ldif._models.events as _flext_ldif__models_events

    events = _flext_ldif__models_events
    import flext_ldif._models.metadata as _flext_ldif__models_metadata

    metadata = _flext_ldif__models_metadata
    import flext_ldif._models.processing as _flext_ldif__models_processing

    processing = _flext_ldif__models_processing
    import flext_ldif._models.results as _flext_ldif__models_results

    results = _flext_ldif__models_results
    import flext_ldif._models.settings as _flext_ldif__models_settings

    settings = _flext_ldif__models_settings

    _ = (
        FlextLdifModelsBases,
        FlextLdifModelsCollections,
        FlextLdifModelsDomains,
        FlextLdifModelsDomainsEntries,
        FlextLdifModelsEvents,
        FlextLdifModelsMetadata,
        FlextLdifModelsProcessing,
        FlextLdifModelsResults,
        FlextLdifModelsSettings,
        base,
        collections,
        domain,
        domain_entries,
        events,
        metadata,
        processing,
        results,
        settings,
    )
_LAZY_IMPORTS = {
    "FlextLdifModelsBases": "flext_ldif._models.base",
    "FlextLdifModelsCollections": "flext_ldif._models.collections",
    "FlextLdifModelsDomains": "flext_ldif._models.domain",
    "FlextLdifModelsDomainsEntries": "flext_ldif._models.domain_entries",
    "FlextLdifModelsEvents": "flext_ldif._models.events",
    "FlextLdifModelsMetadata": "flext_ldif._models.metadata",
    "FlextLdifModelsProcessing": "flext_ldif._models.processing",
    "FlextLdifModelsResults": "flext_ldif._models.results",
    "FlextLdifModelsSettings": "flext_ldif._models.settings",
    "base": "flext_ldif._models.base",
    "collections": "flext_ldif._models.collections",
    "domain": "flext_ldif._models.domain",
    "domain_entries": "flext_ldif._models.domain_entries",
    "events": "flext_ldif._models.events",
    "metadata": "flext_ldif._models.metadata",
    "processing": "flext_ldif._models.processing",
    "results": "flext_ldif._models.results",
    "settings": "flext_ldif._models.settings",
}

__all__ = [
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
