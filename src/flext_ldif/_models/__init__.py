# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Models package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_ldif import (
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
    from flext_ldif.base import FlextLdifModelsBases
    from flext_ldif.collections import FlextLdifModelsCollections
    from flext_ldif.domain import FlextLdifModelsDomains
    from flext_ldif.domain_entries import FlextLdifModelsDomainsEntries
    from flext_ldif.events import FlextLdifModelsEvents
    from flext_ldif.metadata import FlextLdifModelsMetadata
    from flext_ldif.processing import FlextLdifModelsProcessing
    from flext_ldif.results import FlextLdifModelsResults
    from flext_ldif.settings import FlextLdifModelsSettings

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FlextLdifModelsBases": "flext_ldif.base",
    "FlextLdifModelsCollections": "flext_ldif.collections",
    "FlextLdifModelsDomains": "flext_ldif.domain",
    "FlextLdifModelsDomainsEntries": "flext_ldif.domain_entries",
    "FlextLdifModelsEvents": "flext_ldif.events",
    "FlextLdifModelsMetadata": "flext_ldif.metadata",
    "FlextLdifModelsProcessing": "flext_ldif.processing",
    "FlextLdifModelsResults": "flext_ldif.results",
    "FlextLdifModelsSettings": "flext_ldif.settings",
    "base": "flext_ldif.base",
    "collections": "flext_ldif.collections",
    "domain": "flext_ldif.domain",
    "domain_entries": "flext_ldif.domain_entries",
    "events": "flext_ldif.events",
    "metadata": "flext_ldif.metadata",
    "processing": "flext_ldif.processing",
    "results": "flext_ldif.results",
    "settings": "flext_ldif.settings",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
