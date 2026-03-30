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
    from flext_ldif._models.base import *
    from flext_ldif._models.collections import *
    from flext_ldif._models.domain import *
    from flext_ldif._models.domain_entries import *
    from flext_ldif._models.events import *
    from flext_ldif._models.metadata import *
    from flext_ldif._models.processing import *
    from flext_ldif._models.results import *
    from flext_ldif._models.settings import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))
