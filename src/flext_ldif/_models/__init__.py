# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Internal module for FlextLdifModels nested classes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes

    from flext_ldif._models.base import FlextLdifModelsBases
    from flext_ldif._models.collections import FlextLdifModelsCollections
    from flext_ldif._models.conversion import FlextLdifModelsConversions
    from flext_ldif._models.domain import FlextLdifModelsDomains
    from flext_ldif._models.domain_entries import FlextLdifModelsDomainsEntries
    from flext_ldif._models.domain_schema import FlextLdifModelsDomainSchema
    from flext_ldif._models.events import FlextLdifModelsEvents
    from flext_ldif._models.metadata import FlextLdifModelsMetadata
    from flext_ldif._models.processing import FlextLdifModelsProcessing
    from flext_ldif._models.results import FlextLdifModelsResults
    from flext_ldif._models.settings import FlextLdifModelsSettings

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdifModelsBases": ("flext_ldif._models.base", "FlextLdifModelsBases"),
    "FlextLdifModelsCollections": (
        "flext_ldif._models.collections",
        "FlextLdifModelsCollections",
    ),
    "FlextLdifModelsConversions": (
        "flext_ldif._models.conversion",
        "FlextLdifModelsConversions",
    ),
    "FlextLdifModelsDomainSchema": (
        "flext_ldif._models.domain_schema",
        "FlextLdifModelsDomainSchema",
    ),
    "FlextLdifModelsDomains": ("flext_ldif._models.domain", "FlextLdifModelsDomains"),
    "FlextLdifModelsDomainsEntries": (
        "flext_ldif._models.domain_entries",
        "FlextLdifModelsDomainsEntries",
    ),
    "FlextLdifModelsEvents": ("flext_ldif._models.events", "FlextLdifModelsEvents"),
    "FlextLdifModelsMetadata": (
        "flext_ldif._models.metadata",
        "FlextLdifModelsMetadata",
    ),
    "FlextLdifModelsProcessing": (
        "flext_ldif._models.processing",
        "FlextLdifModelsProcessing",
    ),
    "FlextLdifModelsResults": ("flext_ldif._models.results", "FlextLdifModelsResults"),
    "FlextLdifModelsSettings": (
        "flext_ldif._models.settings",
        "FlextLdifModelsSettings",
    ),
}

__all__ = [
    "FlextLdifModelsBases",
    "FlextLdifModelsCollections",
    "FlextLdifModelsConversions",
    "FlextLdifModelsDomainSchema",
    "FlextLdifModelsDomains",
    "FlextLdifModelsDomainsEntries",
    "FlextLdifModelsEvents",
    "FlextLdifModelsMetadata",
    "FlextLdifModelsProcessing",
    "FlextLdifModelsResults",
    "FlextLdifModelsSettings",
]


_LAZY_CACHE: dict[str, FlextTypes.ModuleExport] = {}


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562).

    A local cache ``_LAZY_CACHE`` persists resolved objects across repeated
    accesses during process lifetime.

    Args:
        name: Attribute name requested by dir()/import.

    Returns:
        Lazy-loaded module export type.

    Raises:
        AttributeError: If attribute not registered.

    """
    if name in _LAZY_CACHE:
        return _LAZY_CACHE[name]

    value = lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)
    _LAZY_CACHE[name] = value
    return value


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
