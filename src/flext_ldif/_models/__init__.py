# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Internal module for FlextLdifModels nested classes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from flext_ldif._models.base import (
        AclElement,
        FlextLdifModelsBase,
        FlextLdifModelsBases,
        FrozenIgnoreLdifModel,
        FrozenLdifModel,
        MutableIgnoreLdifModel,
        SchemaElement,
    )
    from flext_ldif._models.collections import FlextLdifModelsCollections
    from flext_ldif._models.conversion import FlextLdifModelsConversions
    from flext_ldif._models.domain import FlextLdifModelsDomains
    from flext_ldif._models.events import FlextLdifModelsEvents
    from flext_ldif._models.metadata import FlextLdifModelsMetadata
    from flext_ldif._models.processing import FlextLdifModelsProcessing
    from flext_ldif._models.results import FlextLdifModelsResults
    from flext_ldif._models.settings import FlextLdifModelsSettings

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "AclElement": ("flext_ldif._models.base", "AclElement"),
    "FlextLdifModelsBase": ("flext_ldif._models.base", "FlextLdifModelsBase"),
    "FlextLdifModelsBases": ("flext_ldif._models.base", "FlextLdifModelsBases"),
    "FlextLdifModelsCollections": (
        "flext_ldif._models.collections",
        "FlextLdifModelsCollections",
    ),
    "FlextLdifModelsConversions": (
        "flext_ldif._models.conversion",
        "FlextLdifModelsConversions",
    ),
    "FlextLdifModelsDomains": ("flext_ldif._models.domain", "FlextLdifModelsDomains"),
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
    "FrozenIgnoreLdifModel": ("flext_ldif._models.base", "FrozenIgnoreLdifModel"),
    "FrozenLdifModel": ("flext_ldif._models.base", "FrozenLdifModel"),
    "MutableIgnoreLdifModel": ("flext_ldif._models.base", "MutableIgnoreLdifModel"),
    "SchemaElement": ("flext_ldif._models.base", "SchemaElement"),
}

__all__ = [
    "AclElement",
    "FlextLdifModelsBase",
    "FlextLdifModelsBases",
    "FlextLdifModelsCollections",
    "FlextLdifModelsConversions",
    "FlextLdifModelsDomains",
    "FlextLdifModelsEvents",
    "FlextLdifModelsMetadata",
    "FlextLdifModelsProcessing",
    "FlextLdifModelsResults",
    "FlextLdifModelsSettings",
    "FrozenIgnoreLdifModel",
    "FrozenLdifModel",
    "MutableIgnoreLdifModel",
    "SchemaElement",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
