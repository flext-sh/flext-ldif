"""FLEXT-LDIF - RFC-First LDIF Processing Library."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import d, e, h, r

    from flext_ldif._shared import FlextLdifShared
    from flext_ldif.api import FlextLdif
    from flext_ldif.base import FlextLdifServiceBase, s
    from flext_ldif.constants import FlextLdifConstants, FlextLdifConstants as c
    from flext_ldif.models import FlextLdifModels, FlextLdifModels as m
    from flext_ldif.protocols import FlextLdifProtocols, FlextLdifProtocols as p
    from flext_ldif.services.categorization import FlextLdifCategorization
    from flext_ldif.services.conversion import FlextLdifConversion
    from flext_ldif.services.detector import FlextLdifDetector
    from flext_ldif.services.dn import FlextLdifDn
    from flext_ldif.services.entries import FlextLdifEntries
    from flext_ldif.services.filters import FlextLdifFilters
    from flext_ldif.services.migration import FlextLdifMigrationPipeline
    from flext_ldif.services.parser import FlextLdifParser
    from flext_ldif.services.pipeline import ProcessingPipeline
    from flext_ldif.services.sorting import FlextLdifSorting
    from flext_ldif.services.statistics import FlextLdifStatistics
    from flext_ldif.services.transformers import ServerTransformer
    from flext_ldif.services.writer import FlextLdifWriter
    from flext_ldif.settings import FlextLdifSettings
    from flext_ldif.typings import FlextLdifTypes, FlextLdifTypes as t
    from flext_ldif.utilities import FlextLdifUtilities, FlextLdifUtilities as u

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdif": ("flext_ldif.api", "FlextLdif"),
    "FlextLdifCategorization": ("flext_ldif.services.categorization", "FlextLdifCategorization"),
    "FlextLdifConstants": ("flext_ldif.constants", "FlextLdifConstants"),
    "FlextLdifConversion": ("flext_ldif.services.conversion", "FlextLdifConversion"),
    "FlextLdifDetector": ("flext_ldif.services.detector", "FlextLdifDetector"),
    "FlextLdifDn": ("flext_ldif.services.dn", "FlextLdifDn"),
    "FlextLdifEntries": ("flext_ldif.services.entries", "FlextLdifEntries"),
    "FlextLdifFilters": ("flext_ldif.services.filters", "FlextLdifFilters"),
    "FlextLdifMigrationPipeline": ("flext_ldif.services.migration", "FlextLdifMigrationPipeline"),
    "FlextLdifModels": ("flext_ldif.models", "FlextLdifModels"),
    "FlextLdifParser": ("flext_ldif.services.parser", "FlextLdifParser"),
    "FlextLdifProtocols": ("flext_ldif.protocols", "FlextLdifProtocols"),
    "FlextLdifServiceBase": ("flext_ldif.base", "FlextLdifServiceBase"),
    "FlextLdifSettings": ("flext_ldif.settings", "FlextLdifSettings"),
    "FlextLdifShared": ("flext_ldif._shared", "FlextLdifShared"),
    "FlextLdifSorting": ("flext_ldif.services.sorting", "FlextLdifSorting"),
    "FlextLdifStatistics": ("flext_ldif.services.statistics", "FlextLdifStatistics"),
    "FlextLdifTypes": ("flext_ldif.typings", "FlextLdifTypes"),
    "FlextLdifUtilities": ("flext_ldif.utilities", "FlextLdifUtilities"),
    "FlextLdifWriter": ("flext_ldif.services.writer", "FlextLdifWriter"),
    "ProcessingPipeline": ("flext_ldif.services.pipeline", "ProcessingPipeline"),
    "ServerTransformer": ("flext_ldif.services.transformers", "ServerTransformer"),
    "c": ("flext_ldif.constants", "FlextLdifConstants"),
    "d": ("flext_core", "d"),
    "e": ("flext_core", "e"),
    "h": ("flext_core", "h"),
    "m": ("flext_ldif.models", "FlextLdifModels"),
    "p": ("flext_ldif.protocols", "FlextLdifProtocols"),
    "r": ("flext_core", "r"),
    "s": ("flext_ldif.base", "s"),
    "t": ("flext_ldif.typings", "FlextLdifTypes"),
    "u": ("flext_ldif.utilities", "FlextLdifUtilities"),
}

__all__ = [
    "FlextLdif",
    "FlextLdifCategorization",
    "FlextLdifConstants",
    "FlextLdifConversion",
    "FlextLdifDetector",
    "FlextLdifDn",
    "FlextLdifEntries",
    "FlextLdifFilters",
    "FlextLdifMigrationPipeline",
    "FlextLdifModels",
    "FlextLdifParser",
    "FlextLdifProtocols",
    "FlextLdifServiceBase",
    "FlextLdifSettings",
    "FlextLdifShared",
    "FlextLdifSorting",
    "FlextLdifStatistics",
    "FlextLdifTypes",
    "FlextLdifUtilities",
    "FlextLdifWriter",
    "ProcessingPipeline",
    "ServerTransformer",
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
