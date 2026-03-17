# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""OUD (Oracle Unified Directory) Server Classes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from flext_ldif.servers._oud.acl import FlextLdifServersOudAcl
    from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants, c
    from flext_ldif.servers._oud.entry import FlextLdifServersOudEntry
    from flext_ldif.servers._oud.schema import FlextLdifServersOudSchema, logger
    from flext_ldif.servers._oud.utilities import FlextLdifServersOudUtilities

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdifServersOudAcl": ("flext_ldif.servers._oud.acl", "FlextLdifServersOudAcl"),
    "FlextLdifServersOudConstants": (
        "flext_ldif.servers._oud.constants",
        "FlextLdifServersOudConstants",
    ),
    "FlextLdifServersOudEntry": (
        "flext_ldif.servers._oud.entry",
        "FlextLdifServersOudEntry",
    ),
    "FlextLdifServersOudSchema": (
        "flext_ldif.servers._oud.schema",
        "FlextLdifServersOudSchema",
    ),
    "FlextLdifServersOudUtilities": (
        "flext_ldif.servers._oud.utilities",
        "FlextLdifServersOudUtilities",
    ),
    "c": ("flext_ldif.servers._oud.constants", "c"),
    "logger": ("flext_ldif.servers._oud.schema", "logger"),
}

__all__ = [
    "FlextLdifServersOudAcl",
    "FlextLdifServersOudConstants",
    "FlextLdifServersOudEntry",
    "FlextLdifServersOudSchema",
    "FlextLdifServersOudUtilities",
    "c",
    "logger",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
