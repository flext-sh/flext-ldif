# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Base server classes for LDIF/LDAP processing."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
    from flext_ldif.servers._base.constants import (
        FlextLdifServersBaseConstants,
        FlextLdifServersBaseConstants as c,
        FlextLdifServersBaseQuirkHelpers,
        QuirkMethodsMixin,
    )
    from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
    from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema, logger

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdifServersBaseConstants": ("flext_ldif.servers._base.constants", "FlextLdifServersBaseConstants"),
    "FlextLdifServersBaseEntry": ("flext_ldif.servers._base.entry", "FlextLdifServersBaseEntry"),
    "FlextLdifServersBaseQuirkHelpers": ("flext_ldif.servers._base.constants", "FlextLdifServersBaseQuirkHelpers"),
    "FlextLdifServersBaseSchema": ("flext_ldif.servers._base.schema", "FlextLdifServersBaseSchema"),
    "FlextLdifServersBaseSchemaAcl": ("flext_ldif.servers._base.acl", "FlextLdifServersBaseSchemaAcl"),
    "QuirkMethodsMixin": ("flext_ldif.servers._base.constants", "QuirkMethodsMixin"),
    "c": ("flext_ldif.servers._base.constants", "FlextLdifServersBaseConstants"),
    "logger": ("flext_ldif.servers._base.schema", "logger"),
}

__all__ = [
    "FlextLdifServersBaseConstants",
    "FlextLdifServersBaseEntry",
    "FlextLdifServersBaseQuirkHelpers",
    "FlextLdifServersBaseSchema",
    "FlextLdifServersBaseSchemaAcl",
    "QuirkMethodsMixin",
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
