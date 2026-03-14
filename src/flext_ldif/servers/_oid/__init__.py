# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""OID (Oracle Internet Directory) Server Classes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl
    from flext_ldif.servers._oid.constants import (
        FlextLdifServersOidConstants,
        FlextLdifServersOidConstants as c,
    )
    from flext_ldif.servers._oid.entry import FlextLdifServersOidEntry
    from flext_ldif.servers._oid.schema import FlextLdifServersOidSchema, logger

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdifServersOidAcl": ("flext_ldif.servers._oid.acl", "FlextLdifServersOidAcl"),
    "FlextLdifServersOidConstants": (
        "flext_ldif.servers._oid.constants",
        "FlextLdifServersOidConstants",
    ),
    "FlextLdifServersOidEntry": (
        "flext_ldif.servers._oid.entry",
        "FlextLdifServersOidEntry",
    ),
    "FlextLdifServersOidSchema": (
        "flext_ldif.servers._oid.schema",
        "FlextLdifServersOidSchema",
    ),
    "c": ("flext_ldif.servers._oid.constants", "FlextLdifServersOidConstants"),
    "logger": ("flext_ldif.servers._oid.schema", "logger"),
}

__all__ = [
    "FlextLdifServersOidAcl",
    "FlextLdifServersOidConstants",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidSchema",
    "c",
    "logger",
]


def __getattr__(name: str) -> t.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
