# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""RFC 4512 Compliant Server Classes for LDIF/LDAP processing."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from flext_ldif.servers._rfc.acl import FlextLdifServersRfcAcl
    from flext_ldif.servers._rfc.constants import FlextLdifServersRfcConstants, c
    from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry
    from flext_ldif.servers._rfc.schema import FlextLdifServersRfcSchema, logger

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdifServersRfcAcl": ("flext_ldif.servers._rfc.acl", "FlextLdifServersRfcAcl"),
    "FlextLdifServersRfcConstants": ("flext_ldif.servers._rfc.constants", "FlextLdifServersRfcConstants"),
    "FlextLdifServersRfcEntry": ("flext_ldif.servers._rfc.entry", "FlextLdifServersRfcEntry"),
    "FlextLdifServersRfcSchema": ("flext_ldif.servers._rfc.schema", "FlextLdifServersRfcSchema"),
    "c": ("flext_ldif.servers._rfc.constants", "c"),
    "logger": ("flext_ldif.servers._rfc.schema", "logger"),
}

__all__ = [
    "FlextLdifServersRfcAcl",
    "FlextLdifServersRfcConstants",
    "FlextLdifServersRfcEntry",
    "FlextLdifServersRfcSchema",
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
