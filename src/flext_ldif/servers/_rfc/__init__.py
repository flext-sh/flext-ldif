"""RFC 4512 Compliant Server Classes for LDIF/LDAP processing."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_ldif.servers._rfc.acl import FlextLdifServersRfcAcl
    from flext_ldif.servers._rfc.constants import FlextLdifServersRfcConstants
    from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry
    from flext_ldif.servers._rfc.schema import FlextLdifServersRfcSchema

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdifServersRfcAcl": ("flext_ldif.servers._rfc.acl", "FlextLdifServersRfcAcl"),
    "FlextLdifServersRfcConstants": ("flext_ldif.servers._rfc.constants", "FlextLdifServersRfcConstants"),
    "FlextLdifServersRfcEntry": ("flext_ldif.servers._rfc.entry", "FlextLdifServersRfcEntry"),
    "FlextLdifServersRfcSchema": ("flext_ldif.servers._rfc.schema", "FlextLdifServersRfcSchema"),
}

__all__ = [
    "FlextLdifServersRfcAcl",
    "FlextLdifServersRfcConstants",
    "FlextLdifServersRfcEntry",
    "FlextLdifServersRfcSchema",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
