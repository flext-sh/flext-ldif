"""Server-Specific Quirks for LDIF/LDAP Parsing."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace

if TYPE_CHECKING:
    from flext_ldif.servers.ad import FlextLdifServersAd
    from flext_ldif.servers.apache import FlextLdifServersApache
    from flext_ldif.servers.base import (
        FlextLdifServersBase,
        FlextLdifServersBase as FlextLdifServer,
    )
    from flext_ldif.servers.ds389 import FlextLdifServersDs389
    from flext_ldif.servers.novell import FlextLdifServersNovell
    from flext_ldif.servers.oid import FlextLdifServersOid
    from flext_ldif.servers.openldap import FlextLdifServersOpenldap
    from flext_ldif.servers.openldap1 import FlextLdifServersOpenldap1
    from flext_ldif.servers.oud import FlextLdifServersOud
    from flext_ldif.servers.relaxed import FlextLdifServersRelaxed
    from flext_ldif.servers.rfc import FlextLdifServersRfc
    from flext_ldif.servers.tivoli import FlextLdifServersTivoli

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdifServer": ("flext_ldif.servers.base", "FlextLdifServersBase"),
    "FlextLdifServersAd": ("flext_ldif.servers.ad", "FlextLdifServersAd"),
    "FlextLdifServersApache": ("flext_ldif.servers.apache", "FlextLdifServersApache"),
    "FlextLdifServersBase": ("flext_ldif.servers.base", "FlextLdifServersBase"),
    "FlextLdifServersDs389": ("flext_ldif.servers.ds389", "FlextLdifServersDs389"),
    "FlextLdifServersNovell": ("flext_ldif.servers.novell", "FlextLdifServersNovell"),
    "FlextLdifServersOid": ("flext_ldif.servers.oid", "FlextLdifServersOid"),
    "FlextLdifServersOpenldap": (
        "flext_ldif.servers.openldap",
        "FlextLdifServersOpenldap",
    ),
    "FlextLdifServersOpenldap1": (
        "flext_ldif.servers.openldap1",
        "FlextLdifServersOpenldap1",
    ),
    "FlextLdifServersOud": ("flext_ldif.servers.oud", "FlextLdifServersOud"),
    "FlextLdifServersRelaxed": (
        "flext_ldif.servers.relaxed",
        "FlextLdifServersRelaxed",
    ),
    "FlextLdifServersRfc": ("flext_ldif.servers.rfc", "FlextLdifServersRfc"),
    "FlextLdifServersTivoli": ("flext_ldif.servers.tivoli", "FlextLdifServersTivoli"),
}

__all__ = [
    "FlextLdifServer",
    "FlextLdifServersAd",
    "FlextLdifServersApache",
    "FlextLdifServersBase",
    "FlextLdifServersDs389",
    "FlextLdifServersNovell",
    "FlextLdifServersOid",
    "FlextLdifServersOpenldap",
    "FlextLdifServersOpenldap1",
    "FlextLdifServersOud",
    "FlextLdifServersRelaxed",
    "FlextLdifServersRfc",
    "FlextLdifServersTivoli",
]


def __getattr__(name: str) -> type:
    """Lazy-load module attributes on first access (PEP 562)."""
    lazy_import = _LAZY_IMPORTS.get(name)
    if lazy_import is None:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)
    module_path, attr_name = lazy_import
    module = import_module(module_path)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
