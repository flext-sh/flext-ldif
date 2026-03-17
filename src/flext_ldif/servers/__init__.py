# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Servers package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from flext_ldif.servers import _base, _oid, _oud, _rfc
    from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
    from flext_ldif.servers._base.constants import (
        FlextLdifServersBaseConstants,
        FlextLdifServersBaseQuirkHelpers,
        QuirkMethodsMixin,
    )
    from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
    from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
    from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl
    from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants, c
    from flext_ldif.servers._oid.entry import FlextLdifServersOidEntry
    from flext_ldif.servers._oid.schema import FlextLdifServersOidSchema
    from flext_ldif.servers._oud.acl import FlextLdifServersOudAcl
    from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants
    from flext_ldif.servers._oud.entry import FlextLdifServersOudEntry
    from flext_ldif.servers._oud.schema import FlextLdifServersOudSchema
    from flext_ldif.servers._oud.utilities import (
        FlextLdifServersOudUtilities,
        FlextLdifServersOudUtilities as u,
    )
    from flext_ldif.servers._rfc.acl import FlextLdifServersRfcAcl
    from flext_ldif.servers._rfc.constants import FlextLdifServersRfcConstants
    from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry
    from flext_ldif.servers._rfc.schema import FlextLdifServersRfcSchema
    from flext_ldif.servers.ad import FlextLdifServersAd
    from flext_ldif.servers.apache import FlextLdifServersApache
    from flext_ldif.servers.base import FlextLdifServersBase
    from flext_ldif.servers.ds389 import FlextLdifServersDs389
    from flext_ldif.servers.novell import FlextLdifServersNovell
    from flext_ldif.servers.oid import FlextLdifServersOid, logger
    from flext_ldif.servers.openldap import FlextLdifServersOpenldap
    from flext_ldif.servers.openldap1 import FlextLdifServersOpenldap1
    from flext_ldif.servers.oud import FlextLdifServersOud
    from flext_ldif.servers.relaxed import FlextLdifServersRelaxed
    from flext_ldif.servers.rfc import FlextLdifServersRfc
    from flext_ldif.servers.tivoli import FlextLdifServersTivoli

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdifServersAd": ("flext_ldif.servers.ad", "FlextLdifServersAd"),
    "FlextLdifServersApache": ("flext_ldif.servers.apache", "FlextLdifServersApache"),
    "FlextLdifServersBase": ("flext_ldif.servers.base", "FlextLdifServersBase"),
    "FlextLdifServersBaseConstants": (
        "flext_ldif.servers._base.constants",
        "FlextLdifServersBaseConstants",
    ),
    "FlextLdifServersBaseEntry": (
        "flext_ldif.servers._base.entry",
        "FlextLdifServersBaseEntry",
    ),
    "FlextLdifServersBaseQuirkHelpers": (
        "flext_ldif.servers._base.constants",
        "FlextLdifServersBaseQuirkHelpers",
    ),
    "FlextLdifServersBaseSchema": (
        "flext_ldif.servers._base.schema",
        "FlextLdifServersBaseSchema",
    ),
    "FlextLdifServersBaseSchemaAcl": (
        "flext_ldif.servers._base.acl",
        "FlextLdifServersBaseSchemaAcl",
    ),
    "FlextLdifServersDs389": ("flext_ldif.servers.ds389", "FlextLdifServersDs389"),
    "FlextLdifServersNovell": ("flext_ldif.servers.novell", "FlextLdifServersNovell"),
    "FlextLdifServersOid": ("flext_ldif.servers.oid", "FlextLdifServersOid"),
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
    "FlextLdifServersOpenldap": (
        "flext_ldif.servers.openldap",
        "FlextLdifServersOpenldap",
    ),
    "FlextLdifServersOpenldap1": (
        "flext_ldif.servers.openldap1",
        "FlextLdifServersOpenldap1",
    ),
    "FlextLdifServersOud": ("flext_ldif.servers.oud", "FlextLdifServersOud"),
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
    "FlextLdifServersRelaxed": (
        "flext_ldif.servers.relaxed",
        "FlextLdifServersRelaxed",
    ),
    "FlextLdifServersRfc": ("flext_ldif.servers.rfc", "FlextLdifServersRfc"),
    "FlextLdifServersRfcAcl": ("flext_ldif.servers._rfc.acl", "FlextLdifServersRfcAcl"),
    "FlextLdifServersRfcConstants": (
        "flext_ldif.servers._rfc.constants",
        "FlextLdifServersRfcConstants",
    ),
    "FlextLdifServersRfcEntry": (
        "flext_ldif.servers._rfc.entry",
        "FlextLdifServersRfcEntry",
    ),
    "FlextLdifServersRfcSchema": (
        "flext_ldif.servers._rfc.schema",
        "FlextLdifServersRfcSchema",
    ),
    "FlextLdifServersTivoli": ("flext_ldif.servers.tivoli", "FlextLdifServersTivoli"),
    "QuirkMethodsMixin": ("flext_ldif.servers._base.constants", "QuirkMethodsMixin"),
    "_base": ("flext_ldif.servers._base", ""),
    "_oid": ("flext_ldif.servers._oid", ""),
    "_oud": ("flext_ldif.servers._oud", ""),
    "_rfc": ("flext_ldif.servers._rfc", ""),
    "c": ("flext_ldif.servers._oid.constants", "c"),
    "logger": ("flext_ldif.servers.oid", "logger"),
    "u": ("flext_ldif.servers._oud.utilities", "FlextLdifServersOudUtilities"),
}

__all__ = [
    "FlextLdifServersAd",
    "FlextLdifServersApache",
    "FlextLdifServersBase",
    "FlextLdifServersBaseConstants",
    "FlextLdifServersBaseEntry",
    "FlextLdifServersBaseQuirkHelpers",
    "FlextLdifServersBaseSchema",
    "FlextLdifServersBaseSchemaAcl",
    "FlextLdifServersDs389",
    "FlextLdifServersNovell",
    "FlextLdifServersOid",
    "FlextLdifServersOidAcl",
    "FlextLdifServersOidConstants",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidSchema",
    "FlextLdifServersOpenldap",
    "FlextLdifServersOpenldap1",
    "FlextLdifServersOud",
    "FlextLdifServersOudAcl",
    "FlextLdifServersOudConstants",
    "FlextLdifServersOudEntry",
    "FlextLdifServersOudSchema",
    "FlextLdifServersOudUtilities",
    "FlextLdifServersRelaxed",
    "FlextLdifServersRfc",
    "FlextLdifServersRfcAcl",
    "FlextLdifServersRfcConstants",
    "FlextLdifServersRfcEntry",
    "FlextLdifServersRfcSchema",
    "FlextLdifServersTivoli",
    "QuirkMethodsMixin",
    "_base",
    "_oid",
    "_oud",
    "_rfc",
    "c",
    "logger",
    "u",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
