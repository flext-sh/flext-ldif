# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Oid package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import flext_ldif.servers._oid.acl as _flext_ldif_servers__oid_acl

    acl = _flext_ldif_servers__oid_acl
    import flext_ldif.servers._oid.constants as _flext_ldif_servers__oid_constants
    from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl

    constants = _flext_ldif_servers__oid_constants
    import flext_ldif.servers._oid.entry as _flext_ldif_servers__oid_entry
    from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants, c

    entry = _flext_ldif_servers__oid_entry
    import flext_ldif.servers._oid.schema as _flext_ldif_servers__oid_schema
    from flext_ldif.servers._oid.entry import FlextLdifServersOidEntry

    schema = _flext_ldif_servers__oid_schema
    from flext_ldif.servers._oid.schema import FlextLdifServersOidSchema, logger
_LAZY_IMPORTS = {
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
    "acl": "flext_ldif.servers._oid.acl",
    "c": ("flext_ldif.servers._oid.constants", "c"),
    "constants": "flext_ldif.servers._oid.constants",
    "entry": "flext_ldif.servers._oid.entry",
    "logger": ("flext_ldif.servers._oid.schema", "logger"),
    "schema": "flext_ldif.servers._oid.schema",
}

__all__ = [
    "FlextLdifServersOidAcl",
    "FlextLdifServersOidConstants",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidSchema",
    "acl",
    "c",
    "constants",
    "entry",
    "logger",
    "schema",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
