# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Rfc package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import flext_ldif.servers._rfc.acl as _flext_ldif_servers__rfc_acl

    acl = _flext_ldif_servers__rfc_acl
    import flext_ldif.servers._rfc.constants as _flext_ldif_servers__rfc_constants
    from flext_ldif.servers._rfc.acl import FlextLdifServersRfcAcl

    constants = _flext_ldif_servers__rfc_constants
    import flext_ldif.servers._rfc.entry as _flext_ldif_servers__rfc_entry
    from flext_ldif.servers._rfc.constants import FlextLdifServersRfcConstants, c

    entry = _flext_ldif_servers__rfc_entry
    import flext_ldif.servers._rfc.schema as _flext_ldif_servers__rfc_schema
    from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry

    schema = _flext_ldif_servers__rfc_schema
    from flext_ldif.servers._rfc.schema import FlextLdifServersRfcSchema, logger
_LAZY_IMPORTS = {
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
    "acl": "flext_ldif.servers._rfc.acl",
    "c": ("flext_ldif.servers._rfc.constants", "c"),
    "constants": "flext_ldif.servers._rfc.constants",
    "entry": "flext_ldif.servers._rfc.entry",
    "logger": ("flext_ldif.servers._rfc.schema", "logger"),
    "schema": "flext_ldif.servers._rfc.schema",
}

__all__ = [
    "FlextLdifServersRfcAcl",
    "FlextLdifServersRfcConstants",
    "FlextLdifServersRfcEntry",
    "FlextLdifServersRfcSchema",
    "acl",
    "c",
    "constants",
    "entry",
    "logger",
    "schema",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
