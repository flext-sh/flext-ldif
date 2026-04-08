# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Rfc package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

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
    "schema": "flext_ldif.servers._rfc.schema",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
