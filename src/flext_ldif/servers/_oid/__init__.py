# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Oid package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

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
    "c": ("flext_ldif.servers._oid.constants", "c"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
