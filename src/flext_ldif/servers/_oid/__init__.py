# AUTO-GENERATED FILE — Regenerate with: make gen
"""Oid package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "FlextLdifServersOidAcl": ".acl",
    "FlextLdifServersOidConstants": ".constants",
    "FlextLdifServersOidEntry": ".entry",
    "FlextLdifServersOidSchema": ".schema",
    "c": ".constants",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
