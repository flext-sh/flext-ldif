# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Oud package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
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
    "c": ("flext_ldif.servers._oud.constants", "c"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
