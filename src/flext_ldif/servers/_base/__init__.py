# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Base package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "FlextLdifQuirkMethodsMixin": (
        "flext_ldif.servers._base.mixins",
        "FlextLdifQuirkMethodsMixin",
    ),
    "FlextLdifServersBaseConstants": (
        "flext_ldif.servers._base.constants",
        "FlextLdifServersBaseConstants",
    ),
    "FlextLdifServersBaseEntry": (
        "flext_ldif.servers._base.entry",
        "FlextLdifServersBaseEntry",
    ),
    "FlextLdifServersBaseSchema": (
        "flext_ldif.servers._base.schema",
        "FlextLdifServersBaseSchema",
    ),
    "FlextLdifServersBaseSchemaAcl": (
        "flext_ldif.servers._base.acl",
        "FlextLdifServersBaseSchemaAcl",
    ),
    "acl": "flext_ldif.servers._base.acl",
    "constants": "flext_ldif.servers._base.constants",
    "entry": "flext_ldif.servers._base.entry",
    "mixins": "flext_ldif.servers._base.mixins",
    "schema": "flext_ldif.servers._base.schema",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
