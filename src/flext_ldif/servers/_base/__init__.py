# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Base package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import flext_ldif.servers._base.acl as _flext_ldif_servers__base_acl

    acl = _flext_ldif_servers__base_acl
    import flext_ldif.servers._base.constants as _flext_ldif_servers__base_constants
    from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl

    constants = _flext_ldif_servers__base_constants
    import flext_ldif.servers._base.entry as _flext_ldif_servers__base_entry
    from flext_ldif.servers._base.constants import FlextLdifServersBaseConstants

    entry = _flext_ldif_servers__base_entry
    import flext_ldif.servers._base.mixins as _flext_ldif_servers__base_mixins
    from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry

    mixins = _flext_ldif_servers__base_mixins
    import flext_ldif.servers._base.schema as _flext_ldif_servers__base_schema
    from flext_ldif.servers._base.mixins import FlextLdifQuirkMethodsMixin

    schema = _flext_ldif_servers__base_schema
    from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
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

__all__ = [
    "FlextLdifQuirkMethodsMixin",
    "FlextLdifServersBaseConstants",
    "FlextLdifServersBaseEntry",
    "FlextLdifServersBaseSchema",
    "FlextLdifServersBaseSchemaAcl",
    "acl",
    "constants",
    "entry",
    "mixins",
    "schema",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
