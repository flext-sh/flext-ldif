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
    from flext_ldif.servers._base.constants import (
        FlextLdifQuirkMethodsMixin,
        FlextLdifServersBaseConstants,
        FlextLdifServersBaseQuirkHelpers,
    )

    entry = _flext_ldif_servers__base_entry
    import flext_ldif.servers._base.schema as _flext_ldif_servers__base_schema
    from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry

    schema = _flext_ldif_servers__base_schema
    from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema, logger
_LAZY_IMPORTS = {
    "FlextLdifQuirkMethodsMixin": "flext_ldif.servers._base.constants",
    "FlextLdifServersBaseConstants": "flext_ldif.servers._base.constants",
    "FlextLdifServersBaseEntry": "flext_ldif.servers._base.entry",
    "FlextLdifServersBaseQuirkHelpers": "flext_ldif.servers._base.constants",
    "FlextLdifServersBaseSchema": "flext_ldif.servers._base.schema",
    "FlextLdifServersBaseSchemaAcl": "flext_ldif.servers._base.acl",
    "acl": "flext_ldif.servers._base.acl",
    "constants": "flext_ldif.servers._base.constants",
    "entry": "flext_ldif.servers._base.entry",
    "logger": "flext_ldif.servers._base.schema",
    "schema": "flext_ldif.servers._base.schema",
}

__all__ = [
    "FlextLdifQuirkMethodsMixin",
    "FlextLdifServersBaseConstants",
    "FlextLdifServersBaseEntry",
    "FlextLdifServersBaseQuirkHelpers",
    "FlextLdifServersBaseSchema",
    "FlextLdifServersBaseSchemaAcl",
    "acl",
    "constants",
    "entry",
    "logger",
    "schema",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
