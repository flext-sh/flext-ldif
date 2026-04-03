# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Oud package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import flext_ldif.servers._oud.acl as _flext_ldif_servers__oud_acl

    acl = _flext_ldif_servers__oud_acl
    import flext_ldif.servers._oud.constants as _flext_ldif_servers__oud_constants
    from flext_ldif.servers._oud.acl import FlextLdifServersOudAcl

    constants = _flext_ldif_servers__oud_constants
    import flext_ldif.servers._oud.entry as _flext_ldif_servers__oud_entry
    from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants, c

    entry = _flext_ldif_servers__oud_entry
    import flext_ldif.servers._oud.schema as _flext_ldif_servers__oud_schema
    from flext_ldif.servers._oud.entry import FlextLdifServersOudEntry

    schema = _flext_ldif_servers__oud_schema
    import flext_ldif.servers._oud.utilities as _flext_ldif_servers__oud_utilities
    from flext_ldif.servers._oud.schema import FlextLdifServersOudSchema, logger

    utilities = _flext_ldif_servers__oud_utilities
    from flext_ldif.servers._oud.utilities import FlextLdifServersOudUtilities
_LAZY_IMPORTS = {
    "FlextLdifServersOudAcl": "flext_ldif.servers._oud.acl",
    "FlextLdifServersOudConstants": "flext_ldif.servers._oud.constants",
    "FlextLdifServersOudEntry": "flext_ldif.servers._oud.entry",
    "FlextLdifServersOudSchema": "flext_ldif.servers._oud.schema",
    "FlextLdifServersOudUtilities": "flext_ldif.servers._oud.utilities",
    "acl": "flext_ldif.servers._oud.acl",
    "c": "flext_ldif.servers._oud.constants",
    "constants": "flext_ldif.servers._oud.constants",
    "entry": "flext_ldif.servers._oud.entry",
    "logger": "flext_ldif.servers._oud.schema",
    "schema": "flext_ldif.servers._oud.schema",
    "utilities": "flext_ldif.servers._oud.utilities",
}

__all__ = [
    "FlextLdifServersOudAcl",
    "FlextLdifServersOudConstants",
    "FlextLdifServersOudEntry",
    "FlextLdifServersOudSchema",
    "FlextLdifServersOudUtilities",
    "acl",
    "c",
    "constants",
    "entry",
    "logger",
    "schema",
    "utilities",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
