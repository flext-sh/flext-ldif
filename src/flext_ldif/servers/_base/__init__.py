# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Base server classes for LDIF/LDAP processing."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes

    from flext_ldif.servers._base.acl import *
    from flext_ldif.servers._base.constants import *
    from flext_ldif.servers._base.entry import *
    from flext_ldif.servers._base.schema import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
