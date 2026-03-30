# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""OID (Oracle Internet Directory) Server Classes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._oid import acl, constants, entry, schema
    from flext_ldif.servers._oid.acl import *
    from flext_ldif.servers._oid.constants import *
    from flext_ldif.servers._oid.entry import *
    from flext_ldif.servers._oid.schema import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "FlextLdifServersOidAcl": "flext_ldif.servers._oid.acl",
    "FlextLdifServersOidConstants": "flext_ldif.servers._oid.constants",
    "FlextLdifServersOidEntry": "flext_ldif.servers._oid.entry",
    "FlextLdifServersOidSchema": "flext_ldif.servers._oid.schema",
    "acl": "flext_ldif.servers._oid.acl",
    "c": "flext_ldif.servers._oid.constants",
    "constants": "flext_ldif.servers._oid.constants",
    "entry": "flext_ldif.servers._oid.entry",
    "logger": "flext_ldif.servers._oid.schema",
    "schema": "flext_ldif.servers._oid.schema",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))
