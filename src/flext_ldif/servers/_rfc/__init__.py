# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""RFC 4512 Compliant Server Classes for LDIF/LDAP processing."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes

    from flext_ldif.servers._rfc.acl import *
    from flext_ldif.servers._rfc.constants import *
    from flext_ldif.servers._rfc.entry import *
    from flext_ldif.servers._rfc.schema import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "FlextLdifServersRfcAcl": "flext_ldif.servers._rfc.acl",
    "FlextLdifServersRfcConstants": "flext_ldif.servers._rfc.constants",
    "FlextLdifServersRfcEntry": "flext_ldif.servers._rfc.entry",
    "FlextLdifServersRfcSchema": "flext_ldif.servers._rfc.schema",
    "acl": "flext_ldif.servers._rfc.acl",
    "c": "flext_ldif.servers._rfc.constants",
    "constants": "flext_ldif.servers._rfc.constants",
    "entry": "flext_ldif.servers._rfc.entry",
    "logger": "flext_ldif.servers._rfc.schema",
    "schema": "flext_ldif.servers._rfc.schema",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
