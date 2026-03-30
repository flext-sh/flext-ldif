# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Servers package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers import (
        ad,
        apache,
        base,
        ds389,
        novell,
        oid,
        openldap,
        openldap1,
        oud,
        relaxed,
        rfc,
        tivoli,
    )
    from flext_ldif.servers._base import *
    from flext_ldif.servers._oid import *
    from flext_ldif.servers._oud import *
    from flext_ldif.servers._rfc import *
    from flext_ldif.servers.ad import *
    from flext_ldif.servers.apache import *
    from flext_ldif.servers.base import *
    from flext_ldif.servers.ds389 import *
    from flext_ldif.servers.novell import *
    from flext_ldif.servers.oid import *
    from flext_ldif.servers.openldap import *
    from flext_ldif.servers.openldap1 import *
    from flext_ldif.servers.oud import *
    from flext_ldif.servers.relaxed import *
    from flext_ldif.servers.rfc import *
    from flext_ldif.servers.tivoli import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "FlextLdifQuirkMethodsMixin": "flext_ldif.servers._base.constants",
    "FlextLdifServersAd": "flext_ldif.servers.ad",
    "FlextLdifServersApache": "flext_ldif.servers.apache",
    "FlextLdifServersBase": "flext_ldif.servers.base",
    "FlextLdifServersBaseConstants": "flext_ldif.servers._base.constants",
    "FlextLdifServersBaseEntry": "flext_ldif.servers._base.entry",
    "FlextLdifServersBaseQuirkHelpers": "flext_ldif.servers._base.constants",
    "FlextLdifServersBaseSchema": "flext_ldif.servers._base.schema",
    "FlextLdifServersBaseSchemaAcl": "flext_ldif.servers._base.acl",
    "FlextLdifServersDs389": "flext_ldif.servers.ds389",
    "FlextLdifServersNovell": "flext_ldif.servers.novell",
    "FlextLdifServersOid": "flext_ldif.servers.oid",
    "FlextLdifServersOidAcl": "flext_ldif.servers._oid.acl",
    "FlextLdifServersOidConstants": "flext_ldif.servers._oid.constants",
    "FlextLdifServersOidEntry": "flext_ldif.servers._oid.entry",
    "FlextLdifServersOidSchema": "flext_ldif.servers._oid.schema",
    "FlextLdifServersOpenldap": "flext_ldif.servers.openldap",
    "FlextLdifServersOpenldap1": "flext_ldif.servers.openldap1",
    "FlextLdifServersOud": "flext_ldif.servers.oud",
    "FlextLdifServersOudAcl": "flext_ldif.servers._oud.acl",
    "FlextLdifServersOudConstants": "flext_ldif.servers._oud.constants",
    "FlextLdifServersOudEntry": "flext_ldif.servers._oud.entry",
    "FlextLdifServersOudSchema": "flext_ldif.servers._oud.schema",
    "FlextLdifServersOudUtilities": "flext_ldif.servers._oud.utilities",
    "FlextLdifServersRelaxed": "flext_ldif.servers.relaxed",
    "FlextLdifServersRfc": "flext_ldif.servers.rfc",
    "FlextLdifServersRfcAcl": "flext_ldif.servers._rfc.acl",
    "FlextLdifServersRfcConstants": "flext_ldif.servers._rfc.constants",
    "FlextLdifServersRfcEntry": "flext_ldif.servers._rfc.entry",
    "FlextLdifServersRfcSchema": "flext_ldif.servers._rfc.schema",
    "FlextLdifServersTivoli": "flext_ldif.servers.tivoli",
    "_base": "flext_ldif.servers._base",
    "_oid": "flext_ldif.servers._oid",
    "_oud": "flext_ldif.servers._oud",
    "_rfc": "flext_ldif.servers._rfc",
    "acl": "flext_ldif.servers._base.acl",
    "ad": "flext_ldif.servers.ad",
    "apache": "flext_ldif.servers.apache",
    "base": "flext_ldif.servers.base",
    "c": "flext_ldif.servers._rfc.constants",
    "constants": "flext_ldif.servers._base.constants",
    "ds389": "flext_ldif.servers.ds389",
    "entry": "flext_ldif.servers._base.entry",
    "logger": "flext_ldif.servers.oid",
    "novell": "flext_ldif.servers.novell",
    "oid": "flext_ldif.servers.oid",
    "openldap": "flext_ldif.servers.openldap",
    "openldap1": "flext_ldif.servers.openldap1",
    "oud": "flext_ldif.servers.oud",
    "relaxed": "flext_ldif.servers.relaxed",
    "rfc": "flext_ldif.servers.rfc",
    "schema": "flext_ldif.servers._base.schema",
    "tivoli": "flext_ldif.servers.tivoli",
    "utilities": "flext_ldif.servers._oud.utilities",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))
