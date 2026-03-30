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
        _base,
        _oid,
        _oud,
        _rfc,
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
    from flext_ldif.servers._base import acl, constants, entry, schema
    from flext_ldif.servers._base.acl import *
    from flext_ldif.servers._base.constants import *
    from flext_ldif.servers._base.entry import *
    from flext_ldif.servers._base.schema import *
    from flext_ldif.servers._oid.acl import *
    from flext_ldif.servers._oid.constants import *
    from flext_ldif.servers._oid.entry import *
    from flext_ldif.servers._oid.schema import *
    from flext_ldif.servers._oud import utilities
    from flext_ldif.servers._oud.acl import *
    from flext_ldif.servers._oud.constants import *
    from flext_ldif.servers._oud.entry import *
    from flext_ldif.servers._oud.schema import *
    from flext_ldif.servers._oud.utilities import *
    from flext_ldif.servers._rfc.acl import *
    from flext_ldif.servers._rfc.constants import *
    from flext_ldif.servers._rfc.entry import *
    from flext_ldif.servers._rfc.schema import *
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

from flext_ldif.servers._base import _LAZY_IMPORTS as __BASE_LAZY
from flext_ldif.servers._oid import _LAZY_IMPORTS as __OID_LAZY
from flext_ldif.servers._oud import _LAZY_IMPORTS as __OUD_LAZY
from flext_ldif.servers._rfc import _LAZY_IMPORTS as __RFC_LAZY

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    **__BASE_LAZY,
    **__OID_LAZY,
    **__OUD_LAZY,
    **__RFC_LAZY,
    "FlextLdifServersAd": "flext_ldif.servers.ad",
    "FlextLdifServersApache": "flext_ldif.servers.apache",
    "FlextLdifServersBase": "flext_ldif.servers.base",
    "FlextLdifServersDs389": "flext_ldif.servers.ds389",
    "FlextLdifServersNovell": "flext_ldif.servers.novell",
    "FlextLdifServersOid": "flext_ldif.servers.oid",
    "FlextLdifServersOpenldap": "flext_ldif.servers.openldap",
    "FlextLdifServersOpenldap1": "flext_ldif.servers.openldap1",
    "FlextLdifServersOud": "flext_ldif.servers.oud",
    "FlextLdifServersRelaxed": "flext_ldif.servers.relaxed",
    "FlextLdifServersRfc": "flext_ldif.servers.rfc",
    "FlextLdifServersTivoli": "flext_ldif.servers.tivoli",
    "_base": "flext_ldif.servers._base",
    "_oid": "flext_ldif.servers._oid",
    "_oud": "flext_ldif.servers._oud",
    "_rfc": "flext_ldif.servers._rfc",
    "ad": "flext_ldif.servers.ad",
    "apache": "flext_ldif.servers.apache",
    "base": "flext_ldif.servers.base",
    "ds389": "flext_ldif.servers.ds389",
    "logger": "flext_ldif.servers.oid",
    "novell": "flext_ldif.servers.novell",
    "oid": "flext_ldif.servers.oid",
    "openldap": "flext_ldif.servers.openldap",
    "openldap1": "flext_ldif.servers.openldap1",
    "oud": "flext_ldif.servers.oud",
    "relaxed": "flext_ldif.servers.relaxed",
    "rfc": "flext_ldif.servers.rfc",
    "tivoli": "flext_ldif.servers.tivoli",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))
