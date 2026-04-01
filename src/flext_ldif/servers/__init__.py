# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Servers package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _TYPE_CHECKING:
    from flext_core import FlextTypes

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
    from flext_ldif.servers._base import (
        FlextLdifQuirkMethodsMixin,
        FlextLdifServersBaseConstants,
        FlextLdifServersBaseEntry,
        FlextLdifServersBaseQuirkHelpers,
        FlextLdifServersBaseSchema,
        FlextLdifServersBaseSchemaAcl,
        acl,
        constants,
        entry,
        schema,
    )
    from flext_ldif.servers._oid import (
        FlextLdifServersOidAcl,
        FlextLdifServersOidConstants,
        FlextLdifServersOidEntry,
        FlextLdifServersOidSchema,
    )
    from flext_ldif.servers._oud import (
        FlextLdifServersOudAcl,
        FlextLdifServersOudConstants,
        FlextLdifServersOudEntry,
        FlextLdifServersOudSchema,
        FlextLdifServersOudUtilities,
        utilities,
    )
    from flext_ldif.servers._rfc import (
        FlextLdifServersRfcAcl,
        FlextLdifServersRfcConstants,
        FlextLdifServersRfcEntry,
        FlextLdifServersRfcSchema,
        c,
    )
    from flext_ldif.servers.ad import FlextLdifServersAd
    from flext_ldif.servers.apache import FlextLdifServersApache
    from flext_ldif.servers.base import FlextLdifServersBase
    from flext_ldif.servers.ds389 import FlextLdifServersDs389
    from flext_ldif.servers.novell import FlextLdifServersNovell
    from flext_ldif.servers.oid import FlextLdifServersOid, logger
    from flext_ldif.servers.openldap import FlextLdifServersOpenldap
    from flext_ldif.servers.openldap1 import FlextLdifServersOpenldap1
    from flext_ldif.servers.oud import FlextLdifServersOud
    from flext_ldif.servers.relaxed import FlextLdifServersRelaxed
    from flext_ldif.servers.rfc import FlextLdifServersRfc
    from flext_ldif.servers.tivoli import FlextLdifServersTivoli

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = merge_lazy_imports(
    (
        "flext_ldif.servers._base",
        "flext_ldif.servers._oid",
        "flext_ldif.servers._oud",
        "flext_ldif.servers._rfc",
    ),
    {
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
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
