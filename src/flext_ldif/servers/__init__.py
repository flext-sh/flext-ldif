# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Servers package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _t.TYPE_CHECKING:
    import flext_ldif.servers._base as _flext_ldif_servers__base

    _base = _flext_ldif_servers__base
    import flext_ldif.servers._oid as _flext_ldif_servers__oid
    from flext_ldif.servers._base import (
        FlextLdifQuirkMethodsMixin,
        FlextLdifServersBaseConstants,
        FlextLdifServersBaseConstants as c,
        FlextLdifServersBaseEntry,
        FlextLdifServersBaseQuirkHelpers,
        FlextLdifServersBaseSchema,
        FlextLdifServersBaseSchemaAcl,
        acl,
        constants,
        entry,
        schema,
    )

    _oid = _flext_ldif_servers__oid
    import flext_ldif.servers._oud as _flext_ldif_servers__oud
    from flext_ldif.servers._oid import (
        FlextLdifServersOidAcl,
        FlextLdifServersOidConstants,
        FlextLdifServersOidEntry,
        FlextLdifServersOidSchema,
    )

    _oud = _flext_ldif_servers__oud
    import flext_ldif.servers._rfc as _flext_ldif_servers__rfc
    from flext_ldif.servers._oud import (
        FlextLdifServersOudAcl,
        FlextLdifServersOudConstants,
        FlextLdifServersOudEntry,
        FlextLdifServersOudSchema,
        FlextLdifServersOudUtilities,
        FlextLdifServersOudUtilities as u,
        utilities,
    )

    _rfc = _flext_ldif_servers__rfc
    import flext_ldif.servers.ad as _flext_ldif_servers_ad
    from flext_ldif.servers._rfc import (
        FlextLdifServersRfcAcl,
        FlextLdifServersRfcConstants,
        FlextLdifServersRfcEntry,
        FlextLdifServersRfcSchema,
    )

    ad = _flext_ldif_servers_ad
    import flext_ldif.servers.apache as _flext_ldif_servers_apache
    from flext_ldif.servers.ad import FlextLdifServersAd

    apache = _flext_ldif_servers_apache
    import flext_ldif.servers.base as _flext_ldif_servers_base
    from flext_ldif.servers.apache import FlextLdifServersApache

    base = _flext_ldif_servers_base
    import flext_ldif.servers.ds389 as _flext_ldif_servers_ds389
    from flext_ldif.servers.base import FlextLdifServersBase

    ds389 = _flext_ldif_servers_ds389
    import flext_ldif.servers.novell as _flext_ldif_servers_novell
    from flext_ldif.servers.ds389 import FlextLdifServersDs389

    novell = _flext_ldif_servers_novell
    import flext_ldif.servers.oid as _flext_ldif_servers_oid
    from flext_ldif.servers.novell import FlextLdifServersNovell

    oid = _flext_ldif_servers_oid
    import flext_ldif.servers.openldap as _flext_ldif_servers_openldap
    from flext_ldif.servers.oid import FlextLdifServersOid, logger

    openldap = _flext_ldif_servers_openldap
    import flext_ldif.servers.openldap1 as _flext_ldif_servers_openldap1
    from flext_ldif.servers.openldap import FlextLdifServersOpenldap

    openldap1 = _flext_ldif_servers_openldap1
    import flext_ldif.servers.oud as _flext_ldif_servers_oud
    from flext_ldif.servers.openldap1 import FlextLdifServersOpenldap1

    oud = _flext_ldif_servers_oud
    import flext_ldif.servers.relaxed as _flext_ldif_servers_relaxed
    from flext_ldif.servers.oud import FlextLdifServersOud

    relaxed = _flext_ldif_servers_relaxed
    import flext_ldif.servers.rfc as _flext_ldif_servers_rfc
    from flext_ldif.servers.relaxed import FlextLdifServersRelaxed

    rfc = _flext_ldif_servers_rfc
    import flext_ldif.servers.tivoli as _flext_ldif_servers_tivoli
    from flext_ldif.servers.rfc import FlextLdifServersRfc

    tivoli = _flext_ldif_servers_tivoli
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_ldif.servers.tivoli import FlextLdifServersTivoli
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "flext_ldif.servers._base",
        "flext_ldif.servers._oid",
        "flext_ldif.servers._oud",
        "flext_ldif.servers._rfc",
    ),
    {
        "FlextLdifServersAd": ("flext_ldif.servers.ad", "FlextLdifServersAd"),
        "FlextLdifServersApache": (
            "flext_ldif.servers.apache",
            "FlextLdifServersApache",
        ),
        "FlextLdifServersBase": ("flext_ldif.servers.base", "FlextLdifServersBase"),
        "FlextLdifServersDs389": ("flext_ldif.servers.ds389", "FlextLdifServersDs389"),
        "FlextLdifServersNovell": (
            "flext_ldif.servers.novell",
            "FlextLdifServersNovell",
        ),
        "FlextLdifServersOid": ("flext_ldif.servers.oid", "FlextLdifServersOid"),
        "FlextLdifServersOpenldap": (
            "flext_ldif.servers.openldap",
            "FlextLdifServersOpenldap",
        ),
        "FlextLdifServersOpenldap1": (
            "flext_ldif.servers.openldap1",
            "FlextLdifServersOpenldap1",
        ),
        "FlextLdifServersOud": ("flext_ldif.servers.oud", "FlextLdifServersOud"),
        "FlextLdifServersRelaxed": (
            "flext_ldif.servers.relaxed",
            "FlextLdifServersRelaxed",
        ),
        "FlextLdifServersRfc": ("flext_ldif.servers.rfc", "FlextLdifServersRfc"),
        "FlextLdifServersTivoli": (
            "flext_ldif.servers.tivoli",
            "FlextLdifServersTivoli",
        ),
        "_base": "flext_ldif.servers._base",
        "_oid": "flext_ldif.servers._oid",
        "_oud": "flext_ldif.servers._oud",
        "_rfc": "flext_ldif.servers._rfc",
        "ad": "flext_ldif.servers.ad",
        "apache": "flext_ldif.servers.apache",
        "base": "flext_ldif.servers.base",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "ds389": "flext_ldif.servers.ds389",
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "h": ("flext_core.handlers", "FlextHandlers"),
        "logger": ("flext_ldif.servers.oid", "logger"),
        "m": ("flext_core.models", "FlextModels"),
        "novell": "flext_ldif.servers.novell",
        "oid": "flext_ldif.servers.oid",
        "openldap": "flext_ldif.servers.openldap",
        "openldap1": "flext_ldif.servers.openldap1",
        "oud": "flext_ldif.servers.oud",
        "p": ("flext_core.protocols", "FlextProtocols"),
        "r": ("flext_core.result", "FlextResult"),
        "relaxed": "flext_ldif.servers.relaxed",
        "rfc": "flext_ldif.servers.rfc",
        "s": ("flext_core.service", "FlextService"),
        "t": ("flext_core.typings", "FlextTypes"),
        "tivoli": "flext_ldif.servers.tivoli",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)
_ = _LAZY_IMPORTS.pop("cleanup_submodule_namespace", None)
_ = _LAZY_IMPORTS.pop("install_lazy_exports", None)
_ = _LAZY_IMPORTS.pop("lazy_getattr", None)
_ = _LAZY_IMPORTS.pop("merge_lazy_imports", None)
_ = _LAZY_IMPORTS.pop("output", None)
_ = _LAZY_IMPORTS.pop("output_reporting", None)

__all__ = [
    "FlextLdifQuirkMethodsMixin",
    "FlextLdifServersAd",
    "FlextLdifServersApache",
    "FlextLdifServersBase",
    "FlextLdifServersBaseConstants",
    "FlextLdifServersBaseEntry",
    "FlextLdifServersBaseQuirkHelpers",
    "FlextLdifServersBaseSchema",
    "FlextLdifServersBaseSchemaAcl",
    "FlextLdifServersDs389",
    "FlextLdifServersNovell",
    "FlextLdifServersOid",
    "FlextLdifServersOidAcl",
    "FlextLdifServersOidConstants",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidSchema",
    "FlextLdifServersOpenldap",
    "FlextLdifServersOpenldap1",
    "FlextLdifServersOud",
    "FlextLdifServersOudAcl",
    "FlextLdifServersOudConstants",
    "FlextLdifServersOudEntry",
    "FlextLdifServersOudSchema",
    "FlextLdifServersOudUtilities",
    "FlextLdifServersRelaxed",
    "FlextLdifServersRfc",
    "FlextLdifServersRfcAcl",
    "FlextLdifServersRfcConstants",
    "FlextLdifServersRfcEntry",
    "FlextLdifServersRfcSchema",
    "FlextLdifServersTivoli",
    "_base",
    "_oid",
    "_oud",
    "_rfc",
    "acl",
    "ad",
    "apache",
    "base",
    "c",
    "constants",
    "d",
    "ds389",
    "e",
    "entry",
    "h",
    "logger",
    "m",
    "novell",
    "oid",
    "openldap",
    "openldap1",
    "oud",
    "p",
    "r",
    "relaxed",
    "rfc",
    "s",
    "schema",
    "t",
    "tivoli",
    "u",
    "utilities",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
