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
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u
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

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = merge_lazy_imports(
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
        "d": ("flext_core.decorators", "FlextDecorators"),
        "ds389": "flext_ldif.servers.ds389",
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "h": ("flext_core.handlers", "FlextHandlers"),
        "logger": "flext_ldif.servers.oid",
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
        "u": ("flext_core.utilities", "FlextUtilities"),
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
