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
    from flext_ldif import (
        _base,
        _oid,
        _oud,
        _rfc,
        acl,
        ad,
        apache,
        base,
        constants,
        ds389,
        entry,
        novell,
        oid,
        openldap,
        openldap1,
        oud,
        relaxed,
        rfc,
        schema,
        tivoli,
        utilities,
    )
    from flext_ldif._base import (
        FlextLdifServersBaseConstants,
        FlextLdifServersBaseEntry,
        FlextLdifServersBaseSchema,
        FlextLdifServersBaseSchemaAcl,
        acl_attribute_name,
        description,
        exclude,
        priority,
        repr,
        server_type,
    )
    from flext_ldif._oid import FlextLdifServersOidConstants, FlextLdifServersOidSchema
    from flext_ldif._oud import (
        FlextLdifServersOudAcl,
        FlextLdifServersOudConstants,
        FlextLdifServersOudEntry,
        FlextLdifServersOudSchema,
        FlextLdifServersOudUtilities,
    )
    from flext_ldif._rfc import (
        FlextLdifServersRfcAcl,
        FlextLdifServersRfcConstants,
        FlextLdifServersRfcEntry,
        FlextLdifServersRfcSchema,
        c,
    )
    from flext_ldif.ad import FlextLdifServersAd
    from flext_ldif.apache import FlextLdifServersApache
    from flext_ldif.base import FlextLdifServersBase
    from flext_ldif.ds389 import FlextLdifServersDs389
    from flext_ldif.novell import FlextLdifServersNovell
    from flext_ldif.oid import FlextLdifServersOid, logger
    from flext_ldif.openldap import FlextLdifServersOpenldap
    from flext_ldif.openldap1 import FlextLdifServersOpenldap1
    from flext_ldif.oud import FlextLdifServersOud
    from flext_ldif.relaxed import FlextLdifServersRelaxed
    from flext_ldif.rfc import FlextLdifServersRfc
    from flext_ldif.tivoli import FlextLdifServersTivoli

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = merge_lazy_imports(
    (
        "flext_ldif._base",
        "flext_ldif._oid",
        "flext_ldif._oud",
        "flext_ldif._rfc",
    ),
    {
        "FlextLdifServersAd": "flext_ldif.ad",
        "FlextLdifServersApache": "flext_ldif.apache",
        "FlextLdifServersBase": "flext_ldif.base",
        "FlextLdifServersDs389": "flext_ldif.ds389",
        "FlextLdifServersNovell": "flext_ldif.novell",
        "FlextLdifServersOid": "flext_ldif.oid",
        "FlextLdifServersOpenldap": "flext_ldif.openldap",
        "FlextLdifServersOpenldap1": "flext_ldif.openldap1",
        "FlextLdifServersOud": "flext_ldif.oud",
        "FlextLdifServersRelaxed": "flext_ldif.relaxed",
        "FlextLdifServersRfc": "flext_ldif.rfc",
        "FlextLdifServersTivoli": "flext_ldif.tivoli",
        "_base": "flext_ldif._base",
        "_oid": "flext_ldif._oid",
        "_oud": "flext_ldif._oud",
        "_rfc": "flext_ldif._rfc",
        "acl": "flext_ldif.acl",
        "ad": "flext_ldif.ad",
        "apache": "flext_ldif.apache",
        "base": "flext_ldif.base",
        "constants": "flext_ldif.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "ds389": "flext_ldif.ds389",
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "entry": "flext_ldif.entry",
        "h": ("flext_core.handlers", "FlextHandlers"),
        "logger": "flext_ldif.oid",
        "m": ("flext_core.models", "FlextModels"),
        "novell": "flext_ldif.novell",
        "oid": "flext_ldif.oid",
        "openldap": "flext_ldif.openldap",
        "openldap1": "flext_ldif.openldap1",
        "oud": "flext_ldif.oud",
        "p": ("flext_core.protocols", "FlextProtocols"),
        "r": ("flext_core.result", "FlextResult"),
        "relaxed": "flext_ldif.relaxed",
        "rfc": "flext_ldif.rfc",
        "s": ("flext_core.service", "FlextService"),
        "schema": "flext_ldif.schema",
        "t": ("flext_core.typings", "FlextTypes"),
        "tivoli": "flext_ldif.tivoli",
        "u": ("flext_core.utilities", "FlextUtilities"),
        "utilities": "flext_ldif.utilities",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
