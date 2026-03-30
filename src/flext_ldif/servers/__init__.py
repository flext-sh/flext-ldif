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
        _base as _base,
        _oid as _oid,
        _oud as _oud,
        _rfc as _rfc,
        ad as ad,
        apache as apache,
        base as base,
        ds389 as ds389,
        novell as novell,
        oid as oid,
        openldap as openldap,
        openldap1 as openldap1,
        oud as oud,
        relaxed as relaxed,
        rfc as rfc,
        tivoli as tivoli,
    )
    from flext_ldif.servers._base import (
        acl as acl,
        constants as constants,
        entry as entry,
        schema as schema,
    )
    from flext_ldif.servers._base.acl import (
        FlextLdifServersBaseSchemaAcl as FlextLdifServersBaseSchemaAcl,
    )
    from flext_ldif.servers._base.constants import (
        FlextLdifQuirkMethodsMixin as FlextLdifQuirkMethodsMixin,
        FlextLdifServersBaseConstants as FlextLdifServersBaseConstants,
        FlextLdifServersBaseQuirkHelpers as FlextLdifServersBaseQuirkHelpers,
    )
    from flext_ldif.servers._base.entry import (
        FlextLdifServersBaseEntry as FlextLdifServersBaseEntry,
    )
    from flext_ldif.servers._base.schema import (
        FlextLdifServersBaseSchema as FlextLdifServersBaseSchema,
    )
    from flext_ldif.servers._oid.acl import (
        FlextLdifServersOidAcl as FlextLdifServersOidAcl,
    )
    from flext_ldif.servers._oid.constants import (
        FlextLdifServersOidConstants as FlextLdifServersOidConstants,
    )
    from flext_ldif.servers._oid.entry import (
        FlextLdifServersOidEntry as FlextLdifServersOidEntry,
    )
    from flext_ldif.servers._oid.schema import (
        FlextLdifServersOidSchema as FlextLdifServersOidSchema,
    )
    from flext_ldif.servers._oud import utilities as utilities
    from flext_ldif.servers._oud.acl import (
        FlextLdifServersOudAcl as FlextLdifServersOudAcl,
    )
    from flext_ldif.servers._oud.constants import (
        FlextLdifServersOudConstants as FlextLdifServersOudConstants,
    )
    from flext_ldif.servers._oud.entry import (
        FlextLdifServersOudEntry as FlextLdifServersOudEntry,
    )
    from flext_ldif.servers._oud.schema import (
        FlextLdifServersOudSchema as FlextLdifServersOudSchema,
    )
    from flext_ldif.servers._oud.utilities import (
        FlextLdifServersOudUtilities as FlextLdifServersOudUtilities,
    )
    from flext_ldif.servers._rfc.acl import (
        FlextLdifServersRfcAcl as FlextLdifServersRfcAcl,
    )
    from flext_ldif.servers._rfc.constants import (
        FlextLdifServersRfcConstants as FlextLdifServersRfcConstants,
        c as c,
    )
    from flext_ldif.servers._rfc.entry import (
        FlextLdifServersRfcEntry as FlextLdifServersRfcEntry,
    )
    from flext_ldif.servers._rfc.schema import (
        FlextLdifServersRfcSchema as FlextLdifServersRfcSchema,
    )
    from flext_ldif.servers.ad import FlextLdifServersAd as FlextLdifServersAd
    from flext_ldif.servers.apache import (
        FlextLdifServersApache as FlextLdifServersApache,
    )
    from flext_ldif.servers.base import FlextLdifServersBase as FlextLdifServersBase
    from flext_ldif.servers.ds389 import FlextLdifServersDs389 as FlextLdifServersDs389
    from flext_ldif.servers.novell import (
        FlextLdifServersNovell as FlextLdifServersNovell,
    )
    from flext_ldif.servers.oid import (
        FlextLdifServersOid as FlextLdifServersOid,
        logger as logger,
    )
    from flext_ldif.servers.openldap import (
        FlextLdifServersOpenldap as FlextLdifServersOpenldap,
    )
    from flext_ldif.servers.openldap1 import (
        FlextLdifServersOpenldap1 as FlextLdifServersOpenldap1,
    )
    from flext_ldif.servers.oud import FlextLdifServersOud as FlextLdifServersOud
    from flext_ldif.servers.relaxed import (
        FlextLdifServersRelaxed as FlextLdifServersRelaxed,
    )
    from flext_ldif.servers.rfc import FlextLdifServersRfc as FlextLdifServersRfc
    from flext_ldif.servers.tivoli import (
        FlextLdifServersTivoli as FlextLdifServersTivoli,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdifQuirkMethodsMixin": [
        "flext_ldif.servers._base.constants",
        "FlextLdifQuirkMethodsMixin",
    ],
    "FlextLdifServersAd": ["flext_ldif.servers.ad", "FlextLdifServersAd"],
    "FlextLdifServersApache": ["flext_ldif.servers.apache", "FlextLdifServersApache"],
    "FlextLdifServersBase": ["flext_ldif.servers.base", "FlextLdifServersBase"],
    "FlextLdifServersBaseConstants": [
        "flext_ldif.servers._base.constants",
        "FlextLdifServersBaseConstants",
    ],
    "FlextLdifServersBaseEntry": [
        "flext_ldif.servers._base.entry",
        "FlextLdifServersBaseEntry",
    ],
    "FlextLdifServersBaseQuirkHelpers": [
        "flext_ldif.servers._base.constants",
        "FlextLdifServersBaseQuirkHelpers",
    ],
    "FlextLdifServersBaseSchema": [
        "flext_ldif.servers._base.schema",
        "FlextLdifServersBaseSchema",
    ],
    "FlextLdifServersBaseSchemaAcl": [
        "flext_ldif.servers._base.acl",
        "FlextLdifServersBaseSchemaAcl",
    ],
    "FlextLdifServersDs389": ["flext_ldif.servers.ds389", "FlextLdifServersDs389"],
    "FlextLdifServersNovell": ["flext_ldif.servers.novell", "FlextLdifServersNovell"],
    "FlextLdifServersOid": ["flext_ldif.servers.oid", "FlextLdifServersOid"],
    "FlextLdifServersOidAcl": ["flext_ldif.servers._oid.acl", "FlextLdifServersOidAcl"],
    "FlextLdifServersOidConstants": [
        "flext_ldif.servers._oid.constants",
        "FlextLdifServersOidConstants",
    ],
    "FlextLdifServersOidEntry": [
        "flext_ldif.servers._oid.entry",
        "FlextLdifServersOidEntry",
    ],
    "FlextLdifServersOidSchema": [
        "flext_ldif.servers._oid.schema",
        "FlextLdifServersOidSchema",
    ],
    "FlextLdifServersOpenldap": [
        "flext_ldif.servers.openldap",
        "FlextLdifServersOpenldap",
    ],
    "FlextLdifServersOpenldap1": [
        "flext_ldif.servers.openldap1",
        "FlextLdifServersOpenldap1",
    ],
    "FlextLdifServersOud": ["flext_ldif.servers.oud", "FlextLdifServersOud"],
    "FlextLdifServersOudAcl": ["flext_ldif.servers._oud.acl", "FlextLdifServersOudAcl"],
    "FlextLdifServersOudConstants": [
        "flext_ldif.servers._oud.constants",
        "FlextLdifServersOudConstants",
    ],
    "FlextLdifServersOudEntry": [
        "flext_ldif.servers._oud.entry",
        "FlextLdifServersOudEntry",
    ],
    "FlextLdifServersOudSchema": [
        "flext_ldif.servers._oud.schema",
        "FlextLdifServersOudSchema",
    ],
    "FlextLdifServersOudUtilities": [
        "flext_ldif.servers._oud.utilities",
        "FlextLdifServersOudUtilities",
    ],
    "FlextLdifServersRelaxed": [
        "flext_ldif.servers.relaxed",
        "FlextLdifServersRelaxed",
    ],
    "FlextLdifServersRfc": ["flext_ldif.servers.rfc", "FlextLdifServersRfc"],
    "FlextLdifServersRfcAcl": ["flext_ldif.servers._rfc.acl", "FlextLdifServersRfcAcl"],
    "FlextLdifServersRfcConstants": [
        "flext_ldif.servers._rfc.constants",
        "FlextLdifServersRfcConstants",
    ],
    "FlextLdifServersRfcEntry": [
        "flext_ldif.servers._rfc.entry",
        "FlextLdifServersRfcEntry",
    ],
    "FlextLdifServersRfcSchema": [
        "flext_ldif.servers._rfc.schema",
        "FlextLdifServersRfcSchema",
    ],
    "FlextLdifServersTivoli": ["flext_ldif.servers.tivoli", "FlextLdifServersTivoli"],
    "_base": ["flext_ldif.servers._base", ""],
    "_oid": ["flext_ldif.servers._oid", ""],
    "_oud": ["flext_ldif.servers._oud", ""],
    "_rfc": ["flext_ldif.servers._rfc", ""],
    "acl": ["flext_ldif.servers._base.acl", ""],
    "ad": ["flext_ldif.servers.ad", ""],
    "apache": ["flext_ldif.servers.apache", ""],
    "base": ["flext_ldif.servers.base", ""],
    "c": ["flext_ldif.servers._rfc.constants", "c"],
    "constants": ["flext_ldif.servers._base.constants", ""],
    "ds389": ["flext_ldif.servers.ds389", ""],
    "entry": ["flext_ldif.servers._base.entry", ""],
    "logger": ["flext_ldif.servers.oid", "logger"],
    "novell": ["flext_ldif.servers.novell", ""],
    "oid": ["flext_ldif.servers.oid", ""],
    "openldap": ["flext_ldif.servers.openldap", ""],
    "openldap1": ["flext_ldif.servers.openldap1", ""],
    "oud": ["flext_ldif.servers.oud", ""],
    "relaxed": ["flext_ldif.servers.relaxed", ""],
    "rfc": ["flext_ldif.servers.rfc", ""],
    "schema": ["flext_ldif.servers._base.schema", ""],
    "tivoli": ["flext_ldif.servers.tivoli", ""],
    "utilities": ["flext_ldif.servers._oud.utilities", ""],
}

_EXPORTS: Sequence[str] = [
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
    "ds389",
    "entry",
    "logger",
    "novell",
    "oid",
    "openldap",
    "openldap1",
    "oud",
    "relaxed",
    "rfc",
    "schema",
    "tivoli",
    "utilities",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
