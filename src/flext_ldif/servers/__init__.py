# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers import _base, _oid, _oud, _rfc
    from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
    from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
    from flext_ldif.servers._base.mixins import FlextLdifServerMethodsMixin
    from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
    from flext_ldif.servers._base.server_constants import FlextLdifServersBaseConstants
    from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl
    from flext_ldif.servers._oud.aci import FlextLdifServersOudAciMixin
    from flext_ldif.servers._oud.acl import FlextLdifServersOudAcl
    from flext_ldif.servers._oud.acl_extract import FlextLdifServersOudAclExtractMixin
    from flext_ldif.servers._oud.acl_metadata import FlextLdifServersOudAclMetadataMixin
    from flext_ldif.servers._oud.comments import FlextLdifServersOudCommentsMixin
    from flext_ldif.servers._oud.entry import FlextLdifServersOudEntry
    from flext_ldif.servers._oud.helpers import FlextLdifServersOudHelpersMixin
    from flext_ldif.servers._oud.schema import FlextLdifServersOudSchema
    from flext_ldif.servers._oud.schema_write import FlextLdifServersOudSchemaWriteMixin
    from flext_ldif.servers._oud.server_constants import FlextLdifServersOudConstants
    from flext_ldif.servers._oud.server_utilities import FlextLdifServersOudUtilities
    from flext_ldif.servers._oud.transform import FlextLdifServersOudTransformMixin
    from flext_ldif.servers._rfc.acl import FlextLdifServersRfcAcl
    from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry
    from flext_ldif.servers._rfc.schema import FlextLdifServersRfcSchema
    from flext_ldif.servers._rfc.server_constants import FlextLdifServersRfcConstants
    from flext_ldif.servers.ad import FlextLdifServersAd
    from flext_ldif.servers.apache import FlextLdifServersApache
    from flext_ldif.servers.base import FlextLdifServersBase
    from flext_ldif.servers.ds389 import FlextLdifServersDs389
    from flext_ldif.servers.oid import (
        FlextLdifServersOid,
        FlextLdifServersOidAclAssemble,
        FlextLdifServersOidAclConvert,
        FlextLdifServersOidAclPipeline,
        FlextLdifServersOidAclRender,
        FlextLdifServersOidAclToOud,
        FlextLdifServersOidConstants,
        FlextLdifServersOidEntry,
        FlextLdifServersOidSchema,
    )
    from flext_ldif.servers.openldap import FlextLdifServersOpenldap
    from flext_ldif.servers.oud import FlextLdifServersOud
    from flext_ldif.servers.relaxed import FlextLdifServersRelaxed
    from flext_ldif.servers.rfc import FlextLdifServersRfc
    from flext_ldif.servers.tivoli import FlextLdifServersTivoli


__all__: tuple[str, ...] = (
    "FlextLdifServerMethodsMixin",
    "FlextLdifServersAd",
    "FlextLdifServersApache",
    "FlextLdifServersBase",
    "FlextLdifServersBaseConstants",
    "FlextLdifServersBaseEntry",
    "FlextLdifServersBaseSchema",
    "FlextLdifServersBaseSchemaAcl",
    "FlextLdifServersDs389",
    "FlextLdifServersOid",
    "FlextLdifServersOidAcl",
    "FlextLdifServersOidAclAssemble",
    "FlextLdifServersOidAclConvert",
    "FlextLdifServersOidAclPipeline",
    "FlextLdifServersOidAclRender",
    "FlextLdifServersOidAclToOud",
    "FlextLdifServersOidConstants",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidSchema",
    "FlextLdifServersOpenldap",
    "FlextLdifServersOud",
    "FlextLdifServersOudAciMixin",
    "FlextLdifServersOudAcl",
    "FlextLdifServersOudAclExtractMixin",
    "FlextLdifServersOudAclMetadataMixin",
    "FlextLdifServersOudCommentsMixin",
    "FlextLdifServersOudConstants",
    "FlextLdifServersOudEntry",
    "FlextLdifServersOudHelpersMixin",
    "FlextLdifServersOudSchema",
    "FlextLdifServersOudSchemaWriteMixin",
    "FlextLdifServersOudTransformMixin",
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
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            "._base": ("_base",),
            "._base.acl": ("FlextLdifServersBaseSchemaAcl",),
            "._base.entry": ("FlextLdifServersBaseEntry",),
            "._base.mixins": ("FlextLdifServerMethodsMixin",),
            "._base.schema": ("FlextLdifServersBaseSchema",),
            "._base.server_constants": ("FlextLdifServersBaseConstants",),
            "._oid": ("_oid",),
            "._oid.acl": ("FlextLdifServersOidAcl",),
            "._oud": ("_oud",),
            "._oud.aci": ("FlextLdifServersOudAciMixin",),
            "._oud.acl": ("FlextLdifServersOudAcl",),
            "._oud.acl_extract": ("FlextLdifServersOudAclExtractMixin",),
            "._oud.acl_metadata": ("FlextLdifServersOudAclMetadataMixin",),
            "._oud.comments": ("FlextLdifServersOudCommentsMixin",),
            "._oud.entry": ("FlextLdifServersOudEntry",),
            "._oud.helpers": ("FlextLdifServersOudHelpersMixin",),
            "._oud.schema": ("FlextLdifServersOudSchema",),
            "._oud.schema_write": ("FlextLdifServersOudSchemaWriteMixin",),
            "._oud.server_constants": ("FlextLdifServersOudConstants",),
            "._oud.server_utilities": ("FlextLdifServersOudUtilities",),
            "._oud.transform": ("FlextLdifServersOudTransformMixin",),
            "._rfc": ("_rfc",),
            "._rfc.acl": ("FlextLdifServersRfcAcl",),
            "._rfc.entry": ("FlextLdifServersRfcEntry",),
            "._rfc.schema": ("FlextLdifServersRfcSchema",),
            "._rfc.server_constants": ("FlextLdifServersRfcConstants",),
            ".ad": ("FlextLdifServersAd",),
            ".apache": ("FlextLdifServersApache",),
            ".base": ("FlextLdifServersBase",),
            ".ds389": ("FlextLdifServersDs389",),
            ".oid": (
                "FlextLdifServersOid",
                "FlextLdifServersOidAclAssemble",
                "FlextLdifServersOidAclConvert",
                "FlextLdifServersOidAclPipeline",
                "FlextLdifServersOidAclRender",
                "FlextLdifServersOidAclToOud",
                "FlextLdifServersOidConstants",
                "FlextLdifServersOidEntry",
                "FlextLdifServersOidSchema",
            ),
            ".openldap": ("FlextLdifServersOpenldap",),
            ".oud": ("FlextLdifServersOud",),
            ".relaxed": ("FlextLdifServersRelaxed",),
            ".rfc": ("FlextLdifServersRfc",),
            ".tivoli": ("FlextLdifServersTivoli",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
