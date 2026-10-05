# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Oid package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl
    from flext_ldif.servers._oid.acl_assemble import FlextLdifServersOidAclAssemble
    from flext_ldif.servers._oid.acl_convert import FlextLdifServersOidAclConvert
    from flext_ldif.servers._oid.acl_convert_oud import FlextLdifServersOidAclToOud
    from flext_ldif.servers._oid.acl_pipeline import FlextLdifServersOidAclPipeline
    from flext_ldif.servers._oid.acl_render import FlextLdifServersOidAclRender
    from flext_ldif.servers._oid.entry import FlextLdifServersOidEntry
    from flext_ldif.servers._oid.schema import FlextLdifServersOidSchema
    from flext_ldif.servers._oid.server_constants import FlextLdifServersOidConstants


__all__: tuple[str, ...] = (
    "FlextLdifServersOidAcl",
    "FlextLdifServersOidAclAssemble",
    "FlextLdifServersOidAclConvert",
    "FlextLdifServersOidAclPipeline",
    "FlextLdifServersOidAclRender",
    "FlextLdifServersOidAclToOud",
    "FlextLdifServersOidConstants",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidSchema",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifServersOidAcl": ".acl",
        "FlextLdifServersOidAclAssemble": ".acl_assemble",
        "FlextLdifServersOidAclConvert": ".acl_convert",
        "FlextLdifServersOidAclPipeline": ".acl_pipeline",
        "FlextLdifServersOidAclRender": ".acl_render",
        "FlextLdifServersOidAclToOud": ".acl_convert_oud",
        "FlextLdifServersOidConstants": ".server_constants",
        "FlextLdifServersOidEntry": ".entry",
        "FlextLdifServersOidSchema": ".schema",
    }),
    public_exports=__all__,
)
