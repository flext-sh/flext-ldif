# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Oid package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

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

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".acl": ("FlextLdifServersOidAcl",),
            ".acl_assemble": ("FlextLdifServersOidAclAssemble",),
            ".acl_convert": ("FlextLdifServersOidAclConvert",),
            ".acl_convert_oud": ("FlextLdifServersOidAclToOud",),
            ".acl_pipeline": ("FlextLdifServersOidAclPipeline",),
            ".acl_render": ("FlextLdifServersOidAclRender",),
            ".entry": ("FlextLdifServersOidEntry",),
            ".schema": ("FlextLdifServersOidSchema",),
            ".server_constants": ("FlextLdifServersOidConstants",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
