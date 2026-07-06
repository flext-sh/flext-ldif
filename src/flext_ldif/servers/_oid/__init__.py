# AUTO-GENERATED FILE — Regenerate with: make gen
"""Oid package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl
    from flext_ldif.servers._oid.acl_assemble import FlextLdifServersOidAclAssemble
    from flext_ldif.servers._oid.acl_convert import FlextLdifServersOidAclConvert
    from flext_ldif.servers._oid.acl_convert_oud import FlextLdifServersOidAclToOud
    from flext_ldif.servers._oid.acl_pipeline import FlextLdifServersOidAclPipeline
    from flext_ldif.servers._oid.acl_render import FlextLdifServersOidAclRender
    from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
    from flext_ldif.servers._oid.entry import FlextLdifServersOidEntry
    from flext_ldif.servers._oid.schema import FlextLdifServersOidSchema
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".acl": ("FlextLdifServersOidAcl",),
        ".acl_assemble": ("FlextLdifServersOidAclAssemble",),
        ".acl_convert": ("FlextLdifServersOidAclConvert",),
        ".acl_convert_oud": ("FlextLdifServersOidAclToOud",),
        ".acl_pipeline": ("FlextLdifServersOidAclPipeline",),
        ".acl_render": ("FlextLdifServersOidAclRender",),
        ".constants": ("FlextLdifServersOidConstants",),
        ".entry": ("FlextLdifServersOidEntry",),
        ".schema": ("FlextLdifServersOidSchema",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
