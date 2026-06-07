# AUTO-GENERATED FILE — Regenerate with: make gen
"""Oid package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
