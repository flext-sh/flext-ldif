# AUTO-GENERATED FILE — Regenerate with: make gen
"""Oud package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".aci": ("FlextLdifServersOudAciMixin",),
        ".acl": ("FlextLdifServersOudAcl",),
        ".acl_extract": ("FlextLdifServersOudAclExtractMixin",),
        ".acl_metadata": ("FlextLdifServersOudAclMetadataMixin",),
        ".comments": ("FlextLdifServersOudCommentsMixin",),
        ".constants": ("FlextLdifServersOudConstants",),
        ".entry": ("FlextLdifServersOudEntry",),
        ".helpers": ("FlextLdifServersOudHelpersMixin",),
        ".schema": ("FlextLdifServersOudSchema",),
        ".transform": ("FlextLdifServersOudTransformMixin",),
        ".utilities": ("FlextLdifServersOudUtilities",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
