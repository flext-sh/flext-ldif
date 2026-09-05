# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Oud package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers.rfc import FlextLdifServersRfc
    from typing import ClassVar, TYPE_CHECKING

    from .aci import FlextLdifServersOudAciMixin
    from .acl import FlextLdifServersOudAcl
    from .acl_extract import FlextLdifServersOudAclExtractMixin
    from .acl_metadata import FlextLdifServersOudAclMetadataMixin
    from .comments import FlextLdifServersOudCommentsMixin
    from .constants import FlextLdifServersOudConstants
    from .entry import FlextLdifServersOudEntry
    from .helpers import FlextLdifServersOudHelpersMixin
    from .schema import FlextLdifServersOudSchema
    from .transform import FlextLdifServersOudTransformMixin
    from .utilities import FlextLdifServersOudUtilities
__all__: tuple[str, ...] = (
    "TYPE_CHECKING",
    "ClassVar",
    "FlextLdifServersOudAciMixin",
    "FlextLdifServersOudAcl",
    "FlextLdifServersOudAclExtractMixin",
    "FlextLdifServersOudAclMetadataMixin",
    "FlextLdifServersOudCommentsMixin",
    "FlextLdifServersOudConstants",
    "FlextLdifServersOudEntry",
    "FlextLdifServersOudHelpersMixin",
    "FlextLdifServersOudSchema",
    "FlextLdifServersOudTransformMixin",
    "FlextLdifServersOudUtilities",
    "FlextLdifServersRfc",
    "MappingProxyType",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
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
            "flext_ldif.servers.rfc": ("FlextLdifServersRfc",),
            "types": ("MappingProxyType",),
            "typing": ("ClassVar", "TYPE_CHECKING"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
