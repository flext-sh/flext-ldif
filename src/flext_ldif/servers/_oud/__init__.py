# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Oud package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from ..rfc import FlextLdifServersRfc as fsr
    from .aci import FlextLdifServersOudAciMixin
    from .acl import FlextLdifServersOudAcl
    from .acl_extract import FlextLdifServersOudAclExtractMixin
    from .acl_metadata import FlextLdifServersOudAclMetadataMixin
    from .comments import FlextLdifServersOudCommentsMixin
    from .constants import (
        FlextLdifServersOudConstants,
        FlextLdifServersOudConstants as c,
    )
    from .entry import FlextLdifServersOudEntry
    from .helpers import FlextLdifServersOudHelpersMixin
    from .schema import FlextLdifServersOudSchema
    from .transform import FlextLdifServersOudTransformMixin
    from .utilities import (
        FlextLdifServersOudUtilities,
        FlextLdifServersOudUtilities as u,
    )
__all__: tuple[str, ...] = (
    "FlextLdifServersOudAciMixin", "FlextLdifServersOudAcl", "FlextLdifServersOudAclExtractMixin", "FlextLdifServersOudAclMetadataMixin",
    "FlextLdifServersOudCommentsMixin", "FlextLdifServersOudConstants", "FlextLdifServersOudEntry", "FlextLdifServersOudHelpersMixin",
    "FlextLdifServersOudSchema", "FlextLdifServersOudTransformMixin", "FlextLdifServersOudUtilities", "c",
    "fsr", "u",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".aci": ("FlextLdifServersOudAciMixin",),
            ".acl": ("FlextLdifServersOudAcl",),
            ".acl_extract": ("FlextLdifServersOudAclExtractMixin",),
            ".acl_metadata": ("FlextLdifServersOudAclMetadataMixin",),
            ".comments": ("FlextLdifServersOudCommentsMixin",),
            ".constants": ("FlextLdifServersOudConstants", "c"),
            ".entry": ("FlextLdifServersOudEntry",),
            ".helpers": ("FlextLdifServersOudHelpersMixin",),
            ".schema": ("FlextLdifServersOudSchema",),
            ".transform": ("FlextLdifServersOudTransformMixin",),
            ".utilities": ("FlextLdifServersOudUtilities", "u"),
        }),
        alias_groups=MappingProxyType({"..rfc": (("fsr", "FlextLdifServersRfc"),)}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
