# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Constants package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .acl_convert import FlextLdifConstantsAclConvert
    from .acl_convert_oud import FlextLdifConstantsAclConvertOud
    from .base import FlextLdifConstantsBase
    from .enums import FlextLdifConstantsEnums
__all__: tuple[str, ...] = (
    "FlextLdifConstantsAclConvert",
    "FlextLdifConstantsAclConvertOud",
    "FlextLdifConstantsBase",
    "FlextLdifConstantsEnums",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".acl_convert": ("FlextLdifConstantsAclConvert",),
            ".acl_convert_oud": ("FlextLdifConstantsAclConvertOud",),
            ".base": ("FlextLdifConstantsBase",),
            ".enums": ("FlextLdifConstantsEnums",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
