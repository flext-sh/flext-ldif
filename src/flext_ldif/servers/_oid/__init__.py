# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Oid package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from enum import StrEnum, unique
    from typing import TYPE_CHECKING, ClassVar

    from flext_ldif.servers.rfc import FlextLdifServersRfc

    from .acl import FlextLdifServersOidAcl
    from .acl_assemble import FlextLdifServersOidAclAssemble
    from .acl_convert import FlextLdifServersOidAclConvert
    from .acl_convert_oud import FlextLdifServersOidAclToOud
    from .acl_pipeline import FlextLdifServersOidAclPipeline
    from .acl_render import FlextLdifServersOidAclRender
    from .constants import (
        FlextLdifServersOidConstants,
        FlextLdifServersOidConstants as c,
    )
    from .entry import FlextLdifServersOidEntry
    from .schema import FlextLdifServersOidSchema
__all__: tuple[str, ...] = (
    "TYPE_CHECKING",
    "ClassVar",
    "FlextLdifServersOidAcl",
    "FlextLdifServersOidAclAssemble",
    "FlextLdifServersOidAclConvert",
    "FlextLdifServersOidAclPipeline",
    "FlextLdifServersOidAclRender",
    "FlextLdifServersOidAclToOud",
    "FlextLdifServersOidConstants",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidSchema",
    "FlextLdifServersRfc",
    "MappingProxyType",
    "StrEnum",
    "c",
    "unique",
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
            ".constants": ("FlextLdifServersOidConstants", "c"),
            ".entry": ("FlextLdifServersOidEntry",),
            ".schema": ("FlextLdifServersOidSchema",),
            "enum": ("StrEnum", "unique"),
            "flext_ldif.servers.rfc": ("FlextLdifServersRfc",),
            "types": ("MappingProxyType",),
            "typing": ("ClassVar", "TYPE_CHECKING"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
