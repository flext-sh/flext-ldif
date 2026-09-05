# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Rfc package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from typing import TYPE_CHECKING, ClassVar

    from flext_ldif.servers._base.constants import FlextLdifServersBaseConstants

    from .acl import FlextLdifServersRfcAcl
    from .constants import (
        FlextLdifServersRfcConstants,
        FlextLdifServersRfcConstants as c,
    )
    from .entry import FlextLdifServersRfcEntry
    from .schema import FlextLdifServersRfcSchema
__all__: tuple[str, ...] = (
    "TYPE_CHECKING",
    "ClassVar",
    "FlextLdifServersBaseConstants",
    "FlextLdifServersRfcAcl",
    "FlextLdifServersRfcConstants",
    "FlextLdifServersRfcEntry",
    "FlextLdifServersRfcSchema",
    "MappingProxyType",
    "c",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".acl": ("FlextLdifServersRfcAcl",),
            ".constants": ("FlextLdifServersRfcConstants", "c"),
            ".entry": ("FlextLdifServersRfcEntry",),
            ".schema": ("FlextLdifServersRfcSchema",),
            "flext_ldif.servers._base.constants": ("FlextLdifServersBaseConstants",),
            "types": ("MappingProxyType",),
            "typing": ("ClassVar", "TYPE_CHECKING"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
