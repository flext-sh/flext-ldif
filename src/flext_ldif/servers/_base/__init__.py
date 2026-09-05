# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Base package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from typing import TYPE_CHECKING, ClassVar

    from .acl import FlextLdifServersBaseSchemaAcl
    from .constants import FlextLdifServersBaseConstants
    from .entry import FlextLdifServersBaseEntry
    from .mixins import FlextLdifServerMethodsMixin
    from .schema import FlextLdifServersBaseSchema
__all__: tuple[str, ...] = (
    "TYPE_CHECKING",
    "ClassVar",
    "FlextLdifServerMethodsMixin",
    "FlextLdifServersBaseConstants",
    "FlextLdifServersBaseEntry",
    "FlextLdifServersBaseSchema",
    "FlextLdifServersBaseSchemaAcl",
    "MappingProxyType",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".acl": ("FlextLdifServersBaseSchemaAcl",),
            ".constants": ("FlextLdifServersBaseConstants",),
            ".entry": ("FlextLdifServersBaseEntry",),
            ".mixins": ("FlextLdifServerMethodsMixin",),
            ".schema": ("FlextLdifServersBaseSchema",),
            "types": ("MappingProxyType",),
            "typing": ("ClassVar", "TYPE_CHECKING"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
