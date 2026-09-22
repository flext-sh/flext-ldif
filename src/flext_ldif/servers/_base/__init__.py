# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Base package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .acl import FlextLdifServersBaseSchemaAcl
    from .entry import FlextLdifServersBaseEntry
    from .mixins import FlextLdifServerMethodsMixin
    from .schema import FlextLdifServersBaseSchema
    from .server_constants import FlextLdifServersBaseConstants


__all__: tuple[str, ...] = (
    "FlextLdifServerMethodsMixin",
    "FlextLdifServersBaseConstants",
    "FlextLdifServersBaseEntry",
    "FlextLdifServersBaseSchema",
    "FlextLdifServersBaseSchemaAcl",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".acl": ("FlextLdifServersBaseSchemaAcl",),
            ".entry": ("FlextLdifServersBaseEntry",),
            ".mixins": ("FlextLdifServerMethodsMixin",),
            ".schema": ("FlextLdifServersBaseSchema",),
            ".server_constants": ("FlextLdifServersBaseConstants",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
