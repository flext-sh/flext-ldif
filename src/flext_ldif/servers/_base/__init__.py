# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Base package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
    from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
    from flext_ldif.servers._base.mixins import FlextLdifServerMethodsMixin
    from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
    from flext_ldif.servers._base.server_constants import FlextLdifServersBaseConstants


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
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
