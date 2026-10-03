# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Protocols package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._protocols.base import FlextLdifProtocolsBase
    from flext_ldif._protocols.client import FlextLdifProtocolsClient
    from flext_ldif._protocols.domain import FlextLdifProtocolsDomain
    from flext_ldif._protocols.ldap3 import FlextLdifProtocolsLdap3
    from flext_ldif._protocols.values import FlextLdifProtocolsValues


__all__: tuple[str, ...] = (
    "FlextLdifProtocolsBase",
    "FlextLdifProtocolsClient",
    "FlextLdifProtocolsDomain",
    "FlextLdifProtocolsLdap3",
    "FlextLdifProtocolsValues",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".base": ("FlextLdifProtocolsBase",),
            ".client": ("FlextLdifProtocolsClient",),
            ".domain": ("FlextLdifProtocolsDomain",),
            ".ldap3": ("FlextLdifProtocolsLdap3",),
            ".values": ("FlextLdifProtocolsValues",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
