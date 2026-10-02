# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Constants package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._constants.acl_convert import FlextLdifConstantsAclConvert
    from flext_ldif._constants.acl_convert_oud import FlextLdifConstantsAclConvertOud
    from flext_ldif._constants.base import FlextLdifConstantsBase
    from flext_ldif._constants.enums import FlextLdifConstantsEnums
    from flext_ldif._constants.servers import (
        FlextLdifConstantsServers,
        FlextLdifConstantsServersBase,
        FlextLdifConstantsServersOid,
        FlextLdifConstantsServersOud,
        FlextLdifConstantsServersRfc,
    )


__all__: tuple[str, ...] = (
    "FlextLdifConstantsAclConvert",
    "FlextLdifConstantsAclConvertOud",
    "FlextLdifConstantsBase",
    "FlextLdifConstantsEnums",
    "FlextLdifConstantsServers",
    "FlextLdifConstantsServersBase",
    "FlextLdifConstantsServersOid",
    "FlextLdifConstantsServersOud",
    "FlextLdifConstantsServersRfc",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".acl_convert": ("FlextLdifConstantsAclConvert",),
            ".acl_convert_oud": ("FlextLdifConstantsAclConvertOud",),
            ".base": ("FlextLdifConstantsBase",),
            ".enums": ("FlextLdifConstantsEnums",),
            ".servers": (
                "FlextLdifConstantsServers",
                "FlextLdifConstantsServersBase",
                "FlextLdifConstantsServersOid",
                "FlextLdifConstantsServersOud",
                "FlextLdifConstantsServersRfc",
            ),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
