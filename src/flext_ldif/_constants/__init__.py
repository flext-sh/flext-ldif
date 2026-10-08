# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Constants package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

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
    from flext_ldif._constants.servers_relaxed import FlextLdifConstantsServersRelaxed


__all__: tuple[str, ...] = (
    "FlextLdifConstantsAclConvert",
    "FlextLdifConstantsAclConvertOud",
    "FlextLdifConstantsBase",
    "FlextLdifConstantsEnums",
    "FlextLdifConstantsServers",
    "FlextLdifConstantsServersBase",
    "FlextLdifConstantsServersOid",
    "FlextLdifConstantsServersOud",
    "FlextLdifConstantsServersRelaxed",
    "FlextLdifConstantsServersRfc",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifConstantsAclConvert": ".acl_convert",
        "FlextLdifConstantsAclConvertOud": ".acl_convert_oud",
        "FlextLdifConstantsBase": ".base",
        "FlextLdifConstantsEnums": ".enums",
        "FlextLdifConstantsServers": ".servers",
        "FlextLdifConstantsServersBase": ".servers",
        "FlextLdifConstantsServersOid": ".servers",
        "FlextLdifConstantsServersOud": ".servers",
        "FlextLdifConstantsServersRelaxed": ".servers_relaxed",
        "FlextLdifConstantsServersRfc": ".servers",
    }),
    public_exports=__all__,
)
