# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Constants package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._constants.acl_convert import FlextLdifConstantsAclConvert
    from flext_ldif._constants.base import (
        FlextLdifConstantsAclConvertOud,
        FlextLdifConstantsBase,
        FlextLdifConstantsEnums,
    )
    from flext_ldif._constants.enums import FlextLdifConstantsBaseParts
    from flext_ldif._constants.servers import FlextLdifConstantsServers
    from flext_ldif._constants.servers_base import FlextLdifConstantsServersBase
    from flext_ldif._constants.servers_oid import FlextLdifConstantsServersOid
    from flext_ldif._constants.servers_oud import FlextLdifConstantsServersOud
    from flext_ldif._constants.servers_relaxed import FlextLdifConstantsServersRelaxed
    from flext_ldif._constants.servers_rfc import FlextLdifConstantsServersRfc
    from flext_ldif._constants.str_enums import FlextLdifConstantsStrEnums


__all__: tuple[str, ...] = (
    "FlextLdifConstantsAclConvert",
    "FlextLdifConstantsAclConvertOud",
    "FlextLdifConstantsBase",
    "FlextLdifConstantsBaseParts",
    "FlextLdifConstantsEnums",
    "FlextLdifConstantsServers",
    "FlextLdifConstantsServersBase",
    "FlextLdifConstantsServersOid",
    "FlextLdifConstantsServersOud",
    "FlextLdifConstantsServersRelaxed",
    "FlextLdifConstantsServersRfc",
    "FlextLdifConstantsStrEnums",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifConstantsAclConvert": ".acl_convert",
        "FlextLdifConstantsAclConvertOud": ".base",
        "FlextLdifConstantsBase": ".base",
        "FlextLdifConstantsBaseParts": ".enums",
        "FlextLdifConstantsEnums": ".base",
        "FlextLdifConstantsServers": ".servers",
        "FlextLdifConstantsServersBase": ".servers_base",
        "FlextLdifConstantsServersOid": ".servers_oid",
        "FlextLdifConstantsServersOud": ".servers_oud",
        "FlextLdifConstantsServersRelaxed": ".servers_relaxed",
        "FlextLdifConstantsServersRfc": ".servers_rfc",
        "FlextLdifConstantsStrEnums": ".str_enums",
    }),
    public_exports=__all__,
)
