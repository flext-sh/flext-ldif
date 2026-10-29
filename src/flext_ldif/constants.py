# AUTO-GENERATED FILE — Regenerate with: make gen
"""LDIF constants and enumerations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_cli import c as flext_cli_c

from flext_ldif._constants import (
    FlextLdifConstantsAclConvert,
    FlextLdifConstantsAclConvertOud,
    FlextLdifConstantsBase,
    FlextLdifConstantsBaseParts,
    FlextLdifConstantsEnums,
    FlextLdifConstantsServers,
    FlextLdifConstantsStrEnums,
)
from flext_ldif.servers._base import FlextLdifConstantsServersBase
from flext_ldif.servers._oid import FlextLdifConstantsServersOid
from flext_ldif.servers._oud import FlextLdifConstantsServersOud
from flext_ldif.servers._relaxed import FlextLdifConstantsServersRelaxed
from flext_ldif.servers._rfc import FlextLdifConstantsServersRfc


class FlextLdifConstants(flext_cli_c):
    """LDIF domain constants extending flext-core FlextConstants."""

    class Ldif(
        FlextLdifConstantsAclConvert,
        FlextLdifConstantsBase,
        FlextLdifConstantsBaseParts,
        FlextLdifConstantsServers,
        FlextLdifConstantsServersBase,
        FlextLdifConstantsServersOid,
        FlextLdifConstantsServersOud,
        FlextLdifConstantsServersRelaxed,
        FlextLdifConstantsServersRfc,
        FlextLdifConstantsStrEnums,
        FlextLdifConstantsEnums,
        FlextLdifConstantsAclConvertOud,
    ):
        """LDIF domain constants namespace."""


c = FlextLdifConstants
__all__: list[str] = ["FlextLdifConstants", "c"]
