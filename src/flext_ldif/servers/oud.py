"""Oracle Unified Directory (OUD) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_ldif.servers._oud.acl import FlextLdifServersOudAcl
from flext_ldif.servers._oud.entry import FlextLdifServersOudEntry
from flext_ldif.servers._oud.schema import FlextLdifServersOudSchema
from flext_ldif.servers._oud.server_constants import FlextLdifServersOudConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOud(FlextLdifServersRfc):
    """Oracle Unified Directory (OUD) Server Implementation."""

    Constants: ClassVar[type[FlextLdifServersOudConstants]] = (
        FlextLdifServersOudConstants
    )
    Acl: ClassVar[type[FlextLdifServersOudAcl]] = FlextLdifServersOudAcl
    Schema: ClassVar[type[FlextLdifServersOudSchema]] = FlextLdifServersOudSchema
    Entry: ClassVar[type[FlextLdifServersOudEntry]] = FlextLdifServersOudEntry


__all__: list[str] = ["FlextLdifServersOud"]
