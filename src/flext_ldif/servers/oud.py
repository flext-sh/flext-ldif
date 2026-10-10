"""Oracle Unified Directory (OUD) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
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
    Acl: ClassVar[type[FlextLdifServersBaseSchemaAcl]] = FlextLdifServersOudAcl
    Schema: ClassVar[type[FlextLdifServersBaseSchema]] = FlextLdifServersOudSchema
    Entry: ClassVar[type[FlextLdifServersBaseEntry]] = FlextLdifServersOudEntry


__all__: list[str] = ["FlextLdifServersOud"]
