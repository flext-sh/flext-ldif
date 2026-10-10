"""Oracle Unified Directory (OUD) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_ldif.servers._base import FlextLdifServersBaseSchemaAcl
from flext_ldif.servers._base import FlextLdifServersBaseEntry
from flext_ldif.servers._base import FlextLdifServersBaseSchema
from flext_ldif.servers._oud import FlextLdifServersOudAcl
from flext_ldif.servers._oud import FlextLdifServersOudEntry
from flext_ldif.servers._oud import FlextLdifServersOudSchema
from flext_ldif.servers._oud import FlextLdifServersOudConstants
from flext_ldif import FlextLdifServersRfc


class FlextLdifServersOud(FlextLdifServersRfc):
    """Oracle Unified Directory (OUD) Server Implementation."""

    Constants: ClassVar[type[FlextLdifServersOudConstants]] = (
        FlextLdifServersOudConstants
    )
    Acl: ClassVar[type[FlextLdifServersBaseSchemaAcl]] = FlextLdifServersOudAcl
    Schema: ClassVar[type[FlextLdifServersBaseSchema]] = FlextLdifServersOudSchema
    Entry: ClassVar[type[FlextLdifServersBaseEntry]] = FlextLdifServersOudEntry


__all__: list[str] = ["FlextLdifServersOud"]
