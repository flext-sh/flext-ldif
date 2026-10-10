"""Oracle Unified Directory (OUD) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_ldif import FlextLdifServersRfc
from flext_ldif.servers._base import (
    FlextLdifServersBaseEntry,
    FlextLdifServersBaseSchema,
    FlextLdifServersBaseSchemaAcl,
)
from flext_ldif.servers._oud import (
    FlextLdifServersOudAcl,
    FlextLdifServersOudConstants,
    FlextLdifServersOudEntry,
    FlextLdifServersOudSchema,
)


class FlextLdifServersOud(FlextLdifServersRfc):
    """Oracle Unified Directory (OUD) Server Implementation."""

    Constants: ClassVar[type[FlextLdifServersOudConstants]] = (
        FlextLdifServersOudConstants
    )
    Acl: ClassVar[type[FlextLdifServersBaseSchemaAcl]] = FlextLdifServersOudAcl
    Schema: ClassVar[type[FlextLdifServersBaseSchema]] = FlextLdifServersOudSchema
    Entry: ClassVar[type[FlextLdifServersBaseEntry]] = FlextLdifServersOudEntry


__all__: list[str] = ["FlextLdifServersOud"]
