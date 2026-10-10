"""RFC 4512 Compliant Server Servers - Base LDAP Schema/ACL/Entry Implementation.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_ldif import FlextLdifServersBase
from flext_ldif.servers._base import (
    FlextLdifServersBaseEntry,
    FlextLdifServersBaseSchema,
    FlextLdifServersBaseSchemaAcl,
)
from flext_ldif.servers._rfc import (
    FlextLdifServersRfcAcl,
    FlextLdifServersRfcConstants,
    FlextLdifServersRfcEntry,
    FlextLdifServersRfcSchema,
)


class FlextLdifServersRfc(FlextLdifServersBase):
    """RFC-Compliant LDAP Server Implementation - STRICT Baseline."""

    Constants: ClassVar[type[FlextLdifServersRfcConstants]] = (
        FlextLdifServersRfcConstants
    )
    Acl: ClassVar[type[FlextLdifServersBaseSchemaAcl]] = FlextLdifServersRfcAcl
    Schema: ClassVar[type[FlextLdifServersBaseSchema]] = FlextLdifServersRfcSchema
    Entry: ClassVar[type[FlextLdifServersBaseEntry]] = FlextLdifServersRfcEntry


__all__: list[str] = ["FlextLdifServersRfc"]
