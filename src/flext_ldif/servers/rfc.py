"""RFC 4512 Compliant Server Servers - Base LDAP Schema/ACL/Entry Implementation.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
from flext_ldif.servers._rfc.acl import FlextLdifServersRfcAcl
from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry
from flext_ldif.servers._rfc.schema import FlextLdifServersRfcSchema
from flext_ldif.servers._rfc.server_constants import FlextLdifServersRfcConstants
from flext_ldif.servers.base import FlextLdifServersBase


class FlextLdifServersRfc(FlextLdifServersBase):
    """RFC-Compliant LDAP Server Implementation - STRICT Baseline."""

    Constants: ClassVar[type[FlextLdifServersRfcConstants]] = (
        FlextLdifServersRfcConstants
    )
    Acl: ClassVar[type[FlextLdifServersBaseSchemaAcl]] = FlextLdifServersRfcAcl
    Schema: ClassVar[type[FlextLdifServersBaseSchema]] = FlextLdifServersRfcSchema
    Entry: ClassVar[type[FlextLdifServersBaseEntry]] = FlextLdifServersRfcEntry


__all__: list[str] = ["FlextLdifServersRfc"]
