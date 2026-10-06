"""RFC 4512 Compliant Server Servers - Base LDAP Schema/ACL/Entry Implementation.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.servers._rfc.acl import FlextLdifServersRfcAcl
from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry
from flext_ldif.servers._rfc.schema import FlextLdifServersRfcSchema
from flext_ldif.servers._rfc.server_constants import FlextLdifServersRfcConstants
from flext_ldif.servers.base import FlextLdifServersBase


class FlextLdifServersRfc(FlextLdifServersBase):
    """RFC-Compliant LDAP Server Implementation - STRICT Baseline."""

    Constants = FlextLdifServersRfcConstants
    Acl = FlextLdifServersRfcAcl
    Schema = FlextLdifServersRfcSchema
    Entry = FlextLdifServersRfcEntry


__all__: list[str] = ["FlextLdifServersRfc"]
