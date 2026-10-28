"""RFC 4512 Compliant Server Servers - Base LDAP Schema/ACL/Entry Implementation.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifConstants
from flext_ldif.servers import FlextLdifServersBase


class FlextLdifServersRfcConstants(
    FlextLdifConstants,
    FlextLdifServersBase,
):
    """Thin inheritor: declarations live in _constants parts."""


__all__: list[str] = ["FlextLdifServersRfcConstants"]
