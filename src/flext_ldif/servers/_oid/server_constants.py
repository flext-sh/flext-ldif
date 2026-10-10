"""Oracle Internet Directory (OID) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._constants.servers_oid import FlextLdifConstantsServersOid
from flext_ldif.servers._rfc import FlextLdifServersRfcConstants


class FlextLdifServersOidConstants(
    FlextLdifConstantsServersOid,
    FlextLdifServersRfcConstants,
):
    """Thin inheritor: declarations live in _constants parts."""
