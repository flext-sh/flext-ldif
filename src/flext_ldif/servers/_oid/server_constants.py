"""Oracle Internet Directory (OID) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._constants import FlextLdifConstantsServers
from flext_ldif.servers._rfc.server_constants import FlextLdifServersRfcConstants


class FlextLdifServersOidConstants(
    FlextLdifConstantsServers.Oid,
    FlextLdifServersRfcConstants,
):
    """Thin inheritor: declarations live in _constants parts."""
