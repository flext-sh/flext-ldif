"""Oracle Internet Directory (OID) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._constants.servers import FlextLdifConstantsServers
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOidConstants(
    FlextLdifConstantsServers.Oid,
    FlextLdifServersRfc.Constants,
):
    """Thin inheritor: declarations live in _constants parts."""
