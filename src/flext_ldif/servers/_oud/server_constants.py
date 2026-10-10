"""Oracle Unified Directory (OUD) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._constants.servers_oud import FlextLdifConstantsServersOud
from flext_ldif.servers._rfc import FlextLdifServersRfcConstants


class FlextLdifServersOudConstants(
    FlextLdifConstantsServersOud,
    FlextLdifServersRfcConstants,
):
    """Thin inheritor: declarations live in _constants parts."""
