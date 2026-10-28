"""Oracle Unified Directory (OUD) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifConstants
from flext_ldif.servers._rfc import FlextLdifServersRfcConstants


class FlextLdifServersOudConstants(
    FlextLdifConstants,
    FlextLdifServersRfcConstants,
):
    """Thin inheritor: declarations live in _constants parts."""


__all__: list[str] = ["FlextLdifServersOudConstants"]
