"""Oracle Unified Directory (OUD) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._constants import FlextLdifConstantsServersOud as _OudConstants
from flext_ldif.servers._rfc import FlextLdifConstantsServersRfc as _RfcConstants


class FlextLdifConstantsServersOud(
    _OudConstants,
    _RfcConstants,
):
    """Thin inheritor: declarations live in _constants parts."""


__all__: list[str] = ["FlextLdifConstantsServersOud"]
