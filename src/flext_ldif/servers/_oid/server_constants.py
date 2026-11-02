"""Oracle Internet Directory (OID) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._constants import FlextLdifConstantsServersOid as _OidConstants
from flext_ldif.servers._rfc import FlextLdifConstantsServersRfc as _RfcConstants


class FlextLdifConstantsServersOid(
    _OidConstants,
    _RfcConstants,
):
    """Thin inheritor: declarations live in _constants parts."""


__all__: list[str] = ["FlextLdifConstantsServersOid"]
