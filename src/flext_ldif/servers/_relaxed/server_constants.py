"""Relaxed server constants for lenient LDIF processing.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._constants import FlextLdifConstantsServersRelaxed as _RelaxedConstants
from flext_ldif.servers._rfc import FlextLdifConstantsServersRfc as _RfcConstants


class FlextLdifConstantsServersRelaxed(
    _RelaxedConstants,
    _RfcConstants,
):
    """Thin inheritor: declarations live in _constants parts."""


__all__: list[str] = ["FlextLdifConstantsServersRelaxed"]
