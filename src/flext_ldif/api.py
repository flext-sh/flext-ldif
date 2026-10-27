"""Public MRO composition for the LDIF service facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.services.facade import FlextLdifFacade


class FlextLdif(FlextLdifFacade):
    """Public LDIF operations composed from their service owners."""

    __init__ = FlextLdifFacade.__init__


ldif: FlextLdif = FlextLdif.fetch_global()
"""Process-wide public facade singleton, the same instance ``fetch_global`` returns."""

__all__: list[str] = ["FlextLdif", "ldif"]
