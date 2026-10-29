# AUTO-GENERATED FILE — Regenerate with: make gen
"""Extracted facade class from FlextLdifUtilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._utilities._server import (
    FlextLdifUtilitiesServerConfig,
    FlextLdifUtilitiesServerDetect,
    FlextLdifUtilitiesServerServerType,
)


class FlextLdifUtilitiesServer(
    FlextLdifUtilitiesServerConfig,
    FlextLdifUtilitiesServerDetect,
    FlextLdifUtilitiesServerServerType,
):
    """Facade for server utilities."""


__all__: list[str] = ["FlextLdifUtilitiesServer"]
