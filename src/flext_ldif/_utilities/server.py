"""LDIF Server Utilities - Helpers for Server Type Resolution and Detection.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._utilities import (
    FlextLdifServerConfig,
    FlextLdifServerDetection,
    FlextLdifServerTypeResolution,
)


class FlextLdifUtilitiesServer(
    FlextLdifServerConfig,
    FlextLdifServerDetection,
    FlextLdifServerTypeResolution,
):
    """Server utilities for LDIF server type resolution."""


__all__: list[str] = ["FlextLdifUtilitiesServer"]
