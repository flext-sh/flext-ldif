"""LDIF Utilities - Re-export from internal utilities module.

For backward compatibility, this module re-exports FlextLdifUtilities from _utilities.
All new code should import directly from flext_ldif._utilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif._utilities import FlextLdifUtilities

__all__ = [
    "FlextLdifUtilities",
]
