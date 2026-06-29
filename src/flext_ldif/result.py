"""Result facade for flext_ldif.

Re-exports the canonical FLEXT result namespace so that ``from flext_ldif import r``
works consistently with other FLEXT packages.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core.result import FlextResult as FlextLdifResult

r = FlextLdifResult

__all__: list[str] = ["FlextLdifResult", "r"]
