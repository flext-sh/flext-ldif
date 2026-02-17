"""Result and response models for LDIF operations - Public API.

Re-exports from _models.results (SSOT). This facade preserves the public import path.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._models.results import (
    DynamicCounts,
    FlextLdifModelsResults,
)

__all__ = [
    "DynamicCounts",
    "FlextLdifModelsResults",
]
