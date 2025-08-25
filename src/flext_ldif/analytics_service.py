"""FLEXT-LDIF Analytics Service (Compatibility Facade).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

COMPATIBILITY FACADE: FlextLdifAnalyticsService is now consolidated in services.py
Import from services for backward compatibility.
"""

from __future__ import annotations

# Import analytics service from consolidated services module
from .services import FlextLdifAnalyticsService

__all__ = ["FlextLdifAnalyticsService"]
