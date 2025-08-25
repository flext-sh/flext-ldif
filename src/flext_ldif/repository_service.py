"""FLEXT-LDIF Repository Service (Compatibility Facade).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

COMPATIBILITY FACADE: FlextLdifRepositoryService is now consolidated in services.py
Import from services for backward compatibility.
"""

from __future__ import annotations

# Import repository service from consolidated services module
from .services import FlextLdifRepositoryService

__all__ = ["FlextLdifRepositoryService"]
