"""FLEXT-LDIF Transformer Service (Compatibility Facade).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

COMPATIBILITY FACADE: FlextLdifTransformerService is now consolidated in utilities.py
Import from utilities for backward compatibility.
"""

from __future__ import annotations

# Import transformer service from consolidated utilities module
from .utilities import FlextLdifTransformerService

__all__ = ["FlextLdifTransformerService"]
