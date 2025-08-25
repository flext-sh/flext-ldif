"""FLEXT-LDIF Validator Service (Compatibility Facade).

LDIF validation implementation using flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

COMPATIBILITY FACADE: FlextLdifValidatorService is now consolidated in services.py
Import from services for backward compatibility.
"""

from __future__ import annotations

# Import LdifValidator for test compatibility
from .format_validator_service import LdifValidator

# Import validator service from consolidated services module
from .services import FlextLdifValidatorService

__all__ = ["FlextLdifValidatorService", "LdifValidator"]
