"""FLEXT-LDIF Writer Service (Compatibility Facade).

LDIF writing implementation using flext-core patterns.

COMPATIBILITY FACADE: FlextLdifWriterService is now consolidated in services.py
Import from services for backward compatibility.
"""

from __future__ import annotations

# Import writer service from consolidated services module
from .services import FlextLdifWriterService

__all__ = ["FlextLdifWriterService"]
