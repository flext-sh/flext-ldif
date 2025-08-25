"""FLEXT-LDIF Parser Service (Compatibility Facade).

LDIF parsing implementation using flext-core patterns.

COMPATIBILITY FACADE: FlextLdifParserService is now consolidated in services.py
Import from services for backward compatibility.
"""

from __future__ import annotations

# Import FlextLdifFactory for test compatibility
from .models import FlextLdifFactory

# Import parser service from consolidated services module
from .services import FlextLdifParserService

__all__ = ["FlextLdifFactory", "FlextLdifParserService"]
