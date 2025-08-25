"""FLEXT-LDIF Helper Functions (Compatibility Facade).

Convenience functions for common LDIF operations.

COMPATIBILITY FACADE: Helper functions are now consolidated in utilities.py
Import from utilities for backward compatibility.
"""

from __future__ import annotations

# Import helper functions from consolidated utilities module
from .utilities import (
    flext_ldif_get_api,
    flext_ldif_parse,
    flext_ldif_validate,
    flext_ldif_write,
)

__all__ = [
    "flext_ldif_get_api",
    "flext_ldif_parse",
    "flext_ldif_validate",
    "flext_ldif_write",
]
