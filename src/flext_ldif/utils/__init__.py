"""FLEXT-LDIF Utilities - LDIF-specific validation only.

⚡ MASSIVE BOILERPLATE ELIMINATION: Only LDIF-specific utilities remain.

All generic utilities (logging, error handling, CLI) now use flext-core patterns
directly, eliminating duplicate implementations.

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

from .validation import LdifSchemaValidator, LdifValidator

__all__ = [
    "LdifSchemaValidator",
    "LdifValidator",
]
