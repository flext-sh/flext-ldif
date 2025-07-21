"""LDIF exceptions using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import DomainError


class LDIFError(DomainError):
    """Base exception for LDIF operations."""


class LDIFParseError(LDIFError):
    """Exception raised when LDIF parsing fails."""


class LDIFValidationError(LDIFError):
    """Exception raised when LDIF validation fails."""


class LDIFEntryError(LDIFError):
    """Exception raised for LDIF entry operations."""


__all__ = [
    "LDIFEntryError",
    "LDIFError",
    "LDIFParseError",
    "LDIFValidationError",
]
