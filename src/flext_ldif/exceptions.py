"""LDIF exceptions using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations


class FlextLdifError(Exception):
    """Base exception for LDIF operations."""


class FlextLdifParseError(FlextLdifError):
    """Exception raised when LDIF parsing fails."""


class FlextLdifValidationError(FlextLdifError):
    """Exception raised when LDIF validation fails."""


class FlextLdifEntryError(FlextLdifError):
    """Exception raised for LDIF entry operations."""


__all__ = [
    "FlextLdifEntryError",
    "FlextLdifError",
    "FlextLdifParseError",
    "FlextLdifValidationError",
]
