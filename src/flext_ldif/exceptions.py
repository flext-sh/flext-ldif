"""FLEXT-LDIF Domain Exceptions.

Standard exception hierarchy for LDIF processing operations.

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations


class FlextLdifError(Exception):
    """Base exception for all FLEXT-LDIF operations."""


class FlextLdifValidationError(FlextLdifError):
    """Exception raised when LDIF validation fails."""


class FlextLdifParseError(FlextLdifError):
    """Exception raised when LDIF parsing fails."""


class FlextLdifEntryError(FlextLdifValidationError):
    """Exception raised when LDIF entry processing fails."""


class FlextLdifConfigurationError(FlextLdifError):
    """Exception raised when configuration is invalid."""


class FlextLdifProcessingError(FlextLdifError):
    """Exception raised during LDIF processing."""


class FlextLdifConnectionError(FlextLdifError):
    """Exception raised when connection fails."""


class FlextLdifAuthenticationError(FlextLdifError):
    """Exception raised when authentication fails."""


class FlextLdifTimeoutError(FlextLdifError):
    """Exception raised when operation times out."""


__all__ = [
    "FlextLdifAuthenticationError",
    "FlextLdifConfigurationError",
    "FlextLdifConnectionError",
    "FlextLdifEntryError",
    "FlextLdifError",
    "FlextLdifParseError",
    "FlextLdifProcessingError",
    "FlextLdifTimeoutError",
    "FlextLdifValidationError",
]
