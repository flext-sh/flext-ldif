"""FLEXT-LDIF Domain Exceptions - Unified Semantic Pattern Integration.

⚡ ZERO BOILERPLATE: Using flext-core exception factory patterns.

All LDIF exceptions are automatically generated from flext-core patterns,
eliminating 200+ lines of duplicate exception handling code.

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

# 🚨 ZERO DUPLICATION: Use flext-core exception factory - eliminates 200+ lines
from flext_core.exceptions import create_module_exception_classes

# Generate all standard exceptions using factory pattern
_ldif_exceptions = create_module_exception_classes("flext_ldif")

# Export available exceptions from factory
FlextLdifError = _ldif_exceptions["FlextLdifError"]
FlextLdifValidationError = _ldif_exceptions["FlextLdifValidationError"]
FlextLdifConfigurationError = _ldif_exceptions["FlextLdifConfigurationError"]
FlextLdifProcessingError = _ldif_exceptions["FlextLdifProcessingError"]
FlextLdifConnectionError = _ldif_exceptions["FlextLdifConnectionError"]
FlextLdifAuthenticationError = _ldif_exceptions["FlextLdifAuthenticationError"]
FlextLdifTimeoutError = _ldif_exceptions["FlextLdifTimeoutError"]

# Create specific aliases for common usage patterns
FlextLdifParseError = FlextLdifProcessingError  # Parse errors are processing errors
FlextLdifEntryError = FlextLdifValidationError  # Entry errors are validation errors

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
