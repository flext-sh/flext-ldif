"""FLEXT-LDIF Domain Exceptions - Unified Semantic Pattern Integration.

⚡ ZERO BOILERPLATE: Using flext-core exception factory patterns.

All LDIF exceptions are automatically generated from flext-core patterns,
eliminating 200+ lines of duplicate exception handling code while providing
comprehensive domain-specific exception types for LDIF operations.

This module provides all necessary exception types for FLEXT-LDIF operations
with automatic inheritance hierarchy and consistent error handling patterns.

Architecture:
- Factory-generated exceptions from flext-core patterns
- Domain-specific exception types for LDIF operations
- Backward compatibility aliases for common usage patterns
- Zero boilerplate with full enterprise exception hierarchy

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# 🚨 ZERO DUPLICATION: Use flext-core exception factory - eliminates 200+ lines
from flext_core.exceptions import create_module_exception_classes

# =============================================================================
# EXCEPTION FACTORY GENERATION
# =============================================================================

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

# =============================================================================
# DOMAIN-SPECIFIC EXCEPTION ALIASES
# =============================================================================

# Create specific aliases for common usage patterns
FlextLdifParseError = FlextLdifProcessingError  # Parse errors are processing errors
FlextLdifEntryError = FlextLdifValidationError  # Entry errors are validation errors
FlextLdifFormatError = FlextLdifValidationError  # Format errors are validation errors
FlextLdifSchemaError = FlextLdifValidationError  # Schema errors are validation errors

# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "FlextLdifAuthenticationError",
    "FlextLdifConfigurationError",
    "FlextLdifConnectionError",
    "FlextLdifEntryError",
    # Core exception hierarchy
    "FlextLdifError",
    "FlextLdifFormatError",
    # Domain-specific aliases
    "FlextLdifParseError",
    "FlextLdifProcessingError",
    "FlextLdifSchemaError",
    "FlextLdifTimeoutError",
    "FlextLdifValidationError",
]
