"""FLEXT-LDIF Error Handling Utilities - Redirects to flext-core.

This module provides compatibility wrappers that redirect to flext-core
error handling patterns, eliminating duplication while maintaining API compatibility.
"""

from __future__ import annotations

from flext_core import FlextResult, get_logger
from flext_core.exceptions import FlextValidationError

logger = get_logger(__name__)

# Compatibility aliases that redirect to flext-core
FlextLdifErrorHandler = FlextValidationError


def format_validation_error(error: str) -> str:
    """Format validation error message."""
    return f"LDIF Validation Error: {error}"


def handle_ldif_error(error: Exception) -> FlextResult[None]:
    """Handle LDIF processing error."""
    logger.error("LDIF processing error", error=str(error))
    return FlextResult.fail(str(error))
