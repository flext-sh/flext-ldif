"""FLEXT-LDIF Error Handling Utilities - Redirects to flext-core.

This module provides compatibility wrappers that redirect to flext-core
error handling patterns, eliminating duplication while maintaining API compatibility.
"""

from __future__ import annotations

import logging

from flext_core import FlextResult, FlextValidationError

logger = logging.getLogger(__name__)

# Compatibility aliases that redirect to flext-core
FlextLdifErrorHandler = FlextValidationError


def format_validation_error(error: str) -> str:
    """Format validation error message."""
    return f"LDIF Validation Error: {error}"


def handle_ldif_error(error: Exception) -> FlextResult[None]:
    """Handle LDIF processing error."""
    logger.exception("LDIF processing error")
    return FlextResult.fail(str(error))
