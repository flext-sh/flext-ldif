"""FLEXT-LDIF - LDIF Processing Library.

This module provides LDIF processing functionality following FLEXT architectural patterns.
Enterprise-grade LDIF parsing, validation, transformation, and writing capabilities.
"""

from __future__ import annotations

# =============================================================================
# FOUNDATION LAYER - Core components, no internal dependencies
# =============================================================================

from flext_ldif.constants import FlextLDIFConstants
from flext_ldif.exceptions import (
    ExceptionBuilder,
    FlextLDIFExceptions,
    FlextLDIFError,
    FlextLDIFValidationError,
    FlextLDIFParseError,
    FlextLDIFAuthenticationError,
    FlextLDIFConnectionError,
    FlextLDIFFileError,
    FlextLDIFProcessingError,
    FlextLDIFTimeoutError,
    FlextLDIFErrorCodes,
)
from flext_ldif.protocols import FlextLDIFProtocols

# =============================================================================
# DOMAIN LAYER - Core business logic, depends on Foundation
# =============================================================================

from flext_ldif.models import FlextLDIFModels
from flext_ldif.core import FlextLDIFCore

# =============================================================================
# APPLICATION LAYER - Use cases and orchestration, depends on Domain
# =============================================================================

from flext_ldif.api import FlextLDIFAPI

# =============================================================================
# INFRASTRUCTURE LAYER - External services and adapters
# =============================================================================

from flext_ldif.services import FlextLDIFServices
from flext_ldif.format_handlers import FlextLDIFFormatHandler
from flext_ldif.format_validators import FlextLDIFFormatValidators
from flext_ldif.utilities import FlextLDIFUtilities

# =============================================================================
# INTERFACE LAYER - CLI and external interfaces
# =============================================================================

# CLI aliases for backward compatibility - import properly now
from flext_ldif.cli import main as cli_main, main

# =============================================================================
# PUBLIC EXPORTS - Manual definition of all public APIs
# =============================================================================

__all__ = [
    # Version and metadata
    "__version__",
    "__author__",
    "__email__",
    "__license__",

    # CLI interface
    "cli_main",
    "main",

    # Core API classes
    "FlextLDIFAPI",

    # Models and data structures
    "FlextLDIFModels",

    # Services
    "FlextLDIFServices",

    # Exceptions and error handling
    "FlextLDIFExceptions",
    "ExceptionBuilder",
    "FlextLDIFError",
    "FlextLDIFValidationError",
    "FlextLDIFParseError",
    "FlextLDIFAuthenticationError",
    "FlextLDIFConnectionError",
    "FlextLDIFFileError",
    "FlextLDIFProcessingError",
    "FlextLDIFTimeoutError",
    "FlextLDIFErrorCodes",

    # Constants
    "FlextLDIFConstants",

    # Protocols
    "FlextLDIFProtocols",

    # Core processing
    "FlextLDIFCore",

    # Format handlers
    "FlextLDIFFormatHandler",

    # Format validators
    "FlextLDIFFormatValidators",

    # Utilities
    "FlextLDIFUtilities",
]

# Version information
__version__ = "0.9.0"
__author__ = "FLEXT Development Team"
__email__ = "dev@flext.com"
__license__ = "MIT"
