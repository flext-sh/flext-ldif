"""Copyright (c) 2025 Algar Telecom. Todos os direitos reservados.

SPDX-License-Identifier: Proprietário.
"""

from __future__ import annotations

# Suprimir warnings do Pydantic V2 para uma CLI limpa
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="pydantic._internal._config")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="pydantic._internal._config")
warnings.filterwarnings("ignore", message=".*validate_all.*renamed.*validate_default.*", category=UserWarning)
warnings.filterwarnings("ignore", message=".*class-based.*config.*deprecated.*", category=DeprecationWarning)

from flext_core import FlextTypes


"""FLEXT-LDIF - LDIF Processing Library.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""


# =============================================================================
# FOUNDATION LAYER - Core components, no internal dependencies
# =============================================================================

from flext_ldif.constants import FlextLDIFConstants
from flext_ldif.exceptions import FlextLDIFExceptions
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

# CLI interface - usando flext-cli corretamente
# from flext_ldif.cli import main  # Temporário - circular import no flext-cli

# Alias temporário para testes CLI
def main() -> None:
    """Função main temporária para testes."""

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
    "main",
    # Core API classes
    "FlextLDIFAPI",
    # Models and data structures
    "FlextLDIFModels",
    # Services
    "FlextLDIFServices",
    # Exceptions and error handling
    "FlextLDIFExceptions",
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
