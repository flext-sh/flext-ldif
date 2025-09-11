"""FLEXT-LDIF - LDIF Processing Library.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import sys
import warnings
from pathlib import Path

from flext_ldif.api import FlextLDIFAPI
from flext_ldif.cli import main as cli_main_function
from flext_ldif.constants import FlextLDIFConstants
from flext_ldif.exceptions import FlextLDIFExceptions
from flext_ldif.format_handlers import FlextLDIFFormatHandler
from flext_ldif.format_validators import FlextLDIFFormatValidators
from flext_ldif.models import FlextLDIFModels
from flext_ldif.protocols import FlextLDIFProtocols
from flext_ldif.services import FlextLDIFServices
from flext_ldif.utilities import FlextLDIFUtilities

# Suprimir warnings do Pydantic V2 para uma CLI limpa
warnings.filterwarnings(
    "ignore", category=UserWarning, module="pydantic._internal._config"
)
warnings.filterwarnings(
    "ignore", category=DeprecationWarning, module="pydantic._internal._config"
)
warnings.filterwarnings(
    "ignore",
    message=".*validate_all.*renamed.*validate_default.*",
    category=UserWarning,
)
warnings.filterwarnings(
    "ignore", message=".*class-based.*config.*deprecated.*", category=DeprecationWarning
)

# CLI interface - usando flext-cli corretamente
# from flext_ldif.cli import main  # Temporário - circular import no flext-cli


# CLI interface - using flext-cli correctly
def main() -> None:
    """Main CLI entry point."""
    try:
        result = cli_main_function()
        sys.exit(result)
    except ImportError:
        # Fallback if CLI is not available
        sys.exit(0)
    except Exception:
        # Return error code for any CLI exception
        sys.exit(1)


__all__ = [
    "FlextLDIFAPI",
    "FlextLDIFConstants",
    "FlextLDIFExceptions",
    "FlextLDIFFormatHandler",
    "FlextLDIFFormatValidators",
    "FlextLDIFModels",
    "FlextLDIFProtocols",
    "FlextLDIFServices",
    "FlextLDIFUtilities",
    "__author__",
    "__email__",
    "__license__",
    "__version__",
    "main",
]

# Version information
__version__ = "0.9.0"
__author__ = "FLEXT Development Team"
__email__ = "dev@flext.com"
__license__ = "MIT"
