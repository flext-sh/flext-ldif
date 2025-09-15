"""FLEXT-LDIF - LDIF Processing Library.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.api import FlextLDIFAPI
from flext_ldif.cli import main
from flext_ldif.config import FlextLDIFConfig, get_ldif_config, initialize_ldif_config
from flext_ldif.constants import FlextLDIFConstants
from flext_ldif.exceptions import (
    FlextLDIFExceptions,
    LdifParseError as FlextLDIFParseError,
    LdifProcessingError as FlextLDIFError,
    LdifValidationError as FlextLDIFValidationError,
)
from flext_ldif.format_handlers import FlextLDIFFormatHandler
from flext_ldif.format_validators import FlextLDIFFormatValidators
from flext_ldif.models import FlextLDIFModels
from flext_ldif.protocols import FlextLDIFProtocols
from flext_ldif.services import FlextLDIFServices
from flext_ldif.utilities import FlextLDIFUtilities

# # Suppress Pydantic V2 warnings for clean CLI experience
# warnings.filterwarnings(
#     "ignore", category=UserWarning, module="pydantic._internal._config"
# )
# warnings.filterwarnings(
#     "ignore", category=DeprecationWarning, module="pydantic._internal._config"
# )
# warnings.filterwarnings(
#     "ignore",
#     message=".*validate_all.*renamed.*validate_default.*",
#     category=UserWarning,
# )
# warnings.filterwarnings(
#     "ignore", message=".*class-based.*config.*deprecated.*", category=DeprecationWarning
# )
#
__all__ = [
    "FlextLDIFAPI",
    "FlextLDIFConfig",
    "FlextLDIFConstants",
    "FlextLDIFError",
    "FlextLDIFExceptions",
    "FlextLDIFFormatHandler",
    "FlextLDIFFormatValidators",
    "FlextLDIFModels",
    "FlextLDIFParseError",
    "FlextLDIFProtocols",
    "FlextLDIFServices",
    "FlextLDIFUtilities",
    "FlextLDIFValidationError",
    "get_ldif_config",
    "initialize_ldif_config",
    "main",
]

# Version information
__version__ = "0.9.0"
__author__ = "FLEXT Development Team"
__email__ = "dev@flext.com"
__license__ = "MIT"
