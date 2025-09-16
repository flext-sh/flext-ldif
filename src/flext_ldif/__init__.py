"""FLEXT-LDIF - LDIF Processing Library.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.api import FlextLDIFAPI
from flext_ldif.cli import main
from flext_ldif.config import FlextLDIFConfig, get_ldif_config, initialize_ldif_config
from flext_ldif.constants import FlextLDIFConstants

# Use flext-core exceptions directly - no custom exception wrappers needed
from flext_ldif.exceptions import (
    FlextLDIFError,
    FlextLDIFParseError,
    FlextLDIFValidationError,
)
from flext_ldif.format_handlers import FlextLDIFFormatHandler
from flext_ldif.format_validators import FlextLDIFFormatValidators
from flext_ldif.models import FlextLDIFModels
from flext_ldif.protocols import FlextLDIFProtocols
from flext_ldif.services import FlextLDIFAnalyticsService, FlextLDIFServices
from flext_ldif.utilities import FlextLDIFUtilities

# Warning filtering is handled by flext-core logging system
__all__ = [
    "FlextLDIFAPI",
    "FlextLDIFAnalyticsService",
    "FlextLDIFConfig",
    "FlextLDIFConstants",
    "FlextLDIFError",
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
