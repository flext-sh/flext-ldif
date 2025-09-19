"""FLEXT-LDIF - LDIF Processing Library.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.analytics_service import FlextLdifAnalyticsService
from flext_ldif.api import FlextLdifAPI
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.exceptions import FlextLdifExceptions
from flext_ldif.format_handlers import FlextLdifFormatHandler
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.services import FlextLdifServices
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

__all__ = [
    "FlextLdifAPI",
    "FlextLdifAnalyticsService",
    "FlextLdifConfig",
    "FlextLdifConstants",
    "FlextLdifExceptions",
    "FlextLdifFormatHandler",
    "FlextLdifModels",
    "FlextLdifProtocols",
    "FlextLdifServices",
    "FlextLdifTypes",
    "FlextLdifUtilities",
]

# Version information
__version__ = "0.9.0"
__author__ = "FLEXT Development Team"
__email__ = "dev@flext.com"
__license__ = "MIT"
