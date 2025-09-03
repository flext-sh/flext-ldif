"""FLEXT-LDIF - LDIF Processing Library.

This module provides LDIF processing functionality following FLEXT architectural patterns.
Enterprise-grade LDIF parsing, validation, transformation, and writing capabilities.
"""

from __future__ import annotations

# =============================================================================
# FOUNDATION LAYER - Core components, no internal dependencies
# =============================================================================

from flext_ldif.constants import *
from flext_ldif.exceptions import *
from flext_ldif.protocols import *

# =============================================================================
# DOMAIN LAYER - Core business logic, depends on Foundation
# =============================================================================

from flext_ldif.models import *
from flext_ldif.core import *

# =============================================================================
# APPLICATION LAYER - Use cases and orchestration, depends on Domain
# =============================================================================

from flext_ldif.api import *

# =============================================================================
# INFRASTRUCTURE LAYER - External services and adapters
# =============================================================================

from flext_ldif.services import *
from flext_ldif.format_handlers import *
from flext_ldif.format_validators import *
from flext_ldif.utilities import *

# =============================================================================
# INTERFACE LAYER - CLI and external interfaces
# =============================================================================

# CLI aliases for backward compatibility
from flext_ldif.cli import main as cli_main

# =============================================================================
# CONSOLIDATED EXPORTS - Combine all __all__ from modules following flext-core pattern
# =============================================================================

import flext_ldif.api as _api
import flext_ldif.cli as _cli
import flext_ldif.constants as _constants
import flext_ldif.core as _core
import flext_ldif.exceptions as _exceptions
import flext_ldif.format_handlers as _format_handlers
import flext_ldif.format_validators as _format_validators
import flext_ldif.models as _models
import flext_ldif.protocols as _protocols
import flext_ldif.services as _services
import flext_ldif.utilities as _utilities

# Collect all __all__ exports from imported modules following flext-core pattern
_temp_exports: list[str] = []

for _module in [
    _constants,
    _exceptions,
    _protocols,
    _models,
    _core,
    _api,
    _services,
    _format_handlers,
    _format_validators,
    _utilities,
]:
    if hasattr(_module, "__all__"):
        _temp_exports.extend(_module.__all__)

# Remove duplicates and sort following flext-core pattern
# Using list() to satisfy Ruff PLE0605 requirement that __all__ must be list or tuple
__all__ = list(sorted(set(_temp_exports)))  # noqa: C413

# Version information
__version__ = "0.9.0"
__author__ = "FLEXT Development Team"
__email__ = "dev@flext.com"
__license__ = "MIT"
