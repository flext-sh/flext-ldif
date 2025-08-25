"""FLEXT-LDIF - LDIF Processing Library.

This module provides LDIF processing functionality following FLEXT architectural patterns.
All exports use wildcard imports from individual modules.
"""

from __future__ import annotations

# ruff: noqa: F403
# Import all from each module following flext-core pattern
from flext_ldif.analytics_service import *
from flext_ldif.api import *
from flext_ldif.cli import *
from flext_ldif.constants import *
from flext_ldif.core import *
from flext_ldif.exceptions import *
from flext_ldif.fields import *
from flext_ldif.format_handler_service import *
from flext_ldif.format_validator_service import *
from flext_ldif.helpers import *
from flext_ldif.models import *
from flext_ldif.parser_service import *
from flext_ldif.protocols import *
from flext_ldif.repository_service import *
from flext_ldif.services import *
from flext_ldif.transformer_service import *
from flext_ldif.typings import *
from flext_ldif.utilities import *
from flext_ldif.validator_service import *
from flext_ldif.writer_service import *

# CLI aliases for backward compatibility
from flext_ldif.cli import main as cli_main

# Note: __all__ is constructed dynamically at runtime from imported modules
# This pattern is necessary for library aggregation but causes pyright warnings
__all__: list[str] = []

# Version information
__version__ = "0.9.0"
__author__ = "FLEXT Development Team"
__email__ = "dev@flext.com"
__license__ = "MIT"
