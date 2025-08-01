"""FLEXT LDIF - Enterprise LDIF Processing Library.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

# Unified API
from .api import (
    FlextLdifAPI,
    flext_ldif_get_api,
    flext_ldif_parse,
    flext_ldif_validate,
    flext_ldif_write,
)

# Configuration and models
from .config import FlextLdifConfig

# Core processing functionality
from .core import TLdif

# Exceptions
from .exceptions import (
    FlextLdifEntryError,
    FlextLdifError,
    FlextLdifParseError,
    FlextLdifValidationError,
)

# Models (consolidated specifications and values)
from .models import (
    FlextLdifAttributes,
    FlextLdifDistinguishedName,
    FlextLdifEntry,
    LDIFContent,
    LDIFLines,
)

if TYPE_CHECKING:
    from collections.abc import Callable

# CLI functionality - import directly since dependencies are required
from .cli import main as cli_main

__version__ = "0.9.0"

__all__ = [
    "FlextLdifAPI",
    "FlextLdifAttributes",
    "FlextLdifConfig",
    "FlextLdifDistinguishedName",
    "FlextLdifEntry",
    "FlextLdifEntryError",
    "FlextLdifError",
    "FlextLdifParseError",
    "FlextLdifValidationError",
    "LDIFContent",
    "LDIFLines",
    "TLdif",
    "__version__",
    "cli_main",
    "flext_ldif_get_api",
    "flext_ldif_parse",
    "flext_ldif_validate",
    "flext_ldif_write",
]
