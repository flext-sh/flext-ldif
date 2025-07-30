"""FLEXT LDIF - Enterprise LDIF Processing Library.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

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

__version__ = "0.9.0"

__all__ = [
    # API
    "FlextLdifAPI",
    # Domain values (consolidated in models)
    "FlextLdifAttributes",
    # Core classes
    "FlextLdifConfig",
    "FlextLdifDistinguishedName",
    "FlextLdifEntry",
    # Exceptions
    "FlextLdifEntryError",
    "FlextLdifError",
    "FlextLdifParseError",
    "FlextLdifValidationError",
    # Types
    "LDIFContent",
    "LDIFLines",
    # Core functionality
    "TLdif",
    # Meta
    "__version__",
    "flext_ldif_get_api",
    "flext_ldif_parse",
    "flext_ldif_validate",
    "flext_ldif_write",
]
