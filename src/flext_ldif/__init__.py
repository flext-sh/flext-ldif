"""FLEXT LDIF - Enterprise LDIF Processing Library.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# Core processing functionality
from .core import TLdif

# Configuration and models
from .config import FlextLdifConfig
from .models import FlextLdifEntry

# Models (consolidated specifications and values)
from .models import (
    FlextLdifAttributes,
    FlextLdifDistinguishedName,
    LDIFContent,
    LDIFLines,
)

# Exceptions
from .exceptions import (
    FlextLdifEntryError,
    FlextLdifError,
    FlextLdifParseError,
    FlextLdifValidationError,
)

# Unified API
from .api import (
    FlextLdifAPI,
    flext_ldif_get_api,
    flext_ldif_parse,
    flext_ldif_validate,
    flext_ldif_write,
)

__version__ = "0.8.0"

__all__ = [
    # Core functionality
    "TLdif",
    
    # API
    "FlextLdifAPI",
    "flext_ldif_get_api",
    "flext_ldif_parse",
    "flext_ldif_validate", 
    "flext_ldif_write",
    
    # Core classes
    "FlextLdifConfig",
    "FlextLdifEntry",
    
    # Types
    "LDIFContent",
    "LDIFLines",
    
    # Domain values (consolidated in models)
    "FlextLdifAttributes", 
    "FlextLdifDistinguishedName",
    
    # Exceptions
    "FlextLdifEntryError",
    "FlextLdifError",
    "FlextLdifParseError",
    "FlextLdifValidationError",
    
    # Meta
    "__version__",
]