"""FLEXT LDIF - Enterprise LDIF Processing Library.

Copyright (c) 2025 FLEXT Team. All rights reserved.

Clean, minimal implementation following SOLID/KISS/DRY principles.
Integrated with flext-core for maximum code reuse and minimal duplication.
"""

from __future__ import annotations

from flext_ldif.config import LDIFConfig

# Exceptions
from flext_ldif.exceptions import (
    LDIFEntryError,
    LDIFError,
    LDIFParseError,
    LDIFValidationError,
)
from flext_ldif.models import LDIFEntry
from flext_ldif.parser import LDIFParser

# Main classes
from flext_ldif.processor import LDIFProcessor

# Types
from flext_ldif.types import (
    DistinguishedName,
    LDIFAttributes,
    LDIFContent,
    LDIFLines,
)
from flext_ldif.utils import LDIFUtils
from flext_ldif.validator import LDIFValidator
from flext_ldif.writer import FlextLDIFWriter, LDIFHierarchicalSorter, LDIFWriter

__version__ = "0.7.0"

__all__ = [
    "DistinguishedName",
    "FlextLDIFWriter",
    "LDIFAttributes",
    "LDIFConfig",
    # Types
    "LDIFContent",
    "LDIFEntry",
    "LDIFEntryError",
    # Exceptions
    "LDIFError",
    "LDIFHierarchicalSorter",
    "LDIFLines",
    "LDIFParseError",
    "LDIFParser",
    # Main classes
    "LDIFProcessor",
    "LDIFUtils",
    "LDIFValidationError",
    "LDIFValidator",
    "LDIFWriter",
    # Version
    "__version__",
]
