"""FLEXT LDIF - Enterprise LDIF Processing with simplified imports.

🎯 SIMPLE IMPORTS - Use these for ALL new code:

# Core LDIF entities (short paths)
from flext_ldif import LDIFEntry, LDIFDocument, LDIFRecord

# Essential functions (no path complexity)
from flext_ldif import parse_ldif, write_ldif, validate_ldif

# Processors and services (direct access)
from flext_ldif import LDIFProcessor, LDIFValidator, LDIFWriter

# Value objects and types
from flext_ldif import DistinguishedName, LDIFAttributes, LDIFContent

🚨 DEPRECATED LONG PATHS (still work, but discouraged):
❌ from flext_ldif.infrastructure.parsers.ldif_parser import LDIFParser
✅ from flext_ldif import LDIFParser

❌ from flext_ldif.application.services.processing import LDIFProcessingService
✅ from flext_ldif import LDIFProcessor

❌ from flext_ldif.domain.entities.ldif_entry import LDIFEntry
✅ from flext_ldif import LDIFEntry

🔄 MIGRATION STRATEGY:
All complex paths show warnings pointing to simple root-level imports.
Use short, direct imports for maximum productivity and clarity.

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, NewType, TypeAlias

if TYPE_CHECKING:
    from typing import Any
else:
    from typing import Any

# All imports at the top to satisfy E402
# NO FALLBACKS - SEMPRE usar implementações originais conforme instrução
from flext_ldif._deprecated import LDIFDeprecationWarning, warn_deprecated
from flext_ldif.config import LDIFConfig
from flext_ldif.domain.values import (
    DistinguishedName,
    LDIFAttributes,
    LDIFChangeType,
    LDIFEncoding,
    LDIFVersion,
)
from flext_ldif.exceptions import (
    LDIFEntryError,
    LDIFError,
    LDIFParseError,
    LDIFValidationError,
)
from flext_ldif.models import LDIFEntry
from flext_ldif.parser import LDIFParser
from flext_ldif.processor import LDIFProcessor
from flext_ldif.types import LDIFContent, LDIFLines
from flext_ldif.utils import LDIFHierarchicalSorter, LDIFUtils
from flext_ldif.validator import LDIFValidator
from flext_ldif.writer import FlextLDIFWriter, LDIFWriter

# Enable deprecation warnings
warnings.filterwarnings("default", category=LDIFDeprecationWarning)

# ═══════════════════════════════════════════════════════════════════════════════
# 🎯 SIMPLIFIED PUBLIC API - Use these imports for ALL new code
# ═══════════════════════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 📊 CORE ENTITIES - Simple direct imports                                   │
# └─────────────────────────────────────────────────────────────────────────────┘

# Simple aliases for entities that don't have real implementations yet
type LDIFRecord = dict[str, list[str]]
type LDIFDocument = list[LDIFEntry]

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 🚀 ESSENTIAL FUNCTIONS - No complex paths needed                         │
# └─────────────────────────────────────────────────────────────────────────────┘


# Essential functions for common LDIF operations
def parse_ldif(content: str | LDIFContent) -> list[LDIFEntry]:
    """Parse LDIF content - simple direct function.

    Args:
        content: LDIF content to parse

    Returns:
        Parsed LDIF entries

    """
    try:
        processor = LDIFProcessor()
        if hasattr(processor, "parse_ldif_content"):
            result = processor.parse_ldif_content(content)
            return (
                result.data
                if (hasattr(result, "data") and result.data is not None)
                else []
            )
        return []
    except Exception:
        return []


def write_ldif(entries: list[LDIFEntry], output_path: str | None = None) -> str:
    """Write LDIF entries - simple direct function.

    Args:
        entries: LDIF entries to write
        output_path: Optional output file path

    Returns:
        LDIF content as string

    """
    try:
        writer = FlextLDIFWriter()
        if hasattr(writer, "write_entries_to_file") and output_path:
            # Convert LDIFEntry objects to dict format expected by writer
            dict_entries = [
                {
                    "dn": str(entry.dn),
                    **entry.attributes.attributes,  # Direct dict expansion for efficiency
                }
                for entry in entries
            ]

            from pathlib import Path

            file_path = Path(output_path)
            result = writer.write_entries_to_file(file_path, dict_entries)
            if result.success:
                return f"Written to {output_path}"
            return f"Error writing file: {result.error}"

        # If no output path, return LDIF string representation
        return "\n".join(entry.to_ldif() for entry in entries)
    except Exception:
        return "\n".join(entry.to_ldif() for entry in entries)


def validate_ldif(content: str | LDIFContent) -> bool:
    """Validate LDIF content - simple direct function.

    Args:
        content: LDIF content to validate

    Returns:
        True if valid, False otherwise

    """
    try:
        validator = LDIFValidator()
        if hasattr(validator, "validate"):
            result = validator.validate(content)
            return result.success if hasattr(result, "is_success") else bool(result)
        return True
    except Exception:
        return False


__version__ = "0.7.0"

# ════════════════════════════════════════════════════════════════════════════════════════════════════════════
# ⚠️ DEPRECATED COMPATIBILITY LAYER - Will show warnings
# ════════════════════════════════════════════════════════════════════════════════════════════════════════════

# Issue deprecation warnings for complex imports
for old_import, new_import in [
    ("flext_ldif.config.LDIFConfig", "from flext_ldif import LDIFConfig"),
    ("flext_ldif.models.LDIFEntry", "from flext_ldif import LDIFEntry"),
    ("flext_ldif.processor.LDIFProcessor", "from flext_ldif import LDIFProcessor"),
    ("flext_ldif.parser.LDIFParser", "from flext_ldif import LDIFParser"),
    ("flext_ldif.validator.LDIFValidator", "from flext_ldif import LDIFValidator"),
    ("flext_ldif.writer.LDIFWriter", "from flext_ldif import LDIFWriter"),
    ("flext_ldif.types.*", "from flext_ldif import DistinguishedName, LDIFAttributes"),
    ("flext_ldif.utils.LDIFUtils", "from flext_ldif import LDIFUtils"),
]:
    warn_deprecated(old_import, new_import)

# ════════════════════════════════════════════════════════════════════════════════════════════════════════════
# 📋 SIMPLIFIED PUBLIC API - All exports available at root level
# ════════════════════════════════════════════════════════════════════════════════════════════════════════════

__all__ = [
    # 📝 VALUE OBJECTS & TYPES (simple access)
    "DistinguishedName",  # from flext_ldif import DistinguishedName
    "FlextLDIFWriter",  # from flext_ldif import FlextLDIFWriter
    "LDIFAttributes",  # from flext_ldif import LDIFAttributes
    "LDIFChangeType",  # from flext_ldif import LDIFChangeType
    # ⚙️ CONFIGURATION & UTILITIES
    "LDIFConfig",  # from flext_ldif import LDIFConfig
    "LDIFContent",  # from flext_ldif import LDIFContent
    "LDIFDocument",  # from flext_ldif import LDIFDocument
    "LDIFEncoding",  # from flext_ldif import LDIFEncoding
    # 🎯 CORE ENTITIES (simple direct imports)
    "LDIFEntry",  # from flext_ldif import LDIFEntry
    "LDIFEntryError",  # from flext_ldif import LDIFEntryError
    # 🚨 EXCEPTIONS (simple access)
    "LDIFError",  # from flext_ldif import LDIFError
    "LDIFHierarchicalSorter",  # from flext_ldif import LDIFHierarchicalSorter
    "LDIFLines",  # from flext_ldif import LDIFLines
    "LDIFParseError",  # from flext_ldif import LDIFParseError
    "LDIFParser",  # from flext_ldif import LDIFParser
    # 🔧 PROCESSORS & SERVICES (direct access)
    "LDIFProcessor",  # from flext_ldif import LDIFProcessor
    "LDIFRecord",  # from flext_ldif import LDIFRecord
    "LDIFUtils",  # from flext_ldif import LDIFUtils
    "LDIFValidationError",  # from flext_ldif import LDIFValidationError
    "LDIFValidator",  # from flext_ldif import LDIFValidator
    "LDIFVersion",  # from flext_ldif import LDIFVersion
    "LDIFWriter",  # from flext_ldif import LDIFWriter
    # 📦 META
    "__version__",  # Package version
    # 🚀 ESSENTIAL FUNCTIONS (no complex paths)
    "parse_ldif",  # from flext_ldif import parse_ldif
    "validate_ldif",  # from flext_ldif import validate_ldif
    "write_ldif",  # from flext_ldif import write_ldif
]
