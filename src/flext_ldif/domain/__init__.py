"""LDIF Domain Layer - Pure Business Logic.

🏗️ CLEAN ARCHITECTURE: Domain Layer
Built on flext-core foundation patterns.

Domain layer for LDIF processing with immutable entities and value objects.
"""

from __future__ import annotations

from flext_ldif.domain.aggregates import LDIFDocument
from flext_ldif.domain.entities import LDIFEntry, LDIFRecord
from flext_ldif.domain.events import (
    LDIFDocumentParsed,
    LDIFEntryValidated,
    LDIFProcessingCompleted,
)
from flext_ldif.domain.interfaces import (
    LDIFParser,
    LDIFValidator,
    LDIFWriter,
)
from flext_ldif.domain.specifications import (
    LDIFEntrySpecification,
    ValidLDIFSpecification,
)
from flext_ldif.domain.values import (
    DistinguishedName,
    LDIFAttributes,
    LDIFContent,
    LDIFLines,
)

__all__ = [
    # Values
    "DistinguishedName",
    "LDIFAttributes",
    "LDIFContent",
    # Aggregates
    "LDIFDocument",
    # Events
    "LDIFDocumentParsed",
    # Entities
    "LDIFEntry",
    # Specifications
    "LDIFEntrySpecification",
    "LDIFEntryValidated",
    "LDIFLines",
    # Interfaces
    "LDIFParser",
    "LDIFProcessingCompleted",
    "LDIFRecord",
    "LDIFValidator",
    "LDIFWriter",
    "ValidLDIFSpecification",
]
