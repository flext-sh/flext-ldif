"""LDIF Domain Layer - Pure Business Logic.

🏗️ CLEAN ARCHITECTURE: Domain Layer
Built on flext-core foundation patterns.

Domain layer for LDIF processing with immutable entities and value objects.
"""

from __future__ import annotations

from flext_ldif.domain.aggregates import FlextLdifDocument
from flext_ldif.domain.entities import FlextLdifEntry, FlextLdifRecord
from flext_ldif.domain.events import (
    FlextLdifDocumentParsed,
    FlextLdifEntryValidated,
    FlextLdifProcessingCompleted,
)
from flext_ldif.domain.interfaces import (
    FlextLdifParserInterface,
    FlextLdifValidatorInterface,
    FlextLdifWriterInterface,
)
from flext_ldif.domain.specifications import (
    FlextLdifEntrySpecification,
    FlextLdifValidSpecification,
)
from flext_ldif.domain.values import (
    FlextLdifAttributes,
    FlextLdifChangeType,
    FlextLdifDistinguishedName,
    FlextLdifEncoding,
    FlextLdifVersion,
    LDIFContent,
    LDIFLines,
)

__all__ = [
    "FlextLdifAttributes",
    "FlextLdifChangeType",
    # Values
    "FlextLdifDistinguishedName",
    # Aggregates
    "FlextLdifDocument",
    # Events
    "FlextLdifDocumentParsed",
    "FlextLdifEncoding",
    # Entities
    "FlextLdifEntry",
    # Specifications
    "FlextLdifEntrySpecification",
    "FlextLdifEntryValidated",
    # Interfaces
    "FlextLdifParserInterface",
    "FlextLdifProcessingCompleted",
    "FlextLdifRecord",
    "FlextLdifValidSpecification",
    "FlextLdifValidatorInterface",
    "FlextLdifVersion",
    "FlextLdifWriterInterface",
    "LDIFContent",
    "LDIFLines",
]
