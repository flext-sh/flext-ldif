"""FLEXT LDIF Constants - Constants and enums ONLY.

Contains ONLY:
- Final constants (literals, strings, numbers)
- Enum and StrEnum definitions
- Frozenset constants

NO types (→ typings.py)
NO protocols (→ protocols.py)
NO models (→ models.py)
NO exceptions (→ exceptions.py)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from flext_core import FlextConstants


class FlextLdifConstants(FlextConstants):
    """LDIF domain constants extending flext-core FlextConstants.

    Contains ONLY constant values, no implementations.
    """

    # =============================================================================
    # FORMAT CONSTANTS
    # =============================================================================

    class Format:
        """LDIF format specifications."""

        DN_ATTRIBUTE: Final[str] = "dn"
        ATTRIBUTE_SEPARATOR: Final[str] = ":"
        DEFAULT_ENCODING: Final[str] = "utf-8"
        MAX_LINE_LENGTH: Final[int] = 78
        MIN_BUFFER_SIZE: Final[int] = 1024
        CONTENT_PREVIEW_LENGTH: Final[int] = 100
        MAX_ATTRIBUTES_DISPLAY: Final[int] = 10

    # =============================================================================
    # PROCESSING CONSTANTS
    # =============================================================================

    class Processing:
        """Processing behavior configuration constants."""

        MIN_WORKERS_FOR_PARALLEL: Final[int] = 2
        MIN_ANALYTICS_CACHE_SIZE: Final[int] = 100
        MIN_PRODUCTION_ENTRIES: Final[int] = 1000
        MAX_WORKERS_LIMIT: Final[int] = 8
        MAX_ANALYTICS_CACHE_SIZE: Final[int] = 10000

    # =============================================================================
    # VALIDATION CONSTANTS
    # =============================================================================

    class LdifValidation:
        """LDIF-specific validation rules and constraints."""

        MIN_DN_COMPONENTS: Final[int] = 1

    # =============================================================================
    # OBJECTCLASS CONSTANTS
    # =============================================================================

    class ObjectClasses:
        """LDAP object class definitions."""

        LDAP_PERSON_CLASSES: Final[frozenset[str]] = frozenset([
            "person",
            "organizationalperson",
            "inetorgperson",
        ])

        LDAP_GROUP_CLASSES: Final[frozenset[str]] = frozenset([
            "groupofnames",
            "groupofuniquenames",
        ])

    # =============================================================================
    # ERROR MESSAGE CONSTANTS
    # =============================================================================

    class ErrorMessages:
        """Error message constants for validation."""

        DN_EMPTY_ERROR: Final[str] = "DN cannot be empty"
        DN_INVALID_FORMAT_ERROR: Final[str] = "DN has invalid format"
        DN_INVALID_CHARS_ERROR: Final[str] = "DN contains invalid characters"
        ATTRIBUTES_TYPE_ERROR: Final[str] = "Attributes must be a dictionary"
        ATTRIBUTE_NAME_ERROR: Final[str] = "Attribute name must be a string"
        ATTRIBUTE_VALUES_ERROR: Final[str] = "Attribute values must be a list"
        ATTRIBUTE_VALUE_TYPE_ERROR: Final[str] = "Attribute values must be strings"


# =============================================================================
# ENUMS
# =============================================================================


class LdifProcessingStage(StrEnum):
    """Processing stages for LDIF operations."""

    PARSING = "parsing"
    VALIDATION = "validation"
    ANALYTICS = "analytics"
    WRITING = "writing"


class LdifHealthStatus(StrEnum):
    """Health status for LDIF services."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class LdifEntryType(StrEnum):
    """Types of LDIF entries."""

    PERSON = "person"
    GROUP = "group"
    ORGANIZATIONAL_UNIT = "organizationalunit"
    DOMAIN = "domain"
    OTHER = "other"


class LdifEntryModification(StrEnum):
    """LDIF entry modification types."""

    ADD = "add"
    MODIFY = "modify"
    DELETE = "delete"
    MODRDN = "modrdn"


__all__ = [
    "FlextLdifConstants",
    "LdifEntryModification",
    "LdifEntryType",
    "LdifHealthStatus",
    "LdifProcessingStage",
]
