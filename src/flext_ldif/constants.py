"""FLEXT-LDIF Constants - Unified LDIF Processing Constants.

ARCHITECTURAL CONSOLIDATION: This module consolidates ALL LDIF constants from
multiple duplicate sources into ONE centralized source following enterprise patterns.

ELIMINATED DUPLICATION:
✅ constants.py + ldif_constants.py → ONE unified constants.py
✅ Consistent naming: LDAP_* prefix for LDAP-specific constants
✅ Comprehensive coverage: All LDIF processing constants centralized
✅ Zero magic strings: All constants properly typed and documented

Enterprise Architecture:
- Single source of truth for all LDIF processing constants
- Comprehensive typing with Final annotations for immutability
- RFC 2849 compliance for LDIF format specifications
- Integration with flext-core foundation patterns

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

from typing import Final

# =============================================================================
# LDIF FORMAT CONSTANTS (RFC 2849)
# =============================================================================

DEFAULT_LINE_WRAP_LENGTH: Final[int] = 76
MIN_LINE_WRAP_LENGTH: Final[int] = 50
MAX_LINE_WRAP_LENGTH: Final[int] = 998
DEFAULT_LINE_SEPARATOR: Final[str] = "\n"
DEFAULT_ENTRY_SEPARATOR: Final[str] = "\n\n"

# =============================================================================
# FILE PROCESSING SETTINGS
# =============================================================================

DEFAULT_INPUT_ENCODING: Final[str] = "utf-8"
DEFAULT_OUTPUT_ENCODING: Final[str] = "utf-8"
DEFAULT_FILE_BUFFER_SIZE: Final[int] = 8192
DEFAULT_LDIF_FILE_PATTERN: Final[str] = "*.ldif"
DEFAULT_MAX_FILE_SIZE_MB: Final[int] = 100

# =============================================================================
# ENTRY PROCESSING LIMITS
# =============================================================================

DEFAULT_MAX_ENTRIES: Final[int] = 20000
MAX_ENTRIES_LIMIT: Final[int] = 1000000
MIN_ENTRIES_LIMIT: Final[int] = 1

# Entry Size Limits
DEFAULT_MAX_ENTRY_SIZE: Final[int] = 1048576  # 1MB
MIN_ENTRY_SIZE: Final[int] = 1024  # 1KB
MAX_ENTRY_SIZE_LIMIT: Final[int] = 104857600  # 100MB

# =============================================================================
# DN (DISTINGUISHED NAME) CONSTANTS
# =============================================================================

MIN_DN_COMPONENTS: Final[int] = 2
MAX_DN_DEPTH: Final[int] = 20
DN_SEPARATOR: Final[str] = ","
DN_ATTRIBUTE_SEPARATOR: Final[str] = "="
ATTRIBUTE_SEPARATOR: Final[str] = "="  # Alias for backward compatibility

# DN Validation Patterns
LDAP_ATTRIBUTE_PATTERN: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"
DN_COMPONENT_PATTERN: Final[str] = r"^[a-zA-Z]+=.+"

# =============================================================================
# LDAP OBJECT CLASSES (CONSOLIDATED - NO DUPLICATION)
# =============================================================================

# Person Object Classes (merged from constants.py + ldif_constants.py)
LDAP_PERSON_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "person",
        "organizationalPerson",
        "inetOrgPerson",
        "user",
        "posixAccount",
    },
)

# Group Object Classes (merged from constants.py + ldif_constants.py)
LDAP_GROUP_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "group",
        "groupOfNames",
        "groupOfUniqueNames",
        "posixGroup",
        "organizationalRole",
        "groupOfMembers",
    },
)

# Organizational Unit Object Classes
LDAP_OU_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "organizationalUnit",
        "top",
    },
)

# Backward Compatibility Aliases (DEPRECATED - use LDAP_ prefixed versions)
PERSON_OBJECT_CLASSES: Final[frozenset[str]] = LDAP_PERSON_CLASSES
GROUP_OBJECT_CLASSES: Final[frozenset[str]] = LDAP_GROUP_CLASSES
OU_OBJECT_CLASSES: Final[frozenset[str]] = LDAP_OU_CLASSES

# =============================================================================
# LDAP ATTRIBUTES (CONSOLIDATED - NO DUPLICATION)
# =============================================================================

# DN-Valued Attributes requiring DN normalization (merged from both files)
LDAP_DN_ATTRIBUTES: Final[frozenset[str]] = frozenset(
    {
        "orcldaspublicgroupdns",
        "member",
        "uniquemember",
        "owner",
        "seealso",
        "distinguishedname",
        "manager",
        "secretary",
        "roleoccupant",
    },
)

# Backward Compatibility Alias (DEPRECATED - use LDAP_DN_ATTRIBUTES)
DN_VALUED_ATTRIBUTES: Final[frozenset[str]] = LDAP_DN_ATTRIBUTES

# =============================================================================
# LDIF CHANGE TYPES
# =============================================================================

LDIF_CHANGE_TYPES: Final[frozenset[str]] = frozenset(
    {
        "add",
        "delete",
        "modify",
        "modrdn",
    },
)

# =============================================================================
# VALIDATION SETTINGS
# =============================================================================

DEFAULT_STRICT_VALIDATION: Final[bool] = True
DEFAULT_ALLOW_EMPTY_ATTRIBUTES: Final[bool] = False
DEFAULT_NORMALIZE_DN: Final[bool] = False
DEFAULT_SORT_ATTRIBUTES: Final[bool] = False

# =============================================================================
# LIBRARY METADATA
# =============================================================================

LIBRARY_NAME: Final[str] = "flext-ldif"
LIBRARY_VERSION: Final[str] = "0.9.0"
LIBRARY_DESCRIPTION: Final[str] = "Enterprise LDIF Processing Library"

# =============================================================================
# COMPREHENSIVE PUBLIC API - All constants exported
# =============================================================================

__all__ = [
    "ATTRIBUTE_SEPARATOR",  # Backward compatibility
    "DEFAULT_ALLOW_EMPTY_ATTRIBUTES",
    "DEFAULT_ENTRY_SEPARATOR",
    "DEFAULT_FILE_BUFFER_SIZE",
    # File Processing Settings
    "DEFAULT_INPUT_ENCODING",
    "DEFAULT_LDIF_FILE_PATTERN",
    "DEFAULT_LINE_SEPARATOR",
    # LDIF Format Constants (RFC 2849)
    "DEFAULT_LINE_WRAP_LENGTH",
    # Entry Processing Limits
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_MAX_ENTRY_SIZE",
    "DEFAULT_MAX_FILE_SIZE_MB",
    "DEFAULT_NORMALIZE_DN",
    "DEFAULT_OUTPUT_ENCODING",
    "DEFAULT_SORT_ATTRIBUTES",
    # Validation Settings
    "DEFAULT_STRICT_VALIDATION",
    "DN_ATTRIBUTE_SEPARATOR",
    "DN_COMPONENT_PATTERN",
    "DN_SEPARATOR",
    "DN_VALUED_ATTRIBUTES",  # Use LDAP_DN_ATTRIBUTES instead
    "GROUP_OBJECT_CLASSES",  # Use LDAP_GROUP_CLASSES instead
    "LDAP_ATTRIBUTE_PATTERN",
    # LDAP Attributes (NEW - consolidated naming)
    "LDAP_DN_ATTRIBUTES",
    "LDAP_GROUP_CLASSES",
    "LDAP_OU_CLASSES",
    # LDAP Object Classes (NEW - consolidated naming)
    "LDAP_PERSON_CLASSES",
    # LDIF Change Types
    "LDIF_CHANGE_TYPES",
    "LIBRARY_DESCRIPTION",
    # Library Metadata
    "LIBRARY_NAME",
    "LIBRARY_VERSION",
    "MAX_DN_DEPTH",
    "MAX_ENTRIES_LIMIT",
    "MAX_ENTRY_SIZE_LIMIT",
    "MAX_LINE_WRAP_LENGTH",
    # DN Constants
    "MIN_DN_COMPONENTS",
    "MIN_ENTRIES_LIMIT",
    "MIN_ENTRY_SIZE",
    "MIN_LINE_WRAP_LENGTH",
    "OU_OBJECT_CLASSES",  # Use LDAP_OU_CLASSES instead
    # Backward Compatibility Aliases (DEPRECATED)
    "PERSON_OBJECT_CLASSES",  # Use LDAP_PERSON_CLASSES instead
]
