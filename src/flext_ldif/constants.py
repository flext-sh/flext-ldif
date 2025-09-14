"""FLEXT LDIF Constants - Inherits from flext-core FlextConstants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, Final

from flext_core import FlextConstants


class FlextLDIFConstants(FlextConstants):
    """LDIF-specific constants for the flext-ldif domain."""

    # LDIF Format Constants
    DEFAULT_ENCODING: Final[str] = "utf-8"
    ATTRIBUTE_SEPARATOR: Final[str] = ": "
    DN_ATTRIBUTE: Final[str] = "dn"

    # LDIF Processing Limits
    DEFAULT_MAX_ENTRIES: Final[int] = 1000000
    DEFAULT_BUFFER_SIZE: Final[int] = 8192
    MAX_LINE_LENGTH: Final[int] = 8192
    MIN_DN_COMPONENTS: Final[int] = 1

    # LDAP DN Pattern - Validates proper DN format with attribute=value pairs (Unicode support)
    DN_PATTERN: Final[str] = r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]*=[\w][\w\-\.\s=,+@]*[\w]$"

    # LDAP Object Classes
    LDAP_PERSON_CLASSES: ClassVar[set[str]] = {
        "person",
        "inetOrgPerson",
        "organizationalPerson",
        "inetorgperson",
        "organizationalperson",
        "user",
        "posixAccount",
    }

    LDAP_GROUP_CLASSES: ClassVar[set[str]] = {
        "groupOfNames",
        "groupOfUniqueNames",
        "group",
        "groupofnames",
        "groupofuniquenames",
    }

    LDAP_ORGANIZATIONAL_CLASSES: ClassVar[set[str]] = {
        "organizationalUnit",
        "organization",
        "domain",
        "organizationalunit",
    }

    # Validation Messages
    VALIDATION_MESSAGES: ClassVar[dict[str, str]] = {
        "INVALID_DN": "Invalid DN",
        "INVALID_DN_FORMAT": "Invalid DN format",
        "MISSING_OBJECTCLASS": "Missing required objectClass",
        "INVALID_ATTRIBUTE_VALUE": "Invalid attribute value",
        "DUPLICATE_ATTRIBUTE": "Duplicate attribute found",
        "EMPTY_ENTRY": "Entry cannot be empty",
    }

    # Required Attributes for Schema Validation
    REQUIRED_PERSON_ATTRIBUTES: ClassVar[set[str]] = {"cn", "sn"}
    REQUIRED_ORGUNIT_ATTRIBUTES: ClassVar[set[str]] = {"ou"}

    # Minimal LDIF-specific analytics keys (only domain-specific additions)
    class Analytics:
        """LDIF-specific analytics constants (minimal additions only)."""

        # Statistics keys specific to LDIF analytics (not in flext-core)
        TOTAL_ENTRIES_KEY = "total_entries"
        ENTRIES_WITH_CN_KEY = "entries_with_cn"
        ENTRIES_WITH_MAIL_KEY = "entries_with_mail"
        ENTRIES_WITH_TELEPHONE_KEY = "entries_with_telephone"
        PERSON_ENTRIES_KEY = "person_entries"
        GROUP_ENTRIES_KEY = "group_entries"
        OU_ENTRIES_KEY = "ou_entries"
        OBJECTCLASS_DISTRIBUTION_KEY = "objectclass_distribution"
        DN_DEPTH_DISTRIBUTION_KEY = "dn_depth_distribution"

        # Use flext-core attribute names as SOURCE OF TRUTH
        CN_ATTRIBUTE = "cn"
        MAIL_ATTRIBUTE = "mail"
        TELEPHONE_ATTRIBUTE = "telephonenumber"
        UID_ATTRIBUTE = "uid"
        SN_ATTRIBUTE = "sn"
        GIVEN_NAME_ATTRIBUTE = "givenname"

        # Configuration limits
        MAX_ENTRIES_LIMIT = 1000000  # 1M entries max
        MAX_CACHE_SIZE = 10000  # 10K cache entries max
        MIN_DN_DEPTH_FOR_BASE = 2  # Minimum depth for base DN extraction


__all__ = ["FlextLDIFConstants"]
