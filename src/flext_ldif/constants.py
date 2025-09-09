"""FLEXT-LDIF Constants - Direct flext-core usage.

Minimal LDIF-specific constants using flext-core SOURCE OF TRUTH directly.
No duplication of existing functionality - only domain-specific additions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_core import FlextConstants


class FlextLDIFConstants:
    """LDIF Constants using flext-core SOURCE OF TRUTH directly.

    Provides direct access to FlextConstants.LDIF plus minimal LDIF-specific
    additions. No duplication of base functionality - uses flext-core as SOURCE OF TRUTH.
    """

    # Direct access to flext-core LDIF constants (SOURCE OF TRUTH)
    LDIF = FlextConstants.LDIF

    # Use flext-core validation messages as SOURCE OF TRUTH
    VALIDATION_MESSAGES = FlextConstants.LDIF.VALIDATION_MESSAGES

    # Use flext-core encoding constants as SOURCE OF TRUTH
    DEFAULT_ENCODING = FlextConstants.LDIF.DEFAULT_ENCODING
    ATTRIBUTE_SEPARATOR = FlextConstants.LDIF.ATTRIBUTE_SEPARATOR
    DN_ATTRIBUTE = FlextConstants.LDIF.DN_ATTRIBUTE

    # Use flext-core object classes as SOURCE OF TRUTH
    PERSON_OBJECTCLASSES = FlextConstants.LDIF.LDAP_PERSON_CLASSES
    ORGANIZATIONAL_OBJECTCLASSES = FlextConstants.LDIF.LDAP_ORGANIZATIONAL_CLASSES
    GROUP_OBJECTCLASSES = FlextConstants.LDIF.LDAP_GROUP_CLASSES

    # Use flext-core processing limits as SOURCE OF TRUTH
    DEFAULT_MAX_ENTRIES = FlextConstants.LDIF.DEFAULT_MAX_ENTRIES
    DEFAULT_BUFFER_SIZE = FlextConstants.LDIF.DEFAULT_BUFFER_SIZE
    MAX_LINE_LENGTH = FlextConstants.LDIF.MAX_LINE_LENGTH

    # LDIF-specific constants not in flext-core (domain-specific additions only)
    MIN_DN_COMPONENTS = 1  # Minimum DN components required
    DN_PATTERN = r"^[\w\s\-=,.+:@/\\()\[\]{}#&*;|<>?'\"~`!$%^]*$"  # Comprehensive DN pattern for LDAP validation

    # Use flext-core object classes with direct attribute access (convert frozenset to set for test compatibility)
    _person_classes: ClassVar[set[str]] = set(FlextConstants.LDIF.LDAP_PERSON_CLASSES)
    # Add lowercase aliases for test compatibility while keeping SOURCE OF TRUTH
    _person_classes.add("inetorgperson")  # Alias for inetOrgPerson
    _person_classes.add("organizationalperson")  # Alias for organizationalPerson
    _person_classes.add("user")  # Simple alias for test compatibility
    LDAP_PERSON_CLASSES: ClassVar[set[str]] = _person_classes

    _group_classes: ClassVar[set[str]] = set(FlextConstants.LDIF.LDAP_GROUP_CLASSES)
    _group_classes.add("groupofnames")  # Alias for groupOfNames
    _group_classes.add("groupofuniquenames")  # Alias for groupOfUniqueNames
    _group_classes.add("group")  # Simple alias for test compatibility
    LDAP_GROUP_CLASSES: ClassVar[set[str]] = _group_classes

    LDAP_ORGANIZATIONAL_CLASSES: ClassVar[set[str]] = set(FlextConstants.LDIF.LDAP_ORGANIZATIONAL_CLASSES)

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
        MAX_CACHE_SIZE = 10000      # 10K cache entries max
        MIN_DN_DEPTH_FOR_BASE = 2   # Minimum depth for base DN extraction


__all__ = ["FlextLDIFConstants"]
