"""FLEXT LDIF Constants - Inherits from flext-core FlextConstants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
from typing import ClassVar, Final

from flext_core import FlextConstants


class FlextLdifConstants(FlextConstants):
    """LDIF-specific constants for the flext-ldif domain."""

    # LDIF Format Constants
    DEFAULT_ENCODING: Final[str] = "utf-8"
    ATTRIBUTE_SEPARATOR: Final[str] = ": "
    DN_ATTRIBUTE: Final[str] = "dn"

    # DN Pattern for validation (RFC 4514 compliant, supports multi-valued RDNs with +)
    DN_PATTERN: Final[str] = (
        r"^([A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)*)\s*=\s*[^,=+]+(?:\s*\+\s*([A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)*)\s*=\s*[^,=+]+)*(?:\s*,\s*([A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)*)\s*=\s*[^,=+]+(?:\s*\+\s*([A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)*)\s*=\s*[^,=+]+)*)*$"
    )

    # Standard LDAP Attributes
    OBJECTCLASS_ATTRIBUTE: Final[str] = "objectClass"
    CN_ATTRIBUTE: Final[str] = "cn"
    SN_ATTRIBUTE: Final[str] = "sn"
    UID_ATTRIBUTE: Final[str] = "uid"
    MAIL_ATTRIBUTE: Final[str] = "mail"
    GIVENNAME_ATTRIBUTE: Final[str] = "givenName"
    OU_ATTRIBUTE: Final[str] = "ou"
    DC_ATTRIBUTE: Final[str] = "dc"
    TELEPHONENUMBER_ATTRIBUTE: Final[str] = "telephoneNumber"
    DESCRIPTION_ATTRIBUTE: Final[str] = "description"

    # LDIF Processing Limits
    DEFAULT_MAX_ENTRIES: Final[int] = 1000000
    DEFAULT_BUFFER_SIZE: Final[int] = 8192
    MAX_LINE_LENGTH: Final[int] = 8192
    MIN_DN_COMPONENTS: Final[int] = 1

    # Note: DN validation handled by FlextLdifModels.DistinguishedName

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
        "MISSING_DN": "Missing DN",
        "INVALID_ATTRIBUTE_NAME": "Invalid attribute name",
    }

    # Required Attributes for Schema Validation
    REQUIRED_PERSON_ATTRIBUTES: ClassVar[set[str]] = {"cn", "sn"}
    REQUIRED_ORGUNIT_ATTRIBUTES: ClassVar[set[str]] = {"ou"}

    # LDIF-specific analytics constants (moved from nested Analytics class)
    # Statistics keys specific to LDIF analytics (not in flext-core)
    ANALYTICS_TOTAL_ENTRIES_KEY: Final[str] = "total_entries"
    ANALYTICS_ENTRIES_WITH_CN_KEY: Final[str] = "entries_with_cn"
    ANALYTICS_ENTRIES_WITH_MAIL_KEY: Final[str] = "entries_with_mail"
    ANALYTICS_ENTRIES_WITH_TELEPHONE_KEY: Final[str] = "entries_with_telephone"
    ANALYTICS_PERSON_ENTRIES_KEY: Final[str] = "person_entries"
    ANALYTICS_GROUP_ENTRIES_KEY: Final[str] = "group_entries"
    ANALYTICS_OU_ENTRIES_KEY: Final[str] = "ou_entries"
    ANALYTICS_OBJECTCLASS_DISTRIBUTION_KEY: Final[str] = "objectclass_distribution"
    ANALYTICS_DN_DEPTH_DISTRIBUTION_KEY: Final[str] = "dn_depth_distribution"

    # Analytics configuration limits
    ANALYTICS_MAX_ENTRIES_LIMIT: Final[int] = 1000000  # 1M entries max
    ANALYTICS_MAX_CACHE_SIZE: Final[int] = 10000  # 10K cache entries max
    ANALYTICS_MIN_DN_DEPTH_FOR_BASE: Final[int] = (
        2  # Minimum depth for base DN extraction  # Minimum depth for base DN extraction
    )
    # Constants moved from utilities.py for centralization
    MIN_BASE_DN_COMPONENTS: Final[int] = 2  # Minimum components for base DN extraction
    ENTRY_IS_COMPLETE: Final[bool] = True  # Constant for entry completeness validation

    class FeatureFlags:
        """Feature toggles for dispatcher integration."""

        @staticmethod
        def _env_enabled(flag_name: str, default: str = "0") -> bool:
            value = os.environ.get(flag_name, default)
            return value.lower() not in {"0", "false", "no"}

        @classmethod
        def dispatcher_enabled(cls) -> bool:
            """Return True when dispatcher path should be used."""
            return cls._env_enabled("FLEXT_LDIF_ENABLE_DISPATCHER")


__all__ = ["FlextLdifConstants"]
