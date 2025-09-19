"""FLEXT LDIF Constants - Inherits from flext-core FlextConstants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
from types import MappingProxyType
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

    MIN_WORKERS_FOR_PARALLEL: int = 2
    MIN_ANALYTICS_CACHE_SIZE: int = 100
    MIN_PRODUCTION_ENTRIES: int = 1000
    MIN_BUFFER_SIZE: int = 4096
    MAX_WORKERS_LIMIT: int = 16
    MAX_ANALYTICS_CACHE_SIZE: int = 50000

    # Analytics and Validation Constants
    MIN_DN_PARTS_FOR_BASE: Final[int] = 2
    MAX_FLAT_ENTRY_DEPTH: Final[int] = 3
    MAX_SUSPICIOUS_DN_LENGTH: Final[int] = 200
    HEALTHY_SUCCESS_RATE_THRESHOLD: Final[float] = 0.90
    DEGRADED_SUCCESS_RATE_THRESHOLD: Final[float] = 0.70
    VALIDATOR_DEGRADED_THRESHOLD: Final[float] = 0.90
    VALIDATOR_UNHEALTHY_THRESHOLD: Final[float] = 0.50
    WRITER_HEALTHY_THRESHOLD: Final[float] = 0.95
    WRITER_DEGRADED_THRESHOLD: Final[float] = 0.80
    HIGH_PERSON_RATIO_THRESHOLD: Final[float] = 0.8
    LOW_PERSON_RATIO_THRESHOLD: Final[float] = 0.1
    HIGH_DUPLICATE_RATIO_THRESHOLD: Final[float] = 0.05
    SMALL_BATCH_SIZE_THRESHOLD: Final[int] = 100
    MEDIUM_BATCH_SIZE_THRESHOLD: Final[int] = 1000
    MAX_CACHE_ENTRIES: Final[int] = 1000
    MANAGEABLE_CACHE_SIZE: Final[int] = 500
    LARGE_DATASET_THRESHOLD: Final[int] = 50000
    RARE_OBJECTCLASS_RATIO_THRESHOLD: Final[float] = 0.001
    RARE_OBJECTCLASS_COUNT_THRESHOLD: Final[int] = 5
    MAX_DEPTH_DEVIATION: Final[int] = 3
    PARSER_HEALTHY_THRESHOLD: Final[float] = 0.95
    REPOSITORY_STORAGE_WARNING_THRESHOLD: Final[int] = 100000
    REPOSITORY_HEALTHY_THRESHOLD: Final[float] = 0.95
    REPOSITORY_DEGRADED_THRESHOLD: Final[float] = 0.80
    CACHE_HIT_RATE_THRESHOLD: Final[float] = 0.50

    # LDAP Object Classes
    LDAP_PERSON_CLASSES: ClassVar[frozenset[str]] = frozenset(
        {
            "person",
            "inetOrgPerson",
            "organizationalPerson",
            "inetorgperson",
            "organizationalperson",
            "user",
            "posixAccount",
        }
    )

    LDAP_GROUP_CLASSES: ClassVar[frozenset[str]] = frozenset(
        {
            "groupOfNames",
            "groupOfUniqueNames",
            "group",
            "groupofnames",
            "groupofuniquenames",
        }
    )

    LDAP_ORGANIZATIONAL_CLASSES: ClassVar[frozenset[str]] = frozenset(
        {
            "organizationalUnit",
            "organization",
            "domain",
            "organizationalunit",
        }
    )

    # Validation Messages
    VALIDATION_MESSAGES: ClassVar[MappingProxyType[str, str]] = MappingProxyType(
        {
            "INVALID_DN": "Invalid DN",
            "INVALID_DN_FORMAT": "Invalid DN format",
            "MISSING_OBJECTCLASS": "Missing required objectClass",
            "INVALID_ATTRIBUTE_VALUE": "Invalid attribute value",
            "DUPLICATE_ATTRIBUTE": "Duplicate attribute found",
            "EMPTY_ENTRY": "Entry cannot be empty",
            "MISSING_DN": "Missing DN",
            "INVALID_ATTRIBUTE_NAME": "Invalid attribute name",
        }
    )

    # Required Attributes for Schema Validation
    REQUIRED_PERSON_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset({"cn", "sn"})
    REQUIRED_ORGUNIT_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset({"ou"})

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

    # Format handler constants (moved from format_handlers.py for centralization)
    MOD_OPS: ClassVar[tuple[str, ...]] = ("add", "delete", "replace")
    CHANGE_TYPES: ClassVar[tuple[str, ...]] = ("add", "delete", "modify", "modrdn")

    # URL and format constants
    ALLOWED_URL_SCHEMES: ClassVar[frozenset[str]] = frozenset({"http", "https"})
    HTTP_OK: Final[int] = 200
    ASCII_PRINTABLE_MIN: Final[int] = 32
    ASCII_PRINTABLE_MAX: Final[int] = 126

    # LDIF format patterns
    UNSAFE_STRING_PATTERN: Final[str] = (
        r"(^[^\x01-\x09\x0b-\x0c\x0e-\x1f\x21-\x39\x3b\x3d-\x7f]"
        r"|[^\x01-\x09\x0b-\x0c\x0e-\x7f])"
    )

    # Exception formatting constants (moved from exceptions.py for centralization)
    CONTENT_PREVIEW_LENGTH: Final[int] = 50
    DN_PREVIEW_LENGTH: Final[int] = 80
    ATTRIBUTE_TRUNCATION_THRESHOLD: Final[int] = 3
    MAX_ATTRIBUTES_DISPLAY: Final[int] = 5

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

    class ErrorTypes:
        """Nested class for error type constants."""

        PARSE = "ldif_parse"
        VALIDATION = "ldif_validation"
        PROCESSING = "ldif_processing"
        FILE = "ldif_file"
        CONFIGURATION = "ldif_configuration"
        CONNECTION = "ldif_connection"
        TIMEOUT = "ldif_timeout"
        AUTHENTICATION = "ldif_authentication"
        GENERIC = "ldif_error"


__all__ = ["FlextLdifConstants"]
