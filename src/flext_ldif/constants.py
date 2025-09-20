"""FLEXT LDIF Constants - Inherits from flext-core FlextConstants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
from types import MappingProxyType
from typing import ClassVar, Final

from flext_core import FlextConstants


class FlextLdifConstants:
    """LDIF domain-specific constants only - universal constants imported from flext-core."""

    # Use universal constants instead of duplicating
    DEFAULT_TIMEOUT = FlextConstants.Network.DEFAULT_TIMEOUT
    VALIDATION_ERROR_BASE = FlextConstants.Errors.VALIDATION_ERROR

    # =========================================================================
    # LDIF-SPECIFIC CONSTANTS ONLY - No universal duplications
    # =========================================================================

    class Format:
        """LDIF format-specific constants."""

        DEFAULT_ENCODING: Final[str] = "utf-8"
        ATTRIBUTE_SEPARATOR: Final[str] = ": "
        DN_ATTRIBUTE: Final[str] = "dn"
        OBJECTCLASS_ATTRIBUTE: Final[str] = "objectClass"

        # LDIF line processing
        MAX_LINE_LENGTH: Final[int] = 8192
        DEFAULT_BUFFER_SIZE: Final[int] = 8192
        MIN_BUFFER_SIZE: Final[int] = 4096

    class Attributes:
        """Standard LDAP attribute names used in LDIF."""

        # Standard LDAP attributes
        CN_ATTRIBUTE: Final[str] = "cn"
        SN_ATTRIBUTE: Final[str] = "sn"
        UID_ATTRIBUTE: Final[str] = "uid"
        MAIL_ATTRIBUTE: Final[str] = "mail"
        GIVENNAME_ATTRIBUTE: Final[str] = "givenName"
        OU_ATTRIBUTE: Final[str] = "ou"
        DC_ATTRIBUTE: Final[str] = "dc"
        TELEPHONENUMBER_ATTRIBUTE: Final[str] = "telephoneNumber"
        DESCRIPTION_ATTRIBUTE: Final[str] = "description"

    class Validation:
        """LDIF-specific validation constants."""

        # DN validation (RFC 4514 compliant)
        DN_PATTERN: Final[str] = (
            r"^([A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)*)\s*=\s*[^,=+]+(?:\s*\+\s*([A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)*)\s*=\s*[^,=+]+)*(?:\s*,\s*([A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)*)\s*=\s*[^,=+]+(?:\s*\+\s*([A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)*)\s*=\s*[^,=+]+)*)*$"
        )
        MIN_DN_COMPONENTS: Final[int] = 1
        MIN_DN_PARTS_FOR_BASE: Final[int] = 2
        MIN_BASE_DN_COMPONENTS: Final[int] = 2
        MAX_SUSPICIOUS_DN_LENGTH: Final[int] = 200

        # Format validation
        UNSAFE_STRING_PATTERN: Final[str] = (
            r"(^[^\x01-\x09\x0b-\x0c\x0e-\x1f\x21-\x39\x3b\x3d-\x7f]"
            r"|[^\x01-\x09\x0b-\x0c\x0e-\x7f])"
        )
        ASCII_PRINTABLE_MIN: Final[int] = 32
        ASCII_PRINTABLE_MAX: Final[int] = 126

    class Processing:
        """LDIF processing limits and thresholds."""

        # Processing limits
        DEFAULT_MAX_ENTRIES: Final[int] = 1000000
        ANALYTICS_MAX_ENTRIES_LIMIT: Final[int] = 1000000
        MAX_CACHE_ENTRIES: Final[int] = 1000
        MANAGEABLE_CACHE_SIZE: Final[int] = 500

        # Performance thresholds
        MIN_WORKERS_FOR_PARALLEL: Final[int] = 2
        MAX_WORKERS_LIMIT: Final[int] = 16
        MIN_ANALYTICS_CACHE_SIZE: Final[int] = 100
        MAX_ANALYTICS_CACHE_SIZE: Final[int] = 50000
        MIN_PRODUCTION_ENTRIES: Final[int] = 1000

        # Quality thresholds
        HEALTHY_SUCCESS_RATE_THRESHOLD: Final[float] = 0.90
        DEGRADED_SUCCESS_RATE_THRESHOLD: Final[float] = 0.70
        VALIDATOR_DEGRADED_THRESHOLD: Final[float] = 0.90
        VALIDATOR_UNHEALTHY_THRESHOLD: Final[float] = 0.50
        WRITER_HEALTHY_THRESHOLD: Final[float] = 0.95
        WRITER_DEGRADED_THRESHOLD: Final[float] = 0.80
        PARSER_HEALTHY_THRESHOLD: Final[float] = 0.95
        REPOSITORY_HEALTHY_THRESHOLD: Final[float] = 0.95
        REPOSITORY_DEGRADED_THRESHOLD: Final[float] = 0.80
        CACHE_HIT_RATE_THRESHOLD: Final[float] = 0.50

    class ObjectClasses:
        """LDAP object class constants for LDIF processing."""

        # Person-related object classes
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

        # Group-related object classes
        LDAP_GROUP_CLASSES: ClassVar[frozenset[str]] = frozenset(
            {
                "groupOfNames",
                "groupOfUniqueNames",
                "group",
                "groupofnames",
                "groupofuniquenames",
            }
        )

        # Organizational object classes
        LDAP_ORGANIZATIONAL_CLASSES: ClassVar[frozenset[str]] = frozenset(
            {"organizationalUnit", "organization", "organizationalunit"}
        )

        # Domain object classes
        LDAP_DOMAIN_CLASSES: ClassVar[frozenset[str]] = frozenset(
            {"domain", "dcobject"}
        )

    class Analytics:
        """LDIF analytics-specific constants."""

        # Analytics thresholds
        HIGH_PERSON_RATIO_THRESHOLD: Final[float] = 0.8
        LOW_PERSON_RATIO_THRESHOLD: Final[float] = 0.1
        HIGH_DUPLICATE_RATIO_THRESHOLD: Final[float] = 0.05
        RARE_OBJECTCLASS_RATIO_THRESHOLD: Final[float] = 0.001
        RARE_OBJECTCLASS_COUNT_THRESHOLD: Final[int] = 5
        LARGE_DATASET_THRESHOLD: Final[int] = 50000

        # Batch size thresholds
        SMALL_BATCH_SIZE_THRESHOLD: Final[int] = 100
        MEDIUM_BATCH_SIZE_THRESHOLD: Final[int] = 1000

        # Depth analysis
        MAX_FLAT_ENTRY_DEPTH: Final[int] = 3
        MAX_DEPTH_DEVIATION: Final[int] = 3

        # Analytics keys
        TOTAL_ENTRIES_KEY: Final[str] = "total_entries"
        ENTRIES_WITH_CN_KEY: Final[str] = "entries_with_cn"
        ENTRIES_WITH_MAIL_KEY: Final[str] = "entries_with_mail"
        ENTRIES_WITH_TELEPHONE_KEY: Final[str] = "entries_with_telephone"
        PERSON_ENTRIES_KEY: Final[str] = "person_entries"
        GROUP_ENTRIES_KEY: Final[str] = "group_entries"
        OU_ENTRIES_KEY: Final[str] = "ou_entries"
        OBJECTCLASS_DISTRIBUTION_KEY: Final[str] = "objectclass_distribution"
        DN_DEPTH_DISTRIBUTION_KEY: Final[str] = "dn_depth_distribution"

    class Required:
        """Required attributes for different object classes."""

        REQUIRED_PERSON_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset({"cn", "sn"})
        REQUIRED_ORGUNIT_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset({"ou"})
        REQUIRED_DOMAIN_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset({"dc"})

    class Operations:
        """LDIF operation constants."""

        # Modification operations
        MOD_OPS: ClassVar[tuple[str, ...]] = ("add", "delete", "replace")
        CHANGE_TYPES: ClassVar[tuple[str, ...]] = ("add", "delete", "modify", "modrdn")

        # Format validation
        ENTRY_IS_COMPLETE: Final[bool] = True
        ORACLE_MIN_PARTS: Final[int] = 3

    class Messages:
        """LDIF-specific validation and error messages."""

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

    class Formatting:
        """LDIF formatting and display constants."""

        CONTENT_PREVIEW_LENGTH: Final[int] = 50
        DN_PREVIEW_LENGTH: Final[int] = 80
        ATTRIBUTE_TRUNCATION_THRESHOLD: Final[int] = 3
        MAX_ATTRIBUTES_DISPLAY: Final[int] = 5

    class Network:
        """LDIF network-related constants."""

        ALLOWED_URL_SCHEMES: ClassVar[frozenset[str]] = frozenset({"http", "https"})
        HTTP_OK: Final[int] = 200

    class Storage:
        """LDIF storage-related constants."""

        REPOSITORY_STORAGE_WARNING_THRESHOLD: Final[int] = 100000

    class Errors:
        """LDIF-specific error codes - extend universal error codes."""

        # Base universal errors from flext-core, prefixed for LDIF domain
        VALIDATION_ERROR: Final[str] = f"LDIF_{FlextConstants.Errors.VALIDATION_ERROR}"
        PROCESSING_ERROR: Final[str] = f"LDIF_{FlextConstants.Errors.PROCESSING_ERROR}"

        # LDIF-specific error types
        PARSE: Final[str] = "ldif_parse"
        VALIDATION: Final[str] = "ldif_validation"
        PROCESSING: Final[str] = "ldif_processing"
        FILE: Final[str] = "ldif_file"
        CONFIGURATION: Final[str] = "ldif_configuration"
        CONNECTION: Final[str] = "ldif_connection"
        TIMEOUT: Final[str] = "ldif_timeout"
        AUTHENTICATION: Final[str] = "ldif_authentication"
        GENERIC: Final[str] = "ldif_error"

    class FeatureFlags:
        """LDIF-specific feature toggles."""

        @staticmethod
        def _env_enabled(flag_name: str, default: str = "0") -> bool:
            value = os.environ.get(flag_name, default)
            return value.lower() not in {"0", "false", "no"}

        @classmethod
        def dispatcher_enabled(cls) -> bool:
            """Return True when dispatcher integration should be used."""
            return cls._env_enabled("FLEXT_LDIF_ENABLE_DISPATCHER")


__all__ = ["FlextLdifConstants"]
