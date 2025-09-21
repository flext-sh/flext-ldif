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
    """Centralized LDIF domain constants with flext-core integration.

    Provides comprehensive configuration centralization for all LDIF processing
    operations, reducing complexity and improving maintainability through
    unified constant management.
    """

    # Use universal constants instead of duplicating
    DEFAULT_TIMEOUT = FlextConstants.Network.DEFAULT_TIMEOUT
    VALIDATION_ERROR_BASE = FlextConstants.Errors.VALIDATION_ERROR

    # =========================================================================
    # LDIF-SPECIFIC CONSTANTS ONLY - No universal duplications
    # =========================================================================

    class Format:
        """LDIF format-specific constants with RFC 2849 compliance."""

        DEFAULT_ENCODING: Final[str] = "utf-8"
        ATTRIBUTE_SEPARATOR: Final[str] = ": "
        BASE64_SEPARATOR: Final[str] = ":: "
        DN_ATTRIBUTE: Final[str] = "dn"
        OBJECTCLASS_ATTRIBUTE: Final[str] = "objectClass"

        # LDIF line processing
        MAX_LINE_LENGTH: Final[int] = 8192
        DEFAULT_BUFFER_SIZE: Final[int] = 8192
        MIN_BUFFER_SIZE: Final[int] = 4096

        # Enhanced line formatting
        DEFAULT_WRAP_COLUMNS: Final[int] = 76
        MIN_WRAP_COLUMNS: Final[int] = 20
        CONTINUATION_PREFIX: Final[str] = " "
        LINE_SEPARATOR: Final[str] = "\n"

        # Attribute parsing patterns
        ATTRIBUTE_DELIMITER: Final[str] = ":"
        KEY_VALUE_DELIMITER: Final[str] = "="
        COMPONENT_SEPARATOR: Final[str] = ","
        MULTIVALUE_SEPARATOR: Final[str] = ";"

    class Attributes:
        """Standard LDAP attribute names used in LDIF processing."""

        # Core identity attributes
        CN_ATTRIBUTE: Final[str] = "cn"
        SN_ATTRIBUTE: Final[str] = "sn"
        UID_ATTRIBUTE: Final[str] = "uid"
        MAIL_ATTRIBUTE: Final[str] = "mail"
        GIVENNAME_ATTRIBUTE: Final[str] = "givenName"

        # Organizational attributes
        OU_ATTRIBUTE: Final[str] = "ou"
        DC_ATTRIBUTE: Final[str] = "dc"
        O_ATTRIBUTE: Final[str] = "o"

        # Contact attributes
        TELEPHONENUMBER_ATTRIBUTE: Final[str] = "telephoneNumber"
        DESCRIPTION_ATTRIBUTE: Final[str] = "description"

        # Extended attributes for enterprise integration
        EMPLOYEE_ID_ATTRIBUTE: Final[str] = "employeeID"
        DEPARTMENT_ATTRIBUTE: Final[str] = "department"
        TITLE_ATTRIBUTE: Final[str] = "title"

    class Validation:
        """LDIF-specific validation constants with enhanced business rules."""

        # DN validation (RFC 4514 compliant)
        DN_PATTERN: Final[str] = (
            r"^([A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)*)\s*=\s*[^,=+]+(?:\s*\+\s*([A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)*)\s*=\s*[^,=+]+)*(?:\s*,\s*([A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)*)\s*=\s*[^,=+]+(?:\s*\+\s*([A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)*)\s*=\s*[^,=+]+)*)*$"
        )

        # DN structure requirements
        MIN_DN_COMPONENTS: Final[int] = 1
        MIN_DN_PARTS_FOR_BASE: Final[int] = 2
        MIN_BASE_DN_COMPONENTS: Final[int] = 2
        MAX_SUSPICIOUS_DN_LENGTH: Final[int] = 200
        MIN_DN_LENGTH: Final[int] = 1

        # Field validation limits
        MIN_FIELD_LENGTH: Final[int] = 1
        MAX_ATTRIBUTE_NAME_LENGTH: Final[int] = 256
        MAX_ATTRIBUTE_VALUE_LENGTH: Final[int] = 65536

        # Format validation patterns
        UNSAFE_STRING_PATTERN: Final[str] = (
            r"(^[^\x01-\x09\x0b-\x0c\x0e-\x1f\x21-\x39\x3b\x3d-\x7f]"
            r"|[^\x01-\x09\x0b-\x0c\x0e-\x7f])"
        )
        ASCII_PRINTABLE_MIN: Final[int] = 32
        ASCII_PRINTABLE_MAX: Final[int] = 126

        # Progress tracking constants
        MIN_PROGRESS_INTERVAL: Final[int] = 100
        PROGRESS_DIVISOR: Final[int] = 10

    class Processing:
        """LDIF processing limits and thresholds with performance optimization."""

        # Processing limits
        DEFAULT_MAX_ENTRIES: Final[int] = 1000000
        MAX_ENTRIES_LIMIT: Final[int] = 10000000
        ANALYTICS_MAX_ENTRIES_LIMIT: Final[int] = 1000000
        MAX_CACHE_ENTRIES: Final[int] = 1000
        MANAGEABLE_CACHE_SIZE: Final[int] = 500

        # Configuration defaults
        DEFAULT_CHUNK_SIZE: Final[int] = 1000
        MAX_CHUNK_SIZE: Final[int] = 10000
        MIN_CHUNK_SIZE: Final[int] = 1

        # File size limits (in MB)
        DEFAULT_MAX_FILE_SIZE_MB: Final[int] = 100
        MAX_FILE_SIZE_LIMIT_MB: Final[int] = 1024
        MIN_FILE_SIZE_MB: Final[int] = 1

        # Performance thresholds
        MIN_WORKERS_FOR_PARALLEL: Final[int] = 2
        DEFAULT_MAX_WORKERS: Final[int] = 4
        MAX_WORKERS_LIMIT: Final[int] = 32
        MIN_WORKERS: Final[int] = 1

        # Analytics configuration
        DEFAULT_ANALYTICS_CACHE_SIZE: Final[int] = 10000
        MIN_ANALYTICS_CACHE_SIZE: Final[int] = 100
        MAX_ANALYTICS_CACHE_SIZE: Final[int] = 100000
        MIN_PRODUCTION_ENTRIES: Final[int] = 1000

        # Quality thresholds for health monitoring
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

        # Mathematical constants for calculations
        MIN_DIVISOR_VALUE: Final[float] = 1.0
        SUCCESS_RATE_MIN: Final[float] = 0.0
        SUCCESS_RATE_MAX: Final[float] = 1.0
        MILLISECONDS_MULTIPLIER: Final[float] = 1000.0

        # Sample sizes for analysis
        MIN_SAMPLE_SIZE: Final[int] = 10
        SAMPLE_DNS_LIMIT: Final[int] = 10

    class ObjectClasses:
        """LDAP object class constants for LDIF processing with enhanced enterprise support."""

        # Person-related object classes
        LDAP_PERSON_CLASSES: ClassVar[frozenset[str]] = frozenset({
            "person",
            "inetOrgPerson",
            "organizationalPerson",
            "inetorgperson",
            "organizationalperson",
            "user",
            "posixAccount",
        })

        # Group-related object classes
        LDAP_GROUP_CLASSES: ClassVar[frozenset[str]] = frozenset({
            "groupOfNames",
            "groupOfUniqueNames",
            "group",
            "groupofnames",
            "groupofuniquenames",
        })

        # Organizational object classes
        LDAP_ORGANIZATIONAL_CLASSES: ClassVar[frozenset[str]] = frozenset({
            "organizationalUnit",
            "organization",
            "organizationalunit",
        })

        # Domain object classes
        LDAP_DOMAIN_CLASSES: ClassVar[frozenset[str]] = frozenset({
            "domain",
            "dcobject",
        })

        # Default object class assignments for factory methods
        DEFAULT_PERSON_CLASSES: ClassVar[list[str]] = ["inetOrgPerson", "person"]
        DEFAULT_OU_CLASSES: ClassVar[list[str]] = ["organizationalUnit"]
        DEFAULT_DOMAIN_CLASSES: ClassVar[list[str]] = ["domain", "dcobject"]
        DEFAULT_GROUP_CLASSES: ClassVar[list[str]] = ["groupOfNames"]

    class Analytics:
        """LDIF analytics-specific constants with enhanced pattern detection."""

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

        # Analytics keys for metrics
        TOTAL_ENTRIES_KEY: Final[str] = "total_entries"
        ENTRIES_WITH_CN_KEY: Final[str] = "entries_with_cn"
        ENTRIES_WITH_MAIL_KEY: Final[str] = "entries_with_mail"
        ENTRIES_WITH_TELEPHONE_KEY: Final[str] = "entries_with_telephone"
        PERSON_ENTRIES_KEY: Final[str] = "person_entries"
        GROUP_ENTRIES_KEY: Final[str] = "group_entries"
        OU_ENTRIES_KEY: Final[str] = "ou_entries"
        OBJECTCLASS_DISTRIBUTION_KEY: Final[str] = "objectclass_distribution"
        DN_DEPTH_DISTRIBUTION_KEY: Final[str] = "dn_depth_distribution"

        # Pattern detection keys
        FLAT_ENTRIES_KEY: Final[str] = "flat_entries"
        OUTLIER_DEPTHS_KEY: Final[str] = "outlier_depths"
        COMBINATION_PATTERNS_KEY: Final[str] = "combination_patterns"

    class Required:
        """Required attributes for different object classes with validation rules."""

        REQUIRED_PERSON_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset({"cn", "sn"})
        REQUIRED_ORGUNIT_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset({"ou"})
        REQUIRED_DOMAIN_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset({"dc"})

        # Extended requirements for enterprise scenarios
        RECOMMENDED_PERSON_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset({
            "cn",
            "sn",
            "mail",
            "uid",
            "givenName",
        })
        RECOMMENDED_GROUP_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset({
            "cn",
            "member",
            "description",
        })

    class Operations:
        """LDIF operation constants with enhanced modification support."""

        # Modification operations
        MOD_OPS: ClassVar[tuple[str, ...]] = ("add", "delete", "replace")
        CHANGE_TYPES: ClassVar[tuple[str, ...]] = ("add", "delete", "modify", "modrdn")

        # Format validation flags
        ENTRY_IS_COMPLETE: Final[bool] = True
        ORACLE_MIN_PARTS: Final[int] = 3

        # Operation status indicators
        SUCCESS_INDICATOR: Final[int] = 1
        FAILURE_INDICATOR: Final[int] = 0

    class Messages:
        """LDIF-specific validation and error messages with enhanced context."""

        VALIDATION_MESSAGES: ClassVar[MappingProxyType[str, str]] = MappingProxyType({
            "INVALID_DN": "Invalid DN",
            "INVALID_DN_FORMAT": "Invalid DN format",
            "MISSING_OBJECTCLASS": "Missing required objectClass",
            "INVALID_ATTRIBUTE_VALUE": "Invalid attribute value",
            "DUPLICATE_ATTRIBUTE": "Duplicate attribute found",
            "EMPTY_ENTRY": "Entry cannot be empty",
            "MISSING_DN": "Missing DN",
            "INVALID_ATTRIBUTE_NAME": "Invalid attribute name",
            "INSUFFICIENT_DN_COMPONENTS": "DN has insufficient components",
            "INVALID_COMPONENT_FORMAT": "Invalid DN component format",
            "PARSE_ERROR": "LDIF parsing error",
            "VALIDATION_FAILED": "Entry validation failed",
            "WRITE_ERROR": "LDIF write operation failed",
        })

    class Formatting:
        """LDIF formatting and display constants with enhanced presentation."""

        CONTENT_PREVIEW_LENGTH: Final[int] = 50
        DN_PREVIEW_LENGTH: Final[int] = 80
        ATTRIBUTE_TRUNCATION_THRESHOLD: Final[int] = 3
        MAX_ATTRIBUTES_DISPLAY: Final[int] = 5

        # Enhanced formatting for different contexts
        SHORT_PREVIEW_LENGTH: Final[int] = 20
        LONG_PREVIEW_LENGTH: Final[int] = 100
        SUMMARY_LINE_LENGTH: Final[int] = 80

        # Sorting and prioritization
        OBJECTCLASS_PRIORITY: Final[int] = 0
        DEFAULT_ATTRIBUTE_PRIORITY: Final[int] = 1

    class Network:
        """LDIF network-related constants with enhanced protocol support."""

        ALLOWED_URL_SCHEMES: ClassVar[frozenset[str]] = frozenset({"http", "https"})
        HTTP_OK: Final[int] = 200

        # Enhanced network configuration
        DEFAULT_CONNECT_TIMEOUT: Final[int] = 30
        DEFAULT_READ_TIMEOUT: Final[int] = 60
        MAX_REDIRECTS: Final[int] = 5

    class Storage:
        """LDIF storage-related constants with capacity management."""

        REPOSITORY_STORAGE_WARNING_THRESHOLD: Final[int] = 100000

        # Enhanced storage configuration
        DEFAULT_BACKUP_RETENTION_DAYS: Final[int] = 30
        MAX_TEMP_FILES: Final[int] = 100
        CLEANUP_INTERVAL_HOURS: Final[int] = 24

    class Errors:
        """LDIF-specific error codes extending flext-core universal patterns."""

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

        # Enhanced error categories
        FORMAT: Final[str] = "ldif_format"
        ENCODING: Final[str] = "ldif_encoding"
        SCHEMA: Final[str] = "ldif_schema"
        RESOURCE: Final[str] = "ldif_resource"

    class FeatureFlags:
        """LDIF-specific feature toggles with enhanced environment integration."""

        @staticmethod
        def _env_enabled(flag_name: str, default: str = "0") -> bool:
            """Check if environment variable indicates feature is enabled.

            Returns:
                bool: True if feature is enabled, False otherwise

            """
            value = os.environ.get(flag_name, default)
            return value.lower() not in {"0", "false", "no"}

        @classmethod
        def dispatcher_enabled(cls) -> bool:
            """Return True when dispatcher integration should be used.

            Returns:
                bool: True if dispatcher integration is enabled

            """
            return cls._env_enabled("FLEXT_LDIF_ENABLE_DISPATCHER")

        @classmethod
        def analytics_enabled(cls) -> bool:
            """Return True when analytics features should be active.

            Returns:
                bool: True if analytics features are enabled

            """
            return cls._env_enabled("FLEXT_LDIF_ENABLE_ANALYTICS", "1")

        @classmethod
        def parallel_processing_enabled(cls) -> bool:
            """Return True when parallel processing should be used.

            Returns:
                bool: True if parallel processing is enabled

            """
            return cls._env_enabled("FLEXT_LDIF_ENABLE_PARALLEL", "1")

        @classmethod
        def debug_mode_enabled(cls) -> bool:
            """Return True when debug mode features should be active.

            Returns:
                bool: True if debug mode is enabled

            """
            return cls._env_enabled("FLEXT_LDIF_DEBUG_MODE")


__all__ = ["FlextLdifConstants"]
