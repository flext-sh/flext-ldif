"""FLEXT-LDIF Constants - Unified constants following flext-core patterns.

Single class per module containing all LDIF constants.
Uses FlextConstants from flext-core as foundation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar


class FlextLDIFConstants:
    """Unified LDIF constants following flext-core single-class-per-module pattern."""

    class FlextLDIFFormatConstants:
        """LDIF format-specific constants."""

        # ObjectClass sets for entry type validation
        PERSON_OBJECTCLASSES: ClassVar[set[str]] = {
            "person",
            "inetorgperson",
            "organizationalperson",
            "user",
        }

        OU_OBJECTCLASSES: ClassVar[set[str]] = {"organizationalunit", "ou"}

        GROUP_OBJECTCLASSES: ClassVar[set[str]] = {
            "group",
            "groupofnames",
            "groupofuniquenames",
        }

        # Required attributes for different entry types
        PERSON_REQUIRED_ATTRIBUTES: ClassVar[list[str]] = ["cn", "objectclass"]
        OU_REQUIRED_ATTRIBUTES: ClassVar[list[str]] = ["ou", "objectclass"]

    class FlextLDIFAnalyticsConstants:
        """Analytics-specific constants."""

        TOTAL_ENTRIES_KEY: ClassVar[str] = "total_entries"
        ENTRIES_WITH_CN_KEY: ClassVar[str] = "entries_with_cn"
        ENTRIES_WITH_MAIL_KEY: ClassVar[str] = "entries_with_mail"
        ENTRIES_WITH_TELEPHONE_KEY: ClassVar[str] = "entries_with_telephone"

        # Attribute names
        CN_ATTRIBUTE: ClassVar[str] = "cn"
        MAIL_ATTRIBUTE: ClassVar[str] = "mail"
        TELEPHONE_ATTRIBUTE: ClassVar[str] = "telephonenumber"

    class FlextLDIFCoreConstants:
        """Core LDIF processing constants."""

        # Regex patterns
        DN_PATTERN_REGEX: ClassVar[str] = r"^[a-zA-Z][\w-]*=.+(?:,[a-zA-Z][\w-]*=.+)*$"
        ATTRIBUTE_PATTERN_REGEX: ClassVar[str] = r"^[a-zA-Z][\w-]*$"
        ATTR_NAME_PATTERN_REGEX: ClassVar[str] = r"^[a-zA-Z][\w-]*$"

        # Separators
        LDIF_LINE_SEPARATOR: ClassVar[str] = "\n"
        NEWLINE_ESCAPE: ClassVar[str] = "\\n"

        # Log messages
        TLDIF_PARSE_CALLED_LOG: ClassVar[str] = "LDIF parse called"
        CONTENT_LENGTH_LOG: ClassVar[str] = "Content length: {length}"
        CONTENT_CONVERTED_LOG: ClassVar[str] = "Content converted"
        CONTENT_PREVIEW_LOG: ClassVar[str] = "Content preview: {preview}"
        CONTENT_PREVIEW_LENGTH: ClassVar[int] = 100
        DELEGATING_TO_MODERNIZED_LOG: ClassVar[str] = "Delegating to modernized LDIF"
        EXCEPTION_TYPE_LOG: ClassVar[str] = "Exception type: {exception_type}"

    class FlextLDIFValidationMessages:
        """Validation message templates."""

        EMPTY_ATTRIBUTE_VALUE_NOT_ALLOWED: ClassVar[str] = (
            "Empty attribute value not allowed for {attr_name}"
        )
        INVALID_DN_FORMAT: ClassVar[str] = "Invalid DN format: {dn}"
        MISSING_REQUIRED_ATTRIBUTE: ClassVar[str] = (
            "Missing required attribute: {attr_name}"
        )

        # DN Validation messages
        EMPTY_DN: ClassVar[str] = "DN cannot be empty"
        INVALID_DN: ClassVar[str] = "Invalid DN format: {dn}"
        DN_TOO_SHORT: ClassVar[str] = (
            "DN has {components} components, minimum {minimum} required"
        )
        MISSING_DN: ClassVar[str] = "Missing DN"

        # Attribute validation messages
        INVALID_ATTRIBUTE_NAME: ClassVar[str] = "Invalid attribute name: {attr_name}"
        INVALID_ATTRIBUTES: ClassVar[str] = "Invalid attributes"
        MISSING_OBJECTCLASS: ClassVar[str] = "Missing objectClass attribute"

        # Entry validation messages
        ENTRIES_CANNOT_BE_NONE: ClassVar[str] = "Entries cannot be None"
        ENTRY_COUNT_EXCEEDED: ClassVar[str] = (
            "Entry count exceeded maximum: {count} > {max_count}"
        )

        # File validation messages
        FILE_NOT_FOUND: ClassVar[str] = "File not found: {file_path}"
        FILE_ENTRY_COUNT_EXCEEDED: ClassVar[str] = (
            "File entry count exceeded maximum: {count} > {max_count}"
        )

        # Record validation messages
        RECORD_MISSING_DN: ClassVar[str] = "Record missing DN"
        MODERNIZED_WRITING_FAILED: ClassVar[str] = "Modernized writing failed"

    # Additional constants referenced in code
    MIN_DN_COMPONENTS: ClassVar[int] = 1

    # LDAP object class constants
    LDAP_PERSON_CLASSES: ClassVar[set[str]] = {
        "person",
        "inetorgperson",
        "organizationalperson",
        "user",
    }

    LDAP_GROUP_CLASSES: ClassVar[set[str]] = {
        "group",
        "groupofnames",
        "groupofuniquenames",
    }

    class FlextLDIFOperationMessages:
        """Operation-related messages."""

        SORT_FAILED: ClassVar[str] = "Sort operation failed: {error}"
        OPERATION_COMPLETED: ClassVar[str] = "Operation completed successfully"


# Export only the main constants class
__all__ = ["FlextLDIFConstants"]
