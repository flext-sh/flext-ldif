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
        CONTENT_LINES_COUNT_LOG: ClassVar[str] = "Content has {count} lines"
        CALLING_MODERNIZED_LDIF_PARSE_LOG: ClassVar[str] = "Calling modernized LDIF parser"
        MODERNIZED_PARSER_RETURNED_ENTRIES_LOG: ClassVar[str] = "Modernized parser returned {count} entries"
        RAW_ENTRIES_DNS_LOG: ClassVar[str] = "Raw entries DNs: {dns}"
        CONVERTING_ENTRIES_LOG: ClassVar[str] = "Converting {count} entries"
        PROCESSING_ENTRY_LOG: ClassVar[str] = "Processing entry {index}: {dn}"
        FAILED_TO_CREATE_ENTRY_MSG: ClassVar[str] = "Failed to create entry from data: {error}"
        SUCCESSFULLY_CONVERTED_ENTRIES_LOG: ClassVar[str] = "Successfully converted {count} entries"
        MODERNIZED_PARSING_COMPLETED_LOG: ClassVar[str] = "Modernized parsing completed successfully"
        EXCEPTION_IN_MODERNIZED_PARSING_LOG: ClassVar[str] = "Exception in modernized parsing: {error}"
        MODERNIZED_LDIF_PARSE_FAILED_WITH_ERROR_MSG: ClassVar[str] = "Modernized LDIF parse failed: {error}"
        VALIDATION_EXCEPTION_DETAILS_LOG: ClassVar[str] = "Validation exception: {error}"
        EXCEPTION_DURING_ENTRY_VALIDATION_LOG: ClassVar[str] = "Exception during entry validation: {error}"
        VALIDATION_FAILED_MSG: ClassVar[str] = "Entry validation failed"
        CONTENT_CONVERTED_LOG: ClassVar[str] = "Content converted"
        CONTENT_PREVIEW_LOG: ClassVar[str] = "Content preview: {preview}"
        CONTENT_PREVIEW_LENGTH: ClassVar[int] = 100
        DELEGATING_TO_MODERNIZED_LOG: ClassVar[str] = "Delegating to modernized LDIF"
        EXCEPTION_TYPE_LOG: ClassVar[str] = "Exception type: {exception_type}"
        FULL_EXCEPTION_DETAILS_LOG: ClassVar[str] = "Full exception details: {details}"
        EXCEPTION_IN_TLDIF_PARSE_LOG: ClassVar[str] = "Exception in LDIF parse: {exception}"
        PARSE_FAILED_MSG: ClassVar[str] = "Parse failed"
        STARTING_MODERNIZED_PARSING_LOG: ClassVar[str] = "Starting modernized parsing"
        MODERNIZED_PARSING_SUCCESS_LOG: ClassVar[str] = "Modernized parsing successful"
        MODERNIZED_PARSING_FAILED_LOG: ClassVar[str] = "Modernized parsing failed"

        # Missing constants referenced in core.py
        CANNOT_VALIDATE_NONE_ENTRY_LOG: ClassVar[str] = "Cannot validate None entry"
        ENTRY_CANNOT_BE_NONE_MSG: ClassVar[str] = "Entry cannot be None"
        VALIDATING_LDIF_ENTRY_LOG: ClassVar[str] = "Validating LDIF entry: {}"
        ENTRY_ATTRIBUTES_COUNT_LOG: ClassVar[str] = "Entry has {} attributes"
        VALIDATING_DN_FORMAT_LOG: ClassVar[str] = "Validating DN format"
        INVALID_DN_FORMAT_BY_PATTERN_LOG: ClassVar[str] = "DN failed pattern validation"
        INVALID_DN_FORMAT_MSG: ClassVar[str] = "Invalid DN format"
        DN_FAILED_FLEXT_LDAP_VALIDATION_LOG: ClassVar[str] = "DN failed FLEXT-LDAP validation"
        DN_FORMAT_VALIDATION_PASSED_LOG: ClassVar[str] = "DN format validation passed"
        VALIDATING_ATTRIBUTE_NAMES_LOG: ClassVar[str] = "Validating attribute names"
        VALIDATING_ATTRIBUTE_NAME_LOG: ClassVar[str] = "Validating attribute name: {}"
        INVALID_ATTRIBUTE_NAME_LOG: ClassVar[str] = "Invalid attribute name: {}"
        ATTRIBUTE_NAME_FAILED_VALIDATION_LOG: ClassVar[str] = "Attribute name failed validation"
        INVALID_ATTRIBUTE_NAME_MSG: ClassVar[str] = "Invalid attribute name"
        ALL_ATTRIBUTE_NAMES_VALIDATED_LOG: ClassVar[str] = "All attribute names validated"
        CHECKING_REQUIRED_OBJECTCLASS_LOG: ClassVar[str] = "Checking required objectClass"
        OBJECTCLASS_ATTRIBUTE: ClassVar[str] = "objectclass"
        FOUND_OBJECTCLASS_VALUES_LOG: ClassVar[str] = "Found objectClass values: {}"
        OBJECTCLASS_REQUIRED_NOT_FOUND_LOG: ClassVar[str] = "Required objectClass not found"
        ENTRY_MISSING_OBJECTCLASS_WARNING_LOG: ClassVar[str] = "Entry missing objectClass"
        ENTRY_MISSING_REQUIRED_OBJECTCLASS_MSG: ClassVar[str] = "Entry missing required objectClass"
        ENTRY_VALIDATION_PASSED_LOG: ClassVar[str] = "Entry validation passed"
        LDIF_ENTRY_VALIDATION_SUCCESSFUL_LOG: ClassVar[str] = "LDIF entry validation successful"
        STARTING_BULK_VALIDATION_LOG: ClassVar[str] = "Starting bulk validation"
        VALIDATING_ENTRY_INDEX_LOG: ClassVar[str] = "Validating entry {}: {}"
        BULK_VALIDATION_ENTRY_FAILED_MSG: ClassVar[str] = "Bulk validation failed for entry {}: {}"
        EXCEPTION_DURING_BULK_VALIDATION_LOG: ClassVar[str] = "Exception during bulk validation: {}"
        BULK_VALIDATION_EXCEPTION_MSG: ClassVar[str] = "Bulk validation exception: {}"
        BULK_VALIDATION_SUCCESSFUL_LOG: ClassVar[str] = "Bulk validation successful"
        BULK_LDIF_VALIDATION_COMPLETED_LOG: ClassVar[str] = "Bulk LDIF validation completed"
        STARTING_LDIF_WRITE_OPERATION_LOG: ClassVar[str] = "Starting LDIF write operation"
        WRITE_OPERATION_USING_MODERNIZED_LOG: ClassVar[str] = "Write operation using modernized LDIF"
        CONVERTING_ENTRIES_TO_LDIF_LOG: ClassVar[str] = "Converting {} entries to LDIF"
        GENERATED_LDIF_CONTENT_LOG: ClassVar[str] = "Generated LDIF content ({} characters)"
        LDIF_WRITE_SUCCESSFUL_LOG: ClassVar[str] = "LDIF write successful"
        LDIF_WRITE_OPERATION_COMPLETED_LOG: ClassVar[str] = "LDIF write operation completed"
        MODERNIZED_LDIF_WRITE_FAILED_NO_ERROR_MSG: ClassVar[str] = "Modernized LDIF write failed (no error details)"
        MODERNIZED_LDIF_WRITE_FAILED_WITH_ERROR_MSG: ClassVar[str] = "Modernized LDIF write failed: {}"
        LDIF_WRITE_OPERATION_FAILED_LOG: ClassVar[str] = "LDIF write operation failed"
        EXCEPTION_DURING_LDIF_WRITE_LOG: ClassVar[str] = "Exception during LDIF write: {}"
        WRITE_FAILED_WITH_EXCEPTION_MSG: ClassVar[str] = "Write failed with exception: {}"
        STARTING_FILE_WRITE_OPERATION_LOG: ClassVar[str] = "Starting file write operation"
        RESOLVED_FILE_PATH_LOG: ClassVar[str] = "Resolved file path: {}"
        CREATING_PARENT_DIRECTORY_LOG: ClassVar[str] = "Creating parent directory: {}"
        PARENT_DIRECTORY_CREATED_LOG: ClassVar[str] = "Parent directory created"
        FILE_ENCODING_LOG: ClassVar[str] = "File encoding: {}"
        WRITING_CONTENT_TO_FILE_LOG: ClassVar[str] = "Writing content to file"
        FILE_WRITE_MODE: ClassVar[str] = "w"
        CONTENT_GENERATION_FAILED_FOR_ENTRIES_MSG: ClassVar[str] = "Content generation failed for entries"
        FILE_WRITE_COMPLETED_LOG: ClassVar[str] = "File write completed"
        LDIF_FILE_WRITE_OPERATION_COMPLETED_LOG: ClassVar[str] = "LDIF file write operation completed"
        FILE_WRITE_EXCEPTION_DETAILS_LOG: ClassVar[str] = "File write exception details: {}"
        EXCEPTION_DURING_FILE_WRITE_LOG: ClassVar[str] = "Exception during file write: {}"
        FILE_WRITE_FAILED_MSG: ClassVar[str] = "File write failed"
        STARTING_LDIF_FILE_READ_OPERATION_LOG: ClassVar[str] = "Starting LDIF file read operation"
        FILE_ENCODING_READ_LOG: ClassVar[str] = "File encoding for read: {}"
        RESOLVED_ABSOLUTE_FILE_PATH_READ_LOG: ClassVar[str] = "Resolved absolute file path: {}"
        LDIF_FILE_NOT_FOUND_ERROR_MSG: ClassVar[str] = "LDIF file not found: {}"
        PATH_NOT_FILE_ERROR_MSG: ClassVar[str] = "Path is not a file: {}"
        FILE_EXISTS_COLLECTING_METADATA_LOG: ClassVar[str] = "File exists, collecting metadata"
        FILE_METADATA_SIZE_MODE_LOG: ClassVar[str] = "File metadata - Size: {}, Mode: {}"
        EMPTY_LDIF_FILE_DETECTED_WARNING_LOG: ClassVar[str] = "Empty LDIF file detected"
        CONTENT_PREVIEW_FILE_LOG: ClassVar[str] = "Content preview from file: {}"
        CONTENT_PREVIEW_SIZE: ClassVar[int] = 100
        CONTENT_PREVIEW_REPLACEMENT: ClassVar[str] = "\\n"
        FILE_PATH_EXISTS_LOG: ClassVar[str] = "File path exists: {}"
        EMPTY_WRITE_RESULT_MSG: ClassVar[str] = "Write result is empty"

        # File handling constants
        READING_FILE_CONTENT_ENCODING_LOG: ClassVar[str] = "Reading file with encoding: {encoding}"
        FILE_READ_MODE: ClassVar[str] = "r"
        ENCODING_ERROR_READING_FILE_MSG: ClassVar[str] = "Encoding error reading file: {error}"
        FILE_CONTENT_READ_SUCCESS_LOG: ClassVar[str] = "File content read successfully"
        CONTENT_PREVIEW_REPLACE_LOG: ClassVar[str] = "Content preview (newlines replaced): {preview}"
        FILE_READ_CONTENT_PREVIEW_SIZE: ClassVar[int] = 100
        NEWLINE_TO_ESCAPED_NEWLINE: ClassVar[str] = "\\n"
        DELEGATING_TO_PARSE_METHOD_FOR_CONTENT_LOG: ClassVar[str] = "Delegating to parse method for content"
        EXCEPTION_TYPE_READ_LOG: ClassVar[str] = "Exception type during read: {exception_type}"
        FILE_READ_EXCEPTION_DETAILS_READ_LOG: ClassVar[str] = "File read exception details: {details}"
        EXCEPTION_DURING_FILE_READ_OPERATION_LOG: ClassVar[str] = "Exception during file read operation"
        LDIF_FILE_READ_FAILED_ERROR_MSG: ClassVar[str] = "LDIF file read failed: {error}"
        FILE_READ_AND_PARSE_SUCCESS_LOG: ClassVar[str] = "File read and parse successful"
        LDIF_FILE_PROCESSING_COMPLETED_SUCCESS_LOG: ClassVar[str] = "LDIF file processing completed successfully"
        LDIF_PARSING_FAILED_FOR_FILE_ERROR_MSG: ClassVar[str] = "LDIF parsing failed for file: {error}"
        PARSE_METHOD_FAILED_AFTER_SUCCESSFUL_READ_LOG: ClassVar[str] = "Parse method failed after successful read"

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
        MODERNIZED_PARSING_FAILED: ClassVar[str] = "Modernized parsing failed"

    # Additional constants referenced in code
    MIN_DN_COMPONENTS: ClassVar[int] = 1

    # Boolean result constants to avoid FBT003 errors
    VALIDATION_SUCCESS: ClassVar[bool] = True
    VALIDATION_FAILURE: ClassVar[bool] = False

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
        LDIF_PARSED_SUCCESS: ClassVar[str] = "LDIF parsed successfully"
        LDIF_WRITTEN_SUCCESS: ClassVar[str] = "LDIF written successfully"
        WRITE_SUCCESS: ClassVar[str] = "Write operation successful"
        WRITE_FAILED: ClassVar[str] = "Write operation failed"


# Export only the main constants class
__all__ = ["FlextLDIFConstants"]
