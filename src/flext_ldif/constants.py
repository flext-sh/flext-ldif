"""FLEXT-LDIF constants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

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
# FLEXT-LDIF VALIDATION MESSAGES
# =============================================================================


class FlextLdifValidationMessages:
    """Validation messages centralized for flext-ldif operations."""

    # DN Validation Messages
    DN_EMPTY_ERROR: Final[str] = "DN must be a non-empty string"
    DN_CANNOT_BE_EMPTY: Final[str] = "DN cannot be empty"
    DN_INVALID_COMPONENT: Final[str] = "Invalid DN component"
    DN_MISSING_EQUALS: Final[str] = "DN must contain at least one attribute=value pair"
    DN_FORMAT_INVALID: Final[str] = "DN format is invalid"
    DN_INVALID_FORMAT: Final[str] = "Invalid DN format: {dn}"

    # Entry Validation Messages
    ENTRY_VALIDATION_FAILED: Final[str] = "Entry validation failed"
    ENTRY_MISSING_DN: Final[str] = "Entry must have a DN"
    ENTRY_MISSING_ATTRIBUTES: Final[str] = "LDIF entry must have at least one attribute"
    ENTRY_MISSING_OBJECTCLASS: Final[str] = "Entry must have objectClass attribute"
    ENTRY_MISSING_REQUIRED_OBJECTCLASS: Final[str] = (
        "Entry missing required objectClass attribute"
    )
    ENTRY_INVALID_TYPE: Final[str] = "Entry must be FlextLdifEntry instance"
    ENTRY_CANNOT_BE_NONE: Final[str] = "Entry cannot be None"
    ENTRY_MUST_HAVE_VALID_DN: Final[str] = "LDIF entry must have a valid DN"
    EMPTY_ATTRIBUTES_NOT_ALLOWED: Final[str] = (
        "Empty attribute values not allowed for '{attr_name}' in strict mode"
    )
    EMPTY_ATTRIBUTE_VALUE_NOT_ALLOWED: Final[str] = (
        "Empty attribute value not allowed for '{attr_name}' in strict mode"
    )

    # Attribute Validation Messages
    ATTRIBUTE_NAME_EMPTY: Final[str] = "Attribute name cannot be empty"
    ATTRIBUTE_NAME_CANNOT_BE_EMPTY: Final[str] = "Attribute name cannot be empty"
    ATTRIBUTE_NAME_WHITESPACE: Final[str] = (
        "Attribute name cannot be empty or whitespace-only"
    )
    INVALID_ATTRIBUTE_NAME_FORMAT: Final[str] = (
        "Invalid LDAP attribute name format: {attr_name}"
    )
    INVALID_ATTRIBUTE_NAME: Final[str] = "Invalid attribute name format: {attr_name}"

    # Configuration Validation Messages
    INVALID_CONFIGURATION: Final[str] = "Invalid configuration"
    INVALID_ENCODING: Final[str] = "Invalid input or output encoding specified"

    # File Processing Messages
    FILE_NOT_FOUND: Final[str] = "File not found: {file_path}"
    FILE_READ_ERROR: Final[str] = "Failed to read file: {file_path}"
    FILE_WRITE_ERROR: Final[str] = "Failed to write file: {file_path}"

    # Entry Count Messages
    ENTRY_COUNT_EXCEEDED: Final[str] = (
        "Entry count {count} exceeds configured limit {limit}"
    )
    FILE_ENTRY_COUNT_EXCEEDED: Final[str] = (
        "File entry count {count} exceeds configured limit {limit}"
    )

    # LDIF Format Messages
    RECORD_MISSING_DN: Final[str] = "Record missing dn: line"
    INVALID_LDIF_FORMAT: Final[str] = "Invalid LDIF format"

    # Modernized LDIF Messages
    MODERNIZED_PARSING_FAILED: Final[str] = "Modernized LDIF parsing failed"
    MODERNIZED_WRITING_FAILED: Final[str] = "Modernized LDIF writing failed"

    # Entries Processing Messages
    ENTRIES_CANNOT_BE_NONE: Final[str] = "Entries cannot be None"
    INTERNAL_ERROR_ENTRIES_NONE: Final[str] = (
        "Internal error: entries is None after successful parse"
    )


# =============================================================================
# FLEXT-LDIF DEFAULT VALUES
# =============================================================================


class FlextLdifDefaultValues:
    """Default values centralized for flext-ldif configurations."""

    # CLI Default Values
    OUTPUT_FORMAT_DEFAULT: Final[str] = "text"
    OUTPUT_FORMAT_PLAIN: Final[str] = "plain"
    STATS_FORMAT_DEFAULT: Final[str] = "table"

    # Test Values
    TEST_LDIF_ENTRY: Final[str] = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
"""

    # Help Messages
    CONFIG_HELP: Final[str] = "Configuration file path"
    OUTPUT_FORMAT_HELP: Final[str] = "Output format"
    VERBOSE_HELP: Final[str] = "Enable verbose output"
    QUIET_HELP: Final[str] = "Reduce output verbosity"
    DEBUG_HELP: Final[str] = "Enable debug output"
    CONFIG_FILE_HELP: Final[str] = "Optional path to config file"
    OUTPUT_FILE_HELP: Final[str] = "Output file path"
    MAX_ENTRIES_HELP: Final[str] = "Maximum entries to parse"
    VALIDATE_HELP: Final[str] = "Validate entries after parsing"
    STATS_HELP: Final[str] = "Display statistics instead of writing output"
    STRICT_HELP: Final[str] = "Enable strict validation mode"
    SCHEMA_HELP: Final[str] = "Schema validation rules"
    FILTER_TYPE_HELP: Final[str] = "Filter entry type"
    SORT_HELP: Final[str] = "Sort entries hierarchically"
    STATISTICS_FORMAT_HELP: Final[str] = "Statistics format"
    DN_HELP: Final[str] = "DN filter pattern (supports substring)"
    ATTRIBUTE_HELP: Final[str] = "Attribute name to display"
    OUTPUT_FILTER_HELP: Final[str] = "Output file for filtered entries"
    LINE_WRAP_HELP: Final[str] = "Optional line wrap width (ignored)"

    # CLI Command Descriptions
    CLI_DESCRIPTION: Final[str] = """FLEXT LDIF - Enterprise LDIF Processing CLI.

Comprehensive command-line interface para parsing, validação
e transformação LDIF com Clean Architecture."""

    PARSE_DESCRIPTION: Final[str] = "Parse LDIF file and display or save entries"
    VALIDATE_DESCRIPTION: Final[str] = "Validate LDIF file entries against schema rules"
    TRANSFORM_DESCRIPTION: Final[str] = (
        "Transform LDIF file with filtering and sorting options"
    )
    STATS_DESCRIPTION: Final[str] = "Display comprehensive statistics for LDIF file"
    FIND_DESCRIPTION: Final[str] = "Find specific entry by Distinguished Name"
    FILTER_BY_CLASS_DESCRIPTION: Final[str] = "Filter entries by objectClass attribute"
    CONVERT_DESCRIPTION: Final[str] = "Convert between different file formats"
    CONFIG_CHECK_DESCRIPTION: Final[str] = (
        "Validate CLI configuration and display settings"
    )
    WRITE_DESCRIPTION: Final[str] = "Reformat LDIF file and print or save the output"


# =============================================================================
# FLEXT-LDIF ANALYTICS CONSTANTS
# =============================================================================


class FlextLdifAnalyticsConstants:
    """Analytics constants centralized for flext-ldif processing."""

    # Pattern Analysis Keys
    TOTAL_ENTRIES_KEY: Final[str] = "total_entries"
    ENTRIES_WITH_CN_KEY: Final[str] = "entries_with_cn"
    ENTRIES_WITH_MAIL_KEY: Final[str] = "entries_with_mail"
    ENTRIES_WITH_TELEPHONE_KEY: Final[str] = "entries_with_telephoneNumber"

    # Attribute Names for Analysis
    CN_ATTRIBUTE: Final[str] = "cn"
    MAIL_ATTRIBUTE: Final[str] = "mail"
    TELEPHONE_ATTRIBUTE: Final[str] = "telephoneNumber"

    # DN Depth Analysis
    DEPTH_KEY_FORMAT: Final[str] = "depth_{depth}"


# =============================================================================
# FLEXT-LDIF CORE PROCESSING MESSAGES
# =============================================================================


class FlextLdifCoreMessages:
    """Core processing messages centralized for flext-ldif operations."""

    # Parsing Messages
    PARSE_FAILED: Final[str] = "Parse failed: {error}"
    MODERNIZED_PARSE_FAILED: Final[str] = "Modernized LDIF parse failed: {error}"
    VALIDATION_FAILED: Final[str] = "Validation failed: {error}"
    WRITE_FAILED: Final[str] = "Write failed with exception: {error}"

    # Entry Validation Messages
    ENTRY_CANNOT_BE_NONE: Final[str] = "Entry cannot be None"
    INVALID_DN_FORMAT: Final[str] = "Invalid DN format: {dn}"
    INVALID_ATTRIBUTE_NAME: Final[str] = "Invalid attribute name: {attr_name}"
    MISSING_OBJECTCLASS: Final[str] = "Entry missing required objectClass attribute"
    ENTRY_VALIDATION_FAILED: Final[str] = (
        "Entry {index} of {total} failed validation ({dn}): {error}"
    )
    BULK_VALIDATION_FAILED: Final[str] = (
        "Bulk validation failed with exception: {error}"
    )

    # File Operation Messages
    FILE_NOT_FOUND: Final[str] = "LDIF file not found: {file_path}"
    PATH_NOT_FILE: Final[str] = "Path is not a file: {file_path}"
    EMPTY_FILE_WARNING: Final[str] = "Empty LDIF file detected: {file_path}"
    ENCODING_ERROR: Final[str] = "Encoding error reading file with {encoding}: {error}"
    FILE_READ_FAILED: Final[str] = "LDIF file read failed: {error}"
    FILE_WRITE_FAILED: Final[str] = "File write failed: {error}"
    CONTENT_GENERATION_FAILED: Final[str] = (
        "Content generation failed for {count} entries: {error}"
    )
    CONTENT_GENERATION_NULL: Final[str] = (
        "Content generation succeeded but returned None data"
    )

    # Parse Specific Messages
    PARSE_FAILED_FOR_FILE: Final[str] = (
        "LDIF parsing failed for file {file_path}: {error}"
    )


# =============================================================================
# FLEXT-LDIF OPERATION MESSAGES
# =============================================================================


class FlextLdifOperationMessages:
    """Operation messages centralized for flext-ldif processing."""

    # Success Messages
    PARSE_SUCCESS: Final[str] = "✅ Parsed {count} entries successfully"
    WRITE_SUCCESS: Final[str] = "Entries written to {path}"
    VALIDATION_SUCCESS: Final[str] = "✓ All {count} entries are valid ({mode} mode)"
    API_VALIDATION_SUCCESS: Final[str] = "✓ API functionality validated"
    ENTRIES_WRITTEN_SUCCESS: Final[str] = "Entries successfully written to file"
    PARSE_COMPLETED_SUCCESS: Final[str] = (
        "Parse completed successfully with {count} entries"
    )
    LDIF_PARSED_SUCCESS: Final[str] = "Successfully parsed {count} LDIF entries"
    LDIF_WRITTEN_SUCCESS: Final[str] = "Successfully wrote {count} LDIF entries"

    # Error Messages
    PARSE_FAILED: Final[str] = "❌ Parse failed: {error}"
    WRITE_FAILED: Final[str] = "Write failed: {error}"
    VALIDATION_FAILED: Final[str] = "Validation failed with {count} errors:"
    FILTER_FAILED: Final[str] = "Failed to filter {filter_type}: {error}"
    SORT_FAILED: Final[str] = "Failed to sort hierarchically: {error}"
    STATISTICS_FAILED: Final[str] = "Failed to get statistics: {error}"
    CONVERT_FAILED: Final[str] = "Failed to convert entries to LDIF: {error}"
    DISPLAY_FAILED: Final[str] = "Statistics display failed: {error}"
    CLI_SETUP_FAILED: Final[str] = "Failed to setup CLI: {error}"

    # Processing Messages
    LOADED_ENTRIES: Final[str] = "Loaded {count} entries"
    FILTERED_ENTRIES: Final[str] = "Filtered to {count} {filter_type} entries"
    ENTRIES_SORTED: Final[str] = "Entries sorted hierarchically"
    FOUND_ENTRIES: Final[str] = "Found {count} entries with objectClass '{objectclass}'"
    CONVERTED_ENTRIES: Final[str] = "Converted {count} entries to {format}: {path}"

    # Status Messages
    VALIDATION_MODE: Final[str] = "Validation mode: {mode}"
    VALIDATION_ERRORS_FOUND: Final[str] = "Validation found {count} errors:"
    NO_VALIDATION_ERRORS: Final[str] = "No validation errors found"
    STATISTICS_FOR_FILE: Final[str] = "Statistics for {file}:"
    FOUND_ENTRY: Final[str] = "Found entry:"
    ENTRY_NOT_FOUND: Final[str] = "Entry with DN matching '{query}' not found"
    USING_SCHEMA: Final[str] = "Using schema validation rules: {schema}"
    SCHEMA_NOTE: Final[str] = (
        "Note: Schema-based validation will be implemented with flext-ldap integration"
    )

    # CLI Configuration Messages
    CLI_CONFIGURATION: Final[str] = "CLI Configuration:"
    OUTPUT_FORMAT_CONFIG: Final[str] = "  Output Format: {format}"
    VERBOSE_CONFIG: Final[str] = "  Verbose: {verbose}"
    DEBUG_CONFIG: Final[str] = "  Debug: {debug}"
    CONFIG_PATH_CONFIG: Final[str] = "  Config Path: {path}"

    # Operation Cancelled Messages
    OPERATION_CANCELLED: Final[str] = "Operation cancelled by user"

    # Filter Messages
    UNKNOWN_FILTER_TYPE: Final[str] = "Unknown filter type: {filter_type}"
    FILTER_OPERATION_FAILED: Final[str] = "Filter operation failed: {error}"

    # Convert Messages
    CONVERTED_TO_LDIF: Final[str] = "Converted to LDIF: {path}"
    CONVERTED_TO_FORMAT: Final[str] = "Converted {count} entries to {format}: {path}"


# =============================================================================
# FLEXT-LDIF FORMAT VALIDATORS CONSTANTS
# =============================================================================


class FlextLdifFormatConstants:
    """Format validation constants for flext-ldif operations."""

    # Module Import Names
    FLEXT_LDAP_UTILS_MODULE: Final[str] = "flext_ldap.utils"

    # Attribute Names
    OBJECTCLASS_ATTRIBUTE: Final[str] = "objectClass"
    CN_ATTRIBUTE: Final[str] = "cn"
    SN_ATTRIBUTE: Final[str] = "sn"
    OU_ATTRIBUTE: Final[str] = "ou"

    # Validation Error Messages - Format Validators
    DN_CANNOT_BE_EMPTY_FORMAT: Final[str] = "DN cannot be empty"
    INVALID_DN_FORMAT_MSG: Final[str] = "Invalid DN format: {dn_value}"
    ATTRIBUTE_NAME_CANNOT_BE_EMPTY_FORMAT: Final[str] = "Attribute name cannot be empty"
    INVALID_ATTRIBUTE_NAME_FORMAT_MSG: Final[str] = (
        "Invalid attribute name format: {attr_name}"
    )
    ENTRY_MISSING_OBJECTCLASS_FORMAT: Final[str] = (
        "Entry missing required objectClass attribute"
    )
    ENTRY_MUST_HAVE_VALID_DN_FORMAT: Final[str] = "LDIF entry must have a valid DN"
    ENTRY_MISSING_OBJECTCLASS_TYPE_VALIDATION: Final[str] = (
        "Entry missing objectClass for type validation"
    )
    ENTRY_TYPE_MISMATCH_FORMAT: Final[str] = (
        "Entry does not match expected type. Expected: {expected_classes}, Found: {object_classes}"
    )
    ENTRY_MISSING_REQUIRED_ATTRIBUTES_FORMAT: Final[str] = (
        "Entry missing required attributes: {missing_attrs}"
    )
    EMPTY_ATTRIBUTE_VALUE_NOT_ALLOWED_FORMAT: Final[str] = (
        "Empty attribute value not allowed for {attr_name}"
    )
    ENTRY_MUST_BE_FLEXTLDIFENTRY_FORMAT: Final[str] = (
        "Entry must be FlextLdifEntry instance"
    )

    # Object Class Sets (for validation)
    PERSON_OBJECTCLASSES: Final[set[str]] = {
        "person",
        "organizationalPerson",
        "inetOrgPerson",
        "user",
        "posixAccount",
    }

    OU_OBJECTCLASSES: Final[set[str]] = {
        "organizationalUnit",
        "top",
    }

    GROUP_OBJECTCLASSES: Final[set[str]] = {
        "group",
        "groupOfNames",
        "groupOfUniqueNames",
        "posixGroup",
        "groupOfMembers",
    }

    # Required Attributes for Schema Validation
    PERSON_REQUIRED_ATTRIBUTES: Final[list[str]] = ["cn", "sn"]
    OU_REQUIRED_ATTRIBUTES: Final[list[str]] = ["ou"]


# =============================================================================
# FLEXT-LDIF CORE PROCESSING CONSTANTS
# =============================================================================


class FlextLdifCoreConstants:
    """Core processing constants for flext-ldif operations."""

    # Regular Expression Patterns
    DN_PATTERN_REGEX: Final[str] = (
        r"^[A-Za-z][A-Za-z0-9-]*=[^,]+(,[A-Za-z][A-Za-z0-9-]*=[^,]+)*$"
    )
    ATTR_NAME_PATTERN_REGEX: Final[str] = r"^[A-Za-z][A-Za-z0-9-]*$"

    # Debug Log Messages
    TLDIF_PARSE_CALLED_LOG: Final[str] = "TLdif.parse called with content type: %s"
    CONTENT_LENGTH_LOG: Final[str] = "Content length: %d characters"
    CONTENT_CONVERTED_LOG: Final[str] = "Content converted to string, length: %d"
    CONTENT_PREVIEW_LOG: Final[str] = "Content preview: %s..."
    DELEGATING_TO_MODERNIZED_LOG: Final[str] = "Delegating to modernized LDIF parser"
    EXCEPTION_TYPE_LOG: Final[str] = "Exception type: %s"
    FULL_EXCEPTION_DETAILS_LOG: Final[str] = "Full exception details"
    EXCEPTION_IN_TLDIF_PARSE_LOG: Final[str] = "Exception in TLdif.parse"
    STARTING_MODERNIZED_PARSING_LOG: Final[str] = "Starting modernized LDIF parsing"
    CONTENT_LINES_COUNT_LOG: Final[str] = "Content lines count: %d"
    CALLING_MODERNIZED_LDIF_PARSE_LOG: Final[str] = "Calling modernized_ldif_parse"
    MODERNIZED_LDIF_PARSE_FAILED_WARNING: Final[str] = (
        "Modernized LDIF parse failed: %s"
    )
    RETURNING_FAILURE_FROM_MODERNIZED_LOG: Final[str] = (
        "Returning failure from modernized parser"
    )

    # Parser Processing Log Messages
    MODERNIZED_PARSER_RETURNED_ENTRIES_LOG: Final[str] = (
        "Modernized parser returned %d raw entries"
    )
    RAW_ENTRIES_DNS_LOG: Final[str] = "Raw entries DNs: %s"
    CONVERTING_ENTRIES_LOG: Final[str] = (
        "Converting raw entries to FlextLdifEntry objects"
    )
    PROCESSING_ENTRY_LOG: Final[str] = "Processing entry %d: DN=%s, attrs_count=%d"
    SUCCESSFULLY_CONVERTED_ENTRIES_LOG: Final[str] = (
        "Successfully converted %d entries to FlextLdifEntry objects"
    )
    MODERNIZED_PARSING_COMPLETED_LOG: Final[str] = (
        "Modernized LDIF parsing completed successfully - raw_entries=%d, converted_entries=%d"
    )
    EXCEPTION_IN_MODERNIZED_PARSING_LOG: Final[str] = (
        "Exception in modernized LDIF parsing"
    )

    # Validation Log Messages
    VALIDATION_EXCEPTION_DETAILS_LOG: Final[str] = "Validation exception details"
    EXCEPTION_DURING_ENTRY_VALIDATION_LOG: Final[str] = (
        "Exception during entry validation"
    )
    CANNOT_VALIDATE_NONE_ENTRY_LOG: Final[str] = "Cannot validate None entry"
    VALIDATING_LDIF_ENTRY_LOG: Final[str] = "Validating LDIF entry: %s"
    ENTRY_ATTRIBUTES_COUNT_LOG: Final[str] = "Entry attributes count: %d"
    VALIDATING_DN_FORMAT_LOG: Final[str] = "Validating DN format: %s"
    INVALID_DN_FORMAT_BY_PATTERN_LOG: Final[str] = (
        "Invalid DN format by TLdif pattern: %s"
    )
    DN_FAILED_FLEXT_LDAP_VALIDATION_LOG: Final[str] = "DN failed flext-ldap validation"
    DN_FORMAT_VALIDATION_PASSED_LOG: Final[str] = "DN format validation passed"
    VALIDATING_ATTRIBUTE_NAMES_LOG: Final[str] = "Validating %d attribute names"
    VALIDATING_ATTRIBUTE_NAME_LOG: Final[str] = "Validating attribute name: %s"
    INVALID_ATTRIBUTE_NAME_LOG: Final[str] = "Invalid attribute name: %s"
    ATTRIBUTE_NAME_FAILED_VALIDATION_LOG: Final[str] = (
        "Attribute name failed flext-ldap validation"
    )
    ALL_ATTRIBUTE_NAMES_VALIDATED_LOG: Final[str] = (
        "All attribute names validated successfully"
    )
    CHECKING_REQUIRED_OBJECTCLASS_LOG: Final[str] = (
        "Checking for required objectClass attribute"
    )
    ENTRY_MISSING_OBJECTCLASS_WARNING_LOG: Final[str] = (
        "Entry missing required objectClass attribute: %s"
    )
    OBJECTCLASS_REQUIRED_NOT_FOUND_LOG: Final[str] = (
        "objectClass attribute is required but not found"
    )
    FOUND_OBJECTCLASS_VALUES_LOG: Final[str] = "Found objectClass values: %s"
    ENTRY_VALIDATION_PASSED_LOG: Final[str] = "Entry validation passed for: %s"
    LDIF_ENTRY_VALIDATION_SUCCESSFUL_LOG: Final[str] = (
        "LDIF entry validation successful - dn=%s, attributes_count=%d, object_classes=%s"
    )

    # Bulk Validation Log Messages
    STARTING_BULK_VALIDATION_LOG: Final[str] = "Starting bulk validation of %d entries"
    VALIDATING_ENTRY_INDEX_LOG: Final[str] = "Validating entry %d/%d: %s"
    BULK_VALIDATION_FAILED_AT_ENTRY_LOG: Final[str] = (
        "Bulk validation failed at entry %d: %s"
    )
    BULK_VALIDATION_SUCCESSFUL_LOG: Final[str] = (
        "Bulk validation successful for all %d entries"
    )
    BULK_LDIF_VALIDATION_COMPLETED_LOG: Final[str] = (
        "Bulk LDIF validation completed successfully - entries_validated=%d"
    )
    EXCEPTION_DURING_BULK_VALIDATION_LOG: Final[str] = (
        "Exception during bulk validation"
    )

    # Write Operation Log Messages
    STARTING_LDIF_WRITE_OPERATION_LOG: Final[str] = (
        "Starting LDIF write operation for %d entries"
    )
    WRITE_OPERATION_USING_MODERNIZED_LOG: Final[str] = (
        "Write operation using modernized LDIF writer"
    )
    LDIF_WRITE_SUCCESSFUL_LOG: Final[str] = (
        "LDIF write successful: %d characters generated"
    )
    LDIF_WRITE_OPERATION_COMPLETED_LOG: Final[str] = (
        "LDIF write operation completed successfully - entries_count=%d, content_length=%d"
    )
    LDIF_WRITE_OPERATION_FAILED_LOG: Final[str] = "LDIF write operation failed: %s"
    EXCEPTION_DURING_LDIF_WRITE_LOG: Final[str] = (
        "Exception during LDIF write operation"
    )

    # File Operation Log Messages
    STARTING_FILE_WRITE_OPERATION_LOG: Final[str] = (
        "Starting file write operation for %d entries to: %s"
    )
    FILE_ENCODING_LOG: Final[str] = "File encoding: %s"
    RESOLVED_FILE_PATH_LOG: Final[str] = "Resolved file path: %s"
    CREATING_PARENT_DIRECTORY_LOG: Final[str] = "Creating parent directory: %s"
    PARENT_DIRECTORY_CREATED_LOG: Final[str] = "Parent directory created successfully"
    FILE_PATH_EXISTS_LOG: Final[str] = "File path exists: %s"
    CONVERTING_ENTRIES_TO_LDIF_LOG: Final[str] = "Converting %d entries to LDIF content"
    GENERATED_LDIF_CONTENT_LOG: Final[str] = "Generated LDIF content: %d characters"
    CONTENT_PREVIEW_FILE_LOG: Final[str] = "Content preview: %s..."
    WRITING_CONTENT_TO_FILE_LOG: Final[str] = (
        "Writing content to file with encoding: %s"
    )
    FILE_WRITE_COMPLETED_LOG: Final[str] = "File write completed successfully: %s"
    LDIF_FILE_WRITE_OPERATION_COMPLETED_LOG: Final[str] = (
        "LDIF file write operation completed successfully - entries_count=%d, file_path=%s, content_size_chars=%d, encoding=%s"
    )
    FILE_WRITE_EXCEPTION_DETAILS_LOG: Final[str] = "File write exception details"
    EXCEPTION_DURING_FILE_WRITE_LOG: Final[str] = "Exception during file write"

    # File Read Operation Log Messages
    STARTING_LDIF_FILE_READ_LOG: Final[str] = "Starting LDIF file read operation: %s"
    RESOLVED_ABSOLUTE_FILE_PATH_LOG: Final[str] = "Resolved absolute file path: %s"
    FILE_EXISTS_COLLECTING_METADATA_LOG: Final[str] = (
        "File exists, collecting file metadata"
    )
    FILE_METADATA_LOG: Final[str] = "File metadata - size: %d bytes, mode: %o"
    EMPTY_LDIF_FILE_DETECTED_LOG: Final[str] = "Empty LDIF file detected: %s"
    READING_FILE_CONTENT_LOG: Final[str] = "Reading file content with encoding: %s"
    FILE_CONTENT_READ_SUCCESSFULLY_LOG: Final[str] = (
        "File content read successfully: %d characters, %d lines"
    )
    CONTENT_PREVIEW_READ_LOG: Final[str] = "Content preview: %s..."
    DELEGATING_TO_PARSE_METHOD_LOG: Final[str] = (
        "Delegating to parse method for content processing"
    )
    FILE_READ_EXCEPTION_DETAILS_LOG: Final[str] = "File read exception details"
    EXCEPTION_DURING_FILE_READ_LOG: Final[str] = "Exception during file read operation"
    FILE_READ_AND_PARSE_SUCCESSFUL_LOG: Final[str] = (
        "File read and parse successful: %d entries from %s"
    )
    LDIF_FILE_PROCESSING_COMPLETED_LOG: Final[str] = (
        "LDIF file processing completed successfully - file_path=%s, file_size_bytes=%d, content_size_chars=%d, lines_count=%d, entries_parsed=%d, encoding=%s"
    )
    PARSE_METHOD_FAILED_LOG: Final[str] = (
        "Parse method failed after successful file read - file accessible but content invalid"
    )

    # String Replacement Characters
    NEWLINE_ESCAPE: Final[str] = "\\n"
    CONTENT_PREVIEW_LENGTH: Final[int] = 200

    # Error Messages for FlextResult[None].fail()
    PARSE_FAILED_MSG: Final[str] = "Parse failed: {error}"
    MODERNIZED_LDIF_PARSE_FAILED_MSG: Final[str] = "Modernized LDIF parse failed"
    FAILED_TO_CREATE_ENTRY_MSG: Final[str] = "Failed to create entry: {error}"
    MODERNIZED_LDIF_PARSE_FAILED_WITH_ERROR_MSG: Final[str] = (
        "Modernized LDIF parse failed: {error}"
    )
    VALIDATION_FAILED_MSG: Final[str] = "Validation failed: {error}"
    ENTRY_CANNOT_BE_NONE_MSG: Final[str] = "Entry cannot be None"
    INVALID_DN_FORMAT_MSG: Final[str] = "Invalid DN format: {dn}"
    INVALID_ATTRIBUTE_NAME_MSG: Final[str] = "Invalid attribute name: {attr_name}"
    ENTRY_MISSING_REQUIRED_OBJECTCLASS_MSG: Final[str] = (
        "Entry missing required objectClass attribute"
    )
    ENTRY_VALIDATION_FAILED_MSG: Final[str] = (
        "Entry {index} of {total} failed validation ({dn}): {error}"
    )
    BULK_VALIDATION_FAILED_MSG: Final[str] = (
        "Bulk validation failed with exception: {error}"
    )
    WRITE_FAILED_WITH_EXCEPTION_MSG: Final[str] = "Write failed with exception: {error}"
    MODERNIZED_LDIF_WRITE_FAILED_MSG: Final[str] = "Modernized LDIF write failed"
    MODERNIZED_LDIF_WRITE_FAILED_WITH_ERROR_MSG: Final[str] = (
        "Modernized LDIF write failed: {error}"
    )
    CONTENT_GENERATION_FAILED_MSG: Final[str] = (
        "Content generation failed for {entries_count} entries: {error}"
    )
    CONTENT_GENERATION_NULL_MSG: Final[str] = (
        "Content generation succeeded but returned None data"
    )
    FILE_WRITE_FAILED_MSG: Final[str] = "File write failed: {error}"
    LDIF_FILE_NOT_FOUND_MSG: Final[str] = "LDIF file not found: {path}"
    PATH_NOT_FILE_MSG: Final[str] = "Path is not a file: {path}"
    ENCODING_ERROR_MSG: Final[str] = (
        "Encoding error reading file with {encoding}: {error}"
    )
    LDIF_FILE_READ_FAILED_MSG: Final[str] = "LDIF file read failed: {error}"
    LDIF_PARSING_FAILED_FOR_FILE_MSG: Final[str] = (
        "LDIF parsing failed for file {path}: {error}"
    )

    # Attribute Names
    OBJECTCLASS_ATTRIBUTE: Final[str] = "objectClass"

    # Default Values
    DEFAULT_UTF8_ENCODING: Final[str] = "utf-8"
    FILE_WRITE_MODE: Final[str] = "w"
    FILE_READ_MODE: Final[str] = "r"

    # Replacement Characters for Content Preview
    NEWLINE_REPLACEMENT: Final[str] = "\\n"

    # Additional Bulk Validation Log Messages (not yet centralized)
    BULK_VALIDATION_ENTRY_FAILED_MSG: Final[str] = (
        "Entry {index} of {total} failed validation ({dn}): {error}"
    )
    BULK_VALIDATION_EXCEPTION_MSG: Final[str] = (
        "Bulk validation failed with exception: {error}"
    )

    # Additional Write Operation Log Messages (not yet centralized)
    MODERNIZED_LDIF_WRITE_FAILED_NO_ERROR_MSG: Final[str] = (
        "Modernized LDIF write failed"
    )
    EMPTY_WRITE_RESULT_MSG: Final[str] = ""

    # Additional File Operation Constants (not yet centralized)
    CONTENT_PREVIEW_SIZE: Final[int] = 100
    CONTENT_PREVIEW_REPLACEMENT: Final[str] = "\\n"
    FILE_CONTENT_PREVIEW_SIZE: Final[int] = 200
    FILE_MODE_FORMAT: Final[str] = "%o"

    # Additional File Write Operation Messages (not yet centralized)
    CONTENT_GENERATION_FAILED_FOR_ENTRIES_MSG: Final[str] = (
        "Content generation failed for {entries_count} entries: {error}"
    )
    CONTENT_GENERATION_NULL_DATA_MSG: Final[str] = (
        "Content generation succeeded but returned None data"
    )

    # File Read Operation Log Messages (remaining hardcoded strings to centralize)
    STARTING_LDIF_FILE_READ_OPERATION_LOG: Final[str] = (
        "Starting LDIF file read operation: %s"
    )
    FILE_ENCODING_READ_LOG: Final[str] = "File encoding: %s"
    RESOLVED_ABSOLUTE_FILE_PATH_READ_LOG: Final[str] = "Resolved absolute file path: %s"
    LDIF_FILE_NOT_FOUND_ERROR_MSG: Final[str] = "LDIF file not found: {absolute_path}"
    PATH_NOT_FILE_ERROR_MSG: Final[str] = "Path is not a file: {absolute_path}"
    FILE_METADATA_SIZE_MODE_LOG: Final[str] = "File metadata - size: %d bytes, mode: %o"
    EMPTY_LDIF_FILE_DETECTED_WARNING_LOG: Final[str] = "Empty LDIF file detected: %s"
    READING_FILE_CONTENT_ENCODING_LOG: Final[str] = (
        "Reading file content with encoding: %s"
    )
    ENCODING_ERROR_READING_FILE_MSG: Final[str] = (
        "Encoding error reading file with {encoding}: {error}"
    )
    FILE_CONTENT_READ_SUCCESS_LOG: Final[str] = (
        "File content read successfully: %d characters, %d lines"
    )
    CONTENT_PREVIEW_REPLACE_LOG: Final[str] = "Content preview: %s..."
    DELEGATING_TO_PARSE_METHOD_FOR_CONTENT_LOG: Final[str] = (
        "Delegating to parse method for content processing"
    )
    EXCEPTION_TYPE_READ_LOG: Final[str] = "Exception type: %s"
    FILE_READ_EXCEPTION_DETAILS_READ_LOG: Final[str] = "File read exception details"
    EXCEPTION_DURING_FILE_READ_OPERATION_LOG: Final[str] = (
        "Exception during file read operation"
    )
    LDIF_FILE_READ_FAILED_ERROR_MSG: Final[str] = "LDIF file read failed: {error}"
    FILE_READ_AND_PARSE_SUCCESS_LOG: Final[str] = (
        "File read and parse successful: %d entries from %s"
    )
    LDIF_FILE_PROCESSING_COMPLETED_SUCCESS_LOG: Final[str] = (
        "LDIF file processing completed successfully - file_path=%s, file_size_bytes=%d, content_size_chars=%d, lines_count=%d, entries_parsed=%d, encoding=%s"
    )
    LDIF_PARSING_FAILED_FOR_FILE_ERROR_MSG: Final[str] = (
        "LDIF parsing failed for file {absolute_path}: {error}"
    )
    PARSE_METHOD_FAILED_AFTER_SUCCESSFUL_READ_LOG: Final[str] = (
        "Parse method failed after successful file read - file accessible but content invalid"
    )

    # File Read Operation Constants
    FILE_READ_CONTENT_PREVIEW_SIZE: Final[int] = 200
    NEWLINE_TO_ESCAPED_NEWLINE: Final[str] = "\\n"


# =============================================================================
# COMPREHENSIVE PUBLIC API - All constants exported
# =============================================================================

__all__ = [
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
    "FlextLdifAnalyticsConstants",
    "FlextLdifCoreConstants",
    "FlextLdifCoreMessages",
    "FlextLdifDefaultValues",
    # 100% String Centralization Classes
    "FlextLdifFormatConstants",
    "FlextLdifOperationMessages",
    # NEW ORGANIZED CLASSES
    "FlextLdifValidationMessages",
]
