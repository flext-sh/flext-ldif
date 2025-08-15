"""FLEXT-LDIF constants."""

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
# FLEXT-LDIF VALIDATION MESSAGES
# =============================================================================

class FlextLdifValidationMessages:
    """Validation messages centralized for flext-ldif operations."""
    
    # DN Validation Messages
    DN_EMPTY_ERROR: Final[str] = "DN must be a non-empty string"
    DN_INVALID_COMPONENT: Final[str] = "Invalid DN component"
    DN_MISSING_EQUALS: Final[str] = "DN must contain at least one attribute=value pair"
    DN_FORMAT_INVALID: Final[str] = "DN format is invalid"
    
    # Entry Validation Messages
    ENTRY_VALIDATION_FAILED: Final[str] = "Entry validation failed"
    EMPTY_ATTRIBUTES_NOT_ALLOWED: Final[str] = "Empty attribute values not allowed for '{attr_name}' in strict mode"
    EMPTY_ATTRIBUTE_VALUE_NOT_ALLOWED: Final[str] = "Empty attribute value not allowed for '{attr_name}' in strict mode"
    
    # Configuration Validation Messages
    INVALID_CONFIGURATION: Final[str] = "Invalid configuration"
    INVALID_ENCODING: Final[str] = "Invalid input or output encoding specified"
    
    # File Processing Messages
    FILE_NOT_FOUND: Final[str] = "File not found: {file_path}"
    FILE_READ_ERROR: Final[str] = "Failed to read file: {file_path}"
    FILE_WRITE_ERROR: Final[str] = "Failed to write file: {file_path}"
    
    # Entry Count Messages
    ENTRY_COUNT_EXCEEDED: Final[str] = "Entry count {count} exceeds configured limit {limit}"
    FILE_ENTRY_COUNT_EXCEEDED: Final[str] = "File entry count {count} exceeds configured limit {limit}"
    
    # LDIF Format Messages
    RECORD_MISSING_DN: Final[str] = "Record missing dn: line"
    INVALID_LDIF_FORMAT: Final[str] = "Invalid LDIF format"
    
    # Modernized LDIF Messages
    MODERNIZED_PARSING_FAILED: Final[str] = "Modernized LDIF parsing failed"
    MODERNIZED_WRITING_FAILED: Final[str] = "Modernized LDIF writing failed"
    
    # Entries Processing Messages
    ENTRIES_CANNOT_BE_NONE: Final[str] = "Entries cannot be None"
    INTERNAL_ERROR_ENTRIES_NONE: Final[str] = "Internal error: entries is None after successful parse"

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
    TRANSFORM_DESCRIPTION: Final[str] = "Transform LDIF file with filtering and sorting options"
    STATS_DESCRIPTION: Final[str] = "Display comprehensive statistics for LDIF file"
    FIND_DESCRIPTION: Final[str] = "Find specific entry by Distinguished Name"
    FILTER_BY_CLASS_DESCRIPTION: Final[str] = "Filter entries by objectClass attribute"
    CONVERT_DESCRIPTION: Final[str] = "Convert between different file formats"
    CONFIG_CHECK_DESCRIPTION: Final[str] = "Validate CLI configuration and display settings"
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
    ENTRY_VALIDATION_FAILED: Final[str] = "Entry {index} of {total} failed validation ({dn}): {error}"
    BULK_VALIDATION_FAILED: Final[str] = "Bulk validation failed with exception: {error}"
    
    # File Operation Messages
    FILE_NOT_FOUND: Final[str] = "LDIF file not found: {file_path}"
    PATH_NOT_FILE: Final[str] = "Path is not a file: {file_path}"
    EMPTY_FILE_WARNING: Final[str] = "Empty LDIF file detected: {file_path}"
    ENCODING_ERROR: Final[str] = "Encoding error reading file with {encoding}: {error}"
    FILE_READ_FAILED: Final[str] = "LDIF file read failed: {error}"
    FILE_WRITE_FAILED: Final[str] = "File write failed: {error}"
    CONTENT_GENERATION_FAILED: Final[str] = "Content generation failed for {count} entries: {error}"
    CONTENT_GENERATION_NULL: Final[str] = "Content generation succeeded but returned None data"
    
    # Parse Specific Messages  
    PARSE_FAILED_FOR_FILE: Final[str] = "LDIF parsing failed for file {file_path}: {error}"

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
    PARSE_COMPLETED_SUCCESS: Final[str] = "Parse completed successfully with {count} entries"
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
    SCHEMA_NOTE: Final[str] = "Note: Schema-based validation will be implemented with flext-ldap integration"
    
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
    # NEW ORGANIZED CLASSES
    "FlextLdifValidationMessages",
    "FlextLdifDefaultValues", 
    "FlextLdifOperationMessages",
    "FlextLdifAnalyticsConstants",
    "FlextLdifCoreMessages",
]
