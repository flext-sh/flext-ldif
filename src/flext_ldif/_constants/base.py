"""FlextLdifConstantsBase - Base constants for LDIF domain.

Owns every compiled ``re.Pattern`` for the LDIF domain. Consumer modules
import the pre-compiled ``*_RE`` constants directly; ``import re`` outside
this module is forbidden by AGENTS.md §3.1 ``regex-from-constants`` rule.
"""

from __future__ import annotations

import re
from typing import ClassVar, Final


class FlextLdifConstantsBase:
    """Base and foundational LDIF constants."""

    # Format and encoding indicators

    # Character ranges
    ASCII_PRINTABLE_MIN: Final[int] = 32
    ASCII_PRINTABLE_MAX: Final[int] = 126
    SAFE_CHAR_MIN: Final[int] = 1
    SAFE_CHAR_MAX: Final[int] = 127
    SAFE_CHAR_EXCLUDE: Final[frozenset[int]] = frozenset({0, 10, 13})
    SAFE_INIT_CHAR_EXCLUDE: Final[frozenset[int]] = frozenset({0, 10, 13, 32, 58, 60})

    # Base64 start characters
    BASE64_START_CHARS: Final[frozenset[str]] = frozenset({" ", "<", ":"})

    # Lines and formatting
    LINE_FOLD_WIDTH: Final[int] = 76
    LINE_CONTINUATION_SPACE: Final[str] = " "
    LINE_SEPARATOR: Final[str] = "\n"

    # DN character exclusions (UTF1 variants)
    DN_LUTF1_EXCLUDE: Final[frozenset[int]] = frozenset({
        0,
        32,
        34,
        35,
        43,
        44,
        59,
        60,
        62,
        92,
    })
    DN_TUTF1_EXCLUDE: Final[frozenset[int]] = frozenset({
        0,
        32,
        34,
        43,
        44,
        59,
        60,
        62,
        92,
    })
    DN_SUTF1_EXCLUDE: Final[frozenset[int]] = frozenset({0, 34, 43, 44, 59, 60, 62, 92})

    # DN escape
    DN_ESCAPE_CHARS: Final[frozenset[str]] = frozenset({
        '"',
        "+",
        ",",
        ";",
        "<",
        ">",
        "\\",
    })

    # DN constants
    MIN_DN_LENGTH: Final[int] = 2
    DN_COMMA: Final[str] = ","
    DN_TRAILING_BACKSLASH_SPACE: Final[str] = "\\\\\\\\s+,"
    DN_SPACES_AROUND_COMMA: Final[str] = ",\\s+"
    DN_UNNECESSARY_ESCAPES: Final[str] = '\\\\([^,+"\\<>;\\\\# ])'
    DN_MULTIPLE_SPACES: Final[str] = "\\s+"

    # Metadata keys
    META_TRANSFORMATION_TIMESTAMP: Final[str] = "_transform_ts"
    META_DN_ORIGINAL: Final[str] = "_dn_original"
    META_DN_WAS_BASE64: Final[str] = "_dn_was_base64"
    META_DN_ESCAPES_APPLIED: Final[str] = "_dn_escapes_applied"

    # Attribute constants
    MAX_ATTRIBUTE_NAME_LENGTH: Final[int] = 127
    ATTRIBUTE_TYPES: Final[str] = "attributeTypes"
    OBJECT_CLASSES: Final[str] = "objectClasses"

    # Boolean and defaults
    TRUE_RFC: Final[str] = "TRUE"
    FALSE_RFC: Final[str] = "FALSE"
    DEFAULT_LINE_WIDTH: Final[int] = 78
    DEFAULT_ACL_FORMAT: Final[str] = "aci"

    # Validation thresholds
    CONFIDENCE_THRESHOLD: Final[float] = 0.6
    ATTRIBUTE_MATCH_SCORE: Final[int] = 2
    DEFAULT_MAX_LINES: Final[int] = 1000
    TUPLE_LENGTH_PAIR: Final[int] = 2

    # Regex patterns - DN and schema
    DN_COMPONENT: Final[str] = "^[a-zA-Z][a-zA-Z0-9-]*=(?:[^\\\\,]|\\\\.)*$"
    SCHEMA_NAME: Final[str] = "(?i)NAME\\s+\\(?\\s*'([^']+)'"
    SCHEMA_DESC: Final[str] = "DESC\\s+'([^']+)'"
    SCHEMA_EQUALITY: Final[str] = "EQUALITY\\s+([^\\s)]+)"
    SCHEMA_SUBSTR: Final[str] = "SUBSTR\\s+([^\\s)]+)"
    SCHEMA_ORDERING: Final[str] = "ORDERING\\s+([^\\s)]+)"
    SCHEMA_SUP: Final[str] = "SUP\\s+'?(\\w+)'?"
    SCHEMA_USAGE: Final[str] = "USAGE\\s+(\\w+)"
    SCHEMA_SYNTAX_LENGTH: Final[str] = (
        "SYNTAX\\s+(?:')?([0-9.]+)(?:')?(?:\\{(\\d+)\\})?"
    )
    SCHEMA_SINGLE_VALUE: Final[str] = "\\bSINGLE-VALUE\\b"
    SCHEMA_NO_USER_MODIFICATION: Final[str] = "\\bNO-USER-MODIFICATION\\b"
    SCHEMA_OBJECTCLASS_KIND: Final[str] = "\\b(ABSTRACT|STRUCTURAL|AUXILIARY)\\b"
    SCHEMA_OBJECTCLASS_SUP: Final[str] = (
        "SUP\\s+(?:\\(\\s*([^)]+)\\s*\\)|'(\\w+)'|(\\w+))"
    )
    SCHEMA_OBJECTCLASS_MUST: Final[str] = "MUST\\s+(?:\\(\\s*([^)]+)\\s*\\)|(\\w+))"
    SCHEMA_OBJECTCLASS_MAY: Final[str] = "MAY\\s+(?:\\(\\s*([^)]+)\\s*\\)|(\\w+))"
    ATTRIBUTE_NAME: Final[str] = "^[a-zA-Z][a-zA-Z0-9-]*$"
    ATTRIBUTE_OPTION: Final[str] = ";[a-zA-Z][a-zA-Z0-9-_]*"
    BINARY_CHAR_PATTERN: Final[str] = "[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f-\\xff]"
    NUMERIC_OID_PATTERN: Final[str] = "^\\d+(\\.\\d+)*$"
    SCHEMA_X_EXTENSION: Final[str] = r"X-([A-Z0-9_-]+)\s+[\"']?([^\"']*)[\"']?(?:\s|$)"
    SCHEMA_DESC_FLEX: Final[str] = r"DESC\s+['\\\"]([^'\\\"]*)['\\\"]"
    SCHEMA_ORDERING_TOKEN: Final[str] = r"ORDERING\s+([A-Za-z0-9_-]+)"
    SCHEMA_SUBSTR_TOKEN: Final[str] = r"SUBSTR\s+([A-Za-z0-9_-]+)"
    SCHEMA_OID_CAPTURE: Final[str] = r"\(\s*([0-9.]+)"

    # === Pre-compiled regex authorities (consumers MUST use these — never re.compile externally). ===
    ATTRIBUTE_NAME_RE: ClassVar[re.Pattern[str]] = re.compile(ATTRIBUTE_NAME)
    ATTRIBUTE_OPTION_RE: ClassVar[re.Pattern[str]] = re.compile(ATTRIBUTE_OPTION)
    BINARY_CHAR_RE: ClassVar[re.Pattern[str]] = re.compile(BINARY_CHAR_PATTERN)
    DN_COMPONENT_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"^[a-zA-Z][a-zA-Z0-9-]*=(?:[^\\,]|\\.)*$",
        re.IGNORECASE,
    )
    NUMERIC_OID_RE: ClassVar[re.Pattern[str]] = re.compile(NUMERIC_OID_PATTERN)
    SCHEMA_X_EXTENSION_RE: ClassVar[re.Pattern[str]] = re.compile(
        SCHEMA_X_EXTENSION, re.IGNORECASE
    )
    SCHEMA_DESC_FLEX_RE: ClassVar[re.Pattern[str]] = re.compile(SCHEMA_DESC_FLEX)
    SCHEMA_ORDERING_TOKEN_RE: ClassVar[re.Pattern[str]] = re.compile(
        SCHEMA_ORDERING_TOKEN
    )
    SCHEMA_SUBSTR_TOKEN_RE: ClassVar[re.Pattern[str]] = re.compile(SCHEMA_SUBSTR_TOKEN)
    SCHEMA_OID_CAPTURE_RE: ClassVar[re.Pattern[str]] = re.compile(SCHEMA_OID_CAPTURE)
    SCHEMA_OBJECTCLASS_KIND_RE: ClassVar[re.Pattern[str]] = re.compile(
        SCHEMA_OBJECTCLASS_KIND, re.IGNORECASE
    )
    SCHEMA_OBJECTCLASS_SUP_RE: ClassVar[re.Pattern[str]] = re.compile(
        SCHEMA_OBJECTCLASS_SUP
    )
    SCHEMA_OBJECTCLASS_MUST_RE: ClassVar[re.Pattern[str]] = re.compile(
        SCHEMA_OBJECTCLASS_MUST
    )
    SCHEMA_OBJECTCLASS_MAY_RE: ClassVar[re.Pattern[str]] = re.compile(
        SCHEMA_OBJECTCLASS_MAY
    )
    SCHEMA_NO_USER_MODIFICATION_RE: ClassVar[re.Pattern[str]] = re.compile(
        SCHEMA_NO_USER_MODIFICATION
    )
    SCHEMA_SYNTAX_LENGTH_RE: ClassVar[re.Pattern[str]] = re.compile(
        SCHEMA_SYNTAX_LENGTH
    )
    SCHEMA_DEFINITION_PARENS_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\(.*\)", re.DOTALL
    )
    SCHEMA_EQUALITY_TOKEN_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\bEQUALITY\b", re.IGNORECASE
    )
    SCHEMA_SUBSTR_TOKEN_BARE_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\bSUBSTR\b", re.IGNORECASE
    )
    SCHEMA_ORDERING_TOKEN_BARE_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\bORDERING\b", re.IGNORECASE
    )
    SCHEMA_OBSOLETE_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\bOBSOLETE\b", re.IGNORECASE
    )
    SCHEMA_TRAILING_PAREN_RE: ClassVar[re.Pattern[str]] = re.compile(r"\)\s*$")
    SCHEMA_LEADING_PAREN_RE: ClassVar[re.Pattern[str]] = re.compile(r"^\s*\(")
    WHITESPACE_TRAILING_RE: ClassVar[re.Pattern[str]] = re.compile(r"(\s+)$")
    WHITESPACE_LEADING_RE: ClassVar[re.Pattern[str]] = re.compile(r"(\s*)")
    OID_CAPTURE_NUMERIC_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\(\s*([0-9.]+)(\s*)"
    )
    QUOTED_NAME_TRIPLE_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"([\"'])([^\"']+)([\"'])"
    )
    SCHEMA_DESC_LOOSE_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"DESC\s+([\"']?)([^\"']+)([\"']?)", re.IGNORECASE
    )
    SCHEMA_SINGLE_VALUE_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"SINGLE-VALUE", re.IGNORECASE
    )
    SCHEMA_SUP_LOOSE_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"SUP\s+([^\s]+)", re.IGNORECASE
    )
    SCHEMA_SYNTAX_LOOSE_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"SYNTAX\s*([\"']?)([0-9.]+)([\"']?)(\{[0-9]+\})?", re.IGNORECASE
    )
    SCHEMA_X_ORIGIN_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"X-ORIGIN\s+([\"']?)([^\"']+)([\"']?)", re.IGNORECASE
    )
    SCHEMA_NAME_LOOSE_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"NAME\s+(\()?\s*([\"']?)([^\"'()]+)([\"']?)(\s*\))?"
    )
    SCHEMA_NAME_MULTIPLE_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"NAME\s+\(\s*([\"'])([^\"']+)([\"'])\s+([\"'])([^\"']+)([\"'])"
    )
    QUOTED_SPACE_QUOTE_RE: ClassVar[re.Pattern[str]] = re.compile(r"[\"']\s+([\"'])")
    LDIF_ATTR_TYPES_PREFIX_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"(attributetypes|attributeTypes):", re.IGNORECASE
    )
    LDIF_OBJECTCLASSES_PREFIX_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"(objectclasses|objectClasses):", re.IGNORECASE
    )
    ACI_MACRO_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\(\$dn\)|\[\$dn\]|\(\$attr\."
    )
    ACL_NAME_QUOTED_RE: ClassVar[re.Pattern[str]] = re.compile(r'acl\s+"[^"]*"')
    DN_SPLIT_OPTIONAL_SPACE_RE: ClassVar[re.Pattern[str]] = re.compile(r"\s*,\s*")

    @staticmethod
    def compile_pattern(
        pattern: str,
        *,
        ignorecase: bool = False,
        multiline: bool = False,
        dotall: bool = False,
    ) -> re.Pattern[str]:
        """Compile a runtime-supplied regex pattern.

        Sole sanctioned ``re.compile`` entry-point for non-constant patterns
        (e.g. user-supplied DN filters). Consumer modules MUST call this
        instead of importing ``re`` directly.
        """
        flags = 0
        if ignorecase:
            flags |= re.IGNORECASE
        if multiline:
            flags |= re.MULTILINE
        if dotall:
            flags |= re.DOTALL
        return re.compile(pattern, flags=flags)

    @staticmethod
    def escape_pattern(value: str) -> str:
        """Escape special regex metacharacters in ``value``.

        Sole sanctioned ``re.escape`` entry-point for non-constant strings.
        """
        return re.escape(value)

    @staticmethod
    def sub_pattern(
        pattern: str,
        replacement: str,
        value: str,
        *,
        ignorecase: bool = False,
        count: int = 0,
    ) -> str:
        """Substitute matches of a runtime-supplied regex pattern in ``value``.

        Sole sanctioned ``re.sub`` entry-point for runtime patterns; the
        compiled pattern is built via ``compile_pattern`` and re-used.
        """
        return FlextLdifConstantsBase.compile_pattern(
            pattern, ignorecase=ignorecase
        ).sub(replacement, value, count=count)

    # Schema metadata keys
    SCHEMA_ORIGINAL_FORMAT: Final[str] = "schema_original_format"
    SCHEMA_ORIGINAL_STRING_COMPLETE: Final[str] = "schema_original_string_complete"
    SCHEMA_SOURCE_SERVER: Final[str] = "schema_source_server"
    OBSOLETE: Final[str] = "obsolete"
    SCHEMA_SOURCE_SYNTAX_OID: Final[str] = "schema_source_syntax_oid"
    SCHEMA_TARGET_SYNTAX_OID: Final[str] = "schema_target_syntax_oid"
    SCHEMA_SOURCE_MATCHING_RULES: Final[str] = "schema_source_matching_rules"
    SCHEMA_TARGET_MATCHING_RULES: Final[str] = "schema_target_matching_rules"
    SCHEMA_TARGET_ATTRIBUTE_NAME: Final[str] = "schema_target_attribute_name"
    SYNTAX_OID_VALID: Final[str] = "syntax_oid_valid"
    SYNTAX_VALIDATION_ERROR: Final[str] = "syntax_validation_error"
    X_ORIGIN: Final[str] = "x_origin"
    COLLECTIVE: Final[str] = "collective"

    # Entry metadata keys
    ORIGINAL_DN_COMPLETE: Final[str] = "original_dn_complete"
    ORIGINAL_ATTRIBUTES_COMPLETE: Final[str] = "original_attributes_complete"
    ENTRY_ORIGINAL_LDIF: Final[str] = "entry_original_ldif"
    WRITE_FORMAT_OPTIONS: Final[str] = "write_format_options"
    BASE_DN: Final[str] = "base_dn"
    DN_REGISTRY: Final[str] = "dn_registry"
    HAS_DIFFERENCES: Final[str] = "has_differences"
    MINIMAL_DIFFERENCES_DN: Final[str] = "minimal_differences_dn"

    # ACL attribute names — canonical set of LDAP ACI/ACL attribute names
    # across all server types (RFC ``aci``, OID ``orclaci``/``orclentrylevelaci``).
    ACL_ATTR_NAMES: Final[frozenset[str]] = frozenset({
        "aci",
        "orclaci",
        "orclentrylevelaci",
    })

    # ACL metadata keys
    ACL_ORIGINAL_FORMAT: Final[str] = "original_format"
    ACL_SOURCE_SUBJECT_TYPE: Final[str] = "source_subject_type"
    ACL_SOURCE_SERVER: Final[str] = "acl_source_server"
    ACL_NAME_SANITIZED: Final[str] = "acl_name_sanitized"
    ACL_ORIGINAL_NAME_RAW: Final[str] = "acl_original_name_raw"
    ACL_FILTER: Final[str] = "filter"
    ACL_CONSTRAINT: Final[str] = "added_object_constraint"
    ACL_BINDMODE: Final[str] = "bindmode"
    ACL_DENY_GROUP_OVERRIDE: Final[str] = "deny_group_override"
    ACL_APPEND_TO_ALL: Final[str] = "append_to_all"
    ACL_BIND_IP_FILTER: Final[str] = "bind_ip_filter"
    ACL_CONSTRAIN_TO_ADDED_OBJECT: Final[str] = "constrain_to_added_object"
    ACL_BIND_TIMEOFDAY: Final[str] = "bind_timeofday"
    ACL_SSF: Final[str] = "ssf"
    ACL_EXTOP: Final[str] = "extop"
    ACL_BIND_DNS: Final[str] = "bind_dns"
    ACL_BIND_DAYOFWEEK: Final[str] = "bind_dayofweek"
    ACL_AUTHMETHOD: Final[str] = "authmethod"
    ACL_TARGETATTR_FILTERS: Final[str] = "targattrfilters"
    ACL_TARGET_CONTROL: Final[str] = "targetcontrol"
    ACL_SOURCE_PERMISSIONS: Final[str] = "source_permissions"
    ACL_SSFS: Final[str] = "ssfs"
    ACL_TARGETSCOPE: Final[str] = "targetscope"
    ACL_NUMBERING: Final[str] = "numbering"

    # Sorting metadata
    ORIGINAL_FORMAT: Final[str] = "original_format"
    VERSION: Final[str] = "version"

    # Source file and conversion
    HIDDEN_ATTRIBUTES: Final[str] = "hidden_attributes"
    COMMENTED_ATTRIBUTE_VALUES: Final[str] = "commented_attribute_values"
    ACL_COMMENTED_ATTRIBUTES: Final[str] = "acl_commented_attributes"
    CONVERSION_BOOLEAN_CONVERSIONS: Final[str] = "boolean_conversions"
    CONVERSION_ORIGINAL_VALUE: Final[str] = "original"
    CONVERSION_CONVERTED_VALUE: Final[str] = "converted"
    CONVERSION_CONVERTED_ATTRIBUTE_NAMES: Final[str] = (
        "conversion_converted_attribute_names"
    )
    CONVERTED_ATTRIBUTES: Final[str] = "converted_attributes"
