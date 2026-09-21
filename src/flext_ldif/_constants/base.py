"""FlextLdifConstantsBase - Base constants for LDIF domain.

Owns every compiled ``re.Pattern`` for the LDIF domain. Consumer modules
import the pre-compiled ``*_RE`` constants directly; ``import re`` outside
this module is forbidden by AGENTS.md §3.1 ``regex-from-constants`` rule.
"""

from __future__ import annotations

import re
import struct
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from .._typings.base import FlextLdifTypesBase as t


class FlextLdifConstantsBase:
    """Base and foundational LDIF constants."""

    # Format and encoding indicators

    # Character ranges
    ASCII_PRINTABLE_MIN: ClassVar[int] = 32
    ASCII_PRINTABLE_MAX: ClassVar[int] = 126
    SAFE_CHAR_MIN: ClassVar[int] = 1
    SAFE_CHAR_MAX: ClassVar[int] = 127
    SAFE_CHAR_EXCLUDE: ClassVar[frozenset[int]] = frozenset({0, 10, 13})
    SAFE_INIT_CHAR_EXCLUDE: ClassVar[frozenset[int]] = frozenset({0, 10, 13, 32, 58, 60})

    # Base64 start characters
    BASE64_START_CHARS: ClassVar[frozenset[str]] = frozenset({" ", "<", ":"})

    # Lines and formatting
    LINE_FOLD_WIDTH: ClassVar[int] = 76
    LINE_CONTINUATION_SPACE: ClassVar[str] = " "
    LINE_SEPARATOR: ClassVar[str] = "\n"

    # DN character exclusions (UTF1 variants)
    DN_LUTF1_EXCLUDE: ClassVar[frozenset[int]] = frozenset({
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
    DN_TUTF1_EXCLUDE: ClassVar[frozenset[int]] = frozenset({
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
    DN_SUTF1_EXCLUDE: ClassVar[frozenset[int]] = frozenset({0, 34, 43, 44, 59, 60, 62, 92})

    # DN escape
    DN_ESCAPE_CHARS: ClassVar[frozenset[str]] = frozenset({
        '"',
        "+",
        ",",
        ";",
        "<",
        ">",
        "\\",
    })

    # DN constants
    MIN_DN_LENGTH: ClassVar[int] = 2
    DN_COMMA: ClassVar[str] = ","
    DN_TRAILING_BACKSLASH_SPACE: ClassVar[str] = "\\\\\\\\s+,"
    DN_SPACES_AROUND_COMMA: ClassVar[str] = ",\\s+"
    DN_UNNECESSARY_ESCAPES: ClassVar[str] = '\\\\([^,+"\\<>;\\\\# ])'
    DN_MULTIPLE_SPACES: ClassVar[str] = "\\s+"

    # Metadata keys
    META_TRANSFORMATION_TIMESTAMP: ClassVar[str] = "_transform_ts"
    META_DN_ORIGINAL: ClassVar[str] = "_dn_original"
    META_DN_WAS_BASE64: ClassVar[str] = "_dn_was_base64"
    META_DN_ESCAPES_APPLIED: ClassVar[str] = "_dn_escapes_applied"

    # Attribute constants
    MAX_ATTRIBUTE_NAME_LENGTH: ClassVar[int] = 127
    ATTRIBUTE_TYPES: ClassVar[str] = "attributeTypes"
    OBJECT_CLASSES: ClassVar[str] = "objectClasses"

    # Boolean and defaults
    TRUE_RFC: ClassVar[str] = "TRUE"
    FALSE_RFC: ClassVar[str] = "FALSE"
    DEFAULT_LINE_WIDTH: ClassVar[int] = 78
    DEFAULT_ACL_FORMAT: ClassVar[str] = "aci"

    # Validation thresholds
    CONFIDENCE_THRESHOLD: ClassVar[float] = 0.6
    ATTRIBUTE_MATCH_SCORE: ClassVar[int] = 2
    DEFAULT_MAX_LINES: ClassVar[int] = 1000
    TUPLE_LENGTH_PAIR: ClassVar[int] = 2

    # Regex patterns - DN and schema
    DN_COMPONENT: ClassVar[str] = "^[a-zA-Z][a-zA-Z0-9-]*=(?:[^\\\\,]|\\\\.)*$"
    SCHEMA_NAME: ClassVar[str] = "(?i)NAME\\s+\\(?\\s*'([^']+)'"
    SCHEMA_DESC: ClassVar[str] = "DESC\\s+'([^']+)'"
    SCHEMA_EQUALITY: ClassVar[str] = "EQUALITY\\s+([^\\s)]+)"
    SCHEMA_SUBSTR: ClassVar[str] = "SUBSTR\\s+([^\\s)]+)"
    SCHEMA_ORDERING: ClassVar[str] = "ORDERING\\s+([^\\s)]+)"
    SCHEMA_SUP: ClassVar[str] = "SUP\\s+'?(\\w+)'?"
    SCHEMA_USAGE: ClassVar[str] = "USAGE\\s+(\\w+)"
    SCHEMA_SYNTAX_LENGTH: ClassVar[str] = (
        "SYNTAX\\s+(?:')?([0-9.]+)(?:')?(?:\\{(\\d+)\\})?"
    )
    SCHEMA_SINGLE_VALUE: ClassVar[str] = "\\bSINGLE-VALUE\\b"
    SCHEMA_NO_USER_MODIFICATION: ClassVar[str] = "\\bNO-USER-MODIFICATION\\b"
    SCHEMA_OBJECTCLASS_KIND: ClassVar[str] = "\\b(ABSTRACT|STRUCTURAL|AUXILIARY)\\b"
    SCHEMA_OBJECTCLASS_SUP: ClassVar[str] = (
        "SUP\\s+(?:\\(\\s*([^)]+)\\s*\\)|'(\\w+)'|(\\w+))"
    )
    SCHEMA_OBJECTCLASS_MUST: ClassVar[str] = "MUST\\s+(?:\\(\\s*([^)]+)\\s*\\)|(\\w+))"
    SCHEMA_OBJECTCLASS_MAY: ClassVar[str] = "MAY\\s+(?:\\(\\s*([^)]+)\\s*\\)|(\\w+))"
    ATTRIBUTE_NAME: ClassVar[str] = "^[a-zA-Z][a-zA-Z0-9-]*$"
    ATTRIBUTE_OPTION: ClassVar[str] = ";[a-zA-Z][a-zA-Z0-9-_]*"
    BINARY_CHAR_PATTERN: ClassVar[str] = "[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f-\\xff]"
    NUMERIC_OID_PATTERN: ClassVar[str] = "^\\d+(\\.\\d+)*$"
    SCHEMA_X_EXTENSION: ClassVar[str] = r"X-([A-Z0-9_-]+)\s+[\"']?([^\"']*)[\"']?(?:\s|$)"
    SCHEMA_DESC_FLEX: ClassVar[str] = r"DESC\s+['\\\"]([^'\\\"]*)['\\\"]"
    SCHEMA_ORDERING_PATTERN: ClassVar[str] = r"ORDERING\s+([A-Za-z0-9_-]+)"
    SCHEMA_SUBSTR_PATTERN: ClassVar[str] = r"SUBSTR\s+([A-Za-z0-9_-]+)"
    SCHEMA_OID_CAPTURE: ClassVar[str] = r"\(\s*([0-9.]+)"

    # === Pre-compiled regex authorities (consumers MUST use these — never re.compile externally). ===
    ATTRIBUTE_NAME_RE: ClassVar[t.RegexPattern] = re.compile(ATTRIBUTE_NAME)
    ATTRIBUTE_OPTION_RE: ClassVar[t.RegexPattern] = re.compile(ATTRIBUTE_OPTION)
    BINARY_CHAR_RE: ClassVar[t.RegexPattern] = re.compile(BINARY_CHAR_PATTERN)
    DN_COMPONENT_RE: ClassVar[t.RegexPattern] = re.compile(
        r"^[a-zA-Z][a-zA-Z0-9-]*=(?:[^\\,]|\\.)*$", re.IGNORECASE
    )
    NUMERIC_OID_RE: ClassVar[t.RegexPattern] = re.compile(NUMERIC_OID_PATTERN)
    SCHEMA_X_EXTENSION_RE: ClassVar[t.RegexPattern] = re.compile(
        SCHEMA_X_EXTENSION, re.IGNORECASE
    )
    SCHEMA_DESC_FLEX_RE: ClassVar[t.RegexPattern] = re.compile(SCHEMA_DESC_FLEX)
    SCHEMA_ORDERING_TOKEN_RE: ClassVar[t.RegexPattern] = re.compile(
        SCHEMA_ORDERING_PATTERN
    )
    SCHEMA_SUBSTR_TOKEN_RE: ClassVar[t.RegexPattern] = re.compile(SCHEMA_SUBSTR_PATTERN)
    SCHEMA_OID_CAPTURE_RE: ClassVar[t.RegexPattern] = re.compile(SCHEMA_OID_CAPTURE)
    SCHEMA_OBJECTCLASS_KIND_RE: ClassVar[t.RegexPattern] = re.compile(
        SCHEMA_OBJECTCLASS_KIND, re.IGNORECASE
    )
    SCHEMA_OBJECTCLASS_SUP_RE: ClassVar[t.RegexPattern] = re.compile(
        SCHEMA_OBJECTCLASS_SUP
    )
    SCHEMA_OBJECTCLASS_MUST_RE: ClassVar[t.RegexPattern] = re.compile(
        SCHEMA_OBJECTCLASS_MUST
    )
    SCHEMA_OBJECTCLASS_MAY_RE: ClassVar[t.RegexPattern] = re.compile(
        SCHEMA_OBJECTCLASS_MAY
    )
    SCHEMA_NO_USER_MODIFICATION_RE: ClassVar[t.RegexPattern] = re.compile(
        SCHEMA_NO_USER_MODIFICATION
    )
    SCHEMA_SYNTAX_LENGTH_RE: ClassVar[t.RegexPattern] = re.compile(SCHEMA_SYNTAX_LENGTH)
    SCHEMA_DEFINITION_PARENS_RE: ClassVar[t.RegexPattern] = re.compile(
        r"\(.*\)", re.DOTALL
    )
    SCHEMA_EQUALITY_TOKEN_RE: ClassVar[t.RegexPattern] = re.compile(
        r"\bEQUALITY\b", re.IGNORECASE
    )
    SCHEMA_SUBSTR_TOKEN_BARE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"\bSUBSTR\b", re.IGNORECASE
    )
    SCHEMA_ORDERING_TOKEN_BARE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"\bORDERING\b", re.IGNORECASE
    )
    SCHEMA_OBSOLETE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"\bOBSOLETE\b", re.IGNORECASE
    )
    SCHEMA_TRAILING_PAREN_RE: ClassVar[t.RegexPattern] = re.compile(r"\)\s*$")
    SCHEMA_LEADING_PAREN_RE: ClassVar[t.RegexPattern] = re.compile(r"^\s*\(")
    WHITESPACE_TRAILING_RE: ClassVar[t.RegexPattern] = re.compile(r"(\s+)$")
    WHITESPACE_LEADING_RE: ClassVar[t.RegexPattern] = re.compile(r"(\s*)")
    OID_CAPTURE_NUMERIC_RE: ClassVar[t.RegexPattern] = re.compile(
        r"\(\s*([0-9.]+)(\s*)"
    )
    QUOTED_NAME_TRIPLE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"([\"'])([^\"']+)([\"'])"
    )
    SCHEMA_DESC_LOOSE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"DESC\s+([\"']?)([^\"']+)([\"']?)", re.IGNORECASE
    )
    SCHEMA_SINGLE_VALUE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"SINGLE-VALUE", re.IGNORECASE
    )
    SCHEMA_SUP_LOOSE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"SUP\s+([^\s]+)", re.IGNORECASE
    )
    SCHEMA_SYNTAX_LOOSE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"SYNTAX\s*([\"']?)([0-9.]+)([\"']?)(\{[0-9]+\})?", re.IGNORECASE
    )
    SCHEMA_X_ORIGIN_RE: ClassVar[t.RegexPattern] = re.compile(
        r"X-ORIGIN\s+([\"']?)([^\"']+)([\"']?)", re.IGNORECASE
    )
    SCHEMA_NAME_LOOSE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"NAME\s+(\()?\s*([\"']?)([^\"'()]+)([\"']?)(\s*\))?"
    )
    SCHEMA_NAME_MULTIPLE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"NAME\s+\(\s*([\"'])([^\"']+)([\"'])\s+([\"'])([^\"']+)([\"'])"
    )
    QUOTED_SPACE_QUOTE_RE: ClassVar[t.RegexPattern] = re.compile(r"[\"']\s+([\"'])")
    LDIF_ATTR_TYPES_PREFIX_RE: ClassVar[t.RegexPattern] = re.compile(
        r"(attributetypes|attributeTypes):", re.IGNORECASE
    )
    LDIF_OBJECTCLASSES_PREFIX_RE: ClassVar[t.RegexPattern] = re.compile(
        r"(objectclasses|objectClasses):", re.IGNORECASE
    )
    ACI_MACRO_RE: ClassVar[t.RegexPattern] = re.compile(r"\(\$dn\)|\[\$dn\]|\(\$attr\.")
    ACL_NAME_QUOTED_RE: ClassVar[t.RegexPattern] = re.compile(r'acl\s+"[^"]*"')
    DN_SPLIT_OPTIONAL_SPACE_RE: ClassVar[t.RegexPattern] = re.compile(r"\s*,\s*")
    DN_SPLIT_UNESCAPED_COMMA_RE: ClassVar[t.RegexPattern] = re.compile(
        r"(?<!\\)\s*,\s*"
    )

    @staticmethod
    def compile_pattern(
        pattern: str,
        *,
        ignorecase: bool = False,
        multiline: bool = False,
        dotall: bool = False,
    ) -> t.RegexPattern:
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
        substituted: str = FlextLdifConstantsBase.compile_pattern(
            pattern, ignorecase=ignorecase
        ).sub(replacement, value, count=count)
        return substituted

    # Schema metadata keys
    SCHEMA_ORIGINAL_FORMAT: ClassVar[str] = "schema_original_format"
    SCHEMA_ORIGINAL_STRING_COMPLETE: ClassVar[str] = "schema_original_string_complete"
    SCHEMA_SOURCE_SERVER: ClassVar[str] = "schema_source_server"
    OBSOLETE: ClassVar[str] = "obsolete"
    SCHEMA_SOURCE_SYNTAX_OID: ClassVar[str] = "schema_source_syntax_oid"
    SCHEMA_TARGET_SYNTAX_OID: ClassVar[str] = "schema_target_syntax_oid"
    SCHEMA_SOURCE_MATCHING_RULES: ClassVar[str] = "schema_source_matching_rules"
    SCHEMA_TARGET_MATCHING_RULES: ClassVar[str] = "schema_target_matching_rules"
    SCHEMA_TARGET_ATTRIBUTE_NAME: ClassVar[str] = "schema_target_attribute_name"
    SYNTAX_OID_VALID: ClassVar[str] = "syntax_oid_valid"
    SYNTAX_VALIDATION_ERROR: ClassVar[str] = "syntax_validation_error"
    X_ORIGIN: ClassVar[str] = "x_origin"
    COLLECTIVE: ClassVar[str] = "collective"

    # Entry metadata keys
    ORIGINAL_DN_COMPLETE: ClassVar[str] = "original_dn_complete"
    ORIGINAL_ATTRIBUTES_COMPLETE: ClassVar[str] = "original_attributes_complete"
    ENTRY_ORIGINAL_LDIF: ClassVar[str] = "entry_original_ldif"
    WRITE_FORMAT_OPTIONS: ClassVar[str] = "write_format_options"
    BASE_DN: ClassVar[str] = "base_dn"
    DN_REGISTRY: ClassVar[str] = "dn_registry"
    HAS_DIFFERENCES: ClassVar[str] = "has_differences"
    MINIMAL_DIFFERENCES_DN: ClassVar[str] = "minimal_differences_dn"

    # ACL attribute names — canonical set of LDAP ACI/ACL attribute names
    # across all server types (RFC ``aci``, OID ``orclaci``/``orclentrylevelaci``).
    ACL_ATTR_NAMES: ClassVar[frozenset[str]] = frozenset({
        "aci",
        "orclaci",
        "orclentrylevelaci",
    })

    # ACL metadata keys
    ACL_ORIGINAL_FORMAT: ClassVar[str] = "original_format"
    ACL_SOURCE_SUBJECT_TYPE: ClassVar[str] = "source_subject_type"
    ACL_SOURCE_SERVER: ClassVar[str] = "acl_source_server"
    ACL_NAME_SANITIZED: ClassVar[str] = "acl_name_sanitized"
    ACL_ORIGINAL_NAME_RAW: ClassVar[str] = "acl_original_name_raw"
    ACL_FILTER: ClassVar[str] = "filter"
    ACL_CONSTRAINT: ClassVar[str] = "added_object_constraint"
    ACL_BINDMODE: ClassVar[str] = "bindmode"
    ACL_DENY_GROUP_OVERRIDE: ClassVar[str] = "deny_group_override"
    ACL_APPEND_TO_ALL: ClassVar[str] = "append_to_all"
    ACL_BIND_IP_FILTER: ClassVar[str] = "bind_ip_filter"
    ACL_CONSTRAIN_TO_ADDED_OBJECT: ClassVar[str] = "constrain_to_added_object"
    ACL_BIND_TIMEOFDAY: ClassVar[str] = "bind_timeofday"
    ACL_SSF: ClassVar[str] = "ssf"
    ACL_EXTOP: ClassVar[str] = "extop"
    ACL_BIND_DNS: ClassVar[str] = "bind_dns"
    ACL_BIND_DAYOFWEEK: ClassVar[str] = "bind_dayofweek"
    ACL_AUTHMETHOD: ClassVar[str] = "authmethod"
    ACL_TARGETATTR_FILTERS: ClassVar[str] = "targattrfilters"
    ACL_TARGET_CONTROL: ClassVar[str] = "targetcontrol"
    ACL_SOURCE_PERMISSIONS: ClassVar[str] = "source_permissions"
    ACL_SSFS: ClassVar[str] = "ssfs"
    ACL_TARGETSCOPE: ClassVar[str] = "targetscope"
    ACL_NUMBERING: ClassVar[str] = "numbering"

    # Sorting metadata
    ORIGINAL_FORMAT: ClassVar[str] = "original_format"
    VERSION: ClassVar[str] = "version"

    # Source file and conversion
    HIDDEN_ATTRIBUTES: ClassVar[str] = "hidden_attributes"
    COMMENTED_ATTRIBUTE_VALUES: ClassVar[str] = "commented_attribute_values"
    ACL_COMMENTED_ATTRIBUTES: ClassVar[str] = "acl_commented_attributes"
    CONVERSION_BOOLEAN_CONVERSIONS: ClassVar[str] = "boolean_conversions"
    CONVERSION_ORIGINAL_VALUE: ClassVar[str] = "original"
    CONVERSION_CONVERTED_VALUE: ClassVar[str] = "converted"
    CONVERSION_CONVERTED_ATTRIBUTE_NAMES: ClassVar[str] = (
        "conversion_converted_attribute_names"
    )
    CONVERTED_ATTRIBUTES: ClassVar[str] = "converted_attributes"

    # ===== Parsing boundary exception tuple (ENFORCE-079 owner) =====
    EXC_LDIF_PARSE: ClassVar[tuple[type[Exception], ...]] = (
        AttributeError,
        KeyError,
        UnicodeDecodeError,
        ValueError,
        struct.error,
    )
    """LDIF parsing boundary catch: attribute access, dict, unicode,
    type, and struct unpacking errors raised during entry parsing."""

    # ===== Operational attributes to ignore in LDIF entry processing =====
    class OperationalAttributes:
        """Operational attributes to ignore in LDIF entry processing."""

        IGNORE_SET: ClassVar[frozenset[str]] = frozenset({
            "createTimestamp",
            "modifyTimestamp",
            "creatorsName",
            "modifiersName",
            "entryUUID",
            "entryCSN",
            "hasSubordinates",
            "numSubordinates",
            "subschemaSubentry",
            "dseType",
        })

    # ===== Service registry name (ENFORCE-079 owner) =====
    SERVERS: ClassVar[str] = "ldif_servers"
    """Registry name for the LDIF server registry DSL."""
