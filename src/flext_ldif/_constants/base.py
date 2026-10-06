"""FlextLdifConstantsBase - Base constants for LDIF domain.

Owns every compiled ``re.Pattern`` for the LDIF domain. Consumer modules
import the pre-compiled ``*_RE`` constants directly; ``import re`` outside
this module is forbidden by AGENTS.md §3.1 ``regex-from-constants`` rule.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
import struct
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Final

from flext_ldif._constants.enums import FlextLdifConstantsEnums

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flext_ldif.typings import FlextLdifTypes as t


def constants_sub_pattern(
    pattern: str,
    replacement: str,
    value: str,
    *,
    ignorecase: bool = False,
    count: int = 0,
) -> str:
    """Substitute matches of a runtime-supplied regex pattern in ``value``.

    Sole sanctioned ``re.sub`` entry-point for runtime patterns; the compiled
    pattern is built via ``FlextLdifConstantsBase.compile_pattern`` and re-used.
    Exposed on ``FlextLdifConstantsBase`` as ``sub_pattern``.

    Returns:
        The resulting ``str``.
    """
    substituted: str = FlextLdifConstantsBase.compile_pattern(
        pattern,
        ignorecase=ignorecase,
    ).sub(replacement, value, count=count)
    return substituted


class FlextLdifConstantsBase:
    """Base and foundational LDIF constants."""

    # Format and encoding indicators

    # Character ranges
    ASCII_PRINTABLE_MIN: ClassVar[int] = 32
    ASCII_PRINTABLE_MAX: ClassVar[int] = 126
    SAFE_CHAR_MIN: ClassVar[int] = 1
    SAFE_CHAR_MAX: ClassVar[int] = 127
    SAFE_CHAR_EXCLUDE: ClassVar[frozenset[int]] = frozenset({0, 10, 13})
    SAFE_INIT_CHAR_EXCLUDE: ClassVar[frozenset[int]] = frozenset({
        0,
        10,
        13,
        32,
        58,
        60,
    })

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
    DN_SUTF1_EXCLUDE: ClassVar[frozenset[int]] = frozenset({
        0,
        34,
        43,
        44,
        59,
        60,
        62,
        92,
    })

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
    SCHEMA_X_EXTENSION: ClassVar[str] = (
        r"X-([A-Z0-9_-]+)\s+[\"']?([^\"']*)[\"']?(?:\s|$)"
    )
    SCHEMA_DESC_FLEX: ClassVar[str] = r"DESC\s+['\\\"]([^'\\\"]*)['\\\"]"
    SCHEMA_ORDERING_PATTERN: ClassVar[str] = r"ORDERING\s+([A-Za-z0-9_-]+)"
    SCHEMA_SUBSTR_PATTERN: ClassVar[str] = r"SUBSTR\s+([A-Za-z0-9_-]+)"
    SCHEMA_OID_CAPTURE: ClassVar[str] = r"\(\s*([0-9.]+)"

    # === Pre-compiled regex authorities (consumers MUST use these —
    # never re.compile externally). ===
    ATTRIBUTE_NAME_RE: ClassVar[t.RegexPattern] = re.compile(ATTRIBUTE_NAME)
    ATTRIBUTE_OPTION_RE: ClassVar[t.RegexPattern] = re.compile(ATTRIBUTE_OPTION)
    BINARY_CHAR_RE: ClassVar[t.RegexPattern] = re.compile(BINARY_CHAR_PATTERN)
    DN_COMPONENT_RE: ClassVar[t.RegexPattern] = re.compile(
        r"^[a-zA-Z][a-zA-Z0-9-]*=(?:[^\\,]|\\.)*$",
        re.IGNORECASE,
    )
    NUMERIC_OID_RE: ClassVar[t.RegexPattern] = re.compile(NUMERIC_OID_PATTERN)
    SCHEMA_X_EXTENSION_RE: ClassVar[t.RegexPattern] = re.compile(
        SCHEMA_X_EXTENSION,
        re.IGNORECASE,
    )
    SCHEMA_DESC_FLEX_RE: ClassVar[t.RegexPattern] = re.compile(SCHEMA_DESC_FLEX)
    SCHEMA_ORDERING_TOKEN_RE: ClassVar[t.RegexPattern] = re.compile(
        SCHEMA_ORDERING_PATTERN,
    )
    SCHEMA_SUBSTR_TOKEN_RE: ClassVar[t.RegexPattern] = re.compile(SCHEMA_SUBSTR_PATTERN)
    SCHEMA_OID_CAPTURE_RE: ClassVar[t.RegexPattern] = re.compile(SCHEMA_OID_CAPTURE)
    SCHEMA_OBJECTCLASS_KIND_RE: ClassVar[t.RegexPattern] = re.compile(
        SCHEMA_OBJECTCLASS_KIND,
        re.IGNORECASE,
    )
    SCHEMA_OBJECTCLASS_SUP_RE: ClassVar[t.RegexPattern] = re.compile(
        SCHEMA_OBJECTCLASS_SUP,
    )
    SCHEMA_OBJECTCLASS_MUST_RE: ClassVar[t.RegexPattern] = re.compile(
        SCHEMA_OBJECTCLASS_MUST,
    )
    SCHEMA_OBJECTCLASS_MAY_RE: ClassVar[t.RegexPattern] = re.compile(
        SCHEMA_OBJECTCLASS_MAY,
    )
    SCHEMA_NO_USER_MODIFICATION_RE: ClassVar[t.RegexPattern] = re.compile(
        SCHEMA_NO_USER_MODIFICATION,
    )
    SCHEMA_SYNTAX_LENGTH_RE: ClassVar[t.RegexPattern] = re.compile(SCHEMA_SYNTAX_LENGTH)
    SCHEMA_DEFINITION_PARENS_RE: ClassVar[t.RegexPattern] = re.compile(
        r"\(.*\)",
        re.DOTALL,
    )
    SCHEMA_EQUALITY_TOKEN_RE: ClassVar[t.RegexPattern] = re.compile(
        r"\bEQUALITY\b",
        re.IGNORECASE,
    )
    SCHEMA_SUBSTR_TOKEN_BARE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"\bSUBSTR\b",
        re.IGNORECASE,
    )
    SCHEMA_ORDERING_TOKEN_BARE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"\bORDERING\b",
        re.IGNORECASE,
    )
    SCHEMA_OBSOLETE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"\bOBSOLETE\b",
        re.IGNORECASE,
    )
    SCHEMA_TRAILING_PAREN_RE: ClassVar[t.RegexPattern] = re.compile(r"\)\s*$")
    SCHEMA_LEADING_PAREN_RE: ClassVar[t.RegexPattern] = re.compile(r"^\s*\(")
    WHITESPACE_TRAILING_RE: ClassVar[t.RegexPattern] = re.compile(r"(\s+)$")
    WHITESPACE_LEADING_RE: ClassVar[t.RegexPattern] = re.compile(r"(\s*)")
    OID_CAPTURE_NUMERIC_RE: ClassVar[t.RegexPattern] = re.compile(
        r"\(\s*([0-9.]+)(\s*)",
    )
    QUOTED_NAME_TRIPLE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"([\"'])([^\"']+)([\"'])",
    )
    SCHEMA_DESC_LOOSE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"DESC\s+([\"']?)([^\"']+)([\"']?)",
        re.IGNORECASE,
    )
    SCHEMA_SINGLE_VALUE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"SINGLE-VALUE",
        re.IGNORECASE,
    )
    SCHEMA_SUP_LOOSE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"SUP\s+([^\s]+)",
        re.IGNORECASE,
    )
    SCHEMA_SYNTAX_LOOSE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"SYNTAX\s*([\"']?)([0-9.]+)([\"']?)(\{[0-9]+\})?",
        re.IGNORECASE,
    )
    SCHEMA_X_ORIGIN_RE: ClassVar[t.RegexPattern] = re.compile(
        r"X-ORIGIN\s+([\"']?)([^\"']+)([\"']?)",
        re.IGNORECASE,
    )
    SCHEMA_NAME_LOOSE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"NAME\s+(\()?\s*([\"']?)([^\"'()]+)([\"']?)(\s*\))?",
    )
    SCHEMA_NAME_MULTIPLE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"NAME\s+\(\s*([\"'])([^\"']+)([\"'])\s+([\"'])([^\"']+)([\"'])",
    )
    QUOTED_SPACE_QUOTE_RE: ClassVar[t.RegexPattern] = re.compile(r"[\"']\s+([\"'])")
    LDIF_ATTR_TYPES_PREFIX_RE: ClassVar[t.RegexPattern] = re.compile(
        r"(attributetypes|attributeTypes):",
        re.IGNORECASE,
    )
    LDIF_OBJECTCLASSES_PREFIX_RE: ClassVar[t.RegexPattern] = re.compile(
        r"(objectclasses|objectClasses):",
        re.IGNORECASE,
    )
    ACI_MACRO_RE: ClassVar[t.RegexPattern] = re.compile(r"\(\$dn\)|\[\$dn\]|\(\$attr\.")
    ACL_NAME_QUOTED_RE: ClassVar[t.RegexPattern] = re.compile(r'acl\s+"[^"]*"')
    DN_SPLIT_OPTIONAL_SPACE_RE: ClassVar[t.RegexPattern] = re.compile(r"\s*,\s*")
    DN_SPLIT_UNESCAPED_COMMA_RE: ClassVar[t.RegexPattern] = re.compile(
        r"(?<!\\)\s*,\s*",
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

        Returns:
            The resulting ``t.RegexPattern``.
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

        Returns:
            The resulting ``str``.
        """
        return re.escape(value)

    sub_pattern = staticmethod(constants_sub_pattern)

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

    # ===== Binary-valued LDAP attribute names (ENFORCE-079 owner) =====
    BINARY_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset({
        "usercertificate",
        "cacertificate",
        "certificaterevocationlist",
        "authorityrevocationlist",
        "crosscertificatepair",
        "photo",
        "jpegphoto",
        "audio",
        "userpkcs12",
        "usersmimecertificate",
        "thumbnailphoto",
        "thumbnaillogo",
        "objectguid",
        "objectsid",
    })
    """Attribute names (compared lowercased) whose values are binary."""

    # ===== Server class-name suffixes (ENFORCE-079 owner) =====
    CLASS_SUFFIXES: ClassVar[tuple[str, ...]] = ("Acl", "Schema", "Entry", "Constants")
    """Class-name suffixes for independent-class server type detection."""

    # ===== Default ACL attribute names (ENFORCE-079 owner) =====
    DEFAULT_ACL_ATTRIBUTES: ClassVar[tuple[str, ...]] = ("acl", "aci", "olcAccess")
    """Attribute names probed for ACL entries by default."""

    # ===== Server validation capabilities (ENFORCE-079 owner) =====
    SERVER_VALIDATION_CAPABILITIES: ClassVar[
        Mapping[FlextLdifConstantsEnums.ServerTypes, frozenset[str]]
    ] = MappingProxyType({
        FlextLdifConstantsEnums.ServerTypes.OID: frozenset({
            "requires_objectclass",
            "requires_naming_attr",
            "requires_binary_option",
        }),
        FlextLdifConstantsEnums.ServerTypes.OUD: frozenset({
            "requires_objectclass",
            "requires_naming_attr",
            "requires_binary_option",
        }),
        FlextLdifConstantsEnums.ServerTypes.OPENLDAP: frozenset({
            "requires_binary_option",
        }),
        FlextLdifConstantsEnums.ServerTypes.OPENLDAP2: frozenset({
            "requires_binary_option",
        }),
        FlextLdifConstantsEnums.ServerTypes.AD: frozenset({
            "requires_objectclass",
            "requires_naming_attr",
        }),
        FlextLdifConstantsEnums.ServerTypes.DS389: frozenset({"requires_objectclass"}),
        FlextLdifConstantsEnums.ServerTypes.NOVELL: frozenset({"requires_objectclass"}),
        FlextLdifConstantsEnums.ServerTypes.IBM_TIVOLI: frozenset({
            "requires_objectclass",
        }),
    })
    """Validation features each server type supports."""

    # ===== Service registry name (ENFORCE-079 owner) =====
    SERVERS: ClassVar[str] = "ldif_servers"
    """Registry name for the LDIF server registry DSL."""

    RFC_ACL_ATTRIBUTES: Final[t.StrSequence] = (
        "aci",
        "acl",
        "olcAccess",
        "aclRights",
        "aclEntry",
    )

    ALL_DN_VALUED: Final[frozenset[str]] = frozenset((
        "member", "uniqueMember", "owner", "managedBy", "manager",
        "secretary", "seeAlso", "parent", "refersTo", "memberOf",
        "groups", "authorizedTo", "hasSubordinates", "subordinateDn",
    ))

    OID_TRUE: Final[str] = "1"

    OID_FALSE: Final[str] = "0"

    OID_BOOLEAN_ATTRIBUTES: Final[frozenset[str]] = frozenset({
        "orclisenabled",
        "orclaccountlocked",
        "orclpwdmustchange",
        "orclpasswordverify",
        "orclisvisible",
        "orclsamlenable",
        "orclsslenable",
        "orcldasenableproductlogo",
        "orcldasenablesubscriberlogo",
        "orcldasshowproductlogo",
        "orcldasenablebranding",
        "orcldasisenabled",
        "orcldasismandatory",
        "orcldasispersonal",
        "orcldassearchable",
        "orcldasselfmodifiable",
        "orcldasviewable",
        "orcldasadminmodifiable",
        "pwdlockout",
        "pwdmustchange",
        "pwdallowuserchange",
    })

    OID_TO_RFC_BOOL: Final[t.StrMapping] = MappingProxyType({
        OID_TRUE: TRUE_RFC,
        OID_FALSE: FALSE_RFC,
        "true": TRUE_RFC,
        "false": FALSE_RFC,
    })

    RFC_TO_OID_BOOL: Final[t.StrMapping] = MappingProxyType({
        TRUE_RFC: OID_TRUE,
        FALSE_RFC: OID_FALSE,
        "true": OID_TRUE,
        "false": OID_FALSE,
    })

    ATTRIBUTE_TRANSFORMATION_OID_TO_RFC: Final[t.StrMapping] = MappingProxyType({
        "orclguid": "entryUUID",
        "orclaci": "aci",
        "orclentrylevelaci": "aci",
    })

    ATTRIBUTE_TRANSFORMATION_RFC_TO_OID: Final[t.StrMapping] = MappingProxyType({
        "entryUUID": "orclguid",
        "aci": "orclaci",
    })

    ACL_PERMISSION_KEYS: Final[t.StrSequence] = (
        "read",
        "write",
        "add",
        "delete",
        "search",
        "compare",
        "self_write",
        "proxy",
        "browse",
        "auth",
        "all",
    )

    VALID_SERVER_TYPES: Final[frozenset[str]] = frozenset(
        server_type.value for server_type in FlextLdifConstantsEnums.ServerTypes
    )

    DETECTION_PATTERN_ATTR: Final[str] = "DETECTION_PATTERN"

    DETECTION_OID_PATTERN_ATTR: Final[str] = "DETECTION_OID_PATTERN"

    DETECTION_ACTIVE_DIRECTORY_ATTRIBUTE: Final[str] = "samaccountname"

    DETECTION_ACTIVE_DIRECTORY_DESCRIPTION: Final[str] = "Active Directory attributes"

    DETECTION_OID_ACL_DESCRIPTION: Final[str] = "Oracle OID ACLs"

    DETECTION_SCORE_SPECS: Final[
        tuple[tuple[FlextLdifConstantsEnums.ServerTypes, str, bool], ...]
    ] = (
        (FlextLdifConstantsEnums.ServerTypes.OID, DETECTION_OID_PATTERN_ATTR, True),
        (FlextLdifConstantsEnums.ServerTypes.OUD, DETECTION_OID_PATTERN_ATTR, False),
        (FlextLdifConstantsEnums.ServerTypes.OPENLDAP, DETECTION_PATTERN_ATTR, True),
        (FlextLdifConstantsEnums.ServerTypes.AD, DETECTION_PATTERN_ATTR, True),
        (FlextLdifConstantsEnums.ServerTypes.NOVELL, DETECTION_PATTERN_ATTR, False),
        (FlextLdifConstantsEnums.ServerTypes.IBM_TIVOLI, DETECTION_PATTERN_ATTR, False),
        (FlextLdifConstantsEnums.ServerTypes.DS389, DETECTION_PATTERN_ATTR, False),
        (FlextLdifConstantsEnums.ServerTypes.APACHE, DETECTION_PATTERN_ATTR, False),
    )

    DETECTION_PATTERN_SPECS: Final[
        tuple[tuple[FlextLdifConstantsEnums.ServerTypes, str, str, bool], ...]
    ] = (
        (
            FlextLdifConstantsEnums.ServerTypes.OID,
            DETECTION_OID_PATTERN_ATTR,
            "Oracle OID namespace (2.16.840.1.113894.*)",
            True,
        ),
        (
            FlextLdifConstantsEnums.ServerTypes.OUD,
            DETECTION_OID_PATTERN_ATTR,
            "Oracle OUD attributes (ds-sync-*)",
            False,
        ),
        (
            FlextLdifConstantsEnums.ServerTypes.OPENLDAP,
            DETECTION_PATTERN_ATTR,
            "OpenLDAP configuration (olc*)",
            True,
        ),
        (
            FlextLdifConstantsEnums.ServerTypes.AD,
            DETECTION_OID_PATTERN_ATTR,
            "Active Directory namespace (1.2.840.113556.*)",
            True,
        ),
        (
            FlextLdifConstantsEnums.ServerTypes.NOVELL,
            DETECTION_PATTERN_ATTR,
            "Novell eDirectory attributes (GUID, Modifiers, etc.)",
            False,
        ),
        (
            FlextLdifConstantsEnums.ServerTypes.DS389,
            DETECTION_PATTERN_ATTR,
            "389 Directory Server attributes (389ds, redhat-ds, dirsrv)",
            False,
        ),
        (
            FlextLdifConstantsEnums.ServerTypes.APACHE,
            DETECTION_PATTERN_ATTR,
            "Apache DS attributes (apacheDS, apache-*)",
            False,
        ),
        (
            FlextLdifConstantsEnums.ServerTypes.IBM_TIVOLI,
            DETECTION_PATTERN_ATTR,
            "IBM Tivoli attributes (ibm-*, tivoli, ldapdb)",
            False,
        ),
    )

    PROCESSING_STAGE_NORMALIZE_DN: Final[str] = "normalize_dn"

    PROCESSING_STAGE_NORMALIZE_ATTRS: Final[str] = "normalize_attrs"

    PROCESSING_STAGE_SERVER_TRANSFORM: Final[str] = "server_transform"

    ENTRY_OPERATION_REMOVE_ATTRIBUTES: Final[str] = "remove_attributes"

    CATEGORY_BUCKET_ORDER: Final[tuple[FlextLdifConstantsEnums.Category, ...]] = (
        FlextLdifConstantsEnums.Category.SCHEMA,
        FlextLdifConstantsEnums.Category.HIERARCHY,
        FlextLdifConstantsEnums.Category.USERS,
        FlextLdifConstantsEnums.Category.GROUPS,
        FlextLdifConstantsEnums.Category.ACL,
        FlextLdifConstantsEnums.Category.REJECTED,
    )

    CATEGORY_FILTERABLE_BY_BASE_DN: Final[
        frozenset[FlextLdifConstantsEnums.Category]
    ] = frozenset({
        FlextLdifConstantsEnums.Category.HIERARCHY,
        FlextLdifConstantsEnums.Category.USERS,
        FlextLdifConstantsEnums.Category.GROUPS,
        FlextLdifConstantsEnums.Category.ACL,
    })

    CATEGORY_VALUES: Final[frozenset[str]] = frozenset(
        category.value for category in FlextLdifConstantsEnums.Category
    )

    DEFAULT_CATEGORIZATION_PRIORITY: Final[
        tuple[FlextLdifConstantsEnums.Category, ...]
    ] = (
        FlextLdifConstantsEnums.Category.HIERARCHY,
        FlextLdifConstantsEnums.Category.USERS,
        FlextLdifConstantsEnums.Category.GROUPS,
        FlextLdifConstantsEnums.Category.ACL,
    )

    CATEGORY_RULE_OBJECTCLASS_FIELDS: Final[t.MappingKV[str, str]] = MappingProxyType({
        FlextLdifConstantsEnums.Category.HIERARCHY: ("hierarchy_objectclasses"),
        FlextLdifConstantsEnums.Category.USERS: "user_objectclasses",
        FlextLdifConstantsEnums.Category.GROUPS: "group_objectclasses",
    })

    CATEGORY_RULE_ATTRIBUTE_FIELDS: Final[t.MappingKV[str, str]] = MappingProxyType({
        FlextLdifConstantsEnums.Category.ACL: "acl_attributes",
    })

    CATEGORY_ATTRIBUTE_MARKER_PREFIX: Final[str] = "attr:"

    DN_PREVIEW_LENGTH: Final[int] = 100

    EMPTY_STR_FROZENSET: Final[frozenset[str]] = frozenset()

    MATCHING_RULES: Final[str] = "matchingRules"

    MATCHING_RULE_USE: Final[str] = "matchingRuleUse"

    LDAP_SYNTAXES: Final[str] = "ldapSyntaxes"

    SCHEMA_OID_ATTRIBUTE_KEYS: Final[t.StrPairTuple] = (
        (ATTRIBUTE_TYPES, "attributetypes"),
        (OBJECT_CLASSES, "objectclasses"),
        (MATCHING_RULES, "matchingrules"),
        (MATCHING_RULE_USE, "matchingruleuse"),
        (LDAP_SYNTAXES, "ldapsyntaxes"),
    )

    SCHEMA_CATEGORY_ATTRIBUTE_KEYS: Final[frozenset[str]] = frozenset(
        key_pair[1] for key_pair in SCHEMA_OID_ATTRIBUTE_KEYS
    )

    OID_SCHEMA_DN: Final[str] = "cn=subschemasubentry"

    RFC_SCHEMA_DN: Final[str] = "cn=schema"

    SCHEMA_DN_MARKERS: Final[frozenset[str]] = frozenset({
        OID_SCHEMA_DN,
        "cn=subschema",
        RFC_SCHEMA_DN,
    })

    SCHEMA_OBJECTCLASS_MARKERS: Final[frozenset[str]] = frozenset({
        "subschema",
        "subentry",
    })

    WHITELIST_RULE_OID_FIELDS: Final[t.StrSequence] = (
        "allowed_attribute_oids",
        "allowed_objectclass_oids",
        "allowed_matchingrule_oids",
        "allowed_matchingruleuse_oids",
        "allowed_ldapsyntax_oids",
    )

    WHITELIST_RULE_SCHEMA_ATTRIBUTE_KEYS: Final[tuple[tuple[str, str], ...]] = tuple(
        (field_name, attr_keys[1])
        for field_name, attr_keys in zip(
            WHITELIST_RULE_OID_FIELDS,
            SCHEMA_OID_ATTRIBUTE_KEYS,
            strict=True,
        )
    )

    REJECTION_REASON_NO_CATEGORY_MATCH: Final[str] = "No category match"

    ERR_FAILED_NORMALIZE_RULES: Final[str] = "Failed to normalize rules"

    ERR_FAILED_FILTER_ENTRIES: Final[str] = "Failed to filter entries"

    ERR_SERVER_REGISTRY_UNAVAILABLE: Final[str] = "Server registry not available"

    ERR_UNKNOWN: Final[str] = "Unknown error"

    BINARY_SYNTAX = "binary"

    OID_TO_NAME: ClassVar[t.StrMapping] = MappingProxyType({
        "2.5.5.5": "integer",
        "1.3.6.1.4.1.1466.115.121.1.1": "aci",
        "1.3.6.1.4.1.1466.115.121.1.2": "access_point",
        "1.3.6.1.4.1.1466.115.121.1.3": "attribute_type_description",
        "1.3.6.1.4.1.1466.115.121.1.4": "audio",
        "1.3.6.1.4.1.1466.115.121.1.5": "binary",
        "1.3.6.1.4.1.1466.115.121.1.6": "bit_string",
        "1.3.6.1.4.1.1466.115.121.1.7": "boolean",
        "1.3.6.1.4.1.1466.115.121.1.8": "certificate",
        "1.3.6.1.4.1.1466.115.121.1.9": "certificate_list",
        "1.3.6.1.4.1.1466.115.121.1.10": "certificate_pair",
        "1.3.6.1.4.1.1466.115.121.1.11": "country_string",
        "1.3.6.1.4.1.1466.115.121.1.12": "dn",
        "1.3.6.1.4.1.1466.115.121.1.13": "data_quality_syntax",
        "1.3.6.1.4.1.1466.115.121.1.14": "delivery_method",
        "1.3.6.1.4.1.1466.115.121.1.15": "directory_string",
        "1.3.6.1.4.1.1466.115.121.1.16": "dit_content_rule_description",
        "1.3.6.1.4.1.1466.115.121.1.17": "dit_structure_rule_description",
        "1.3.6.1.4.1.1466.115.121.1.18": "dlexp_time",
        "1.3.6.1.4.1.1466.115.121.1.19": "dn_with_binary",
        "1.3.6.1.4.1.1466.115.121.1.20": "dn_with_string",
        "1.3.6.1.4.1.1466.115.121.1.21": "directory_string",
        "1.3.6.1.4.1.1466.115.121.1.22": "enhanced_guide",
        "1.3.6.1.4.1.1466.115.121.1.23": "facsimile_telephone_number",
        "1.3.6.1.4.1.1466.115.121.1.24": "fax",
        "1.3.6.1.4.1.1466.115.121.1.25": "generalized_time",
        "1.3.6.1.4.1.1466.115.121.1.26": "guide",
        "1.3.6.1.4.1.1466.115.121.1.27": "ia5_string",
        "1.3.6.1.4.1.1466.115.121.1.28": "jpeg",
        "1.3.6.1.4.1.1466.115.121.1.29": "ldap_syntax_description",
        "1.3.6.1.4.1.1466.115.121.1.30": "matching_rule_description",
        "1.3.6.1.4.1.1466.115.121.1.31": "matching_rule_use_description",
        "1.3.6.1.4.1.1466.115.121.1.32": "mhs_or_address",
        "1.3.6.1.4.1.1466.115.121.1.33": "modify_increment",
        "1.3.6.1.4.1.1466.115.121.1.34": "name_and_optional_uid",
        "1.3.6.1.4.1.1466.115.121.1.35": "name_form_description",
        "1.3.6.1.4.1.1466.115.121.1.36": "numeric_string",
        "1.3.6.1.4.1.1466.115.121.1.37": "object_class_description",
        "1.3.6.1.4.1.1466.115.121.1.38": "oid",
        "1.3.6.1.4.1.1466.115.121.1.39": "octet_string",
        "1.3.6.1.4.1.1466.115.121.1.40": "other_mailbox",
        "1.3.6.1.4.1.1466.115.121.1.41": "postal_address",
        "1.3.6.1.4.1.1466.115.121.1.42": "protocol_information",
        "1.3.6.1.4.1.1466.115.121.1.43": "presentation_address",
        "1.3.6.1.4.1.1466.115.121.1.44": "printable_string",
        "1.3.6.1.4.1.1466.115.121.1.50": "telephone_number",
        "1.3.6.1.4.1.1466.115.121.1.51": "teletex_terminal_identifier",
        "1.3.6.1.4.1.1466.115.121.1.52": "telex_number",
        "1.3.6.1.4.1.1466.115.121.1.53": "time_of_day",
        "1.3.6.1.4.1.1466.115.121.1.54": "utctime",
        "1.3.6.1.4.1.1466.115.121.1.55": "utf8_string",
        "1.3.6.1.4.1.1466.115.121.1.56": "unicode_string",
        "1.3.6.1.4.1.1466.115.121.1.57": "uui",
        "1.3.6.1.4.1.1466.115.121.1.58": "substring_assertion",
    })

    NAME_TO_TYPE_CATEGORY: Final[t.StrMapping] = MappingProxyType({
        "integer": "integer",
        "boolean": "boolean",
        "distinguished_name": "dn",
        "dn": "dn",
        "generalized_time": "time",
        "utc_time": "time",
        "binary": "binary",
        "octet_string": "binary",
        "directory_string": "string",
        "ia5_string": "string",
        "printable_string": "string",
        "numeric_string": "string",
        "telephone_number": "string",
        "mail_preference": "string",
        "other_mailbox": "string",
        "postal_address": "string",
        "country_string": "string",
        "dn_qualifier": "string",
        "certificate": "binary",
        "certificate_list": "binary",
        "certificate_pair": "binary",
        "supported_algorithm": "binary",
        "dsa_quality": "string",
        "data_quality_syntax": "binary",
        "dsi_mods": "binary",
        "entry_information_information": "binary",
        "facsimile_telephone_number": "string",
        "fax": "binary",
        "jpeg": "binary",
        "master_and_shadow_access_points": "dn",
        "name_and_optional_uid": "string",
        "name_forms": "string",
        "nis_netgroup_triple": "string",
        "object_class_description": "string",
        "oid": "string",
        "presentation_address": "binary",
        "protocol_information": "binary",
        "substring_assertion": "string",
        "teletex_terminal_identifier": "string",
        "telex_number": "string",
        "unique_member": "dn",
        "user_password": BINARY_SYNTAX,
        "user_certificate": "binary",
        "ca_certificate": "binary",
        "authority_revocation_list": "binary",
        "certificate_revocation_list": "binary",
        "cross_certificate_pair": "binary",
        "delta_revocation_list": "binary",
        "dit_content_rule_description": "string",
        "dit_structure_rule_description": "string",
        "dse_type": "string",
        "ldap_syntax_description": "string",
        "matching_rule_description": "string",
        "matching_rule_use_description": "string",
        "name_form_description": "string",
        "subschema": "binary",
        "access_point": "dn",
        "attribute_type_description": "string",
        "audio": "binary",
        "bit_string": "string",
        "aci": "string",
        "utf8_string": "string",
        "unicode_string": "string",
        "uui": "string",
    })

    DEFAULT_ENCODING: Final[str] = FlextLdifConstantsEnums.Encoding.UTF8.value

    DEFAULT_STRICT_VALIDATION: Final[bool] = True

    UNKNOWN_VALUE: Final[str] = "unknown"

    ASCII_THRESHOLD: Final[int] = 127
