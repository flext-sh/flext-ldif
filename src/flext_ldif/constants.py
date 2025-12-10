"""LDIF constants and enumerations.

This module defines constant values and enumerations used throughout the
LDIF library. Types, protocols, and models are defined in separate modules.

Python 3.13+ strict features:
- PEP 695 type aliases (type keyword) - no TypeAlias
- collections.abc for type hints (preferred over typing)
- StrEnum for type-safe string enums
- Literal types derived from StrEnum values

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from types import MappingProxyType
from typing import ClassVar, Final, Literal

from flext_core import FlextConstants

# Validation level literal - no corresponding StrEnum (uses hardcoded strings)
type ValidationLevelLiteral = Literal["strict", "moderate", "lenient"]


class FlextLdifConstants(FlextConstants):
    """LDIF domain constants extending flext-core FlextConstants.

    Contains ONLY constant values, no implementations.
    DRY Pattern: Base string constants defined first, then reused in StrEnum.

    Architecture:
    - All LDIF constants are organized in the .Ldif namespace
    - Direct access via c.* (ALWAYS use namespace completo)
    - Root aliases are PROIBIDOS - always use c.* following FLEXT architecture patterns
    """

    # =========================================================================
    # NAMESPACE: .Ldif - All LDIF domain constants
    # =========================================================================

    class Ldif:
        """LDIF domain constants namespace.

        All LDIF-specific constants are organized here for better namespace
        organization and to enable composition with other domain constants.
        """

        # =========================================================================
        # BASE STRING CONSTANTS (Single Source of Truth - DRY)
        # =========================================================================
        # FORMAT CONSTANTS
        # =============================================================================

        # NOTE: ORACLE_OID_NAMESPACE removed - server-specific constants belong in quirks
        # OID-specific constants should be defined in src/flext_ldif/servers/oid.py

        # NOTE: LdapServerType removed - use ServerTypes instead (canonical source)
        # LdapServerType was duplicate of ServerTypeEnum - consolidated to ServerTypes

        class SortStrategy(StrEnum):
            """Valid sorting strategies for LDIF entries (V2 type-safe enum).

            DRY Pattern:
                StrEnum is the single source of truth. Use SortStrategy.HIERARCHY.value
                or SortStrategy.HIERARCHY directly - no base strings needed.
            """

            HIERARCHY = "hierarchy"
            DN = "dn"
            ALPHABETICAL = "alphabetical"
            SCHEMA = "schema"
            CUSTOM = "custom"

        class SortingStrategyType(StrEnum):
            """Sorting strategy types for metadata tracking.

            DRY Pattern:
                StrEnum is the single source of truth. Use SortingStrategyType.ALPHABETICAL_CASE_SENSITIVE.value
                or SortingStrategyType.ALPHABETICAL_CASE_SENSITIVE directly - no base strings needed.
            """

            ALPHABETICAL_CASE_SENSITIVE = "alphabetical_case_sensitive"
            ALPHABETICAL_CASE_INSENSITIVE = "alphabetical_case_insensitive"
            CUSTOM_ORDER = "custom_order"

        class SortTarget(StrEnum):
            """What to sort in LDIF data (V2 type-safe enum).

            DRY Pattern:
                StrEnum is the single source of truth. Use SortTarget.ENTRIES.value
                or SortTarget.ENTRIES directly - no base strings needed.
            """

            ENTRIES = "entries"
            ATTRIBUTES = "attributes"
            ACL = "acl"
            SCHEMA = "schema"
            COMBINED = "combined"

        # ===== RFC 4876 ACL PERMISSION ENUMS (Type-Safe) =====
        class RfcAclPermission(StrEnum):
            """RFC 4876 standard ACL permissions (type-safe enum).

            Base permissions supported by all RFC-compliant LDAP servers.
            Server-specific extensions defined in respective server Constants classes:
            - OUD: FlextLdifServersOud.Constants.OudPermission
            - Other servers: Check respective server Constants classes

            DRY Pattern:
                StrEnum is the single source of truth. Use RfcAclPermission.READ.value
                or RfcAclPermission.READ directly - no base strings needed.
            """

            READ = "read"
            WRITE = "write"
            ADD = "add"
            DELETE = "delete"
            SEARCH = "search"
            COMPARE = "compare"
            ALL = "all"
            NONE = "none"

        # ===== COMPREHENSIVE ACL PERMISSION ENUMS (Type-Safe) =====
        class AclPermission(StrEnum):
            """Comprehensive ACL permissions covering all server types (type-safe enum).

            This enum consolidates all ACL permissions from RFC and
            server-specific implementations. Use this for type-safe ACL
            permission handling across all server types.

            Python 3.13+ StrEnum with Pydantic 2 compatibility.

            DRY Pattern:
                StrEnum is the single source of truth. Use AclPermission.READ.value
                or AclPermission.READ directly - no base strings needed.
            """

            # RFC 4876 base permissions
            READ = "read"
            WRITE = "write"
            ADD = "add"
            DELETE = "delete"
            SEARCH = "search"
            COMPARE = "compare"
            ALL = "all"
            NONE = "none"

            # Server-specific extensions
            AUTH = "auth"
            CREATE = "create"
            CONTROL_ACCESS = "control_access"

        # ===== ACL ACTION ENUMS (Type-Safe) =====
        class AclAction(StrEnum):
            """ACL action types for all server implementations (type-safe enum).

            This enum consolidates all ACL action types from server implementations.
            Use this for type-safe ACL action handling across all server types.

            DRY Pattern:
                StrEnum is the single source of truth. Use AclAction.ALLOW.value
                or AclAction.ALLOW directly - no base strings needed.

            Python 3.13+ StrEnum with Pydantic 2 compatibility.
            """

            ALLOW = "allow"
            DENY = "deny"

        # ===== CHARACTER ENCODING ENUMS (Type-Safe) =====
        class Encoding(StrEnum):
            """Standard character encodings used in LDIF processing.

            Maps to Python codec names for encoding/decoding operations.
            Server-specific encodings (if any) defined in respective server
            Constants.

            DRY Pattern:
                StrEnum is the single source of truth. Use Encoding.UTF8.value
                or Encoding.UTF8 directly - no base strings needed.
            """

            UTF8 = "utf-8"
            UTF16LE = "utf-16-le"
            UTF16 = "utf-16"
            UTF32 = "utf-32"
            ASCII = "ascii"
            LATIN1 = "latin-1"
            CP1252 = "cp1252"
            ISO8859_1 = "iso-8859-1"

        # Encoding constants - derived from Encoding StrEnum (lines 199-218)
        # Reuse DEFAULT_ENCODING from flext-core (no duplication)
        DEFAULT_ENCODING: Final[str] = FlextConstants.Utilities.DEFAULT_ENCODING
        # Supported encodings - derived from Encoding StrEnum for DRY principle
        # Uses comprehension over StrEnum members instead of explicit listing

        # ===== RFC 2849 LDIF FORMAT CONSTANTS =====
        class LdifFormat(StrEnum):
            """RFC 2849 LDIF format indicators for attribute value encoding.

            - REGULAR: Single colon (:) for regular text values
            - BASE64: Double colon (::) for base64-encoded values
            (UTF-8, binary, special chars)
            - URL: Less than and colon (:<) for URL-referenced values

            Per RFC 2849 Section 2:
            - Use :: when value contains non-ASCII, leading/trailing space, or special chars
            - Base64 encoding preserves exact byte sequence for round-trip

            DRY Pattern:
                StrEnum is the single source of truth. Use LdifFormat.REGULAR.value
                or LdifFormat.REGULAR directly - no base strings needed.
            """

            REGULAR = ":"
            BASE64 = "::"
            URL = ":<"

        # LDIF format detection constants - derived from LdifFormat StrEnum (lines 237-256)
        # Values match LdifFormat enum members for DRY principle
        LDIF_BASE64_INDICATOR: Final[str] = LdifFormat.BASE64.value
        LDIF_REGULAR_INDICATOR: Final[str] = LdifFormat.REGULAR.value
        LDIF_URL_INDICATOR: Final[str] = LdifFormat.URL.value
        # Default encoding - reuse from flext-core (no duplication)
        LDIF_DEFAULT_ENCODING: Final[str] = FlextConstants.Utilities.DEFAULT_ENCODING

        # ===== ACL SUBJECT TYPE ENUMS (Type-Safe) =====
        class AclSubjectType(StrEnum):
            """ACL subject/who types for permission subjects.

            Identifies what entity the ACL permission applies to.
            Server-specific extensions in respective server Constants.

            DRY Pattern:
                StrEnum is the single source of truth. Use AclSubjectType.USER.value
                or AclSubjectType.USER directly - no base strings needed.
            """

            USER = "user"
            GROUP = "group"
            ROLE = "role"
            SELF = "self"
            ALL = "all"
            PUBLIC = "public"
            ANONYMOUS = "anonymous"
            AUTHENTICATED = "authenticated"
            SDDL = "sddl"  # Active Directory SDDL format

        class DictKeys(StrEnum):
            """Dictionary keys for LDIF entry data access - CORE KEYS ONLY per SRP.

            IMPORTANT: This class contains ONLY core LDIF/entry keys.
            Server-specific keys → QuirkMetadataKeys
            ACL keys → AclKeys

            DRY Pattern:
                StrEnum is the single source of truth. Use DictKeys.DN.value
                or DictKeys.DN directly - no base strings needed.
            """

            # Core entry and LDIF keys (63+ usages)
            DN = "dn"
            ATTRIBUTES = "attributes"
            OBJECTCLASS = "objectClass"
            CN = "cn"
            OID = "oid"

            # NOTE: Removed server-specific keys (use QuirkMetadataKeys instead):
            # SERVER_TYPE, IS_CONFIG_ENTRY, IS_TRADITIONAL_DIT

            # NOTE: Removed ACL keys (use AclKeys instead):
            # ACL_ATTRIBUTE, ACI, ACCESS, OLCACCESS, NTSECURITYDESCRIPTOR, HAS_OID_ACLS

            # NOTE: Removed service keys (use local constants in respective modules):
            # SERVICE_NAMES, INITIALIZED, DATA

        class Domain(FlextConstants.Domain):
            """Domain constants extending FlextConstants.Domain.

            Extends base domain with LDIF-specific enums.
            """

            class ServerType(StrEnum):
                """Server type values for LDIF processing.

                DRY Pattern:
                    StrEnum is the single source of truth. Use ServerType.OUD.value
                    or ServerType.OUD directly - no base strings needed.
                """

                OUD = "oud"
                OID = "oid"
                RFC = "rfc"
                AD = "ad"
                OPENLDAP = "openldap"
                OPENLDAP1 = "openldap1"
                OPENLDAP2 = "openldap2"
                DS389 = "ds389"
                APACHE = "apache"
                NOVELL = "novell"
                IBM_TIVOLI = "tivoli"
                RELAXED = "relaxed"

            class ValidationStatus(StrEnum):
                """Validation status values for LDIF entries.

                DRY Pattern:
                    StrEnum is the single source of truth. Use ValidationStatus.VALID.value
                    or ValidationStatus.VALID directly - no base strings needed.
                """

                VALID = "valid"
                INVALID = "invalid"
                WARNING = "warning"

            class CaseFoldOption(StrEnum):
                """Case folding options for DN normalization."""

                NONE = "none"
                LOWER = "lower"
                UPPER = "upper"

            class QuirkMetadataKeys(StrEnum):
                """Dictionary keys for quirk metadata and server-specific entry properties.

                Used in Entry.metadata.extensions for server-specific attributes.
                Consolidates server-specific entry properties per SRP.

                DRY Pattern:
                    StrEnum is the single source of truth. Use QuirkMetadataKeys.SERVER_TYPE.value
                    or QuirkMetadataKeys.SERVER_TYPE directly - no base strings needed.
                """

                # Quirk metadata keys (20 usages across server quirks)
                SERVER_TYPE = "server_type"
                IS_CONFIG_ENTRY = "is_config_entry"
                IS_TRADITIONAL_DIT = "is_traditional_dit"

            class AclKeys(StrEnum):
                """Dictionary keys for ACL-related attributes and operations.

                Used in ACL parsing, writing, and entry processing across server quirks.
                Consolidates ACL-specific keys per SRP.

                DRY Pattern:
                    StrEnum is the single source of truth. Use AclKeys.ACL_ATTRIBUTE.value
                    or AclKeys.ACL_ATTRIBUTE directly - no base strings needed.
                """

                # ACL attribute keys (11 usages across server ACL quirks)
                ACL_ATTRIBUTE = "acl"
                ACI = "aci"
                ACCESS = "access"
                # NOTE: Server-specific ACL attributes moved to their Constants:
                # - OLCACCESS → FlextLdifServersOpenldap.Constants.ACL_ATTRIBUTE_NAME
                # - NTSECURITYDESCRIPTOR → FlextLdifServersAd.Constants.ACL_ATTRIBUTE_NAME

        class Format:
            """LDIF format specifications."""

            DN_ATTRIBUTE: Final[str] = "dn"
            ATTRIBUTE_SEPARATOR: Final[str] = ":"

            # LDIF ObjectClass constants
            LDIF_OBJECTCLASS_GROUPOFNAMES: Final[str] = "groupOfNames"

            # Line length constraints (RFC 2849 compliance)
            MIN_LINE_LENGTH: Final[int] = 40  # Minimum allowed line length
            MAX_LINE_LENGTH: Final[int] = 78  # RFC 2849 standard
            MAX_LINE_LENGTH_EXTENDED: Final[int] = 200  # Extended for non-strict mode

            MIN_BUFFER_SIZE: Final[int] = 1024
            CONTENT_PREVIEW_LENGTH: Final[int] = 100
            MINIMAL_DIFF_PREVIEW_LENGTH: Final[int] = 50
            MAX_ATTRIBUTES_DISPLAY: Final[int] = 10

            # Filesystem constraints
            MAX_FILENAME_LENGTH: Final[int] = 255  # Common filesystem limit

            # RFC 2849 specific constants
            BASE64_PREFIX: Final[str] = "::"
            COMMENT_PREFIX: Final[str] = "#"
            VERSION_PREFIX: Final[str] = "version:"
            CHANGE_TYPE_PREFIX: Final[str] = "changetype:"
            ATTRIBUTE_OPTION_SEPARATOR: Final[str] = ";"
            URL_PREFIX: Final[str] = "<"
            URL_SUFFIX: Final[str] = ">"

            # LDIF version constants
            LDIF_VERSION_1: Final[str] = "1"
            DEFAULT_LDIF_VERSION: Final[str] = LDIF_VERSION_1

            class Rfc:
                """RFC 2849/4512/4514 Standard Constants.

                Official IETF RFC specifications for LDAP/LDIF processing.
                All constants derived from official RFC documents.

                References:
                    RFC 2849: LDIF Data Interchange Format
                    RFC 4512: LDAP Directory Information Models
                    RFC 4514: LDAP Distinguished Names
                    RFC 4517: LDAP Syntaxes and Matching Rules

                """

            # =================================================================
            # RFC 2849: LDIF Data Interchange Format
            # =================================================================

            # RFC 2849 §2 - Characters requiring base64 encoding at value start
            # "The distinguishing characteristic of an LDIF file is that it
            #  begins with a version number."

            # RFC 2849 §2 - SAFE-CHAR range (no base64 needed)
            # SAFE-CHAR = %x01-09 / %x0B-0C / %x0E-7F (all but NUL, LF, CR)
            SAFE_CHAR_MIN: Final[int] = 0x01
            SAFE_CHAR_MAX: Final[int] = 0x7F
            SAFE_CHAR_EXCLUDE: Final[frozenset[int]] = frozenset({0x00, 0x0A, 0x0D})

            # RFC 2849 §2 - SAFE-INIT-CHAR (valid first character of SAFE-STRING)
            # SAFE-INIT-CHAR = %x01-09 / %x0B-0C / %x0E-1F / %x21-39 / %x3B / %x3D-7F
            # Excludes: NUL, LF, CR, SPACE(0x20), COLON(0x3A), LESSTHAN(0x3C)
            SAFE_INIT_CHAR_EXCLUDE: Final[frozenset[int]] = frozenset({
                0x00,
                0x0A,
                0x0D,
                0x20,
                0x3A,
                0x3C,
            })

            # RFC 2849 §2 - BASE64-CHAR (StrEnum Source of Truth)
            # Note: BASE64 characters enumerated per RFC 2849 §2
            # BASE64-CHAR = %x2B / %x2F / %x30-39 / %x3D / %x41-5A / %x61-7A
            # Using frozenset of string directly for efficiency
            BASE64_CHARS: Final[frozenset[str]] = frozenset(
                "+/0123456789=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            )

            # RFC 2849 §2 - Characters at Start (StrEnum Source of Truth)
            class Base64StartChar(StrEnum):
                """RFC 2849 §2 - Characters requiring base64 encoding at value start."""

                SPACE = " "  # ASCII 32 - space at start
                LANGLE = "<"  # Less-than sign (URL indicator conflict)
                COLON = ":"  # Colon (separator conflict)

            # RFC 2849 §2 - Characters requiring base64 encoding at value start
            # SAFE-INIT-CHAR excludes these at position 0
            BASE64_START_CHARS: Final[frozenset[str]] = frozenset({
                Base64StartChar.SPACE,
                Base64StartChar.LANGLE,
                Base64StartChar.COLON,
            })

            # RFC 2849 §3 - Line folding constants
            LINE_FOLD_WIDTH: Final[int] = 76  # Max chars before fold
            LINE_CONTINUATION_SPACE: Final[str] = " "  # Single space for continuation
            LINE_SEPARATOR: Final[str] = "\n"  # Unix line ending (default)

            # RFC 2849 §3 - LDIF separators
            ENTRY_SEPARATOR: Final[str] = "\n\n"  # Empty line between entries
            ATTR_SEPARATOR: Final[str] = ":"  # attribute: value
            BASE64_SEPARATOR: Final[str] = "::"  # attribute:: base64value
            URL_SEPARATOR: Final[str] = ":<"  # attribute:< url

            # RFC 2849 §4 - Change record types
            # RFC 2849 §4 - Modify operation types (see ModifyOperation StrEnum)

            # RFC 2849 §5 - Control record keywords
            KEYWORD_DN: Final[str] = "dn"
            KEYWORD_CHANGETYPE: Final[str] = "changetype"
            KEYWORD_CONTROL: Final[str] = "control"
            KEYWORD_NEWRDN: Final[str] = "newrdn"
            KEYWORD_DELETEOLDRDN: Final[str] = "deleteoldrdn"
            KEYWORD_NEWSUPERIOR: Final[str] = "newsuperior"

            # =================================================================
            # RFC 4512: LDAP Directory Information Models
            # =================================================================

            # RFC 4512 §4.1 - Schema usage values (see SchemaUsage StrEnum)

            # RFC 4512 §4.1.1 - ObjectClass kinds (see SchemaKind StrEnum)

            # RFC 4512 - ABNF Syntax Characters
            # WSP = 0*SPACE, SP = 1*SPACE, SPACE = %x20
            SCHEMA_WSP: Final[str] = " "  # Whitespace (0 or more spaces)
            SCHEMA_SPACE: Final[str] = " "  # Single space %x20

            # RFC 4512 - ABNF Delimiters
            SCHEMA_LPAREN: Final[str] = "("  # Left parenthesis %x28
            SCHEMA_RPAREN: Final[str] = ")"  # Right parenthesis %x29
            SCHEMA_SQUOTE: Final[str] = "'"  # Single quote %x27
            SCHEMA_DQUOTE: Final[str] = '"'  # Double quote %x22
            SCHEMA_LCURLY: Final[str] = "{"  # Left curly brace %x7B
            SCHEMA_RCURLY: Final[str] = "}"  # Right curly brace %x7D
            SCHEMA_DOLLAR: Final[str] = "$"  # Dollar sign %x24

            # RFC 4512 §4.1 - Schema extension prefix (X-<name>)
            SCHEMA_EXTENSION_PREFIX: Final[str] = "X-"

            # RFC 4512 §4.1 - Schema definition keywords
            SCHEMA_KW_OBSOLETE: Final[str] = "OBSOLETE"
            SCHEMA_KW_SUP: Final[str] = "SUP"
            SCHEMA_KW_EQUALITY: Final[str] = "EQUALITY"
            SCHEMA_KW_ORDERING: Final[str] = "ORDERING"
            SCHEMA_KW_SUBSTR: Final[str] = "SUBSTR"
            SCHEMA_KW_SYNTAX: Final[str] = "SYNTAX"
            SCHEMA_KW_SINGLE_VALUE: Final[str] = "SINGLE-VALUE"
            SCHEMA_KW_COLLECTIVE: Final[str] = "COLLECTIVE"
            SCHEMA_KW_NO_USER_MODIFICATION: Final[str] = "NO-USER-MODIFICATION"
            SCHEMA_KW_USAGE: Final[str] = "USAGE"
            SCHEMA_KW_MUST: Final[str] = "MUST"
            SCHEMA_KW_MAY: Final[str] = "MAY"
            SCHEMA_KW_APPLIES: Final[str] = "APPLIES"
            SCHEMA_KW_AUX: Final[str] = "AUX"
            SCHEMA_KW_NOT: Final[str] = "NOT"
            SCHEMA_KW_OC: Final[str] = "OC"
            SCHEMA_KW_FORM: Final[str] = "FORM"

            # RFC 4512 §4.2.1 - Standard operational attributes
            ATTR_CREATORS_NAME: Final[str] = "creatorsName"
            ATTR_CREATE_TIMESTAMP: Final[str] = "createTimestamp"
            ATTR_MODIFIERS_NAME: Final[str] = "modifiersName"
            ATTR_MODIFY_TIMESTAMP: Final[str] = "modifyTimestamp"
            ATTR_STRUCTURAL_OBJECTCLASS: Final[str] = "structuralObjectClass"
            ATTR_GOVERNING_STRUCTURE_RULE: Final[str] = "governingStructureRule"
            ATTR_SUBSCHEMA_SUBENTRY: Final[str] = "subschemaSubentry"
            ATTR_ENTRY_DN: Final[str] = "entryDN"

            # RFC 4512 §4.2.1 - Operational attributes as StrEnum
            class OperationalAttribute(StrEnum):
                """RFC 4512 §4.2.1 - Standard operational attributes."""

                CREATORS_NAME = "creatorsName"
                CREATE_TIMESTAMP = "createTimestamp"
                MODIFIERS_NAME = "modifiersName"
                MODIFY_TIMESTAMP = "modifyTimestamp"
                STRUCTURAL_OBJECTCLASS = "structuralObjectClass"
                GOVERNING_STRUCTURE_RULE = "governingStructureRule"
                SUBSCHEMA_SUBENTRY = "subschemaSubentry"
                ENTRY_DN = "entryDN"

            OPERATIONAL_ATTRIBUTES: Final[frozenset[str]] = frozenset({
                OperationalAttribute.CREATORS_NAME,
                OperationalAttribute.CREATE_TIMESTAMP,
                OperationalAttribute.MODIFIERS_NAME,
                OperationalAttribute.MODIFY_TIMESTAMP,
                OperationalAttribute.STRUCTURAL_OBJECTCLASS,
                OperationalAttribute.GOVERNING_STRUCTURE_RULE,
                OperationalAttribute.SUBSCHEMA_SUBENTRY,
                OperationalAttribute.ENTRY_DN,
            })

            # RFC 4512 - Schema entry attribute names
            ATTR_OBJECTCLASSES: Final[str] = "objectClasses"
            ATTR_ATTRIBUTETYPES: Final[str] = "attributeTypes"
            ATTR_MATCHINGRULES: Final[str] = "matchingRules"
            ATTR_MATCHINGRULEUSE: Final[str] = "matchingRuleUse"
            ATTR_LDAPSYNTAXES: Final[str] = "ldapSyntaxes"
            ATTR_DITCONTENTRULES: Final[str] = "dITContentRules"
            ATTR_DITSTRUCTURERULES: Final[str] = "dITStructureRules"
            ATTR_NAMEFORMS: Final[str] = "nameForms"

            # =================================================================
            # RFC 4514: LDAP Distinguished Names
            # =================================================================

            # RFC 4514 - ABNF Character Classes for DN String Representation
            # LUTF1 = %x01-1F / %x21 / %x24-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
            # (leadchar - not SPACE, not '#', not special)
            # TUTF1 = %x01-1F / %x21 / %x23-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
            # (trailchar - not SPACE, can have '#')
            # SUTF1 = %x01-21 / %x23-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
            # (stringchar - allows SPACE except at boundaries)

            # Characters excluded from LUTF1 (lead char) - includes SPACE(0x20), SHARP(0x23)
            DN_LUTF1_EXCLUDE: Final[frozenset[int]] = frozenset({
                0x00,
                0x20,
                0x22,
                0x23,
                0x2B,
                0x2C,
                0x3B,
                0x3C,
                0x3E,
                0x5C,
            })
            # Characters excluded from TUTF1 (trail char) - includes SPACE(0x20)
            DN_TUTF1_EXCLUDE: Final[frozenset[int]] = frozenset({
                0x00,
                0x20,
                0x22,
                0x2B,
                0x2C,
                0x3B,
                0x3C,
                0x3E,
                0x5C,
            })
            # Characters excluded from SUTF1 (string char)
            DN_SUTF1_EXCLUDE: Final[frozenset[int]] = frozenset({
                0x00,
                0x22,
                0x2B,
                0x2C,
                0x3B,
                0x3C,
                0x3E,
                0x5C,
            })

            # RFC 4514 §2.4 - DN Escape Characters (StrEnum Source of Truth)
            class DnEscapeChar(StrEnum):
                """RFC 4514 §2.4 - Characters always requiring escape in DN values."""

                DQUOTE = '"'  # 0x22 - Quotation mark
                PLUS = "+"  # 0x2B - Plus sign (RDN separator)
                COMMA = ","  # 0x2C - Comma (RDN separator)
                SEMICOLON = ";"  # 0x3B - Semicolon (alternative RDN separator)
                LANGLE = "<"  # 0x3C - Less-than
                RANGLE = ">"  # 0x3E - Greater-than
                BACKSLASH = "\\"  # 0x5C - Backslash (escape character)

            # RFC 4514 §2.4 - Characters requiring escaping in DN attribute values
            DN_ESCAPE_CHARS: Final[frozenset[str]] = frozenset({
                DnEscapeChar.DQUOTE,
                DnEscapeChar.PLUS,
                DnEscapeChar.COMMA,
                DnEscapeChar.SEMICOLON,
                DnEscapeChar.LANGLE,
                DnEscapeChar.RANGLE,
                DnEscapeChar.BACKSLASH,
            })

            # RFC 4514 §2.4 - Characters at Start/End (StrEnum Source of Truth)
            class DnEscapeAtStart(StrEnum):
                """RFC 4514 §2.4 - Characters requiring escape at DN value start."""

                SPACE = " "  # 0x20 - Space at start
                SHARP = "#"  # 0x23 - Hash at start (indicates hex string)

            class DnEscapeAtEnd(StrEnum):
                """RFC 4514 §2.4 - Characters requiring escape at DN value end."""

                SPACE = " "  # 0x20 - Space at end

            # RFC 4514 §2.4 - Characters requiring escaping at value start/end
            DN_ESCAPE_AT_START: Final[frozenset[str]] = frozenset({
                DnEscapeAtStart.SPACE,
                DnEscapeAtStart.SHARP,
            })
            DN_ESCAPE_AT_END: Final[frozenset[str]] = frozenset({
                DnEscapeAtEnd.SPACE,
            })

            # RFC 4514 §3 - Required attribute type short names
            DN_ATTR_CN: Final[str] = "CN"  # commonName (2.5.4.3)
            DN_ATTR_L: Final[str] = "L"  # localityName (2.5.4.7)
            DN_ATTR_ST: Final[str] = "ST"  # stateOrProvinceName (2.5.4.8)
            DN_ATTR_O: Final[str] = "O"  # organizationName (2.5.4.10)
            DN_ATTR_OU: Final[str] = "OU"  # organizationalUnitName (2.5.4.11)
            DN_ATTR_C: Final[str] = "C"  # countryName (2.5.4.6)
            DN_ATTR_STREET: Final[str] = "STREET"  # streetAddress (2.5.4.9)
            DN_ATTR_DC: Final[str] = (
                "DC"  # domainComponent (0.9.2342.19200300.100.1.25)
            )
            DN_ATTR_UID: Final[str] = "UID"  # userId (0.9.2342.19200300.100.1.1)

            # RFC 4514 §3 - Mapping from short name to OID
            DN_ATTRIBUTE_TYPES: Final[MappingProxyType[str, str]] = MappingProxyType({
                "CN": "2.5.4.3",
                "L": "2.5.4.7",
                "ST": "2.5.4.8",
                "O": "2.5.4.10",
                "OU": "2.5.4.11",
                "C": "2.5.4.6",
                "STREET": "2.5.4.9",
                "DC": "0.9.2342.19200300.100.1.25",
                "UID": "0.9.2342.19200300.100.1.1",
            })

            # RFC 4514 - RDN separator (comma is primary, semicolon is alternative)
            DN_RDN_SEPARATOR: Final[str] = ","
            DN_RDN_SEPARATOR_ALT: Final[str] = ";"
            DN_MULTIVALUE_SEPARATOR: Final[str] = "+"  # Multi-valued RDN separator
            DN_ATTR_VALUE_SEPARATOR: Final[str] = "="  # Attribute=Value separator

            # RFC 4514 - Minimum DN length for validation
            MIN_DN_LENGTH: Final[int] = (
                2  # Minimum length for valid DN strings (to check trailing escape)
            )

            # ASCII control character boundaries for sanitization
            ASCII_PRINTABLE_MIN: Final[int] = 0x20  # Space (first printable character)
            ASCII_PRINTABLE_MAX: Final[int] = 0x7E  # Tilde (last printable character)

            # Base64 pattern matching
            MIN_BASE64_LENGTH: Final[int] = (
                8  # Minimum length for base64 pattern matching
            )

            # =================================================================
            # RFC 4517: LDAP Syntaxes and Matching Rules (common OIDs)
            # =================================================================

            # Common LDAP syntax OIDs
            SYNTAX_DIRECTORY_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.15"
            SYNTAX_OCTET_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.40"
            SYNTAX_INTEGER: Final[str] = "1.3.6.1.4.1.1466.115.121.1.27"
            SYNTAX_BOOLEAN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.7"
            SYNTAX_DN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.12"
            SYNTAX_GENERALIZED_TIME: Final[str] = "1.3.6.1.4.1.1466.115.121.1.24"
            SYNTAX_OID: Final[str] = "1.3.6.1.4.1.1466.115.121.1.38"
            SYNTAX_BIT_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.6"
            SYNTAX_JPEG: Final[str] = "1.3.6.1.4.1.1466.115.121.1.28"

            # Common matching rule OIDs
            MATCH_CASE_IGNORE: Final[str] = "2.5.13.2"
            MATCH_CASE_EXACT: Final[str] = "2.5.13.5"
            MATCH_DISTINGUISHED_NAME: Final[str] = "2.5.13.1"
            MATCH_INTEGER: Final[str] = "2.5.13.14"
            MATCH_GENERALIZED_TIME: Final[str] = "2.5.13.27"
            MATCH_OID: Final[str] = "2.5.13.0"

            # =================================================================
            # RFC Parsing/Writing Metadata Keys
            # =================================================================
            # Used for tracking RFC compliance and transformation metadata

            # RFC 2849 - Entry/LDIF Metadata
            META_RFC_VERSION: Final[str] = "_rfc_version"  # LDIF version (1)
            META_RFC_LINE_FOLDING: Final[str] = "_rfc_line_folding"  # Line was folded
            META_RFC_BASE64_ENCODED: Final[str] = "_rfc_base64"  # Value was base64
            META_RFC_URL_REFERENCE: Final[str] = "_rfc_url_ref"  # Value from URL
            META_RFC_CHANGETYPE: Final[str] = "_rfc_changetype"  # Change record type
            META_RFC_CONTROLS: Final[str] = "_rfc_controls"  # LDAP controls

            # RFC 4512 - Schema Metadata
            META_SCHEMA_EXTENSIONS: Final[str] = "_schema_extensions"  # X-* extensions
            META_SCHEMA_ORIGIN: Final[str] = "_schema_origin"  # X-ORIGIN value
            META_SCHEMA_OBSOLETE: Final[str] = "_schema_obsolete"  # OBSOLETE flag

            # RFC 4514 - DN Metadata
            META_DN_ORIGINAL: Final[str] = "_dn_original"  # Original DN before norm
            META_DN_WAS_BASE64: Final[str] = "_dn_was_base64"  # DN was base64 encoded
            META_DN_ESCAPES_APPLIED: Final[str] = "_dn_escapes"  # Escape sequences used

            # Transformation Tracking
            META_TRANSFORMATION_SOURCE: Final[str] = (
                "_transform_source"  # Source server
            )
            META_TRANSFORMATION_TARGET: Final[str] = (
                "_transform_target"  # Target server
            )
            META_TRANSFORMATION_TIMESTAMP: Final[str] = (
                "_transform_ts"  # When transformed
            )

        # =============================================================================
        # FEATURE CAPABILITIES - Cross-Server Translation System
        # =============================================================================

        class FeatureCapabilities:
            r"""Feature capability definitions for cross-server translation.

            This system enables:
            1. RFC as STRICT baseline - always supported by all servers
            2. Vendor features mapped to standard feature IDs
            3. Metadata preservation for round-trip conversion
            4. Servers declare their own capabilities without knowing other servers

            Architecture:
            =============
            Server A → RFC Intermediate → Server B
                    (features preserved in metadata)

            Feature Categories:
            ===================
            - RFC_STANDARD: Core RFC features (mandatory for all servers)
            - ACL_VENDOR: Server-specific ACL features (may not translate)
            - SCHEMA_VENDOR: Server-specific schema features
            - ENTRY_VENDOR: Server-specific entry features

            Server Implementation Pattern:
            ==============================
            Each server declares in its OWN Constants class:

            class Constants:
                # Features this server supports
                SUPPORTED_FEATURES: frozenset[str] = frozenset({
                    FeatureCapabilities.ACL_SELF_WRITE,
                    FeatureCapabilities.ACL_PROXY_AUTH,
                    ...
                })

                # Local permission name → feature ID mapping (immutable)
                LOCAL_TO_FEATURE: ClassVar[Mapping[str, str]] = MappingProxyType({
                    "selfwrite": FeatureCapabilities.ACL_SELF_WRITE,
                    "proxy": FeatureCapabilities.ACL_PROXY_AUTH,
                })

                # Feature ID → local permission name mapping (immutable)
                FEATURE_TO_LOCAL: ClassVar[Mapping[str, str]] = MappingProxyType({
                    FeatureCapabilities.ACL_SELF_WRITE: "selfwrite",
                    FeatureCapabilities.ACL_PROXY_AUTH: "proxy",
                })

            Hook Methods (in rfc.py base, servers override):
            =================================================
            - _normalize_feature(feature_id, value) → RFC value + metadata
            - _denormalize_feature(feature_id, rfc_value, metadata) → server value
            - _supports_feature(feature_id) → bool
            - _get_feature_fallback(feature_id) → RFC_FALLBACKS value or None

            """

            # =====================================================================
            # RFC STANDARD FEATURES (supported by ALL servers)
            # =====================================================================

            # ACL Permission Features (RFC 4876 / RFC 2820 concepts)
            ACL_READ: Final[str] = "acl:read"
            ACL_WRITE: Final[str] = "acl:write"
            ACL_ADD: Final[str] = "acl:add"
            ACL_DELETE: Final[str] = "acl:delete"
            ACL_SEARCH: Final[str] = "acl:search"
            ACL_COMPARE: Final[str] = "acl:compare"

            # ACL Subject Features
            ACL_SUBJECT_USER_DN: Final[str] = "acl:subject:user_dn"
            ACL_SUBJECT_GROUP_DN: Final[str] = "acl:subject:group_dn"
            ACL_SUBJECT_SELF: Final[str] = "acl:subject:self"
            ACL_SUBJECT_ANONYMOUS: Final[str] = "acl:subject:anonymous"
            ACL_SUBJECT_ALL: Final[str] = "acl:subject:all"

            # ACL Target Features
            ACL_TARGET_ENTRY: Final[str] = "acl:target:entry"
            ACL_TARGET_ATTRS: Final[str] = "acl:target:attrs"
            ACL_TARGET_DN: Final[str] = "acl:target:dn"

            # Schema Features (RFC 4512)
            SCHEMA_ATTR_SYNTAX: Final[str] = "schema:attr:syntax"
            SCHEMA_ATTR_MATCHING: Final[str] = "schema:attr:matching"
            SCHEMA_ATTR_SINGLE_VALUE: Final[str] = "schema:attr:single_value"
            SCHEMA_OC_SUP: Final[str] = "schema:oc:sup"
            SCHEMA_OC_KIND: Final[str] = "schema:oc:kind"

            # Entry Features (RFC 2849)
            ENTRY_DN: Final[str] = "entry:dn"
            ENTRY_CHANGETYPE: Final[str] = "entry:changetype"
            ENTRY_CONTROLS: Final[str] = "entry:controls"

            # =====================================================================
            # VENDOR ACL FEATURES (may not translate between servers)
            # =====================================================================
            # Each server declares which of these it supports in its Constants

            # Self-write permission (user can modify own entry)
            ACL_SELF_WRITE: Final[str] = "acl:vendor:self_write"

            # Proxy authentication permission
            ACL_PROXY_AUTH: Final[str] = "acl:vendor:proxy_auth"

            # Browse permission (typically read+search combined)
            ACL_BROWSE_PERMISSION: Final[str] = "acl:vendor:browse"

            # Authentication permission
            ACL_AUTH_PERMISSION: Final[str] = "acl:vendor:auth"

            # All permissions macro (expands to full permission set)
            ACL_ALL_PERMISSIONS: Final[str] = "acl:vendor:all"

            # Negative/deny permissions (noread, nowrite, etc.)
            ACL_NEGATIVE_PERMISSIONS: Final[str] = "acl:vendor:negative"

            # DN attribute-based subject (subject from entry attribute)
            ACL_DNATTR_SUBJECT: Final[str] = "acl:vendor:dnattr"

            # GUID attribute-based subject
            ACL_GUIDATTR_SUBJECT: Final[str] = "acl:vendor:guidattr"

            # IP-based bind rules
            ACL_BIND_IP: Final[str] = "acl:vendor:bind_ip"

            # Time-based bind rules (time of day, day of week)
            ACL_BIND_TIME: Final[str] = "acl:vendor:bind_time"

            # Authentication method requirement
            ACL_BIND_AUTHMETHOD: Final[str] = "acl:vendor:bind_authmethod"

            # Security strength factor threshold
            ACL_BIND_SSF: Final[str] = "acl:vendor:bind_ssf"

            # Filter-based target selection
            ACL_TARGET_FILTER: Final[str] = "acl:vendor:target_filter"

            # =====================================================================
            # VENDOR SCHEMA FEATURES
            # =====================================================================

            # X-ORIGIN extension (common but not RFC-required)
            SCHEMA_X_ORIGIN: Final[str] = "schema:vendor:x_origin"

            # X-SCHEMA-FILE extension
            SCHEMA_X_SCHEMA_FILE: Final[str] = "schema:vendor:x_schema_file"

            # Custom syntaxes (vendor-specific OIDs)
            SCHEMA_CUSTOM_SYNTAX: Final[str] = "schema:vendor:custom_syntax"

            # =====================================================================
            # VENDOR ENTRY FEATURES
            # =====================================================================

            # Operational attributes preservation
            ENTRY_OPERATIONAL_ATTRS: Final[str] = "entry:vendor:operational"

            # Server-specific controls
            ENTRY_VENDOR_CONTROLS: Final[str] = "entry:vendor:controls"

            # =====================================================================
            # FEATURE CATEGORY SETS
            # =====================================================================
            # RFC FALLBACK VALUES (when vendor feature not supported)
            # =====================================================================
            # Servers declare their own FEATURE_TO_LOCAL mappings in their Constants
            # These are generic RFC fallbacks when a feature cannot be translated

            RFC_FALLBACKS: Final[MappingProxyType[str, str | None]] = MappingProxyType({
                ACL_SELF_WRITE: "write",  # Degrade to write
                ACL_BROWSE_PERMISSION: "read,search",  # Expand to RFC permissions
                ACL_PROXY_AUTH: None,  # No RFC equivalent, preserve in metadata
                ACL_AUTH_PERMISSION: None,  # No RFC equivalent, preserve in metadata
                ACL_ALL_PERMISSIONS: "read,write,add,delete,search,compare",
                ACL_DNATTR_SUBJECT: None,  # Server-specific, preserve in metadata
                ACL_GUIDATTR_SUBJECT: None,  # Server-specific, preserve in metadata
                ACL_NEGATIVE_PERMISSIONS: None,  # Preserve in metadata
                ACL_BIND_IP: None,  # Preserve in metadata
                ACL_BIND_TIME: None,  # Preserve in metadata
                ACL_BIND_AUTHMETHOD: None,  # Preserve in metadata
                ACL_BIND_SSF: None,  # Preserve in metadata
                ACL_TARGET_FILTER: None,  # Preserve in metadata
            })

            # =====================================================================
            # METADATA KEYS FOR FEATURE PRESERVATION
            # =====================================================================

            META_UNSUPPORTED_FEATURES: Final[str] = "_unsupported_features"
            META_FEATURE_SOURCE: Final[str] = "_feature_source_server"
            META_FEATURE_ORIGINAL_VALUE: Final[str] = "_feature_original_value"
            META_FEATURE_FALLBACK_USED: Final[str] = "_feature_fallback_used"
            META_FEATURE_EXPANSION_APPLIED: Final[str] = "_feature_expansion_applied"

        # =============================================================================
        # PROCESSING CONSTANTS
        # =============================================================================

        # Processing constants organized in LdifProcessing class
        class LdifProcessing:
            """LDIF processing-related constants."""

            # Worker configuration
            MIN_WORKERS: Final[int] = 1  # Minimum workers allowed
            MIN_WORKERS_FOR_PARALLEL: Final[int] = 2  # Minimum for parallel processing
            MAX_WORKERS_LIMIT: Final[int] = 16  # Maximum allowed workers
            PERFORMANCE_MIN_WORKERS: Final[int] = 4  # Minimum workers for performance

            # Chunk size configuration
            MIN_CHUNK_SIZE: Final[int] = 100  # Minimum chunk size
            MAX_CHUNK_SIZE: Final[int] = 10000  # Maximum chunk size
            PERFORMANCE_MIN_CHUNK_SIZE: Final[int] = 1000  # Minimum for performance

            # Failure rate thresholds
            HIGH_FAILURE_RATE_THRESHOLD: Final[float] = (
                50.0  # Percentage threshold for high severity
            )

            # Entry limits
            MIN_ENTRIES: Final[int] = 1000
            MAX_ENTRIES_ABSOLUTE: Final[int] = 10000000  # 10 million entry hard limit

            # Analytics configuration
            MIN_ANALYTICS_CACHE_SIZE: Final[int] = 100
            MAX_ANALYTICS_CACHE_SIZE: Final[int] = 10000
            MIN_SAMPLE_RATE: Final[float] = 0.0  # Minimum analytics sample rate
            MAX_SAMPLE_RATE: Final[float] = 1.0  # Maximum analytics sample rate (100%)
            MAX_ANALYTICS_ENTRIES_ABSOLUTE: Final[int] = (
                100000  # Maximum analytics entries
            )

            # Memory configuration
            MIN_MEMORY_MB: Final[int] = 64  # Minimum memory limit in MB
            MAX_MEMORY_MB: Final[int] = 8192  # Maximum memory limit in MB

            # Other thresholds
            ENCODING_CONFIDENCE_THRESHOLD: Final[float] = (
                0.7  # Encoding detection confidence
            )

            # Batch size configuration - reuse from flext-core (no duplication)
            # DEFAULT_BATCH_SIZE inherited from FlextConstants.Utilities.DEFAULT_BATCH_SIZE
            # Use FlextConstants.Performance.BatchProcessing.MAX_ITEMS for max batch size
            MIN_BATCH_SIZE: Final[int] = 1  # Minimum batch size (domain-specific)
            MAX_BATCH_SIZE: Final[int] = (
                FlextConstants.Performance.BatchProcessing.MAX_ITEMS
            )

            # Additional constants for config validation
            PERFORMANCE_MEMORY_MB_THRESHOLD: Final[int] = (
                512  # Memory threshold for performance
            )
            DEBUG_MAX_WORKERS: Final[int] = 2  # Max workers in debug mode
            SMALL_ENTRY_COUNT_THRESHOLD: Final[int] = (
                100  # Threshold for small entry counts
            )
            MEDIUM_ENTRY_COUNT_THRESHOLD: Final[int] = (
                1000  # Threshold for medium entry counts
            )
            MIN_ATTRIBUTE_PARTS: Final[int] = 2  # Minimum parts for attribute parsing

            # Text and Binary Processing constants (RFC 2849 § 2)
            ASCII_SPACE_CHAR: Final[int] = (
                32  # ASCII code for space (first printable char)
            )
            ASCII_TILDE_CHAR: Final[int] = (
                126  # ASCII code for tilde (last printable char)
            )
            ASCII_DEL_CHAR: Final[int] = (
                127  # ASCII code for DEL control character (0x7F)
            )
            ASCII_NON_ASCII_START: Final[int] = 128  # Start of non-ASCII range (0x80)
            DN_TRUNCATE_LENGTH: Final[int] = 100  # Maximum DN length for error messages
            DN_LOG_PREVIEW_LENGTH: Final[int] = 80  # DN preview length in logging
            ACI_PREVIEW_LENGTH: Final[int] = 200  # ACI value preview length for logging
            ACI_LIST_PREVIEW_LIMIT: Final[int] = (
                3  # Maximum number of ACIs to show in preview
            )

            # Search configuration defaults
            DEFAULT_SEARCH_TIME_LIMIT: Final[int] = (
                30  # Default search time limit in seconds
            )
            DEFAULT_SEARCH_SIZE_LIMIT: Final[int] = (
                0  # Default search size limit (0 = unlimited)
            )

            # Version constants (moved from version.py for FLEXT compliance)
            # Note: Cannot override parent VERSION (Final), use LDIF_VERSION instead
            LDIF_VERSION: Final[str] = "0.9.9"  # Current LDIF library version
            LDIF_VERSION_INFO: Final[tuple[int, int, int]] = (0, 9, 9)  # Version tuple

            # Client operation constants
            MAX_PATH_LENGTH_CHECK: Final[int] = (
                500  # Maximum path length for file operations
            )
            MAX_LOGGED_ERRORS: Final[int] = (
                5  # Maximum number of errors to log in output
            )

        # =============================================================================
        # CONFIGURATION DEFAULTS
        # =============================================================================

        class ConfigDefaults:
            """Default values for FlextLdifConfig fields.

            Zero Tolerance: All Field(default=...) values MUST be defined here.
            """

            # Format Configuration Defaults
            LDIF_SKIP_COMMENTS: Final[bool] = False
            LDIF_VALIDATE_DN_FORMAT: Final[bool] = True
            LDIF_STRICT_VALIDATION: Final[bool] = True
            LDIF_LINE_SEPARATOR: Final[str] = "\n"
            LDIF_VERSION_STRING: Final[str] = "version: 1"
            # Reuse DEFAULT_ENCODING from flext-core (no duplication)
            LDIF_DEFAULT_ENCODING: Final[str] = (
                FlextConstants.Utilities.DEFAULT_ENCODING
            )

            # Processing Configuration Defaults
            LDIF_MAX_ENTRIES: Final[int] = 1000000
            ENABLE_PERFORMANCE_OPTIMIZATIONS: Final[bool] = True
            ENABLE_PARALLEL_PROCESSING: Final[bool] = True

            # Analytics Configuration Defaults
            LDIF_ENABLE_ANALYTICS: Final[bool] = True
            LDIF_FAIL_ON_WARNINGS: Final[bool] = False
            LDIF_ANALYTICS_SAMPLE_RATE: Final[float] = 1.0
            LDIF_ANALYTICS_MAX_ENTRIES: Final[int] = 10000
            ANALYTICS_DETAIL_LEVEL_LOW: Final[str] = "low"
            ANALYTICS_DETAIL_LEVEL_MEDIUM: Final[str] = "medium"
            ANALYTICS_DETAIL_LEVEL_HIGH: Final[str] = "high"

            # Server Configuration Defaults
            LDIF_SERVER_SPECIFICS: Final[bool] = True
            STRICT_RFC_COMPLIANCE: Final[bool] = True

            # Error Handling Defaults
            ERROR_RECOVERY_MODE_CONTINUE: Final[str] = "continue"

            # Development Defaults
            DEBUG_MODE: Final[bool] = False
            VERBOSE_LOGGING: Final[bool] = False

        # =============================================================================
        # QUALITY ANALYSIS CONSTANTS
        # =============================================================================

        class QualityAnalysis:
            """Quality analysis threshold constants."""

            # Quality thresholds for LDIF analysis
            QUALITY_THRESHOLD_MEDIUM: Final[float] = 0.8  # Medium quality threshold
            MIN_DN_COMPONENTS_FOR_BASE_PATTERN: Final[int] = (
                2  # Minimum DN components for base pattern analysis
            )

        # =============================================================================
        # UTILITY CONSTANTS
        # =============================================================================

        # Utilities constants are inherited from parent FlextConstants

        # =============================================================================
        # VALIDATION CONSTANTS
        # =============================================================================

        class LdifGeneralValidation:
            """General validation constants."""

            NAME_LENGTH_MIN: Final[int] = 1
            NAME_LENGTH_MAX: Final[int] = 255

        class LdifValidation:
            """LDIF-specific validation rules and constraints."""

            MIN_DN_COMPONENTS: Final[int] = 1

            # RFC 4514 DN length limit (increased from 255 to support real-world long DNs)
            MAX_DN_LENGTH: Final[int] = 2048

            # Reasonable limits for LDAP attributes
            MAX_ATTRIBUTES_PER_ENTRY: Final[int] = 1000
            MAX_VALUES_PER_ATTRIBUTE: Final[int] = 100
            MAX_ATTRIBUTE_VALUE_LENGTH: Final[int] = 10000

            # Attribute name constraints (RFC 4512 - max 127 chars)
            MIN_ATTRIBUTE_NAME_LENGTH: Final[int] = 1
            MAX_ATTRIBUTE_NAME_LENGTH: Final[int] = 127
            ATTRIBUTE_NAME_PATTERN: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"

            # URL validation constraints
            MIN_URL_LENGTH: Final[int] = 1
            MAX_URL_LENGTH: Final[int] = 2048
            URL_PATTERN: Final[str] = r"^(https?|ldap)://[^\s/$.?#].[^\s]*$"

            # Encoding constraints
            MIN_ENCODING_LENGTH: Final[int] = 1
            MAX_ENCODING_LENGTH: Final[int] = 50

            # LDIF line parsing constraints
            MIN_LDIF_LINE_PARTS: Final[int] = 2

        # =============================================================================
        # OBJECTCLASS CONSTANTS
        # =============================================================================

        class ObjectClasses:
            """LDAP object class name constants (RFC 4512 standard classes).

            Core LDIF-level object class definitions used across the FLEXT ecosystem.
            These are the fundamental LDAP schema object classes defined in RFC 4512
            and commonly used across all LDAP server implementations.
            """

            # Structural object classes (RFC 4512)
            TOP: Final[str] = "top"
            ORGANIZATIONAL_PERSON: Final[str] = "organizationalPerson"
            INET_ORG_PERSON: Final[str] = "inetOrgPerson"
            GROUP_OF_NAMES: Final[str] = "groupOfNames"
            GROUP_OF_UNIQUE_NAMES: Final[str] = "groupOfUniqueNames"
            POSIX_GROUP: Final[str] = "posixGroup"
            ORGANIZATION: Final[str] = "organization"
            DOMAIN: Final[str] = "domain"

            # Common auxiliary object classes
            COUNTRY: Final[str] = "country"
            LOCALITY: Final[str] = "locality"

            # Standard structural hierarchy

        class RfcBinaryAttributes:
            """RFC 4517 Binary attribute names that typically require ;binary option.

            These attributes are defined as binary in LDAP schemas and SHOULD use
            the ;binary transfer option when transmitted in LDIF format (RFC 4522).

            Common binary attributes from RFC standards and practical LDAP usage.
            """

            # RFC 4523 - X.509 Certificate attributes
            USER_CERTIFICATE: Final[str] = "usercertificate"
            CA_CERTIFICATE: Final[str] = "cacertificate"
            CERTIFICATE_REVOCATION_LIST: Final[str] = "certificaterevocationlist"
            AUTHORITY_REVOCATION_LIST: Final[str] = "authorityrevocationlist"
            CROSS_CERTIFICATE_PAIR: Final[str] = "crosscertificatepair"

            # RFC 4524 - Common multimedia attributes
            PHOTO: Final[str] = "photo"
            JPEG_PHOTO: Final[str] = "jpegphoto"

            # PKCS#12 and other security attributes
            USER_PKCS12: Final[str] = "userpkcs12"
            USER_SMIME_CERTIFICATE: Final[str] = "usersmimecertificate"

            # Microsoft Active Directory binary attributes
            THUMBNAIL_PHOTO: Final[str] = "thumbnailphoto"
            THUMBNAIL_LOGO: Final[str] = "thumbnaillogo"
            OBJECT_GUID: Final[str] = "objectguid"
            OBJECT_SID: Final[str] = "objectsid"

            # =====================================================================
            # BINARY ATTRIBUTE ENUMERATION (Source of Truth)
            # =====================================================================

            class BinaryAttribute(StrEnum):
                """RFC 4517/4523/4524 - Binary attributes requiring ;binary option."""

                USER_CERTIFICATE = "usercertificate"
                CA_CERTIFICATE = "cacertificate"
                CERTIFICATE_REVOCATION_LIST = "certificaterevocationlist"
                AUTHORITY_REVOCATION_LIST = "authorityrevocationlist"
                CROSS_CERTIFICATE_PAIR = "crosscertificatepair"
                PHOTO = "photo"
                JPEG_PHOTO = "jpegphoto"
                AUDIO = "audio"
                USER_PKCS12 = "userpkcs12"
                USER_SMIME_CERTIFICATE = "usersmimecertificate"
                THUMBNAIL_PHOTO = "thumbnailphoto"
                THUMBNAIL_LOGO = "thumbnaillogo"
                OBJECT_GUID = "objectguid"
                OBJECT_SID = "objectsid"

            # Convenience set for validation - all binary attribute names
            BINARY_ATTRIBUTE_NAMES: Final[frozenset[str]] = frozenset([
                BinaryAttribute.USER_CERTIFICATE,
                BinaryAttribute.CA_CERTIFICATE,
                BinaryAttribute.CERTIFICATE_REVOCATION_LIST,
                BinaryAttribute.AUTHORITY_REVOCATION_LIST,
                BinaryAttribute.CROSS_CERTIFICATE_PAIR,
                BinaryAttribute.PHOTO,
                BinaryAttribute.JPEG_PHOTO,
                BinaryAttribute.AUDIO,
                BinaryAttribute.USER_PKCS12,
                BinaryAttribute.USER_SMIME_CERTIFICATE,
                BinaryAttribute.THUMBNAIL_PHOTO,
                BinaryAttribute.THUMBNAIL_LOGO,
                BinaryAttribute.OBJECT_GUID,
                BinaryAttribute.OBJECT_SID,
            ])

        class ServerValidationRules:
            """Server-specific validation rules for Entry model validators.

            Defines how different LDAP servers handle RFC compliance variations.
            Used by Entry.validate_entry_consistency to apply server-specific rules
            while maintaining RFC baseline.

            Design Pattern: RFC baseline + server-specific extensions
            - All servers get RFC validation
            - Server-specific rules add/modify checks based on server_type
            - Violations captured in metadata for round-trip conversions
            """

            # =============================================================================
            # OBJECTCLASS REQUIREMENTS
            # =============================================================================

            # =============================================================================
            # SCHEMA ENTRY DETECTION PATTERNS
            # =============================================================================

            # Schema entry DN patterns per server (case-insensitive, immutable)
            SCHEMA_ENTRY_PATTERNS: ClassVar[Mapping[str, Sequence[str]]] = (
                MappingProxyType({
                    "rfc": ("cn=schema",),  # RFC 4512 standard
                    "oid": ("cn=schema", "cn=subschema"),  # OID uses both
                    "oud": ("cn=schema",),  # OUD follows RFC
                    "openldap": ("cn=schema", "cn=subschema"),  # OpenLDAP flexible
                    "openldap1": ("cn=schema",),  # OpenLDAP 1.x
                    "ad": ("cn=schema", "cn=aggregate"),  # AD schema container
                    "389ds": ("cn=schema",),  # 389 DS
                    "apache_directory": ("ou=schema",),  # Apache DS uses ou=schema
                    "novell_edirectory": ("cn=schema",),  # Novell
                    "ibm_tivoli": ("cn=schema",),  # IBM Tivoli
                    "relaxed": (
                        "cn=schema",
                        "cn=subschema",
                        "ou=schema",
                    ),  # Accept all
                })
            )

            # =============================================================================
            # NAMING ATTRIBUTE (RDN) REQUIREMENTS
            # =============================================================================

            # =============================================================================
            # BINARY ATTRIBUTE HANDLING
            # =============================================================================

            # Server-specific binary attributes (in addition to RFC standard, immutable)
            SERVER_BINARY_ATTRIBUTES: ClassVar[Mapping[str, frozenset[str]]] = (
                MappingProxyType({
                    "oid": frozenset(
                        [
                            "orclguid",  # Oracle GUID
                            "userpassword",  # OID may store binary passwords
                        ],
                    ),
                    "oud": frozenset(
                        [
                            "ds-sync-hist",  # OUD synchronization history
                            "ds-sync-state",  # OUD sync state
                        ],
                    ),
                    "ad": frozenset(
                        [
                            "objectguid",  # AD GUID (already in RFC list but emphasizing)
                            "objectsid",  # AD Security ID
                            "msexchmailboxguid",  # Exchange mailbox GUID
                            "msexchmailboxsecuritydescriptor",  # Exchange security
                        ],
                    ),
                    "openldap": frozenset(
                        [
                            "entryuuid",  # OpenLDAP entry UUID (binary format)
                        ],
                    ),
                })
            )

            # =============================================================================
            # SPECIAL ATTRIBUTES PER SERVER
            # =============================================================================

            # Operational attributes that may be missing and should not trigger
            # warnings (immutable)
            OPERATIONAL_ATTRIBUTES: ClassVar[Mapping[str, frozenset[str]]] = (
                MappingProxyType({
                    "oid": frozenset(
                        [
                            "orclguid",
                            "createtimestamp",
                            "modifytimestamp",
                            "creatorsname",
                            "modifiersname",
                        ],
                    ),
                    "oud": frozenset(
                        [
                            "entryuuid",
                            "ds-sync-generation-id",
                            "ds-sync-state",
                            "createtimestamp",
                            "modifytimestamp",
                        ],
                    ),
                    "ad": frozenset(
                        [
                            "objectguid",
                            "objectsid",
                            "whencreated",
                            "whenchanged",
                            "usnchanged",
                            "usncreated",
                        ],
                    ),
                    "openldap": frozenset(
                        [
                            "entryuuid",
                            "entrycsn",
                            "createtimestamp",
                            "modifytimestamp",
                            "creatorsname",
                            "modifiersname",
                        ],
                    ),
                })
            )

            # NOTE: ErrorMessages class removed (removed unused error message constants)
            # Error messages are now defined in appropriate validation modules

        class ProcessingStage(StrEnum):
            """Processing stages for LDIF operations.

            DRY Pattern:
                StrEnum is the single source of truth. Use ProcessingStage.PARSING.value
                or ProcessingStage.PARSING directly - no base strings needed.
            """

            PARSING = "parsing"
            VALIDATION = "validation"
            ANALYTICS = "analytics"
            WRITING = "writing"

        class LdifHealthStatus(StrEnum):
            """Health status for LDIF services.

            DRY Pattern:
                StrEnum is the single source of truth. Use LdifHealthStatus.HEALTHY.value
                or LdifHealthStatus.HEALTHY directly - no base strings needed.
            """

            HEALTHY = "healthy"
            DEGRADED = "degraded"
            UNHEALTHY = "unhealthy"

        class EntryType(StrEnum):
            """Types of LDIF entries.

            DRY Pattern:
                StrEnum is the single source of truth. Use EntryType.PERSON.value
                or EntryType.PERSON directly - no base strings needed.
            """

            PERSON = "person"
            GROUP = "group"
            ORGANIZATIONAL_UNIT = "organizationalunit"
            DOMAIN = "domain"
            OTHER = "other"

        class EntryModification(StrEnum):
            """LDIF entry modification types.

            DRY Pattern:
                StrEnum is the single source of truth. Use EntryModification.ADD.value
                or EntryModification.ADD directly - no base strings needed.
            """

            ADD = "add"
            MODIFY = "modify"
            DELETE = "delete"
            MODRDN = "modrdn"

        class TransformationType(StrEnum):
            """Types of transformations applied to entries.

            Used in EntryStatistics to track what conversions were applied.
            Follows FLEXT pattern of using constants instead of hard-coded strings.

            DRY Pattern:
                StrEnum is the single source of truth. Use TransformationType.NORMALIZE.value
                or TransformationType.NORMALIZE directly - no base strings needed.
            """

            # DN transformations
            DN_CLEANED = "dn_cleaned"
            DN_NORMALIZED = "dn_normalized"
            TAB_NORMALIZED = "tab_normalized"
            SPACE_CLEANED = "space_cleaned"
            UTF8_DECODED = "utf8_decoded"
            BASE64_DECODED = "base64_decoded"
            TRAILING_SPACE_REMOVED = "trailing_space_removed"
            ESCAPE_NORMALIZED = "escape_normalized"

            # Attribute transformations
            BOOLEAN_CONVERTED = "boolean_converted"
            ACL_CONVERTED = "acl_converted"
            ATTRIBUTE_REMOVED = "attribute_removed"
            ATTRIBUTE_ADDED = "attribute_added"
            ATTRIBUTE_RENAMED = "attribute_renamed"
            MODIFIED = "modified"

            # Schema transformations
            MATCHING_RULE_REPLACED = "matching_rule_replaced"
            SYNTAX_OID_REPLACED = "syntax_oid_replaced"
            OBJECTCLASS_FILTERED = "objectclass_filtered"

        class FilterType(StrEnum):
            """Types of filters applied to entries.

            Used in EntryStatistics to track filtering decisions.

            DRY Pattern:
                StrEnum is the single source of truth. Use FilterType.BASE_DN_FILTER.value
                or FilterType.BASE_DN_FILTER directly - no base strings needed.
            """

            BASE_DN_FILTER = "base_dn_filter"
            SCHEMA_WHITELIST = "schema_whitelist"
            FORBIDDEN_ATTRIBUTES = "forbidden_attributes"
            FORBIDDEN_OBJECTCLASSES = "forbidden_objectclasses"
            OPERATIONAL_ATTRIBUTES = "operational_attributes"
            ACL_EXTRACTION = "acl_extraction"
            SCHEMA_ENTRY = "schema_entry"

        class ValidationStatus(StrEnum):
            """Entry validation status levels.

            Used in EntryStatistics to indicate validation result.

            DRY Pattern:
                StrEnum is the single source of truth. Use ValidationStatus.VALID.value
                or ValidationStatus.VALID directly - no base strings needed.
            """

            VALID = "valid"
            WARNING = "warning"
            ERROR = "error"
            REJECTED = "rejected"

        class RejectionCategory(StrEnum):
            """Categories for entry rejection.

            Used in EntryStatistics to classify why entry was rejected.

            DRY Pattern:
                StrEnum is the single source of truth. Use RejectionCategory.INVALID_DN.value
                or RejectionCategory.INVALID_DN directly - no base strings needed.
            """

            INVALID_DN = "invalid_dn"
            BASE_DN_FILTER = "base_dn_filter"
            SCHEMA_VIOLATION = "schema_violation"
            FORBIDDEN_ATTRIBUTE = "forbidden_attribute"
            FORBIDDEN_OBJECTCLASS = "forbidden_objectclass"
            CATEGORIZATION_FAILED = "categorization_failed"
            NO_CATEGORY_MATCH = "no_category_match"
            PARSING_ERROR = "parsing_error"
            CONVERSION_ERROR = "conversion_error"

        class ErrorCategory(StrEnum):
            """Categories of errors that can occur during processing.

            Used in EntryStatistics to categorize errors.

            DRY Pattern:
                StrEnum is the single source of truth. Use ErrorCategory.PARSING.value
                or ErrorCategory.PARSING directly - no base strings needed.
            """

            PARSING = "parsing"
            VALIDATION = "validation"
            CONVERSION = "conversion"
            SYNC = "sync"
            SCHEMA = "schema"
            ACL = "acl"
            MODRDN = "modrdn"

        class AttributeMarkerStatus(StrEnum):
            """Marker status for attribute processing in metadata.

            Used by filters/entry services to mark attributes without removing them.
            Writer services use this status to determine output behavior.

            SRP Architecture:
                - filters.py: MARKS attributes with this status (never removes)
                - entry.py: REMOVES attributes based on this status
                - writer.py: Uses status + WriteOutputOptions for output

            DRY Pattern:
                StrEnum is the single source of truth. Use AttributeMarkerStatus.NORMAL.value
                or AttributeMarkerStatus.NORMAL directly - no base strings needed.
            """

            NORMAL = "normal"
            """Attribute is in normal state, no special handling."""

            MARKED_FOR_REMOVAL = "marked_for_removal"
            """Marked for removal by filters; removed by entry service."""

            FILTERED = "filtered"
            """Attribute filtered out based on filter rules."""

            OPERATIONAL = "operational"
            """Attribute is operational (server-managed), typically hidden in output."""

            HIDDEN = "hidden"
            """Attribute explicitly marked as hidden in output."""

            RENAMED = "renamed"
            """Attribute was renamed from original name."""

            # NOTE: ServerTypeEnum removed - use ServerTypes instead (canonical source)
            # ServerTypeEnum was duplicate of LdapServerType - consolidated to ServerTypes

        # =============================================================================
        # SERVER TYPES - Single source of truth for all server types
        # =============================================================================

        class ServerTypes(StrEnum):
            """Server type identifiers - Single source of truth for all server types.

            Zero Tolerance: All server type identifier strings MUST be defined here.
            Uses SHORT identifiers for code usage.

            DRY Pattern:
                StrEnum is the single source of truth. Use ServerTypes.OID.value
                or ServerTypes.OID directly - no base strings needed.
            """

            # Short identifiers (used in code, configuration, and processing)
            OID = "oid"
            OUD = "oud"
            OPENLDAP = "openldap"
            OPENLDAP1 = "openldap1"
            OPENLDAP2 = "openldap2"
            AD = "ad"
            APACHE = "apache"
            DS389 = "ds389"
            RFC = "rfc"
            RELAXED = "relaxed"
            NOVELL = "novell"
            IBM_TIVOLI = "ibm_tivoli"
            GENERIC = "generic"

        # =============================================================================
        # LITERAL TYPE CONSTANTS - All Literal types MUST be declared here
        # =============================================================================
        # NOTE: extract_enum_values() is inherited from FlextConstants
        # Use c.extract_enum_values() to extract values from
        # StrEnum classes

        class LiteralTypes:
            """Literal type constants for type annotations.

            Python 3.13+ best practices:
            - All tuple constants must match their corresponding StrEnum values
            - Literal types are manually defined (Python type system requirement)
            - Uses PEP 695 type aliases (type keyword) for better type checking
            - Runtime validation via validate_literal_matches_enum() ensures Literal types
            stay in sync with StrEnum classes

            Note: Tuple constants are manually defined to match StrEnum values,
            then validated at module initialization. This ensures type safety
            while working within Python's type system limitations (cannot
            dynamically create Literal types).
            """

            # Processing stages (must match ProcessingStage StrEnum values)
            # Validated at module initialization via validate_literal_matches_enum()
            PROCESSING_STAGES: Final[tuple[str, ...]] = (
                "parsing",
                "validation",
                "analytics",
                "writing",
            )

            # Health status (must match LdifHealthStatus StrEnum values)
            # Validated at module initialization via validate_literal_matches_enum()
            HEALTH_STATUS: Final[tuple[str, ...]] = ("healthy", "degraded", "unhealthy")

            # Entry types (must match EntryType StrEnum values)
            # Validated at module initialization via validate_literal_matches_enum()
            ENTRY_TYPES: Final[tuple[str, ...]] = (
                "person",
                "group",
                "organizationalunit",
                "domain",
                "other",
            )

            # Modification types (must match EntryModification StrEnum values)
            # Validated at module initialization via validate_literal_matches_enum()
            MODIFICATION_TYPES: Final[tuple[str, ...]] = (
                "add",
                "modify",
                "delete",
                "modrdn",
            )

            # NOTE: SERVER_TYPES removed - use ServerTypes class for identifiers
            # All server types (short forms: oid, oud, openldap, etc.) in ServerTypes

            # Encoding types (must match Encoding StrEnum values)
            # Validated at module initialization via validate_literal_matches_enum()
            ENCODING_TYPES: Final[tuple[str, ...]] = (
                "utf-8",
                "utf-16-le",
                "utf-16",
                "utf-32",
                "ascii",
                "latin-1",
                "cp1252",
                "iso-8859-1",
            )

            # Search scopes
            SCOPE: Final[tuple[str, ...]] = (
                "base",
                "one",
                "onelevel",
                "sub",
                "subtree",
            )

            # Validation levels
            VALIDATION_LEVELS: Final[tuple[str, ...]] = (
                "strict",
                "moderate",
                "lenient",
            )

            # Analytics detail levels
            ANALYTICS_DETAIL_LEVELS: Final[tuple[str, ...]] = ("low", "medium", "high")

            # Quirks detection modes
            DETECTION_MODES: Final[tuple[str, ...]] = ("auto", "manual", "disabled")

            # Error recovery modes
            ERROR_RECOVERY_MODES: Final[tuple[str, ...]] = ("continue", "stop", "skip")

            # Attribute output modes (show/hide/comment for writer)
            ATTRIBUTE_OUTPUT_MODES: Final[tuple[str, ...]] = ("show", "hide", "comment")

            # Attribute marker statuses (for metadata processing)
            ATTRIBUTE_MARKER_STATUSES: Final[tuple[str, ...]] = (
                "normal",
                "marked_for_removal",
                "filtered",
                "operational",
                "hidden",
                "renamed",
            )

            # Project types
            PROJECT_TYPES: Final[tuple[str, ...]] = (
                "library",
                "application",
                "service",
                "tool",
                "migration",
                "validation",
                "analysis",
            )

            # Processing stage literals

            # Health status literals
            HEALTH_STATUSES: Final[tuple[str, ...]] = (
                "healthy",
                "degraded",
                "unhealthy",
            )

            # Entry type literals

            # Modification type literals

            # Server type literals

            # Encoding type literals

            # Validation level literals

            # LDIF-specific project types
            LDIF_PROJECT_TYPES: Final[tuple[str, ...]] = (
                "library",
                "application",
                "service",
                "ldif-processor",
                "directory-converter",
                "ldif-validator",
                "ldif-analyzer",
                "ldif-parser",
                "directory-migrator",
                "ldap-data-processor",
                "ldif-transformer",
                "directory-sync",
                "ldif-exporter",
                "ldif-importer",
                "data-migration",
                "ldif-etl",
                "directory-backup",
                "ldif-merger",
                "ldif-splitter",
                "directory-validator",
                "ldif-normalizer",
                "ldap-directory-tool",
            )

            # Literal type definitions for type annotations
            # (Python 3.13+ PEP 695 best practices)
            # Using PEP 695 type statement for better type checking and IDE support
            # NOTE: These Literal types match their corresponding StrEnum values exactly.
            # Cannot reference StrEnum members directly due to Python class scoping rules
            # (nested classes cannot reference sibling classes during class definition).
            # The string values are kept here to match StrEnum values exactly - DRY at doc level.
            
            """Literal type matching ProcessingStage StrEnum values exactly."""

            """Literal type matching LdifHealthStatus StrEnum values exactly."""

            """Literal type matching EntryType StrEnum values exactly."""

            """Literal type matching EntryModification StrEnum values exactly."""

            """Output mode for attribute visibility in LDIF output.

            - show: Write attribute normally
            - hide: Don't write attribute at all
            - comment: Write attribute as a comment (# attr: value)
            """
            
            """Marker status for attribute processing metadata.

            NOTE: Matches AttributeMarkerStatus StrEnum values exactly.
            Cannot reference directly due to Python class scoping rules.
            """

            # Additional Literal types consolidated from outside the class
            # These complement the ones above and are derived from Enums/StrEnums
            
            """Category literals derived from Categories StrEnum."""

            """Change type literals derived from RFC constants."""

            """Modify operation literals derived from RFC constants."""

            """Sort strategy literals matching SortStrategy StrEnum values exactly."""

            """Sort target literals matching SortTarget StrEnum values exactly."""

            """Encoding literals matching Encoding StrEnum values exactly."""

            """LDIF format literals matching LdifFormat StrEnum values exactly."""

            """Quirk operation literals for parse/write operations."""

            """Schema parse operation literal."""

            """ACL write operation literal."""

            """Parse operation literal."""

            """Write operation literal."""

            """Parse/write operation literal."""

            # =====================================================================
            # ENUM-DERIVED LITERAL TYPES (Python 3.13+ PEP 695 best practices)
            # =====================================================================
            # These Literal types are derived from StrEnum classes above
            # Use these for type annotations in Pydantic models and function signatures
            # Using PEP 695 type statement for better type checking and IDE support

            """RFC ACL permission literals matching RfcAclPermission StrEnum values exactly."""

            """Comprehensive ACL permission literals matching AclPermission StrEnum values exactly.

            Includes RFC 4876 base permissions plus server-specific extensions.
            Use this for type-safe ACL permission handling across all server types.
            """

            """ACL action literals matching AclAction StrEnum values exactly.

            Use this for type-safe ACL action handling across all server types.
            """

            """ACL subject type literals matching AclSubjectType StrEnum values exactly.

            Includes server-specific extensions like "sddl" for Active Directory.
            Note: "dn", "user_dn", "userdn" are not in the base enum - they may be server-specific.
            """

            """Transformation type literals derived from TransformationType StrEnum."""

            """Filter type literals derived from FilterType StrEnum."""

            """Validation status literals derived from ValidationStatus StrEnum."""

            """Rejection category literals derived from RejectionCategory StrEnum."""

            """Error category literals derived from ErrorCategory StrEnum."""

            """Sorting strategy type literals derived from SortingStrategyType StrEnum."""

            # DictKeys StrEnum → Literal
            
            """Dictionary key literals derived from DictKeys StrEnum."""

            # QuirkMetadataKeys StrEnum → Literal
            
            """Quirk metadata key literals derived from QuirkMetadataKeys StrEnum."""

            # AclKeys StrEnum → Literal
            
            """ACL key literals derived from AclKeys StrEnum."""

            # FilterTypes StrEnum → Literal
            
            """Filter type enum literals derived from FilterTypes StrEnum."""

            # Modes StrEnum → Literal
            
            """Mode literals derived from Modes StrEnum."""

            # Categories StrEnum → Literal (already defined above, skipping duplicate)

            # DataTypes StrEnum → Literal
            
            """Data type literals derived from DataTypes StrEnum."""

            # ChangeType StrEnum → Literal
            
            """Change type enum literals derived from ChangeType StrEnum."""

            # ServiceType StrEnum → Literal (complete list matching ServiceType StrEnum)

            """Service type enum literals derived from ServiceType StrEnum.

        Complete list matching all ServiceType StrEnum values for
        type-safe annotations. Use this in function signatures and
        Pydantic models instead of direct StrEnum references.
        """

            # ServerTypes StrEnum → Literal

            type ServerTypeLiteral = Literal[
                "oid",
                "oud",
                "openldap",
                "openldap1",
                "openldap2",
                "ad",
                "apache",
                "ds389",
                "rfc",
                "relaxed",
                "novell",
                "ibm_tivoli",
                "generic",
            ]
            """Server type enum literals derived from ServerTypes StrEnum."""

            type TransformationTypeLiteral = Literal[
                "dn_cleaned",
                "dn_normalized",
                "tab_normalized",
                "space_cleaned",
                "utf8_decoded",
                "base64_decoded",
                "trailing_space_removed",
                "escape_normalized",
                "boolean_converted",
                "acl_converted",
                "attribute_removed",
                "attribute_added",
                "attribute_renamed",
                "modified",
                "matching_rule_replaced",
                "syntax_oid_replaced",
                "objectclass_filtered",
                "removed",
                "renamed",
                "basedn_transform",
            ]
            """Transformation type literals derived from TransformationType StrEnum."""

            type EncodingLiteral = Literal[
                "utf-8",
                "utf-16-le",
                "utf-16",
                "utf-32",
                "ascii",
                "latin-1",
                "cp1252",
                "iso-8859-1",
            ]
            """Encoding literals matching Encoding StrEnum values exactly."""

            type ChangeTypeLiteral = Literal[
                "add",
                "delete",
                "modify",
                "modrdn",
                "moddn",
            ]
            """Change type literals derived from RFC constants."""

            type ModifyOperationLiteral = Literal["add", "delete", "replace"]
            """Modify operation literals derived from RFC constants."""

            type AclSubjectTypeLiteral = Literal[
                "user",
                "group",
                "role",
                "self",
                "all",
                "public",
                "anonymous",
                "authenticated",
                "sddl",
            ]
            """ACL subject type literals matching AclSubjectType StrEnum values exactly."""

            type AttributeMarkerStatusLiteral = Literal[
                "normal",
                "marked_for_removal",
                "filtered",
                "operational",
                "hidden",
                "renamed",
            ]
            """Marker status literals matching AttributeMarkerStatus StrEnum."""

            type AnalyticsDetailLevelLiteral = Literal["low", "medium", "high"]
            """Analytics detail level literals."""

            type CategoryLiteral = Literal[
                "all",
                "users",
                "groups",
                "hierarchy",
                "schema",
                "acl",
                "rejected",
            ]
            """Category literals derived from Categories StrEnum."""

            type DetectionModeLiteral = Literal["auto", "manual", "disabled"]
            """Detection mode literals."""

            type ErrorRecoveryModeLiteral = Literal["continue", "stop", "skip"]
            """Error recovery mode literals."""

            type ValidationLevelLiteral = Literal["strict", "moderate", "lenient"]
            """Validation level literals."""

        # =============================================================================
        # ENCODING CONSTANTS
        # =============================================================================

        class LdapServers:
            """LDAP server implementation constants."""

            # Server types - reference ServerTypes enum for DRY compliance
            # No string duplication - all server types defined in ServerTypes enum above
            ACTIVE_DIRECTORY: Final = "ad"
            OPENLDAP: Final = "openldap"
            OPENLDAP_2: Final = "openldap2"
            OPENLDAP_1: Final = "openldap1"
            APACHE_DIRECTORY: Final = "apache"
            NOVELL_EDIRECTORY: Final = "novell"
            IBM_TIVOLI: Final = "ibm_tivoli"
            GENERIC: Final = "generic"
            ORACLE_OID: Final = "oid"
            ORACLE_OUD: Final = "oud"
            DS_389: Final = "ds389"

            # NOTE: Server-specific DN patterns, attributes, and object classes migrated:
            # - AD_DN_PATTERNS → FlextLdifServersAd.Constants.AD_DN_PATTERNS
            # - AD_REQUIRED_CLASSES → FlextLdifServersAd.Constants.AD_REQUIRED_CLASSES
            # - OPENLDAP_DN_PATTERNS →
            #   FlextLdifServersOpenldap.Constants.OPENLDAP_DN_PATTERNS
            # - OPENLDAP_2_ATTRIBUTES →
            #   FlextLdifServersOpenldap.Constants.OPENLDAP_2_ATTRIBUTES
            # - OPENLDAP_2_DN_PATTERNS →
            #   FlextLdifServersOpenldap.Constants.OPENLDAP_2_DN_PATTERNS
            # - OPENLDAP_1_ATTRIBUTES →
            #   FlextLdifServersOpenldap1.Constants.OPENLDAP_1_ATTRIBUTES
            # - OPENLDAP_REQUIRED_CLASSES →
            #   (if needed, add to FlextLdifServersOpenldap.Constants)
            # All server-specific constants should be defined in their respective
            # server Constants classes

        # =============================================================================
        # RFC 2849 COMPLIANCE CONSTANTS
        # =============================================================================

        class RfcCompliance:
            """RFC 2849 compliance validation constants."""

            # RFC 2849 format constants
            LINE_LENGTH_LIMIT: Final[int] = 76
            LINE_WITH_NEWLINE: Final[int] = LINE_LENGTH_LIMIT + 1  # 77

            # Validation strictness levels
            MODERATE: Final[str] = "moderate"

        class Acl:
            """ACL-related constants - RFC 4876 baseline ONLY.

            NOTE: Extended permissions (OUD SELF_WRITE, PROXY, etc.) moved to
            server-specific Constants.
            """

            # ACL operation types
            GRANT: Final[str] = "grant"
            DENY: Final[str] = "deny"
            ALLOW: Final[str] = "allow"

            # ACL scope types

            # RFC 4876 ACL permissions (baseline only - no extensions)
            READ: Final[str] = "read"
            WRITE: Final[str] = "write"
            SEARCH: Final[str] = "search"
            COMPARE: Final[str] = "compare"
            ADD: Final[str] = "add"
            DELETE: Final[str] = "delete"
            MODIFY: Final[str] = "modify"

            # Extended permissions (used by OID, OUD, etc.)
            # NOTE: Also defined in server-specific Constants for server-specific use
            SELF_WRITE: Final[str] = "self_write"
            PROXY: Final[str] = "proxy"

            # NOTE: Server-specific permissions may have additional definitions:
            # - SELF_WRITE variations in FlextLdifServersOud.Constants.OudPermission
            # - PROXY variations in FlextLdifServersOud.Constants.OudPermission
            # - BROWSE → Server-specific Constants
            # NOTE: Novell ACL parsing indices migrated to
            # FlextLdifServersNovell.Constants:
            # - NOVELL_SEGMENT_INDEX_TRUSTEE →
            #   FlextLdifServersNovell.Constants.NOVELL_SEGMENT_INDEX_TRUSTEE
            # - NOVELL_SEGMENT_INDEX_RIGHTS →
            #   FlextLdifServersNovell.Constants.NOVELL_SEGMENT_INDEX_RIGHTS

        class AclSubjectTypes:
            """ACL subject type identifiers for permission subjects.

            Used in ACL rules to identify what entity the permission applies to
            (user, group, role, self, everyone, etc.)
            """

            # Subject types for ACL permissions
            ROLE: Final[str] = "role"
            SELF: Final[str] = "self"  # Self (person modifying own entry)
            PUBLIC: Final[str] = "public"  # Public access
            ANONYMOUS: Final[str] = "anonymous"  # Anonymous access
            AUTHENTICATED: Final[str] = "authenticated"  # Any authenticated user

            class Schema:
                """Schema-related constants."""

            # Schema object types
            OBJECTCLASS: Final[str] = "objectclass"
            ATTRIBUTE: Final[str] = "attribute"
            SYNTAX: Final[str] = "syntax"
            MATCHINGRULE: Final[str] = "matchingrule"

            # Schema validation levels

            # Schema status
            ACTIVE: Final[str] = "active"
            DEPRECATED: Final[str] = "deprecated"

            # Object class kinds (RFC 4512)
            STRUCTURAL: Final[str] = "STRUCTURAL"
            AUXILIARY: Final[str] = "AUXILIARY"
            ABSTRACT: Final[str] = "ABSTRACT"

        # =============================================================================
        # OPERATIONAL ATTRIBUTES - Server-generated read-only attributes
        # =============================================================================

        class OperationalAttributes:
            """Operational (server-generated) attributes by server type.

            These attributes MUST be stripped during migration to prevent:
            - OUD rejection (read-only attributes)
            - Inconsistent state (OUD generates its own)
            - Sync conflicts (timestamp mismatches)

            Zero Tolerance: All operational attribute names MUST be defined here.
            """

            # NOTE: Server-specific operational attributes migrated to server Constants:
            # - OID_SPECIFIC → FlextLdifServersOid.Constants.OPERATIONAL_ATTRIBUTES
            # - OID_BOOLEAN_ATTRIBUTES →
            #   FlextLdifServersOid.Constants.BOOLEAN_ATTRIBUTES
            # - OUD_SPECIFIC →
            #   FlextLdifServersOud.Constants.OPERATIONAL_ATTRIBUTES
            # - OPENLDAP_SPECIFIC →
            #   FlextLdifServersOpenldap.Constants.OPERATIONAL_ATTRIBUTES
            # - DS_389_SPECIFIC →
            #   FlextLdifServersDs389.Constants.OPERATIONAL_ATTRIBUTES
            # - AD_SPECIFIC →
            #   FlextLdifServersAd.Constants.OPERATIONAL_ATTRIBUTES
            # - NOVELL_SPECIFIC →
            #   FlextLdifServersNovell.Constants.OPERATIONAL_ATTRIBUTES
            # - IBM_TIVOLI_SPECIFIC →
            #   FlextLdifServersTivoli.Constants.OPERATIONAL_ATTRIBUTES
            # All server-specific constants defined in their respective server
            # Constants

            # Common operational attributes to filter from ALL entries
            # These are always filtered regardless of entry type

            # Schema-related operational attributes to filter from NON-SCHEMA entries only
            # These are preserved in schema entries (cn=schema, cn=subschemasubentry, etc.)
            # as they contain the actual schema content

        class SchemaFields:
            """LDIF schema structure field names (case-sensitive).

            Consolidates all schema dictionary key names used throughout parsing.
            Critical for consistency when parsing RFC 2849 schema declarations.
            """

            # Primary schema field names (RFC 2849 section 5)
            ATTRIBUTE_TYPES: Final[str] = (
                "attributeTypes"  # RFC 4512 attribute definitions
            )
            OBJECT_CLASSES: Final[str] = (
                "objectClasses"  # RFC 4512 object class definitions
            )
            MATCHING_RULES: Final[str] = "matchingRules"  # RFC 4512 matching rules
            MATCHING_RULE_USE: Final[str] = (
                "matchingRuleUse"  # RFC 4512 matching rule use
            )
            DIT_CONTENT_RULES: Final[str] = (
                "dITContentRules"  # RFC 4512 DIT content rules
            )
            DIT_STRUCTURE_RULES: Final[str] = (
                "dITStructureRules"  # RFC 4512 DIT structure rules
            )
            NAME_FORMS: Final[str] = "nameForms"  # RFC 4512 name forms
            LDAP_SYNTAXES: Final[str] = "ldapSyntaxes"  # RFC 4512 LDAP syntaxes

            # Schema field names (lowercase variants for compatibility with some servers)
            ATTRIBUTE_TYPES_LOWER: Final[str] = "attributetypes"
            OBJECT_CLASSES_LOWER: Final[str] = "objectclasses"

            # ObjectClass field name (camelCase - used in entry attributes)
            OBJECT_CLASS_CAMEL: Final[str] = "objectClass"

            # All schema field names as frozenset for membership testing

        # =============================================================================
        # ACL ATTRIBUTES - ACL attribute names consolidated by server type
        # =============================================================================

        class AclAttributes:
            """RFC baseline ACL attribute names for LDAP.

            Consolidates RFC-standard ACL attributes for universal detection.
            Server-specific ACL attributes defined in respective server Constants classes:
            - OID: ORCLACI, ORCL_ENTRY_LEVEL_ACI → FlextLdifServersOid.Constants
            - AD: nTSecurityDescriptor → FlextLdifServersAd.Constants
            - Apache DS: ads-aci → FlextLdifServersApache.Constants
            - Tivoli: ibm-slapdaccesscontrol → FlextLdifServersTivoli.Constants
            - Other servers: Check respective server Constants classes
            """

            # RFC 4876 standard

            # Common ACL-related attributes for filtering
            ACLRIGHTS: Final[str] = "aclrights"  # Generic ACL rights attribute
            ACLENTRY: Final[str] = "aclentry"  # Generic ACL entry attribute

            # Default ACL attributes for sorting (RFC baseline + common server attributes)
            DEFAULT_ACL_ATTRIBUTES: Final[list[str]] = [
                "acl",  # Generic ACL attribute
                "aci",  # RFC 4876 standard (OUD, 389 DS)
                "olcAccess",  # OpenLDAP ACL attribute
            ]

            # Set of RFC baseline ACL attributes for quick membership testing.
            # NOTE: Server-specific attributes (e.g., orclaci,
            # nTSecurityDescriptor, ads-aci) are defined in their respective
            # server Constants classes

            # ACL attributes to filter/detect during migration
            # NOTE: All values commented, list empty - add as needed

            # NOTE: Server-specific ACL attribute sets should be defined in
            # their respective server Constants classes:
            # - OID: FlextLdifServersOid.Constants.ORCLACI,
            #   ORCL_ENTRY_LEVEL_ACI
            # - OUD: FlextLdifServersOud.Constants.ACL_ATTRIBUTE_NAME ("aci")
            # - OpenLDAP:
            #   FlextLdifServersOpenldap.Constants.ACL_ATTRIBUTE_NAME ("olcAccess")

        # =============================================================================
        # DN-VALUED ATTRIBUTES - Attributes that contain DN values
        # =============================================================================

        class DnValuedAttributes:
            """Attributes that contain Distinguished Names as values.

            Consolidated list of all attributes that hold DN references across
            all supported LDAP servers. Used for DN consistency validation during
            server-to-server migrations and conversions.

            These attributes require special handling during DN normalization
            and case preservation (especially for OUD compatibility).
            """

            # Member/ownership attributes (point to user/group DNs)
            MEMBER: Final[str] = "member"  # RFC 4512 group members
            UNIQUE_MEMBER: Final[str] = "uniqueMember"  # RFC 4512 unique members
            OWNER: Final[str] = "owner"  # Entry owner DN
            MANAGED_BY: Final[str] = "managedBy"  # Active Directory manager
            MANAGER: Final[str] = "manager"  # inetOrgPerson manager
            SECRETARY: Final[str] = "secretary"  # inetOrgPerson secretary
            SEES_ALSO: Final[str] = "seeAlso"  # See also reference

            # Parent/hierarchy attributes
            PARENT: Final[str] = "parent"  # Parent entry reference
            REFERS_TO: Final[str] = "refersTo"  # Generic reference

            # Group/role attributes (point to group/role DNs)
            MEMBER_OF: Final[str] = "memberOf"  # Active Directory member of groups
            GROUPS: Final[str] = "groups"  # Generic group membership

            # Authorization/delegation attributes
            AUTHORIZED_TO: Final[str] = "authorizedTo"  # Delegation target
            HAS_SUBORDINATES: Final[str] = "hasSubordinates"  # RFC 3673 operational
            SUBORDINATE_DN: Final[str] = "subordinateDn"  # Subordinate reference

            # =====================================================================
            # DN-VALUED ATTRIBUTE ENUMERATION (Source of Truth)
            # =====================================================================

            class DnValuedAttribute(StrEnum):
                """Attributes that contain Distinguished Names as values."""

                MEMBER = "member"
                UNIQUE_MEMBER = "uniqueMember"
                OWNER = "owner"
                MANAGED_BY = "managedBy"
                MANAGER = "manager"
                SECRETARY = "secretary"
                SEES_ALSO = "seeAlso"
                PARENT = "parent"
                REFERS_TO = "refersTo"
                MEMBER_OF = "memberOf"
                GROUPS = "groups"
                AUTHORIZED_TO = "authorizedTo"
                HAS_SUBORDINATES = "hasSubordinates"
                SUBORDINATE_DN = "subordinateDn"

            # All DN-valued attributes as frozenset for membership testing
            ALL_DN_VALUED: Final[frozenset[str]] = frozenset([
                DnValuedAttribute.MEMBER,
                DnValuedAttribute.UNIQUE_MEMBER,
                DnValuedAttribute.OWNER,
                DnValuedAttribute.MANAGED_BY,
                DnValuedAttribute.MANAGER,
                DnValuedAttribute.SECRETARY,
                DnValuedAttribute.SEES_ALSO,
                DnValuedAttribute.PARENT,
                DnValuedAttribute.REFERS_TO,
                DnValuedAttribute.MEMBER_OF,
                DnValuedAttribute.GROUPS,
                DnValuedAttribute.AUTHORIZED_TO,
                DnValuedAttribute.HAS_SUBORDINATES,
                DnValuedAttribute.SUBORDINATE_DN,
            ])

            # =============================================================================
            # DN PATTERNS - Standard DN patterns for schema and configuration
            # =============================================================================

        # =============================================================================
        # PERMISSION NAMES - ACL Permission Type Identifiers
        # =============================================================================

        # =============================================================================
        # BOOLEAN FORMATS - Server-Specific Boolean Representations
        # =============================================================================

        class BooleanFormats:
            """Boolean value representations and conversions across LDAP servers.

            Different servers use different boolean formats:
            - RFC 4517 compliant: "TRUE" / "FALSE"
            - Legacy formats: "true" / "false", "yes" / "no"

            Zero Tolerance: Boolean conversions MUST use these constants.
            DO NOT hard-code boolean strings like "TRUE" or "1" in servers/*.py

            NOTE: Server-specific boolean formats (e.g., Oracle OID "1"/"0") are defined
            in their respective server Constants classes:
            - OID: FlextLdifServersOid.Constants.ONE_OID, ZERO_OID, OID_TO_RFC, RFC_TO_OID
            - OUD: Uses RFC 4517 compliant format (TRUE/FALSE)
            """

            # RFC 4517 compliant (OUD, modern servers)
            TRUE_RFC: Final[str] = "TRUE"
            FALSE_RFC: Final[str] = "FALSE"

            # Legacy variants (case-insensitive)
            TRUE_LOWER: Final[str] = "true"
            FALSE_LOWER: Final[str] = "false"

        # =============================================================================
        # METADATA KEYS - Quirk Processing and Entry Extension Metadata
        # =============================================================================

        class MetadataKeys:
            """Metadata extension keys used in quirk processing and entry transformations.

            Used in _metadata dictionaries and extension fields within
            Entry/ACL/Schema models.

            Zero Tolerance: All metadata key strings MUST be defined here.
            DO NOT use hard-coded keys like metadata["proxy_permissions"] in
            servers/*.py
            """

            # =========================
            # OID-Specific Metadata
            # =========================

            PROXY_PERMISSIONS: Final[str] = "proxy_permissions"
            SELF_WRITE_TO_WRITE: Final[str] = "self_write_to_write"
            # NOTE: OID metadata keys moved to FlextLdifServersOid.Constants:
            # - ORIGINAL_OID_PERMS →
            #   FlextLdifServersOid.Constants.ORIGINAL_OID_PERMS
            # - OID_SPECIFIC_RIGHTS →
            #   FlextLdifServersOid.Constants.OID_SPECIFIC_RIGHTS
            # - RFC_NORMALIZED →
            #   FlextLdifServersOid.Constants.RFC_NORMALIZED (generic RFC
            #   transformation tracking)
            # Server-specific metadata keys should be defined in their respective
            # server Constants classes

            # =========================
            # Schema Conversion Metadata (GENERIC for ANY LDAP server
            # bidirectional conversion)
            # =========================
            # Servers MUST NOT know about each other - only communicate via these
            # GENERIC standardized keys
            # All Schema conversion metadata MUST use these keys for 100%
            # bidirectional conversion between ANY servers

            # === CORE SCHEMA METADATA (required for ALL servers) ===
            SCHEMA_ORIGINAL_FORMAT: Final[str] = (
                "schema_original_format"  # Original schema string format
                # (always preserve)
            )
            SCHEMA_ORIGINAL_STRING_COMPLETE: Final[str] = (
                "schema_original_string_complete"  # Complete original string
                # with ALL formatting preserved
            )
            SCHEMA_SOURCE_SERVER: Final[str] = (
                "schema_source_server"  # Server that parsed this schema
                # (oid, oud, openldap, etc.)
            )
            # === SCHEMA FORMATTING DETAILS (Zero Data Loss) ===
            SCHEMA_SYNTAX_QUOTES: Final[str] = (
                "schema_syntax_quotes"  # Whether SYNTAX had quotes
                # (OID: True, OUD/RFC: False)
            )
            SCHEMA_SYNTAX_SPACING: Final[str] = (
                "schema_syntax_spacing"  # Spaces after SYNTAX keyword
                # (OID: '  ', OUD: '', RFC: ' ')
            )
            SCHEMA_SYNTAX_SPACING_BEFORE: Final[str] = (
                "schema_syntax_spacing_before"  # Spaces before SYNTAX keyword
            )
            SCHEMA_ATTRIBUTE_CASE: Final[str] = (
                "schema_attribute_case"  # Case of attributeTypes keyword
                # (attributetypes vs attributeTypes)
            )
            SCHEMA_OBJECTCLASS_CASE: Final[str] = (
                "schema_objectclass_case"  # Case of objectClasses keyword
                # (objectclasses vs objectClasses)
            )
            SCHEMA_NAME_FORMAT: Final[str] = (
                "schema_name_format"  # Format: 'single' (NAME 'uid') vs
                # 'multiple' (NAME ( 'uid' 'userid' ))
            )
            SCHEMA_NAME_VALUES: Final[str] = (
                "schema_name_values"  # Original name values if multiple (['uid', 'userid'])
            )
            SCHEMA_X_ORIGIN_PRESENCE: Final[str] = (
                "schema_x_origin_presence"  # Whether X-ORIGIN was present in original
            )
            SCHEMA_X_ORIGIN_VALUE: Final[str] = (
                "schema_x_origin_value"  # Original X-ORIGIN value if present
            )
            SCHEMA_OBSOLETE_PRESENCE: Final[str] = (
                "schema_obsolete_presence"  # Whether OBSOLETE was present
            )
            SCHEMA_OBSOLETE_POSITION: Final[str] = (
                "schema_obsolete_position"  # Position of OBSOLETE in definition
                # (for order preservation)
            )
            SCHEMA_FIELD_ORDER: Final[str] = (
                "schema_field_order"  # Original field order in definition
            )
            SCHEMA_SPACING_BETWEEN_FIELDS: Final[str] = (
                "schema_spacing_between_fields"  # Spaces between fields
                # (dict of field pairs)
            )
            SCHEMA_TRAILING_SPACES: Final[str] = (
                "schema_trailing_spaces"  # Trailing spaces after closing paren
            )
            SCHEMA_SOURCE_SYNTAX_OID: Final[str] = (
                "schema_source_syntax_oid"  # Original syntax OID from source server
            )
            SCHEMA_TARGET_SYNTAX_OID: Final[str] = (
                "schema_target_syntax_oid"  # Normalized syntax OID for RFC/target
            )
            SCHEMA_SOURCE_MATCHING_RULES: Final[str] = (
                "schema_source_matching_rules"  # Original matching rules
                # (EQUALITY, SUBSTR, ORDERING)
            )
            SCHEMA_TARGET_MATCHING_RULES: Final[str] = (
                "schema_target_matching_rules"  # Normalized matching rules for RFC/target
            )
            SCHEMA_SOURCE_ATTRIBUTE_NAME: Final[str] = (
                "schema_source_attribute_name"  # Original attribute name from source
            )
            SCHEMA_TARGET_ATTRIBUTE_NAME: Final[str] = (
                "schema_target_attribute_name"  # Normalized attribute name for RFC/target
            )

            # === SCHEMA VALIDATION FLAGS (server-agnostic) ===
            SYNTAX_OID_VALID: Final[str] = "syntax_oid_valid"
            SYNTAX_VALIDATION_ERROR: Final[str] = "syntax_validation_error"
            X_ORIGIN: Final[str] = "x_origin"  # RFC 2252 X-ORIGIN extension
            COLLECTIVE: Final[str] = "collective"  # RFC 2876 COLLECTIVE flag

            # =========================
            # Entry Conversion Metadata (GENERIC for ANY LDAP server
            # bidirectional conversion)
            # =========================
            # Servers MUST NOT know about each other - only communicate via
            # these GENERIC standardized keys
            # All Entry conversion metadata MUST use these keys for 100%
            # bidirectional conversion between ANY servers

            # === CORE ENTRY METADATA (required for ALL servers) ===
            ENTRY_ORIGINAL_FORMAT: Final[str] = (
                "entry_original_format"  # Original entry format (always preserve)
            )
            ENTRY_SOURCE_SERVER: Final[str] = (
                "entry_source_server"  # Server that parsed this entry
                # (oid, oud, openldap, etc.)
            )
            ENTRY_SOURCE_ATTRIBUTES: Final[str] = (
                "entry_source_attributes"  # Original attribute names from source server
            )
            ENTRY_TARGET_ATTRIBUTES: Final[str] = (
                "entry_target_attributes"  # Normalized attribute names for RFC/target
            )
            ENTRY_SOURCE_OBJECTCLASSES: Final[str] = (
                "entry_source_objectclasses"  # Original objectClass values from source
            )
            ENTRY_TARGET_OBJECTCLASSES: Final[str] = (
                "entry_target_objectclasses"  # Normalized objectClass values for RFC/target
            )
            ENTRY_SOURCE_OPERATIONAL_ATTRS: Final[str] = (
                "entry_source_operational_attrs"  # Original operational attributes
            )
            ENTRY_TARGET_OPERATIONAL_ATTRS: Final[str] = (
                "entry_target_operational_attrs"  # Normalized operational attributes
            )
            ENTRY_SOURCE_DN_CASE: Final[str] = (
                "entry_source_dn_case"  # Original DN case from source server
            )
            ENTRY_TARGET_DN_CASE: Final[str] = (
                "entry_target_dn_case"  # Normalized DN case for RFC/target
            )

            # === ENTRY PROCESSING FLAGS (server-agnostic) ===
            BASE64_ATTRS: Final[str] = "_base64_attrs"  # Attributes encoded in base64
            MODIFY_ADD_ATTRIBUTETYPES: Final[str] = (
                "_modify_add_attributetypes"  # New attribute types in changetype: modify
            )
            MODIFY_ADD_OBJECTCLASSES: Final[str] = (
                "_modify_add_objectclasses"  # New object classes in changetype: modify
            )
            SKIPPED_ATTRIBUTES: Final[str] = (
                "_skipped_attributes"  # Attributes removed during conversion
            )
            CONVERTED_ATTRIBUTES: Final[str] = (
                "converted_attributes"  # Attribute names that changed
                # (no underscore - Pydantic extra silently ignores
                # underscore-prefixed keys)
            )

            # =========================
            # ACL Conversion Metadata (GENERIC for ANY LDAP server
            # bidirectional conversion)
            # =========================
            # Servers MUST NOT know about each other - only communicate via
            # these GENERIC standardized keys
            # All ACL conversion metadata MUST use these keys for 100%
            # bidirectional conversion between ANY servers

            # === CORE ACL METADATA (required for ALL servers) ===
            ACL_ORIGINAL_FORMAT: Final[str] = (
                "original_format"  # Original ACL string format (always preserve)
            )
            ACL_SOURCE_SERVER: Final[str] = (
                "source_server"  # Server that parsed this ACL (oid, oud, openldap, etc.)
            )
            ACL_SOURCE_SUBJECT_TYPE: Final[str] = (
                "source_subject_type"  # Original subject type from source server
            )
            ACL_TARGET_SUBJECT_TYPE: Final[str] = (
                "target_subject_type"  # Normalized subject type for RFC/target
            )
            ACL_ORIGINAL_SUBJECT_VALUE: Final[str] = (
                "original_subject_value"  # Original subject value before normalization
            )
            ACL_SOURCE_PERMISSIONS: Final[str] = (
                "source_permissions"  # Original permissions list from source
                # (before normalization)
            )
            ACL_TARGET_PERMISSIONS: Final[str] = (
                "target_permissions"  # Normalized permissions for RFC/target
            )
            ACL_ACTION_TYPE: Final[str] = (
                "action_type"  # ACL action type (allow or deny) - for OUD deny rules
            )
            ACL_NEGATIVE_PERMISSIONS: Final[str] = (
                "negative_permissions"  # Negative permissions list
                # (nowrite, noadd, etc.) - for OID
            )

            # === SERVER-SPECIFIC EXTENSIONS (optional, per-server features) ===
            # OID-specific
            ACL_FILTER: Final[str] = "filter"  # OID filter expression
            ACL_CONSTRAINT: Final[str] = (
                "added_object_constraint"  # OID entry-level constraint
            )
            ACL_BINDMODE: Final[str] = (
                "bindmode"  # OID BINDMODE (authentication/encryption requirements)
            )
            ACL_DENY_GROUP_OVERRIDE: Final[str] = (
                "deny_group_override"  # OID DenyGroupOverride flag
            )
            ACL_APPEND_TO_ALL: Final[str] = "append_to_all"  # OID AppendToAll flag
            ACL_BIND_IP_FILTER: Final[str] = (
                "bind_ip_filter"  # OID BINDIPFILTER (IP-based access restriction)
            )
            ACL_CONSTRAIN_TO_ADDED_OBJECT: Final[str] = (
                "constrain_to_added_object"  # OID constraintonaddedobject filter
            )

            # Generic subject attribute metadata (works for ANY LDAP server -
            # not OID-specific)
            ACL_DN_ATTR: Final[str] = (
                "dn_attr"  # DN attribute name (e.g., "manager" from "by dnattr=(manager)")
            )
            ACL_GUID_ATTR: Final[str] = (
                "guid_attr"  # GUID attribute name
                # (e.g., "orclguid" from "by guidattr=(orclguid)")
            )
            ACL_GROUP_ATTR: Final[str] = (
                "group_attr"  # Group attribute name
                # (e.g., "groupattr" from "by groupattr=(uniqueMember)")
            )

            # Generic permission metadata (works for ANY LDAP server - not OID-specific)
            ACL_BROWSE_EXPANDED: Final[str] = (
                "browse_expanded"  # True if "browse" was expanded to "read+search"
            )
            ACL_SELFWRITE_NORMALIZED: Final[str] = (
                "selfwrite_normalized"  # True if "selfwrite" was normalized to "self_write"
            )

            # OUD/RFC4876-specific (for ACI format servers: OUD, 389DS, OpenLDAP with ACI)
            ACL_TARGETSCOPE: Final[str] = (
                "targetscope"  # ACI target scope (base, one, sub, subordinate)
            )
            ACL_VERSION: Final[str] = "version"  # ACI version string (e.g., "3.0")
            ACL_DN_SPACES: Final[str] = (
                "dn_spaces"  # Whether DN has spaces around comma delimiters (", " vs ",")
            )
            ACL_LINE_BREAKS: Final[str] = (
                "line_breaks"  # Multiline ACI formatting (list of line break positions)
            )
            ACL_IS_MULTILINE: Final[str] = (
                "is_multiline"  # Flag: ACL spans multiple lines
            )

            # OpenLDAP-specific (for olcAccess format)
            ACL_NUMBERING: Final[str] = (
                "numbering"  # OpenLDAP ACL numbering (e.g., "{0}", "{1}")
            )
            ACL_SSFS: Final[str] = (
                "ssfs"  # OpenLDAP SSFS (Simple Security Framework Syntax)
            )

            # OUD/RFC4876 Advanced Bind Rules (for complex access control)
            ACL_TARGETATTR_FILTERS: Final[str] = (
                "targattrfilters"  # OUD targattrfilters (attribute value filtering)
            )
            ACL_TARGET_CONTROL: Final[str] = (
                "targetcontrol"  # OUD targetcontrol (LDAP control OID targeting)
            )
            ACL_EXTOP: Final[str] = "extop"  # OUD extop (extended operation OID)
            ACL_BIND_DNS: Final[str] = (
                "bind_dns"  # OUD dns bind rule (DNS pattern matching)
            )
            ACL_BIND_DAYOFWEEK: Final[str] = (
                "bind_dayofweek"  # OUD dayofweek bind rule (day restrictions)
            )
            ACL_BIND_TIMEOFDAY: Final[str] = (
                "bind_timeofday"  # OUD timeofday bind rule (time restrictions)
            )
            ACL_AUTHMETHOD: Final[str] = (
                "authmethod"  # OUD authmethod bind rule (required auth method)
            )
            ACL_SSF: Final[str] = (
                "ssf"  # OUD ssf bind rule (Security Strength Factor threshold)
            )

            # ACL Name Origin Tracking (OID→OUD conversion)
            ACL_NAME_SANITIZED: Final[str] = (
                "name_sanitized"  # True if ACL name was sanitized (had control chars)
            )
            ACL_ORIGINAL_NAME_RAW: Final[str] = (
                "original_name_raw"  # Original ACL name before sanitization (for audit)
            )

            # Active Directory-specific (for nTSecurityDescriptor format)
            ACL_SDDL: Final[str] = (
                "sddl"  # Security Descriptor Definition Language string
            )
            ACL_BINARY_SD: Final[str] = "binary_sd"  # Binary security descriptor

            # Server conversion tracking (server-agnostic)
            CONVERTED_FROM_SERVER: Final[str] = (
                "converted_from_server"  # Source server type that generated this ACL
            )
            CONVERSION_COMMENTS: Final[str] = (
                "conversion_comments"  # List of conversion comment lines
                # added during transformation
            )

            # =========================
            # Legacy/Generic Metadata
            # =========================

            ORIGINAL_FORMAT: Final[str] = (
                "original_format"  # Source format before conversion
            )
            ORIGINAL_SOURCE: Final[str] = (
                "original_source"  # Source server type that generated
            )

            # =========================
            # ACL/Permission Metadata
            # =========================

            VERSION: Final[str] = "version"  # ACL version/format number
            LINE_BREAKS: Final[str] = "line_breaks"  # Whether ACL uses line breaks
            IS_MULTILINE: Final[str] = "is_multiline"  # ACL spans multiple lines
            DN_SPACES: Final[str] = (
                "dn_spaces"  # Whether DN has spaces around delimiters
            )
            TARGETSCOPE: Final[str] = (
                "targetscope"  # ACL target scope (base, one, sub, etc)
            )
            ATTRIBUTE_ORDER: Final[str] = (
                "attribute_order"  # Order of attributes in original
            )
            SUBJECT_BINDING: Final[str] = "subject_binding"  # Subject binding type

            # =========================
            # Sorting Metadata
            # =========================

            SORTING_NEW_ATTRIBUTE_ORDER: Final[str] = (
                "sorting_new_attribute_order"  # New attribute order after sorting
            )
            SORTING_STRATEGY: Final[str] = (
                "sorting_strategy"  # Sorting strategy used
                # (alphabetical, custom_order, etc.)
            )
            SORTING_CUSTOM_ORDER: Final[str] = (
                "sorting_custom_order"  # Custom attribute order list used for sorting
            )
            SORTING_ORDERED_ATTRIBUTES: Final[str] = (
                "sorting_ordered_attributes"  # Attributes that were ordered by custom order
            )
            SORTING_REMAINING_ATTRIBUTES: Final[str] = (
                "sorting_remaining_attributes"  # Remaining attributes after custom order
            )
            SORTING_ACL_ATTRIBUTES: Final[str] = (
                "sorting_acl_attributes"  # ACL attribute names that were sorted
            )
            SORTING_ACL_SORTED: Final[str] = (
                "sorting_acl_sorted"  # Flag indicating ACL attributes were sorted
            )

            # =========================
            # Processing Metadata
            # =========================

            PARSED_TIMESTAMP: Final[str] = (
                "parsed_timestamp"  # ISO timestamp when entry was parsed
            )
            SOURCE_FILE: Final[str] = (
                "source_file"  # Source file path where entry was parsed from
            )
            HIDDEN_ATTRIBUTES: Final[str] = (
                "hidden_attributes"  # List of attributes to write as comments
                # (display/processing flag)
            )

            METADATA: Final[str] = "_metadata"
            ACL_ATTRIBUTES: Final[str] = (
                "_acl_attributes"  # ACL-related attributes in entry
            )
            HAS_SYNTAX_EXTENSIONS: Final[str] = (
                "_has_syntax_extensions"  # Custom SYNTAX extensions
            )
            REQUIRES_RFC_TRANSLATION: Final[str] = (
                "_requires_rfc_translation"  # Needs RFC conversion
            )
            IS_RELAXED_PARSED: Final[str] = (
                "_is_relaxed_parsed"  # Parsed using relaxed mode
            )

            # =========================
            # Conversion/Migration Metadata
            # =========================
            # NOTE: CONVERTED_FROM_SERVER and CONVERSION_COMMENTS are defined
            # in ACL Conversion Metadata section above (lines ~1526-1527) -
            # no duplication needed here

            # ===== COMPATIBILITY ALIASES (Deprecated - use ACL_* prefixed
            # versions above) =====
            # Legacy aliases for backward compatibility with existing code
            # NEW CODE MUST USE: ACL_OID_SUBJECT_TYPE, ACL_OUD_SUBJECT_TYPE,
            # ACL_RFC_SUBJECT_TYPE, ACL_ORIGINAL_SUBJECT_VALUE
            OID_SUBJECT_TYPE: Final[str] = (
                "oid_subject_type"  # DEPRECATED: Use ACL_OID_SUBJECT_TYPE
            )
            OUD_SUBJECT_TYPE: Final[str] = (
                "oud_subject_type"  # DEPRECATED: Use ACL_OUD_SUBJECT_TYPE
            )
            RFC_SUBJECT_TYPE: Final[str] = (
                "rfc_subject_type"  # DEPRECATED: Use ACL_RFC_SUBJECT_TYPE
            )
            ORIGINAL_SUBJECT_VALUE: Final[str] = (
                "original_subject_value"  # DEPRECATED: Use ACL_ORIGINAL_SUBJECT_VALUE
            )
            ORIGINAL_ENTRY: Final[str] = (
                "original_entry"  # Original entry before conversion
            )
            REMOVED_ATTRIBUTES: Final[str] = (
                "removed_attributes"  # Attributes removed/commented during processing
            )
            REMOVED_ATTRIBUTES_WITH_VALUES: Final[str] = (
                "removed_attributes_with_values"  # Attributes with values for RFC writer
            )

            # ===== ROUNDTRIP METADATA KEYS (Used for perfect round-trip conversion) =====
            # These keys store original data for exact LDIF recreation after processing
            MINIMAL_DIFFERENCES_DN: Final[str] = (
                "minimal_differences_dn"  # DN differences between original and converted
            )
            MINIMAL_DIFFERENCES_ATTRIBUTES: Final[str] = (
                "minimal_differences_attributes"  # Attribute differences
            )
            HAS_DIFFERENCES: Final[str] = (
                "has_differences"  # Boolean flag indicating DN/attribute differences exist
            )
            ORIGINAL_DN_COMPLETE: Final[str] = (
                "original_dn_complete"  # Original DN string before any normalization
            )
            ORIGINAL_ATTRIBUTES_COMPLETE: Final[str] = (
                "original_attributes_complete"  # Complete original attributes dict
            )
            ORIGINAL_DN_LINE_COMPLETE: Final[str] = (
                "original_dn_line_complete"  # Original DN line from LDIF file
            )
            ORIGINAL_ATTR_LINES_COMPLETE: Final[str] = (
                "original_attr_lines_complete"  # Original attribute lines from LDIF
            )

            WRITE_OPTIONS: Final[str] = (
                "_write_options"  # Write format options for LDIF output
            )

            # ===== NESTED CONVERSION METADATA KEYS (Keys within
            # CONVERTED_ATTRIBUTES structure) =====
            # These keys are used within the nested structure stored under
            # CONVERTED_ATTRIBUTES
            # Structure: CONVERTED_ATTRIBUTES = {
            #   "boolean_conversions": {...},
            #   "attribute_name_conversions": {...},
            #   "converted_attribute_names": [...]
            # }
            CONVERSION_BOOLEAN_CONVERSIONS: Final[str] = (
                "boolean_conversions"  # Nested key: boolean attribute conversions dict
            )
            CONVERSION_ATTRIBUTE_NAME_CONVERSIONS: Final[str] = (
                "attribute_name_conversions"  # Nested key: attribute name conversions dict
            )
            CONVERSION_CONVERTED_ATTRIBUTE_NAMES: Final[str] = (
                "converted_attribute_names"  # Nested key: list of converted attribute names
            )
            CONVERSION_ORIGINAL_VALUE: Final[str] = (
                "original"  # Nested key: original value(s) in conversion dict
            )
            CONVERSION_CONVERTED_VALUE: Final[str] = (
                "converted"  # Nested key: converted value(s) in conversion dict
            )
            # Legacy OID-specific key for backward compatibility
            # (deprecated, use nested structure)
            LEGACY_OID_BOOLEAN_CONVERSIONS_KEY: Final[str] = (
                "oid_boolean_conversions"  # Legacy top-level key for boolean
                # conversions (OID-specific, deprecated)
            )

            # =========================
            # All Metadata Keys Registry
            # =========================

            # NOTE: ALL_OID_KEYS moved to FlextLdifServersOid.Constants.ALL_OID_KEYS
            # Use FlextLdifServersOid.Constants for OID-specific metadata keys

        class DnPatterns:
            """Standard DN patterns used in LDAP/LDIF processing.

            Zero Tolerance: All DN pattern strings MUST be defined here.
            DO NOT use hard-coded DN strings anywhere in the codebase.
            """

            # Schema subentry DNs (server-specific)
            CN_SCHEMA: Final[str] = "cn=schema"
            CN_SUBSCHEMA: Final[str] = "cn=subschema"
            CN_SUBSCHEMA_SUBENTRY: Final[str] = "cn=subschemasubentry"
            CN_SCHEMA_CN_CONFIG: Final[str] = "cn=schema,cn=configuration"

            CN_SUBSCHEMASUBENTRY: Final[str] = "cn=subschemasubentry"

            CN_SCHEMA_CN_CONFIGURATION: Final[str] = "cn=schema,cn=configuration"

            # Configuration DNs
            CN_CONFIG: Final[str] = "cn=config"

            # NOTE: Oracle-specific DNs moved to FlextLdifServersOid.Constants:
            # - CN_ORCL → FlextLdifServersOid.Constants.CN_ORCL
            # - OU_ORACLE → FlextLdifServersOid.Constants.OU_ORACLE
            # - DC_ORACLE → FlextLdifServersOid.Constants.DC_ORACLE
            # - ORACLE_DN_PATTERNS → FlextLdifServersOid.Constants.ORACLE_DN_PATTERNS

            # DN component patterns
            DN_EQUALS: Final[str] = "="
            DN_COMMA: Final[str] = ","
            DN_PLUS: Final[str] = "+"

            # DN cleaning patterns (RFC 4514 normalization)
            DN_SPACES_AROUND_EQUALS: Final[str] = r"\s*=\s*"
            DN_TRAILING_BACKSLASH_SPACE: Final[str] = r"\\\s+,"
            DN_SPACES_AROUND_COMMA: Final[str] = r",\s+"
            DN_BACKSLASH_SPACE: Final[str] = r"\\\s+"
            DN_UNNECESSARY_ESCAPES: Final[str] = r'\\([^,+"\<>;\\# ])'
            DN_MULTIPLE_SPACES: Final[str] = r"\s+"

            # ACI DN reference patterns
            ACI_LDAP_URL_PATTERN: Final[str] = r"ldap:///([^\"]+?)"
            ACI_QUOTED_DN_PATTERN: Final[str] = (
                r'"((?:[a-zA-Z]+=[^,\";\)]+)(?:,[a-zA-Z]+=[^,\";\)]+)*)"'
            )

            # Schema parsing patterns
            SCHEMA_OID_EXTRACTION: Final[str] = r"\(\s*([\d.]+)"

            # Common DN prefix patterns
            CN_PREFIX: Final[str] = "cn="
            OU_PREFIX: Final[str] = "ou="
            DC_PREFIX: Final[str] = "dc="
            UID_PREFIX: Final[str] = "uid="
            O_PREFIX: Final[str] = "o="
            L_PREFIX: Final[str] = "l="
            ST_PREFIX: Final[str] = "st="
            C_PREFIX: Final[str] = "c="

            # NOTE: OpenLDAP config-specific patterns moved to server Constants:
            # - OLCDATABASE_PREFIX → FlextLdifServersOpenldap.Constants.OLCDATABASE_PREFIX
            # - OLCOVERLAY_PREFIX → FlextLdifServersOpenldap.Constants.OLCOVERLAY_PREFIX

            # All schema subentry patterns

            # NOTE: ORACLE_DN_PATTERNS moved to
            # FlextLdifServersOid.Constants.ORACLE_DN_PATTERNS

        # =============================================================================
        # ACL FORMATS - ACL format identifiers
        # =============================================================================

        class AclFormats:
            """ACL format identifier constants.

            NOTE: Server-specific ACL formats are now defined in their respective
            server Constants classes.
            This class retains only generic/RFC ACL format constants.

            Server-specific constants location:
            - OID: FlextLdifServersOid.Constants.ACL_FORMAT ("orclaci")
            - OUD: FlextLdifServersOud.Constants.ACL_FORMAT ("aci")
            - OpenLDAP: FlextLdifServersOpenldap.Constants.ACL_FORMAT ("olcAccess")
            - OpenLDAP1: FlextLdifServersOpenldap1.Constants.ACL_FORMAT ("access")
            - AD: FlextLdifServersAd.Constants.ACL_FORMAT ("nTSecurityDescriptor")
            - DS389: FlextLdifServersDs389.Constants.ACL_FORMAT ("aci")
            - Apache: FlextLdifServersApache.Constants.ACL_FORMAT ("aci")
            - Novell: FlextLdifServersNovell.Constants.ACL_FORMAT ("aci")
            - Tivoli: FlextLdifServersTivoli.Constants.ACL_FORMAT ("aci")
            - RFC: FlextLdifServersRfc.Constants.ACL_FORMAT ("rfc_generic")
            - Relaxed: FlextLdifServersRelaxed.Constants.ACL_FORMAT ("rfc_generic")

            Use FlextLdifModels.Acl.get_acl_format() to get the correct ACL format
            for a server type.
            It automatically queries the server Constants via registry.
            """

            # Generic/RFC ACL formats (only generic constants remain)
            RFC_GENERIC: Final[str] = "rfc_generic"
            ACI: Final[str] = "aci"  # RFC 4876 standard ACI attribute

            # RFC Baseline defaults (for core modules that cannot access services/*)
            DEFAULT_ACL_FORMAT: Final[str] = ACI
            DEFAULT_ACL_ATTRIBUTE_NAME: Final[str] = ACI

        class ServerTypesMappings:
            """Server type mappings and aliases (separate from enum to avoid conflicts)."""

            # Mapping from short forms to long forms (for backward compatibility)
            # Using string values directly (matching ServerTypes enum values)
            # Using MappingProxyType for immutability (read-only semantics)
            _LONG_NAMES_DICT: ClassVar[dict[str, str]] = {
                "oid": "oid",
                "oud": "oud",
                "openldap": "openldap",
                "openldap1": "openldap1",
                "openldap2": "openldap2",
                "ad": "ad",
                "apache": "apache",
                "generic": "generic",
                "rfc": "rfc",
                "ds389": "ds389",
                "relaxed": "relaxed",
                "novell": "novell",
                "ibm_tivoli": "ibm_tivoli",
            }
            LONG_NAMES: Final[Mapping[str, str]] = MappingProxyType(_LONG_NAMES_DICT)

            # Reverse mapping from long forms to short forms (read-only)
            _FROM_LONG_DICT: ClassVar[dict[str, str]] = {
                v: k for k, v in _LONG_NAMES_DICT.items()
            }
            FROM_LONG: Final[Mapping[str, str]] = MappingProxyType(_FROM_LONG_DICT)

            # Common short aliases (used in tests and user input) (read-only)
            _ALIASES_DICT: ClassVar[dict[str, str]] = {
                # Short forms
                "ad": "ad",
                "389": "ds389",
                "389ds": "ds389",
                "apache": "apache",
                "novell": "novell",
                "tivoli": "ibm_tivoli",
                # OpenLDAP aliases (openldap → openldap2 for backward compatibility)
                "openldap": "openldap2",
                # Long forms (backward compatibility)
                "active_directory": "ad",
                "apache_directory": "apache",
                "novell_edirectory": "novell",
                "ibm_tivoli": "ibm_tivoli",
                "oracle_oid": "oid",
                "oracle_oud": "oud",
            }
            ALIASES: Final[Mapping[str, str]] = MappingProxyType(_ALIASES_DICT)

            # Server type variants (for compatibility checks)

            # All validation functions removed - use utilities instead

        # =============================================================================
        # ADVANCED VALIDATION HELPERS - Python 3.13+ collections.abc patterns
        # =============================================================================

        class ValidationMappings:
            """Immutable validation mappings using collections.abc.Mapping.

            Python 3.13+ best practice for read-only validation data.
            All mappings are Final and use collections.abc for type safety.
            Derived directly from StrEnum classes to avoid duplication (DRY).
            """

            # LDIF format validation mapping - using hardcoded values
            # Note: No FormatType enum exists, using direct values
            LDIF_FORMAT_VALIDATION_MAP: Final[Mapping[str, str]] = MappingProxyType({
                "RFC2849": "RFC2849",
                "EXTENDED": "EXTENDED",
                "CUSTOM": "CUSTOM",
            })

            # Server types validation mapping - hardcoded to avoid forward reference
            # Canonical types only (excludes ORACLE_* aliases)
            SERVER_TYPE_VALIDATION_MAP: Final[Mapping[str, str]] = MappingProxyType({
                "oid": "oid",
                "oud": "oud",
                "openldap": "openldap",
                "openldap1": "openldap1",
                "openldap2": "openldap2",
                "active_directory": "active_directory",
                "apache_directory": "apache_directory",
                "generic": "generic",
                "rfc": "rfc",
                "389ds": "389ds",
                "relaxed": "relaxed",
                "novell_edirectory": "novell_edirectory",
                "ibm_tivoli": "ibm_tivoli",
            })

            # All validation/getter functions removed - use utilities instead

        # =============================================================================
        # OPERATION CONSTANTS - Filter types, modes, categories, data types
        # =============================================================================

        class FilterTypes(StrEnum):
            """Filter type identifier constants.

            Zero Tolerance: All filter type strings MUST be defined here.
            Used throughout filtering operations to avoid hardcoded strings.

            DRY Pattern:
                StrEnum is the single source of truth. Use FilterTypes.OBJECTCLASS.value
                or FilterTypes.OBJECTCLASS directly - no base strings needed.
            """

            OBJECTCLASS = "objectclass"
            DN_PATTERN = "dn_pattern"
            ATTRIBUTES = "attributes"
            SCHEMA_OID = "schema_oid"
            OID_PATTERN = "oid_pattern"
            ATTRIBUTE = "attribute"

        class Modes(StrEnum):
            """Operation mode constants.

            Zero Tolerance: All mode strings MUST be defined here.
            Used for filter modes, detection modes, and operation modes.

            DRY Pattern:
                StrEnum is the single source of truth. Use Modes.STRICT.value
                or Modes.STRICT directly - no base strings needed.
            """

            INCLUDE = "include"
            EXCLUDE = "exclude"
            AUTO = "auto"
            MANUAL = "manual"
            DISABLED = "disabled"

        class Categories(StrEnum):
            """Entry category constants.

            Zero Tolerance: All category strings MUST be defined here.
            Used for LDIF entry categorization in pipelines.

            DRY Pattern:
                StrEnum is the single source of truth. Use Categories.USER.value
                or Categories.USER directly - no base strings needed.
            """

            ALL = "all"
            USERS = "users"
            GROUPS = "groups"
            HIERARCHY = "hierarchy"
            SCHEMA = "schema"
            ACL = "acl"
            REJECTED = "rejected"

        class DataTypes(StrEnum):
            """Data type identifier constants.

            Zero Tolerance: All data type strings MUST be defined here.
            Used in quirks conversion matrix and data processing.

            DRY Pattern:
                StrEnum is the single source of truth. Use DataTypes.STRING.value
                or DataTypes.STRING directly - no base strings needed.
            """

            ATTRIBUTE = "attribute"
            OBJECTCLASS = "objectclass"
            ACL = "acl"
            ENTRY = "entry"
            SCHEMA = "schema"

        # =============================================================================
        # TYPE ALIASES - Root-level access to LiteralTypes
        # =============================================================================
        # NOTE: Convenience aliases removed per FLEXT architecture rules.
        # Always use full path: c.Ldif.LiteralTypes.ServerTypeLiteral

        class RuleTypes:
            """ACL rule type constants.

            Zero Tolerance: All rule type strings MUST be defined here.
            Used in ACL service for rule type identification.
            """

            COMPOSITE: Final[str] = "composite"
            PERMISSION: Final[str] = "permission"
            SUBJECT: Final[str] = "subject"
            TARGET: Final[str] = "target"

        class EntryTypes:
            """Entry type identifier constants.

            Zero Tolerance: All entry type strings MUST be defined here.
            Used in entry builder and API for entry type identification.
            """

            OU: Final[str] = "ou"
            CUSTOM: Final[str] = "custom"

        class ConversionTypes:
            """Conversion type identifier constants.

            Zero Tolerance: All conversion type strings MUST be defined here.
            Used in API for data conversion operations.
            """

            ENTRY_TO_DICT: Final[str] = "entry_to_dict"
            ENTRIES_TO_DICTS: Final[str] = "entries_to_dicts"
            DICTS_TO_ENTRIES: Final[str] = "dicts_to_entries"
            ENTRIES_TO_JSON: Final[str] = "entries_to_json"
            JSON_TO_ENTRIES: Final[str] = "json_to_entries"

            # Python 3.13+ PEP 695 type alias for better type checking

        class ProcessorTypes:
            """Processor type identifier constants.

            Zero Tolerance: All processor type strings MUST be defined here.
            Used in API for processor selection.
            """

            TRANSFORM: Final[str] = "transform"
            VALIDATE: Final[str] = "validate"

        class MatchTypes:
            """Match type constants for filtering.

            Zero Tolerance: All match type strings MUST be defined here.
            """

            ANY: Final[str] = "any"

            # Python 3.13+ PEP 695 type alias for better type checking

        class Scopes:
            """LDAP search scope constants.

            Zero Tolerance: All scope strings MUST be defined here.
            """

            ONE: Final[str] = "one"
            SUB: Final[str] = "sub"
            SUBORDINATE: Final[str] = "subordinate"

            # Python 3.13+ PEP 695 type alias for better type checking

        class Parameters:
            """Parameter name constants.

            Zero Tolerance: All parameter name strings MUST be defined here.
            Used for function/method parameter naming consistency.
            """

            FILE_PATH: Final[str] = "file_path"
            CONTENT: Final[str] = "content"
            PARSE_CHANGES: Final[str] = "parse_changes"
            PARSE_ATTRIBUTES: Final[str] = "parse_attributes"
            PARSE_OBJECTCLASSES: Final[str] = "parse_objectclasses"

            # Python 3.13+ PEP 695 type alias for better type checking

        # =============================================================================
        # REGEX PATTERNS - All regex patterns centralized
        # =============================================================================

        class LdifPatterns:
            """Regex pattern constants for LDIF processing.

            Zero Tolerance: ALL regex patterns MUST be defined here.
            NO re.compile() or pattern strings outside this namespace.
            """

            # Encoding detection patterns (from utilities.py)
            XML_ENCODING: Final[str] = r'<\?xml[^>]*encoding=["\']([^"\']+)["\']'
            HTML_CHARSET: Final[str] = r'<meta[^>]*charset=["\']([^"\']+)["\']'
            PYTHON_CODING: Final[str] = r"#.*-\*-.*coding:\s*([^\s;]+)"
            LDIF_ENCODING: Final[str] = r"#\s*encoding:\s*([^\s\n]+)"

            # DN validation patterns (RFC 4514)
            # attribute=value where attribute starts with letter,
            # value can be anything (including escaped chars)
            # This pattern ensures each component has both attribute and = sign
            # Full validation happens in DN validator
            # which parses escaped characters
            DN_COMPONENT: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*=(?:[^\\,]|\\.)*$"
            DN_SEPARATOR: Final[str] = r"(?<!\\),"

            # LDAP filter pattern (RFC 4515)
            LDAP_FILTER: Final[str] = r"^\(.*\)$"

            # Object class name pattern (similar to attribute names but allowing uppercase)
            OBJECTCLASS_NAME: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"

            # Attribute name patterns (RFC 4512 § 2.5)
            # Base attribute name: starts with letter, followed by letters/digits/hyphens
            ATTRIBUTE_NAME: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"
            # RFC 4512 constraint: attribute names must not exceed 127 characters
            MAX_ATTRIBUTE_NAME_LENGTH: Final[int] = 127
            # Attribute option: RFC 4512 § 2.5 + RFC 3066 (language tags with underscore)
            # Examples: lang-ar, binary, lang-es_es (es_ES = Spanish Spain)
            ATTRIBUTE_OPTION: Final[str] = r";[a-zA-Z][a-zA-Z0-9-_]*"

            # OID patterns
            OID_NUMERIC: Final[str] = r"^\d+(\.\d+)*$"
            OID_DESCRIPTOR: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"

            # Schema parsing patterns
            SCHEMA_OID: Final[str] = r"^\s*\(\s*([\d.]+)"
            SCHEMA_OID_EXTRACTION: Final[str] = (
                r"\(\s*([\d.]+)"  # For re.search() without ^ anchor
            )
            # Regex pattern for extracting OID from schema definitions (with start anchor)
            SCHEMA_OID_EXTRACTION_START: Final[str] = (
                r"^\s*\(\s*([0-9.]+)"  # For re.search() with ^ anchor (common use case)
            )
            SCHEMA_NAME: Final[str] = r"(?i)NAME\s+\(?\s*'([^']+)'"
            SCHEMA_DESC: Final[str] = r"DESC\s+'([^']+)'"
            SCHEMA_SYNTAX: Final[str] = r"SYNTAX\s+([\d.]+)"
            SCHEMA_EQUALITY: Final[str] = r"EQUALITY\s+([^\s)]+)"
            SCHEMA_SUBSTR: Final[str] = r"SUBSTR\s+([^\s)]+)"
            SCHEMA_ORDERING: Final[str] = r"ORDERING\s+([^\s)]+)"
            SCHEMA_SUP: Final[str] = r"SUP\s+(\w+)"
            SCHEMA_USAGE: Final[str] = r"USAGE\s+(\w+)"
            SCHEMA_X_ORIGIN: Final[str] = r"X-ORIGIN\s+'([^']+)'"
            SCHEMA_SYNTAX_LENGTH: Final[str] = (
                r"SYNTAX\s+(?:')?([0-9.]+)(?:')?(?:\{(\d+)\})?"
            )
            SCHEMA_SINGLE_VALUE: Final[str] = r"\bSINGLE-VALUE\b"
            SCHEMA_COLLECTIVE: Final[str] = r"\bCOLLECTIVE\b"
            SCHEMA_NO_USER_MODIFICATION: Final[str] = r"\bNO-USER-MODIFICATION\b"
            SCHEMA_OBSOLETE: Final[str] = r"\bOBSOLETE\b"

            # ObjectClass specific schema parsing patterns
            SCHEMA_OBJECTCLASS_KIND: Final[str] = r"\b(ABSTRACT|STRUCTURAL|AUXILIARY)\b"
            SCHEMA_OBJECTCLASS_SUP: Final[str] = r"SUP\s+(?:\(\s*([^)]+)\s*\)|(\w+))"
            SCHEMA_OBJECTCLASS_MUST: Final[str] = r"MUST\s+(?:\(\s*([^)]+)\s*\)|(\w+))"
            SCHEMA_OBJECTCLASS_MAY: Final[str] = r"MAY\s+(?:\(\s*([^)]+)\s*\)|(\w+))"

            # Server detection patterns moved to ServerDetection class below

        # =============================================================================
        # SERVER DETECTION - Comprehensive server type detection patterns and weights
        # =============================================================================

        class ServerDetection:
            """Server type detection patterns and weights for LDIF content analysis.

            Comprehensive patterns for identifying LDAP server types from LDIF content.
            Higher weight values indicate more specific patterns.
            """

            # NOTE: Server-specific detection patterns have been moved to
            # their respective server Constants classes:
            # - ORACLE_OID_PATTERN, ORACLE_OID_ATTRIBUTES, ORACLE_OID_WEIGHT →
            #   FlextLdifServersOid.Constants.DETECTION_*
            # - ORACLE_OUD_PATTERN, ORACLE_OUD_ATTRIBUTES, ORACLE_OUD_WEIGHT →
            #   FlextLdifServersOud.Constants.DETECTION_*
            # - OPENLDAP_PATTERN, OPENLDAP_ATTRIBUTES, OPENLDAP_WEIGHT →
            #   FlextLdifServersOpenldap.Constants.DETECTION_*
            # - ACTIVE_DIRECTORY_PATTERN, ACTIVE_DIRECTORY_ATTRIBUTES,
            #   ACTIVE_DIRECTORY_WEIGHT → FlextLdifServersAd.Constants.DETECTION_*
            # - NOVELL_EDIR_PATTERN, NOVELL_EDIR_WEIGHT →
            #   FlextLdifServersNovell.Constants.DETECTION_*
            # - IBM_TIVOLI_PATTERN, IBM_TIVOLI_WEIGHT →
            #   FlextLdifServersTivoli.Constants.DETECTION_*
            # - DS_389_PATTERN, DS_389_WEIGHT → FlextLdifServersDs389.Constants.DETECTION_*

            # Detection thresholds
            DETECTION_THRESHOLD: Final[int] = 5
            CONFIDENCE_THRESHOLD: Final[float] = 0.6

            # Detection scoring
            ATTRIBUTE_MATCH_SCORE: Final[int] = (
                2  # Points awarded for matching server-specific attributes
            )

            # Detection performance limits
            DEFAULT_MAX_LINES: Final[int] = 1000

            # ObjectClass schema field names (RFC 4512)
            SCHEMA_FIELD_SUPERIOR: Final[str] = "superior"
            SCHEMA_FIELD_REQUIRED_ATTRIBUTES: Final[str] = "required_attributes"
            SCHEMA_FIELD_OPTIONAL_ATTRIBUTES: Final[str] = "optional_attributes"
            SCHEMA_FIELD_STRUCTURAL: Final[str] = "structural"

            # Schema parsing constants
            SCHEMA_SUBENTRY_DN: Final[str] = "cn=subschemasubentry"
            ATTRIBUTE_TYPES_PREFIX: Final[str] = "attributetypes:"
            OBJECT_CLASSES_PREFIX: Final[str] = "objectclasses:"
            ATTRIBUTE_TYPES_PREFIX_LENGTH: Final[int] = len(ATTRIBUTE_TYPES_PREFIX)
            OBJECT_CLASSES_PREFIX_LENGTH: Final[int] = len(OBJECT_CLASSES_PREFIX)

            # LDIF parsing constants
            CONTENT_PARAMETER: Final[str] = "content"
            PARSE_CHANGES_PARAMETER: Final[str] = "parse_changes"
            DEFAULT_PARSE_CHANGES: Final[bool] = False

            # Error message templates
            ERROR_UNSUPPORTED_ENTRY_TYPE: Final[str] = "Unsupported entry type"
            ERROR_LDIF_WRITE_FAILED: Final[str] = "LDIF write failed"
            ERROR_FAILED_TO_WRITE: Final[str] = "Failed to write"

            # Parser message templates
            MSG_PARSING_LDIF_CONTENT: Final[str] = (
                "Parsing LDIF content string (RFC 2849 via ldif3)"
            )
            MSG_PARSING_LDIF_FILE: Final[str] = "Parsing LDIF file (RFC 2849 via ldif3)"
            MSG_LDIF_CONTENT_PARSED: Final[str] = "LDIF content parsed successfully"
            MSG_LDIF_PARSED_SUCCESS: Final[str] = "LDIF parsed successfully"
            MSG_FAILED_EXECUTE_PARSER: Final[str] = "Failed to execute RFC LDIF parser"
            MSG_FAILED_PARSE_LDIF3: Final[str] = "Failed to parse LDIF with ldif3"
            MSG_EITHER_CONTENT_OR_PATH_REQUIRED: Final[str] = (
                "Either content or file_path must be provided"
            )

            # Writer message templates
            MSG_LDIF_FILE_WRITTEN: Final[str] = "LDIF file written"
            MSG_LDIF_CONTENT_GENERATED: Final[str] = "LDIF content generated"
            MSG_AT_LEAST_ONE_REQUIRED: Final[str] = (
                "At least one of entries, schema, or acls must be provided"
            )

            # ACL utility constants
            ACL_WILDCARD_DN: Final[str] = "*"
            LDIF_FILE_EXTENSION: Final[str] = ".ldif"

            # Schema builder constants
            DEFAULT_ENTRY_COUNT: Final[int] = 0
            DEFAULT_SINGLE_VALUE: Final[bool] = False

            # Change type patterns
            CHANGETYPE: Final[str] = r"^changetype:\s*(add|delete|modify|modrdn|moddn)$"

        # Change type enum
        class ChangeType(StrEnum):
            """LDIF change types for entry operations.

            DRY Pattern:
                StrEnum is the single source of truth. Use ChangeType.ADD.value
                or ChangeType.ADD directly - no base strings needed.

            Note: Both MODRDN and MODDN are valid - MODRDN is RFC 2849 standard,
            MODDN is an accepted alternative form.
            """

            ADD = "add"
            DELETE = "delete"
            MODIFY = "modify"
            MODRDN = "modrdn"
            MODDN = "moddn"

        class ModifyOperation(StrEnum):
            """LDIF modify operation types.

            DRY Pattern:
                StrEnum is the single source of truth. Use ModifyOperation.ADD.value
                or ModifyOperation.ADD directly - no separate frozenset needed.
            """

            ADD = "add"
            DELETE = "delete"
            REPLACE = "replace"

        class SchemaUsage(StrEnum):
            """RFC 4512 attribute usage types.

            DRY Pattern:
                StrEnum is the single source of truth. Use SchemaUsage.USER_APPLICATIONS.value
                or SchemaUsage.USER_APPLICATIONS directly - no separate frozenset needed.
            """

            USER_APPLICATIONS = "userApplications"
            DIRECTORY_OPERATION = "directoryOperation"
            DISTRIBUTED_OPERATION = "distributedOperation"
            DSA_OPERATION = "dSAOperation"

        class SchemaKind(StrEnum):
            """RFC 4512 objectClass kind types.

            DRY Pattern:
                StrEnum is the single source of truth. Use SchemaKind.ABSTRACT.value
                or SchemaKind.ABSTRACT directly - no separate frozenset or Final[str] needed.
            """

            ABSTRACT = "ABSTRACT"
            STRUCTURAL = "STRUCTURAL"
            AUXILIARY = "AUXILIARY"

        # LDAP SERVERS - Server-specific detection patterns
        # =============================================================================

        class LdapServerDetection:
            """Server-specific detection patterns and markers for LDAP servers.

            Centralizes all OID patterns, attribute prefixes, objectClass names,
            and DN markers used for server detection across all quirk implementations.

            Zero Tolerance: All server detection constants MUST be defined here,
            NO hardcoding in server implementations.
            """

            # NOTE: Server-specific detection constants migrated to their respective
            # server Constants classes:
            # - AD: FlextLdifServersAd.Constants (DETECTION_OID_PATTERN,
            #   DETECTION_ATTRIBUTE_NAMES, DETECTION_OBJECTCLASS_NAMES,
            #   DETECTION_DN_MARKERS, DETECTION_ATTRIBUTE_MARKERS)
            # - Apache: FlextLdifServersApache.Constants (DETECTION_OID_PATTERN,
            #   DETECTION_ATTRIBUTE_PREFIXES, DETECTION_OBJECTCLASS_NAMES,
            #   DETECTION_DN_MARKERS)
            # - Novell: FlextLdifServersNovell.Constants
            #   (DETECTION_ATTRIBUTE_MARKERS, DETECTION_OBJECTCLASS_NAMES,
            #   DETECTION_DN_MARKERS)
            # - Tivoli: FlextLdifServersTivoli.Constants
            #   (DETECTION_ATTRIBUTE_MARKERS, DETECTION_OBJECTCLASS_NAMES,
            #   DETECTION_DN_MARKERS)
            # - OID: FlextLdifServersOid.Constants (DETECTION_OID_PATTERN,
            #   DETECTION_ATTRIBUTE_PREFIXES, DETECTION_OBJECTCLASS_NAMES,
            #   DETECTION_DN_MARKERS)
            # - OUD: FlextLdifServersOud.Constants (
            #   DETECTION_OID_PATTERN, DETECTION_ATTRIBUTE_PREFIXES,
            #   DETECTION_OBJECTCLASS_NAMES, DETECTION_DN_MARKERS)
            # - OpenLDAP: FlextLdifServersOpenldap.Constants (
            #   DETECTION_OID_PATTERN, DETECTION_ATTRIBUTE_PREFIXES,
            #   DETECTION_OBJECTCLASS_NAMES, DETECTION_DN_MARKERS)
            # - DS389: FlextLdifServersDs389.Constants (
            #   DETECTION_OID_PATTERN, DETECTION_ATTRIBUTE_PREFIXES,
            #   DETECTION_OBJECTCLASS_NAMES, DETECTION_DN_MARKERS)
            # All server-specific constants should be defined in their respective
            # server Constants classes

        # =============================================================================
        # VALIDATION RULES - Validation logic constants
        # =============================================================================

        class ValidationRules:
            """Validation rule constants.

            Zero Tolerance: All validation logic constants MUST be defined here.
            NO hard-coded validation strings in validators.

            NOTE: Server-specific validation rules belong in servers/* modules,
            NOT here. This class contains only RFC-generic validation constants.
            """

            # Numeric validation rules
            MIN_WORKERS_PERFORMANCE_RULE: Final[int] = 4
            MIN_CHUNK_SIZE_PERFORMANCE_RULE: Final[int] = 1000
            MAX_WORKERS_DEBUG_RULE: Final[int] = 2
            MIN_ANALYTICS_CACHE_RULE: Final[int] = 1
            MIN_PARALLEL_THRESHOLD_RULE: Final[int] = 1

            # Validation limits
            DEFAULT_MAX_ATTR_VALUE_LENGTH: Final[int] = 1048576  # 1MB default
            TYPICAL_ATTR_NAME_LENGTH_LIMIT: Final[int] = 127  # RFC 4512 typical limit

        class RfcSyntaxOids:
            """RFC 4517 LDAP Attribute Syntax OIDs.

            Standard LDAP attribute syntax definitions per RFC 4517.
            OID format: 1.3.6.1.4.1.1466.115.121.1.X
            """

            # RFC 4517 Syntax OIDs (base: 1.3.6.1.4.1.1466.115.121.1)

            # Basic syntaxes
            ACCESS_POINT: Final[str] = "1.3.6.1.4.1.1466.115.121.1.2"  # Access Point
            ATTRIBUTE_TYPE_DESCRIPTION: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.3"  # Attribute Type Description
            )
            BINARY: Final[str] = "1.3.6.1.4.1.1466.115.121.1.5"  # Binary
            BIT_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.6"  # Bit String
            BOOLEAN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.7"  # Boolean
            CERTIFICATE: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.8"  # Certificate (DER encoded)
            )
            CERTIFICATE_LIST: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.9"  # Certificate List (DER encoded)
            )
            CERTIFICATE_PAIR: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.10"  # Certificate Pair (DER encoded)
            )
            COUNTRY_STRING: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.11"  # Country String
            )
            DN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.12"  # Distinguished Name (DN)
            DATA_QUALITY_SYNTAX: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.13"  # Data Quality Syntax
            )
            DELIVERY_METHOD: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.14"  # Delivery Method
            )
            DIRECTORY_STRING: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.15"  # Directory String
            )
            DIT_CONTENT_RULE_DESCRIPTION: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.16"  # DIT Content Rule Description
            )
            DIT_STRUCTURE_RULE_DESCRIPTION: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.17"  # DIT Structure Rule Description
            )
            DLEXP_TIME: Final[str] = "1.3.6.1.4.1.1466.115.121.1.18"  # DLEXP Time
            DN_WITH_BINARY: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.19"  # DN With Binary
            )
            DN_WITH_STRING: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.20"  # DN With String
            )

            # String-based syntaxes
            DIRECTORY_STRING_21: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.21"  # Directory String
            )
            ENHANCED_GUIDE: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.22"  # Enhanced Guide
            )
            FACSIMILE_TELEPHONE_NUMBER: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.23"  # Facsimile Telephone Number
            )
            FAX: Final[str] = "1.3.6.1.4.1.1466.115.121.1.24"  # Fax
            GENERALIZED_TIME: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.25"  # Generalized Time
            )
            GUIDE: Final[str] = "1.3.6.1.4.1.1466.115.121.1.26"  # Guide
            IA5_STRING: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.27"  # IA5 String (ASCII)
            )
            INTEGER_RFC: Final[str] = "2.5.5.5"  # INTEGER (RFC 2252/4517 standard)
            JPEG: Final[str] = "1.3.6.1.4.1.1466.115.121.1.28"  # JPEG Image
            LDAP_SYNTAX_DESCRIPTION: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.29"  # LDAP Syntax Description
            )

            # Numeric and structured syntaxes
            MATCHING_RULE_DESCRIPTION: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.30"  # Matching Rule Description
            )
            MATCHING_RULE_USE_DESCRIPTION: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.31"  # Matching Rule Use Description
            )
            MHS_OR_ADDRESS: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.32"  # MHS OR Address
            )
            MODIFY_INCREMENT: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.33"  # Modify Increment
            )
            NAME_AND_OPTIONAL_UID: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.34"  # Name and Optional UID
            )
            NAME_FORM_DESCRIPTION: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.35"  # Name Form Description
            )
            NUMERIC_STRING: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.36"  # Numeric String
            )
            OBJECT_CLASS_DESCRIPTION: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.37"  # Object Class Description
            )
            OID: Final[str] = "1.3.6.1.4.1.1466.115.121.1.38"  # OID
            OCTET_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.39"  # Octet String

            # Additional standard syntaxes
            OTHER_MAILBOX: Final[str] = "1.3.6.1.4.1.1466.115.121.1.40"  # Other Mailbox
            OCTET_STRING_40: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.40"  # Octet String (same as 39)
            )
            POSTAL_ADDRESS: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.41"  # Postal Address
            )
            PROTOCOL_INFORMATION: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.42"  # Protocol Information
            )
            PRESENTATION_ADDRESS: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.43"  # Presentation Address
            )
            PRINTABLE_STRING: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.44"  # Printable String
            )
            SUBSTRING_ASSERTION: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.58"  # Substring Assertion
            )
            TELEPHONE_NUMBER: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.50"  # Telephone Number
            )
            TELETEX_TERMINAL_IDENTIFIER: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.51"  # Teletex Terminal Identifier
            )
            TELEX_NUMBER: Final[str] = "1.3.6.1.4.1.1466.115.121.1.52"  # Telex Number
            TIME_OF_DAY: Final[str] = "1.3.6.1.4.1.1466.115.121.1.53"  # Time of Day
            UTCTIME: Final[str] = "1.3.6.1.4.1.1466.115.121.1.54"  # UTC Time
            LDAP_SYNTAX: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.54"  # LDAP Syntax (alias)
            )
            UTF8_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.55"  # UTF-8 String
            UNICODE_STRING: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.56"  # Unicode String (also UCS-2)
            )
            UUI: Final[str] = (
                "1.3.6.1.4.1.1466.115.121.1.57"  # UUI (User-defined attribute)
            )

            # Mapping of OID to human-readable name (immutable)
            OID_TO_NAME: ClassVar[Mapping[str, str]] = MappingProxyType({
                "2.5.5.5": "integer",  # INTEGER (RFC 2252/4517 standard)
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

            # Mapping of human-readable name to OID
            NAME_TO_OID: Final[dict[str, str]] = {v: k for k, v in OID_TO_NAME.items()}

            # Mapping of syntax names to type categories (immutable)
            NAME_TO_TYPE_CATEGORY: ClassVar[Mapping[str, str]] = MappingProxyType({
                "boolean": "boolean",
                "integer": "integer",
                "dn": "dn",
                "distinguished_name": "dn",
                "generalized_time": "time",
                "utc_time": "time",
                "utctime": "time",
                "time_of_day": "time",
                "dlexp_time": "time",
                "audio": "binary",
                "binary": "binary",
                "certificate": "binary",
                "certificate_list": "binary",
                "certificate_pair": "binary",
                "fax": "binary",
                "jpeg": "binary",
                "octet_string": "binary",
                "directory_string": "string",
                "ia5_string": "string",
                "printable_string": "string",
                "utf8_string": "string",
                "unicode_string": "string",
                "teletex_terminal_identifier": "string",
                "telephone_number": "string",
                "facsimile_telephone_number": "string",
                "guide": "string",
                "enhanced_guide": "string",
                "access_point": "string",
                "attribute_type_description": "string",
                "country_string": "string",
                "dn_with_binary": "string",
                "dn_with_string": "string",
                "ldap_syntax_description": "string",
                "matching_rule_description": "string",
                "matching_rule_use_description": "string",
                "name_and_optional_uid": "string",
                "name_form_description": "string",
                "numeric_string": "string",
                "object_class_description": "string",
                "oid": "string",
                "other_mailbox": "string",
                "postal_address": "string",
                "protocol_information": "string",
                "presentation_address": "string",
                "telex_number": "string",
                "teletex_number": "string",
                "uui": "string",
                "substring_assertion": "string",
                "mhs_or_address": "string",
                "aci": "string",
                "delivery_method": "string",
                "data_quality_syntax": "string",
                "dit_content_rule_description": "string",
                "dit_structure_rule_description": "string",
                "modify_increment": "integer",
                "bit_string": "string",
            })

            # Service and initialization keys
            SERVICE_NAMES: Final[str] = "service_names"
            DATA: Final[str] = "data"

        class LdifFormatting:
            """LDIF formatting constants (line width, folding).

            Defines constants for LDIF formatting options including line width
            and other formatting preferences. Different from LdifFormat which
            defines RFC 2849 value indicators (::, :, :<).
            """

            # Default line width for LDIF folding (RFC 2849 recommends 76)
            DEFAULT_LINE_WIDTH: Final[int] = 78

            # Maximum allowed line width
            MAX_LINE_WIDTH: Final[int] = 199

            # Minimum allowed line width
            MIN_LINE_WIDTH: Final[int] = 10

        class CommentFormats:
            """LDIF comment formatting constants for documentation.

            Provides standardized comment formats for documenting entry modifications,
            rejections, and transformations in LDIF output. These formats support
            bidirectional conversion and audit trails.
            """

            # Comment separator lines
            SEPARATOR_DOUBLE: Final[str] = "# " + ("═" * 51)
            SEPARATOR_SINGLE: Final[str] = "# " + ("─" * 51)
            SEPARATOR_EMPTY: Final[str] = "#"

            # Comment headers
            HEADER_REJECTION_REASON: Final[str] = "# REJECTION REASON"
            HEADER_REMOVED_ATTRIBUTES: Final[str] = (
                "# REMOVED ATTRIBUTES (Original Values)"
            )

            # Comment prefixes
            PREFIX_COMMENT: Final[str] = "# "

        class MigrationHeaders:
            """Migration header templates for LDIF output.

            Provides default templates for migration headers that can be customized
            via WriteFormatOptions.migration_header_template.
            """

            # Default migration header template (Python f-string format)
            DEFAULT_TEMPLATE: Final[str] = """# Migration Phase: {phase}
# Timestamp: {timestamp}
# Source Server: {source_server}
# Target Server: {target_server}
# Base DN: {base_dn}
# Total Entries: {total_entries}
# Processed: {processed_entries} ({processed_percentage:.1f}%)
# Rejected: {rejected_entries} ({rejected_percentage:.1f}%)
#
"""

            # Minimal header template
            MINIMAL_TEMPLATE: Final[
                str
            ] = """# Phase: {phase} | {timestamp} | Entries: {total_entries}
#
"""

            # Detailed header template
            DETAILED_TEMPLATE: Final[
                str
            ] = """# ============================================================
# LDIF MIGRATION - {phase_name}
# ============================================================================
# Migration Phase: {phase}
# Timestamp: {timestamp}
#
# SOURCE & TARGET:
#   Source Server: {source_server}
#   Target Server: {target_server}
#   Base DN: {base_dn}
#
# STATISTICS:
#   Total Entries: {total_entries}
#   Processed: {processed_entries} ({processed_percentage:.1f}%)
#   Rejected: {rejected_entries} ({rejected_percentage:.1f}%)
#
# ============================================================================
#
"""

        # =============================================================================
        # CONVERSION STRATEGY - RFC as Canonical Format (Adapter Pattern)
        # =============================================================================

        class ConversionStrategy:
            """Server conversion strategy using RFC as canonical intermediate format.

            **Architecture**: Adapter Pattern with RFC as Hub

            **Algorithm**:
            1. Any→RFC: source.normalize_to_rfc() → RFC canonical format + metadata
            2. RFC→Any: target.denormalize_from_rfc() → target format
            (metadata guides conversion)
            3. Any→Any: source.normalize_to_rfc() → target.denormalize_from_rfc()

            **Benefits**:
            - Eliminates N×N complexity (N servers = N² direct conversions)
            - Reduces to 2N conversions (N to RFC + N from RFC)
            - Metadata in RFC format preserves original for round-trip fidelity
            - Single source of truth (RFC) for validation and compliance

            **Example**:
                OID → OUD:
                1. oid_entry.normalize_to_rfc() → rfc_entry (with oid metadata)
                2. oud.denormalize_from_rfc(rfc_entry) → oud_entry

            **Conversion Strategy**:
            RFC is the universal intermediate format - no normalization/denormalization
            needed. All conversions use: Source → RFC (via source quirks) → Target
            (via target quirks).
            """

            # Canonical format - all conversions pass through this
            CANONICAL_FORMAT: Final[str] = "rfc"

            # Conversion algorithm type
            ALGORITHM: Final[str] = "adapter_pattern_with_rfc_hub"

            # Complexity: O(2N) instead of O(N²)
            CONVERSION_COMPLEXITY: Final[str] = "2N"  # vs "N²" for direct conversions

            # All conversions MUST go through RFC - no direct server-to-server
            ENFORCE_RFC_INTERMEDIATE: Final[bool] = True

            # Preserve original format in metadata for round-trip
            PRESERVE_SOURCE_METADATA: Final[bool] = True

            # Conversion direction constants
            DIRECTION_TO_RFC: Final[str] = "normalize"
            DIRECTION_FROM_RFC: Final[str] = "denormalize"

            # Metadata keys for tracking conversions
            METADATA_ORIGINAL_SERVER: Final[str] = "original_server_type"
            METADATA_CONVERSION_PATH: Final[str] = "conversion_path"
            METADATA_INTERMEDIATE_FORMAT: Final[str] = "rfc_intermediate"

        class AclSubjectTransformations:
            """Subject transformation mappings for ACL conversions.

            Maps (source_server, target_server, subject_type) → (new_type, value_template)
            Wildcard "*" matches any server for generic transformations.
            """

            # NOTE: Server-specific ACL subject transformations moved to respective
            # server Constants:
            # - OID_TO_RFC_SUBJECTS → FlextLdifServersOid.Constants.OID_TO_RFC_SUBJECTS
            # - RFC_TO_OID_SUBJECTS → FlextLdifServersOid.Constants.RFC_TO_OID_SUBJECTS
            # - RFC_TO_OUD_SUBJECTS → FlextLdifServersOud.Constants.RFC_TO_OUD_SUBJECTS
            # - OUD_TO_RFC_SUBJECTS → FlextLdifServersOud.Constants.OUD_TO_RFC_SUBJECTS

            # 389DS transformations via RFC
            DS389_TO_RFC_SUBJECTS: Final[dict[str, tuple[str, str]]] = {
                "groupdn": ("group_dn", "{value}"),
                "userdn": ("user_dn", "{value}"),
            }

            # Generic transformations (preserved across all servers)
            UNIVERSAL_SUBJECTS: Final[dict[str, tuple[str, str]]] = {
                "anonymous": ("anonymous", "*"),
                "self": ("self", "self"),
                "all": ("all", "*"),
            }

        class AclPermissionCompatibility:
            """Permission compatibility matrix for server types.

            NOTE: Server-specific constants (SUPPORTED_PERMISSIONS, PERMISSION_ALTERNATIVES)
            have been migrated to each server's Constants class:
            - OID: FlextLdifServersOid.Constants.SUPPORTED_PERMISSIONS,
                PERMISSION_ALTERNATIVES
            - OUD: FlextLdifServersOud.Constants.SUPPORTED_PERMISSIONS
            - RFC: FlextLdifServersRfc.Constants.SUPPORTED_PERMISSIONS
            - OpenLDAP: FlextLdifServersOpenldap.Constants.SUPPORTED_PERMISSIONS
            - AD: FlextLdifServersAd.Constants.SUPPORTED_PERMISSIONS
            - 389DS: FlextLdifServersDs389.Constants.SUPPORTED_PERMISSIONS
            - Novell: FlextLdifServersNovell.Constants.SUPPORTED_PERMISSIONS
            - Tivoli: FlextLdifServersTivoli.Constants.SUPPORTED_PERMISSIONS
            - Apache: FlextLdifServersApache.Constants.SUPPORTED_PERMISSIONS
            - OpenLDAP1: FlextLdifServersOpenldap1.Constants.SUPPORTED_PERMISSIONS

            This class is kept for backward compatibility but should not be used
            for new code.
            Use the server-specific Constants classes instead.
            """

        class SchemaConversionMappings:
            """Schema attribute and objectClass conversion mappings.

            Defines server-specific schema quirks and how to normalize/denormalize them.
            All mappings use RFC-as-hub strategy.
            """

            # NOTE: SERVER_SPECIFIC_ATTRIBUTE_FIELDS and OBJECTCLASS_KIND_REQUIREMENTS
            # have been removed. These constants have been migrated to each server's
            # Constants class:
            # - ATTRIBUTE_FIELDS → Each server's Constants.ATTRIBUTE_FIELDS
            # - OBJECTCLASS_REQUIREMENTS → Each server's Constants.OBJECTCLASS_REQUIREMENTS
            # - OID: FlextLdifServersOid.Constants.ATTRIBUTE_FIELDS,
            #   OBJECTCLASS_REQUIREMENTS
            # - OUD: FlextLdifServersOud.Constants.ATTRIBUTE_FIELDS,
            #   OBJECTCLASS_REQUIREMENTS
            # - OpenLDAP: FlextLdifServersOpenldap.Constants.ATTRIBUTE_FIELDS,
            #   OBJECTCLASS_REQUIREMENTS
            # - 389DS: FlextLdifServersDs389.Constants.ATTRIBUTE_FIELDS,
            #   OBJECTCLASS_REQUIREMENTS
            # - RFC: FlextLdifServersRfc.Constants.ATTRIBUTE_FIELDS,
            #   OBJECTCLASS_REQUIREMENTS
            # - AD, Novell, Tivoli, Apache, OpenLDAP1: Inherit RFC baseline
            #   (empty ATTRIBUTE_FIELDS, RFC OBJECTCLASS_REQUIREMENTS)
            # Use the server-specific Constants classes instead.

            # Matching rule normalizations (moved from utilities)
            MATCHING_RULE_NORMALIZATIONS: Final[dict[str, str]] = {
                "caseIgnoreIA5SubstringsMatch": "caseIgnoreIA5Match",
                "caseIgnoreOrdinalMatch": "caseIgnoreMatch",
            }

            # NOTE: Server-specific attribute transformations moved to respective
            # server Constants:
            # - ATTRIBUTE_TRANSFORMATION_OID_TO_RFC →
            #   FlextLdifServersOid.Constants.ATTRIBUTE_TRANSFORMATION_OID_TO_RFC
            # - ATTRIBUTE_TRANSFORMATION_RFC_TO_OID →
            #   FlextLdifServersOid.Constants.ATTRIBUTE_TRANSFORMATION_RFC_TO_OID
            # - ATTRIBUTE_TRANSFORMATION_RFC_TO_OUD →
            #   FlextLdifServersOud.Constants.ATTRIBUTE_TRANSFORMATION_RFC_TO_OUD
            # - ATTRIBUTE_TRANSFORMATION_OUD_TO_RFC →
            #   FlextLdifServersOud.Constants.ATTRIBUTE_TRANSFORMATION_OUD_TO_RFC

            # NOTE: Server-specific attribute aliases have been migrated to each
            # server's Constants class:
            # - OID: FlextLdifServersOid.Constants.ATTRIBUTE_ALIASES
            # - OUD: FlextLdifServersOud.Constants.ATTRIBUTE_ALIASES
            # Other servers have empty ATTRIBUTE_ALIASES (use RFC standard)
            # This comment is kept for reference but the constant has been removed.

            # NOTE: OperationalAttributeMappings class has been removed.
            # Server-specific constants (OPERATIONAL_ATTRIBUTES, PRESERVE_ON_MIGRATION)
            # have been migrated to each server's Constants class:
            # - OID: FlextLdifServersOid.Constants.OPERATIONAL_ATTRIBUTES, PRESERVE_ON_MIGRATION
            # - OUD: FlextLdifServersOud.Constants.OPERATIONAL_ATTRIBUTES, PRESERVE_ON_MIGRATION
            # - RFC: FlextLdifServersRfc.Constants.OPERATIONAL_ATTRIBUTES, PRESERVE_ON_MIGRATION
            # - OpenLDAP: FlextLdifServersOpenldap.Constants.OPERATIONAL_ATTRIBUTES,
            #   PRESERVE_ON_MIGRATION
            # - AD: FlextLdifServersAd.Constants.OPERATIONAL_ATTRIBUTES,
            #   PRESERVE_ON_MIGRATION
            # - 389DS: FlextLdifServersDs389.Constants.OPERATIONAL_ATTRIBUTES,
            #   PRESERVE_ON_MIGRATION
            # - Novell: FlextLdifServersNovell.Constants.OPERATIONAL_ATTRIBUTES,
            #   PRESERVE_ON_MIGRATION
            # - Tivoli: FlextLdifServersTivoli.Constants.OPERATIONAL_ATTRIBUTES,
            #   PRESERVE_ON_MIGRATION
            # - Apache: FlextLdifServersApache.Constants.OPERATIONAL_ATTRIBUTES,
            #   PRESERVE_ON_MIGRATION
            # - OpenLDAP1: FlextLdifServersOpenldap1.Constants.OPERATIONAL_ATTRIBUTES,
            #   PRESERVE_ON_MIGRATION
            # Use the server-specific Constants classes instead.

        class AclAttributeRegistry:
            """LDAP Server-specific ACL attributes with RFC foundation.

            Implements HIERARCHY pattern:
            - RFC Foundation: aci, acl, olcAccess (all servers)
            - Server Quirks: Incremental additions per server type
            - Override: categorization_rules can override completely
            """

            # RFC Foundation - Standard LDAP (all servers)
            RFC_FOUNDATION: Final[list[str]] = [
                "aci",  # Standard LDAP ACL
                "acl",  # Alternative ACL format
                "olcAccess",  # OpenLDAP Access Control
                "aclRights",  # Generic ACL Rights
                "aclEntry",  # ACL Entry reference
            ]

            # Server-specific additions (incremental over RFC)
            SERVER_QUIRKS: Final[dict[str, list[str]]] = {
                "oid": [
                    "orclaci",  # Oracle Internet Directory ACI
                    "orclentrylevelaci",  # OID entry-level ACI
                    "orclContainerLevelACL",  # OID container ACL
                ],
                "oud": [
                    "orclaci",  # Oracle Unified Directory ACI
                    "orclentrylevelaci",  # OUD entry-level ACI
                ],
                "ad": [
                    "nTSecurityDescriptor",  # Active Directory security descriptor
                ],
                "generic": [],  # No additions, just RFC
            }

            # All functions removed - use utilities instead

        class ServiceType(StrEnum):
            """Service types for internal management.

            DRY Pattern:
                StrEnum is the single source of truth. Use ServiceType.PARSER.value
                or ServiceType.PARSER directly - no base strings needed.
            """

            PARSER = "parser"
            ACL = "acl"
            WRITER = "writer"
            ENTRIES = "entries"
            ANALYSIS = "analysis"
            PROCESSING = "processing"
            DETECTOR = "detector"
            FILTERS = "filters"
            CATEGORIZATION = "categorization"
            CONVERSION = "conversion"
            VALIDATION = "validation"
            SYNTAX = "syntax"

        # =============================================================================
        # ADVANCED VALIDATION HELPERS - Python 3.13+ collections.abc patterns
        # =============================================================================

        # =============================================================================
        # LITERAL VALIDATION HELPERS (Python 3.13+ runtime validation)
        # =============================================================================

        # All validation functions removed - use utilities instead

        # =========================================================================
        # NORMALIZATION OPTIONS (moved from models.py)
        # =========================================================================

        class CaseFoldOption(StrEnum):
            """Case folding options for DN normalization."""

            NONE = "none"
            LOWER = "lower"
            UPPER = "upper"

        class SpaceHandlingOption(StrEnum):
            """Space handling options for DN normalization."""

            PRESERVE = "preserve"
            TRIM = "trim"
            NORMALIZE = "normalize"

        class EscapeHandlingOption(StrEnum):
            """Escape sequence handling options."""

            PRESERVE = "preserve"
            UNESCAPE = "unescape"
            NORMALIZE = "normalize"

        class SortOption(StrEnum):
            """Sorting options for attribute ordering."""

            NONE = "none"
            ALPHABETICAL = "alphabetical"
            HIERARCHICAL = "hierarchical"
    class DnPrefixField(StrEnum):
        """Dn_Prefix field constants."""

        PREFIX = 'dn:'
        PREFIX_SHORT = 'dn'

    class SchemaKwField(StrEnum):
        """Schema_Kw field constants."""

        NAME = 'NAME'
        DESC = 'DESC'

    class AclBindIpField(StrEnum):
        """Acl_Bind_Ip field constants."""

        IP_FULL = 'acl:vendor:bind_ip'
        IP = 'bind_ip'

    class PersonField(StrEnum):
        """Person field constants."""

        PERSON = 'person'

    class OrganizationalUnitField(StrEnum):
        """Organizational_Unit field constants."""

        UNIT = 'organizationalUnit'
        UNIT_LOWER = 'organizationalunit'

    class UserField(StrEnum):
        """User field constants."""

        USER = 'user'

    class GroupField(StrEnum):
        """Group field constants."""

        GROUP = 'group'

    class AudioField(StrEnum):
        """Audio field constants."""

        AUDIO = 'audio'
        AUDIO_OID = '1.3.6.1.4.1.1466.115.121.1.4'

    class StrictField(StrEnum):
        """Strict field constants."""

        STRICT = 'strict'

    class LenientField(StrEnum):
        """Lenient field constants."""

        LENIENT = 'lenient'

    class SubtreeField(StrEnum):
        """Subtree field constants."""

        SUBTREE = 'subtree'

    class OnelevelField(StrEnum):
        """Onelevel field constants."""

        ONELEVEL = 'onelevel'

    class BaseField(StrEnum):
        """Base field constants."""

        BASE = 'base'
        BASE_OID = '1.3.6.1.4.1.1466.115.121.1'

    class AllField(StrEnum):
        """All field constants."""

        ALL = 'all'

    class ObsoleteField(StrEnum):
        """Obsolete field constants."""

        OBSOLETE = 'obsolete'

    class AciField(StrEnum):
        """Aci field constants."""

        ACI = 'aci'
        ACI_OID = '1.3.6.1.4.1.1466.115.121.1.1'
    class AclWildcardField(StrEnum):
        """Acl_Wildcard field constants."""
        
        TYPE = 'all'
        VALUE = '*'
        
        class OutputFormat(StrEnum):
            """Output format options."""

            LDIF = "ldif"
            JSON = "json"
            CSV = "csv"
            YAML = "yaml"

    # =========================================================================
    # NAMESPACE ACCESS
    # =========================================================================
    # All constants are accessed via .Ldif namespace
    # Use c.* for all LDIF domain constants
    # No aliases - use namespaces directly following FLEXT architecture patterns


# Runtime alias for basic class (objetos nested sem aliases redundantes)
# Pattern: Classes básicas sempre com runtime alias, objetos nested sem aliases redundantes
c = FlextLdifConstants

__all__ = [
    "FlextLdifConstants",
    "c",
]
