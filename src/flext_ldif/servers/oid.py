"""Oracle Internet Directory (OID) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Implements Oracle OID-specific extensions as quirks on top of RFC-compliant
base parsers. This wraps existing OID parser logic as composable quirks.

OID-specific features:
- Oracle OID attribute types (2.16.840.1.113894.* namespace)
- Oracle orclaci and orclentrylevelaci ACLs
- Oracle-specific schema attributes
- Oracle operational attributes
"""

from __future__ import annotations

import enum as enum_module
import re
from collections.abc import Mapping
from functools import reduce
from typing import ClassVar, cast

from flext_core import FlextLogger, FlextResult, FlextRuntime, FlextUtilities

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.utilities import FlextLdifUtilities

logger = FlextLogger(__name__)


class FlextLdifServersOid(FlextLdifServersRfc):
    """Oracle OID server quirks - implements FlextLdifProtocols.Quirks.SchemaProtocol.

    Extends RFC 4512 schema parsing with Oracle OID-specific features:
    - Oracle OID namespace (2.16.840.1.113894.*)
    - Oracle-specific syntaxes
    - Oracle attribute extensions
    - RFC compliance normalizations (OID proprietary → RFC standard)

    **Protocol Compliance**: Fully implements
    FlextLdifProtocols.Quirks.SchemaProtocol through structural typing.
    All methods match protocol signatures exactly for type safety.

    **Validation**: Verify protocol compliance with:
        from flext_ldif.protocols import FlextLdifProtocols
        quirk = FlextLdifServersOid()
        # Protocol compliance verified via structural typing
        if not isinstance(quirk, FlextLdifProtocols.Quirks.SchemaProtocol):
            raise TypeError("Quirk does not satisfy SchemaProtocol")

    Example:
        quirk = FlextLdifServersOid()
        if quirk.schema.can_handle_attribute(attr_def):
            result = quirk.schema._parse_attribute(attr_def)
            if result.is_success:
                parsed_attr = result.unwrap()

    """

    # =========================================================================
    # STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY
    # =========================================================================
    class Constants(FlextLdifServersRfc.Constants):
        """Oracle Internet Directory-specific constants for server operations.

        Extends RFC baseline constants with OID-specific patterns for detection,
        ACL format, attribute mappings, and schema configuration.

        All configuration including SERVER_TYPE and PRIORITY are defined here
        following the standardized pattern used across all server implementations.
        """

        # Server identity and priority (defined at Constants level)
        SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.OID
        PRIORITY: ClassVar[int] = 10

        # Logging and debug constants
        MAX_LOG_LINE_LENGTH: ClassVar[int] = 200  # Maximum length for log line excerpts

        # LDAP Connection Defaults (RFC 4511 §4.1 - Standard LDAP ports)
        DEFAULT_PORT: ClassVar[int] = 389  # Standard LDAP port
        DEFAULT_SSL_PORT: ClassVar[int] = 636  # Standard LDAPS port (LDAP over SSL/TLS)
        DEFAULT_PAGE_SIZE: ClassVar[int] = 1000  # RFC 2696 Simple Paged Results default

        # Oracle OID ACL attribute names
        ORCLACI: ClassVar[str] = "orclaci"  # Standard Oracle OID ACL
        ORCLENTRYLEVELACI: ClassVar[str] = "orclentrylevelaci"  # Entry-level ACI
        ACL_FORMAT: ClassVar[str] = "orclaci"  # OID ACL format
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "orclaci"  # ACL attribute name

        # NOTE: ACL metadata keys removed - use FlextLdifConstants.MetadataKeys instead
        # These standardized GENERIC keys are defined in constants.py for ANY LDAP server (lines 1498-1547):
        # - ACL_ORIGINAL_FORMAT, ACL_SOURCE_SERVER, ACL_SOURCE_SUBJECT_TYPE, ACL_TARGET_SUBJECT_TYPE
        # - ACL_ORIGINAL_SUBJECT_VALUE, ACL_SOURCE_PERMISSIONS, ACL_TARGET_PERMISSIONS
        # - Server-specific: ACL_FILTER, ACL_CONSTRAINT (OID), ACL_TARGETSCOPE (OUD), ACL_NUMBERING (OpenLDAP)
        # Servers MUST NOT know about each other - only communicate via GENERIC metadata keys

        # Matching rule normalizations (OID proprietary → RFC 4517 standard)
        # Used by PARSER: OID → RFC (normalization)
        MATCHING_RULE_TO_RFC: ClassVar[dict[str, str]] = {
            # Fix RFC capitalization (uppercase S → lowercase s)
            "caseIgnoreSubStringsMatch": "caseIgnoreSubstringsMatch",
            # OID proprietary → RFC 4517 standard
            "accessDirectiveMatch": "caseIgnoreMatch",
        }

        # INVERSE mapping for WRITER: RFC → OID (denormalization)
        MATCHING_RULE_RFC_TO_OID: ClassVar[dict[str, str]] = {
            # Restore OID capitalization (lowercase s → uppercase S)
            "caseIgnoreSubstringsMatch": "caseIgnoreSubStringsMatch",
            # RFC standard → OID proprietary
            "caseIgnoreMatch": "accessDirectiveMatch",
        }

        # Syntax OID normalizations (OID proprietary → RFC 4517 standard)
        # Used by PARSER: OID → RFC (normalization)
        SYNTAX_OID_TO_RFC: ClassVar[dict[str, str]] = {
            # OID ACI List Syntax → RFC 4517 Directory String
            "1.3.6.1.4.1.1466.115.121.1.1": ("1.3.6.1.4.1.1466.115.121.1.15"),
        }

        # INVERSE mapping for WRITER: RFC → OID (denormalization)
        SYNTAX_RFC_TO_OID: ClassVar[dict[str, str]] = {
            # RFC Directory String → OID ACI List Syntax
            "1.3.6.1.4.1.1466.115.121.1.15": "1.3.6.1.4.1.1466.115.121.1.1",
        }

        # Attribute name case normalizations (OID lowercase → RFC CamelCase)
        # OID exports objectClass MAY/MUST with lowercase but attributeTypes define CamelCase
        # This map corrects case during parsing to ensure RFC compliance
        ATTR_NAME_CASE_MAP: ClassVar[dict[str, str]] = {
            # RFC 4519 standard attributes (used in Oracle schemas)
            "middlename": "middleName",
            # Oracle attributes (inherit CamelCase from source attributeType definitions)
            # Note: Oracle attrs starting with 'orcl' are already handled by existing
            # ATTRIBUTE_TRANSFORMATION mappings defined below around line 550
        }

        # Note: ATTRIBUTE_TRANSFORMATION_OID_TO_RFC and
        # ATTRIBUTE_TRANSFORMATION_RFC_TO_OID are defined further below
        # in the Constants class (line ~550)

        # OID extends RFC operational attributes with Oracle-specific ones
        OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = (
            FlextLdifServersRfc.Constants.OPERATIONAL_ATTRIBUTES
            | frozenset(
                [
                    "orclguid",
                    "orclobjectguid",
                    "orclentryid",
                    "orclaccount",
                    "pwdChangedTime",
                    "pwdHistory",
                    "pwdFailureTime",
                ],
            )
        )

        # NOTE: PRESERVE_ON_MIGRATION inherited from RFC.Constants

        # Detection constants (server-specific)
        # Match Oracle OIDs OR orcl* attributes (case-insensitive)
        DETECTION_OID_PATTERN: ClassVar[str] = r"(?i)(2\.16\.840\.1\.113894\.|orcl)"
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset(
            [
                "orcl",
                "orclguid",
            ],
        )
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
                "orcldirectory",
                "orcldomain",
                "orcldirectoryserverconfig",
                # Oracle OID container objectClass (case-insensitive match)
                "orclcontainer",
            ],
        )
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset(
            [
                "cn=orcl",
                "cn=subscriptions",
                "cn=oracle context",
            ],
        )

        # === SCHEMA PROCESSING CONFIGURATION ===
        # Schema field names
        SCHEMA_FIELD_ATTRIBUTE_TYPES: ClassVar[str] = "attributetypes"
        SCHEMA_FIELD_ATTRIBUTE_TYPES_LOWER: ClassVar[str] = "attributetypes"
        SCHEMA_FIELD_OBJECT_CLASSES: ClassVar[str] = "objectclasses"
        SCHEMA_FIELD_OBJECT_CLASSES_LOWER: ClassVar[str] = "objectclasses"
        SCHEMA_FIELD_MATCHING_RULES: ClassVar[str] = "matchingrules"
        SCHEMA_FIELD_LDAP_SYNTAXES: ClassVar[str] = "ldapsyntaxes"

        # Schema fields that should be processed with OID filtering
        SCHEMA_FILTERABLE_FIELDS: ClassVar[frozenset[str]] = frozenset(
            [
                SCHEMA_FIELD_ATTRIBUTE_TYPES,
                SCHEMA_FIELD_ATTRIBUTE_TYPES_LOWER,
                SCHEMA_FIELD_OBJECT_CLASSES,
                SCHEMA_FIELD_OBJECT_CLASSES_LOWER,
                SCHEMA_FIELD_MATCHING_RULES,
                SCHEMA_FIELD_LDAP_SYNTAXES,
            ],
        )

        # Schema DN for OID - Oracle-specific quirk
        # NOTE: This is OID's QUIRK format, NOT RFC-compliant!
        # RFC 4512 standard is "cn=schema" or "cn=subschema"
        # OID uses "cn=subschemasubentry" which must be normalized during parsing
        # The normalized DN "cn=schema" is stored in Entry, original goes to metadata
        SCHEMA_DN_QUIRK: ClassVar[str] = "cn=subschemasubentry"  # OID quirk (non-RFC)

        # Oracle OID boolean attributes (non-RFC: use "0"/"1" not "TRUE"/"FALSE")
        # RFC 4517 Boolean syntax requires "TRUE" or "FALSE"
        # OID quirks convert "0"→"FALSE", "1"→"TRUE" during OID→RFC
        BOOLEAN_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                # Oracle DAS (Directory Application Server) boolean attributes
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
                "orcldasREDACTED_LDAP_BIND_PASSWORDmodifiable",
                # Oracle password policy boolean attributes
                "pwdlockout",
                "pwdmustchange",
                "pwdallowuserchange",
            ],
        )

        # Server type variants
        VARIANTS: ClassVar[frozenset[str]] = frozenset(["oid", "oracle_oid"])

        # Schema attribute fields that are server-specific
        ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset(["usage", "x_origin"])

        # ObjectClass requirements (extends RFC - allows multiple SUP)
        OBJECTCLASS_REQUIREMENTS: ClassVar[Mapping[str, bool]] = {
            "requires_sup_for_auxiliary": True,
            "allows_multiple_sup": True,  # OID allows multiple SUP
            "requires_explicit_structural": False,
        }

        # Oracle OID specific operational attributes (extended set)
        OID_SPECIFIC: ClassVar[frozenset[str]] = frozenset(
            [
                # Note: Using literal strings to avoid circular reference during class definition
                # These correspond to Constants.ACL_ATTRIBUTE_NAME and Constants.ORCLENTRYLEVELACI
                "orclaci",
                "orclentrylevelaci",
                "orclguid",  # Oracle GUID
                "orclmailaddr",  # Mail address
                "orcluseractivefrom",  # User active from date
                "orcluserinactivefrom",  # User inactive from date
            ],
        )

        # Oracle OID specific attributes (categorization)
        OID_SPECIFIC_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                # Note: Using literal strings to avoid circular reference during class definition
                # These correspond to Constants.ACL_ATTRIBUTE_NAME and Constants.ORCLENTRYLEVELACI
                "orcloid",  # Oracle OID identifier
                "orclguid",  # Oracle GUID
                "orclpassword",  # Oracle password attribute
                "orclaci",
                "orclentrylevelaci",
                "orcldaslov",  # Oracle DASLOV configuration
            ],
        )

        # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
        CANONICAL_NAME: ClassVar[str] = "oid"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["oid", "oracle_oid"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["oid"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["oid", "rfc"])

        # Server detection patterns and weights
        DETECTION_PATTERN: ClassVar[str] = (
            r"(?i)(2\.16\.840\.1\.113894\.|orcl)"  # Match Oracle OIDs OR orcl* attributes (case-insensitive)
        )
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "orclOID",
                "orclGUID",
                "orclPassword",
                "orclaci",
                "orclentrylevelaci",
                "orcldaslov",
            ],
        )
        DETECTION_WEIGHT: ClassVar[int] = (
            12  # Increased to ensure OID detection wins over other servers when OID-specific attributes/objectClasses are present
        )

        # Oracle OID metadata keys
        OID_SPECIFIC_RIGHTS: ClassVar[str] = "oid_specific_rights"
        RFC_NORMALIZED: ClassVar[str] = "rfc_normalized"
        ORIGINAL_OID_PERMS: ClassVar[str] = "original_oid_perms"

        # All OID metadata keys
        ALL_OID_KEYS: ClassVar[frozenset[str]] = frozenset(
            [
                OID_SPECIFIC_RIGHTS,
                RFC_NORMALIZED,
                ORIGINAL_OID_PERMS,
            ],
        )

        # =====================================================================
        # CATEGORIZATION RULES - OID-specific entry categorization
        # =====================================================================
        # These define how entries are categorized during migration
        # Priority order determines which category is checked first
        # CRITICAL for entries with multiple objectClasses (e.g., cn=PERFIS)

        # Categorization priority: acl → users → hierarchy → groups
        # ACL FIRST ensures entries with ACL attributes are categorized as ACL
        # regardless of other objectClasses they may have
        CATEGORIZATION_PRIORITY: ClassVar[list[str]] = [
            "acl",  # ACL entries checked FIRST (orclaci, orclentrylevelaci)
            "users",  # User accounts
            "hierarchy",  # Structural containers (orclContainer, ou, o)
            "groups",  # Groups (groupOfNames, orclGroup)
        ]

        # ObjectClasses defining each category
        CATEGORY_OBJECTCLASSES: ClassVar[dict[str, frozenset[str]]] = {
            "users": frozenset(
                [
                    "person",
                    "inetOrgPerson",
                    "orclUser",  # OID-specific user
                    "orclUserV2",
                ],
            ),
            "hierarchy": frozenset(
                [
                    "organizationalUnit",
                    "organization",
                    "domain",
                    "country",
                    "locality",
                    "orclContainer",  # OID structural container
                    "orclContainerOC",  # OID container objectClass variant
                    "orclContext",  # OID context
                    "orclApplicationEntity",  # Application entity container
                    "orclConfigSet",  # Configuration set
                    "orclDASAttrCategory",  # DAS attribute category
                    "orclDASOperationURL",  # DAS operation URL
                    "orclDASConfigPublicGroup",  # DAS public group config
                ],
            ),
            "groups": frozenset(
                [
                    "groupOfNames",
                    "groupOfUniqueNames",
                    "orclGroup",  # OID group
                    "orclPrivilegeGroup",  # OID privilege (unless has orclContainer!)
                ],
            ),
        }

        # ObjectClasses that ALWAYS categorize as hierarchy
        # Even if entry also has group objectClasses
        # Solves cn=PERFIS: orclContainer + orclPrivilegeGroup → hierarchy
        HIERARCHY_PRIORITY_OBJECTCLASSES: ClassVar[frozenset[str]] = frozenset(
            [
                "orclContainer",  # Always hierarchy
                "organizationalUnit",
                "organization",
                "domain",
            ],
        )

        # ACL attributes (reuse existing constant)
        # NOTE: Includes BOTH pre-normalization (orclaci) AND post-normalization
        # (aci) names because _normalize_attribute_name() transforms orclaci→aci
        CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "aci",  # RFC standard (normalized from orclaci/orclentrylevelaci)
                "orclaci",  # OID format (before normalization)
                "orclentrylevelaci",  # OID entry-level format (before normalization)
            ],
        )

        # =====================================================================
        # DN PATTERNS - OID-specific DN markers
        # =====================================================================
        CN_ORCL: ClassVar[str] = "cn=orcl"
        OU_ORACLE: ClassVar[str] = "ou=oracle"
        DC_ORACLE: ClassVar[str] = "dc=oracle"

        # All Oracle DN patterns
        ORACLE_DN_PATTERNS: ClassVar[frozenset[str]] = frozenset(
            [
                CN_ORCL,
                OU_ORACLE,
                DC_ORACLE,
            ],
        )

        # Permission names inherited from RFC.Constants
        # (PERMISSION_READ, PERMISSION_WRITE, PERMISSION_ADD, PERMISSION_DELETE, PERMISSION_SEARCH, PERMISSION_COMPARE)

        # ACL subject types
        ACL_SUBJECT_TYPE_USER: ClassVar[str] = "user"
        ACL_SUBJECT_TYPE_GROUP: ClassVar[str] = "group"
        ACL_SUBJECT_TYPE_SELF: ClassVar[str] = "self"
        ACL_SUBJECT_TYPE_ANONYMOUS: ClassVar[str] = "anonymous"

        # ACL parsing patterns
        ACL_TYPE_PATTERN: ClassVar[str] = r"^(orclaci|orclentrylevelaci):"
        ACL_TARGET_PATTERN: ClassVar[str] = r"access to (entry|attr=\(([^)]+)\))"
        ACL_SUBJECT_PATTERN: ClassVar[str] = (
            r"by\s+(group=\"[^\"]+\"|dnattr=\([^)]+\)|guidattr=\([^)]+\"|groupattr=\([^)]+\)|\"[^\"]+\"|self|\*)"
        )
        ACL_PERMISSIONS_PATTERN: ClassVar[str] = r"\(([^)]+)\)(?:\s*$)"
        ACL_FILTER_PATTERN: ClassVar[str] = r"filter=(\([^)]*(?:\([^)]*\)[^)]*)*\))"
        ACL_CONSTRAINT_PATTERN: ClassVar[str] = r"added_object_constraint=\(([^)]+)\)"

        # ACL pattern dictionary keys (used in _get_oid_patterns)
        ACL_PATTERN_KEY_TYPE: ClassVar[str] = "acl_type"
        ACL_PATTERN_KEY_TARGET: ClassVar[str] = "target"
        ACL_PATTERN_KEY_SUBJECT: ClassVar[str] = "subject"
        ACL_PATTERN_KEY_PERMISSIONS: ClassVar[str] = "permissions"
        ACL_PATTERN_KEY_FILTER: ClassVar[str] = "filter"
        ACL_PATTERN_KEY_CONSTRAINT: ClassVar[str] = "constraint"

        # ObjectClass typo fix constant
        OBJECTCLASS_TYPO_AUXILLARY: ClassVar[str] = "AUXILLARY"
        OBJECTCLASS_TYPO_AUXILIARY: ClassVar[str] = "AUXILIARY"

        # Matching rule normalization constants
        MATCHING_RULE_CASE_IGNORE_SUBSTRINGS: ClassVar[str] = (
            "caseIgnoreSubstringsMatch"
        )
        MATCHING_RULE_CASE_IGNORE_SUBSTRINGS_ALT: ClassVar[str] = (
            "caseIgnoreSubStringsMatch"
        )
        MATCHING_RULE_CASE_IGNORE: ClassVar[str] = "caseIgnoreMatch"

        # Oracle OID boolean format constants (non-RFC compliant)
        # RFC 4517 compliant uses "TRUE" / "FALSE"
        # Oracle OID uses "1" / "0"
        ONE_OID: ClassVar[str] = "1"
        ZERO_OID: ClassVar[str] = "0"

        # Boolean conversion mappings (using Constants for consistency)
        OID_TO_RFC: ClassVar[dict[str, str]] = {
            ONE_OID: "TRUE",  # Use Constants.ONE_OID
            ZERO_OID: "FALSE",  # Use Constants.ZERO_OID
            "true": "TRUE",
            "false": "FALSE",
        }

        RFC_TO_OID: ClassVar[dict[str, str]] = {
            "TRUE": ONE_OID,  # Use Constants.ONE_OID
            "FALSE": ZERO_OID,  # Use Constants.ZERO_OID
            "true": ONE_OID,  # Use Constants.ONE_OID
            "false": ZERO_OID,  # Use Constants.ZERO_OID
        }

        # Universal boolean check
        OID_TRUE_VALUES: ClassVar[frozenset[str]] = frozenset(
            [
                ONE_OID,
                "true",
                "True",
                "TRUE",
            ],
        )
        OID_FALSE_VALUES: ClassVar[frozenset[str]] = frozenset(
            [
                ZERO_OID,
                "false",
                "False",
                "FALSE",
            ],
        )

        # Matching rule replacement mappings for invalid substr rules
        INVALID_SUBSTR_RULES: ClassVar[dict[str, str | None]] = {
            "caseIgnoreMatch": "caseIgnoreSubstringsMatch",
            "caseExactMatch": "caseExactSubstringsMatch",
            "distinguishedNameMatch": None,
            "integerMatch": None,
            "numericStringMatch": "numericStringSubstringsMatch",
        }

        # NOTE: Transformation mappings removed - not used in current implementation
        # Conversions should be handled by services/conversion.py, not in server constants

        # === ACL FORMATTING CONSTANTS ===
        ACL_ACCESS_TO: ClassVar[str] = "access to"
        ACL_BY: ClassVar[str] = "by"
        ACL_FORMAT_DEFAULT: ClassVar[str] = "default"
        ACL_FORMAT_ONELINE: ClassVar[str] = "oneline"
        ACL_NAME: ClassVar[str] = "OID ACL"

        # === ACL SUBJECT PATTERNS ===
        # Subject detection patterns for OID ACL parsing
        ACL_SUBJECT_PATTERNS: ClassVar[dict[str, tuple[str | None, str, str]]] = {
            " by self ": (None, "self", "ldap:///self"),
            " by self)": (None, "self", "ldap:///self"),
            ' by "': (r'by\s+"([^"]+)"', "user_dn", "ldap:///{0}"),
            " by group=": (r'by\s+group\s*=\s*"([^"]+)"', "group_dn", "ldap:///{0}"),
            " by dnattr=": (r"by\s+dnattr\s*=\s*\(([^)]+)\)", "dn_attr", "{0}#LDAPURL"),
            " by guidattr=": (
                r"by\s+guidattr\s*=\s*\(([^)]+)\)",
                "guid_attr",
                "{0}#USERDN",
            ),
            " by groupattr=": (
                r"by\s+groupattr\s*=\s*\(([^)]+)\)",
                "group_attr",
                "{0}#GROUPDN",
            ),
        }

        # === ACL SUBJECT FORMATTERS ===
        # Subject formatters for OID ACL writing
        ACL_SUBJECT_FORMATTERS: ClassVar[dict[str, tuple[str, bool]]] = {
            "self": ("self", False),
            "user_dn": ('"{0}"', True),
            "group_dn": ('group="{0}"', True),
            "group": (
                'group="{0}"',
                True,
            ),  # Alias for group_dn (alternate subject type from RFC conversion)
            "dn_attr": ("dnattr=({0})", False),
            "guid_attr": ("guidattr=({0})", False),
            "group_attr": ("groupattr=({0})", False),
        }

        # === ACL PERMISSION MAPPINGS ===
        # Permission name mappings for OID ACL parsing
        ACL_PERMISSION_MAPPING: ClassVar[dict[str, list[str]]] = {
            # Compound permissions
            "all": ["read", "write", "add", "delete", "search", "compare", "proxy"],
            "browse": ["read", "search"],  # OID: browse maps to read+search
            # Standard permissions
            "read": ["read"],
            "write": ["write"],
            "add": ["add"],
            "delete": ["delete"],
            "search": ["search"],
            "compare": ["compare"],
            # Server-specific extended permissions
            "selfwrite": ["self_write"],
            "proxy": ["proxy"],
            "auth": ["auth"],
            # Negative permissions (deny specific rights)
            "nowrite": ["no_write"],
            "noadd": ["no_add"],
            "nodelete": ["no_delete"],
            "nobrowse": ["no_browse"],
            "noselfwrite": ["no_self_write"],
        }

        # === ACL PERMISSION NAMES ===
        # Permission name mappings for OID ACL writing (model field → OID syntax)
        ACL_PERMISSION_NAMES: ClassVar[dict[str, str]] = {
            # Standard permissions
            "read": "read",
            "write": "write",
            "add": "add",
            "delete": "delete",
            "search": "search",
            "compare": "compare",
            # Server-specific extended permissions
            "self_write": "selfwrite",
            "proxy": "proxy",
            "browse": "browse",
            "auth": "auth",
            "all": "all",
            # Negative permissions
            "no_write": "nowrite",
            "no_add": "noadd",
            "no_delete": "nodelete",
            "no_browse": "nobrowse",
            "no_self_write": "noselfwrite",
        }

        # === OID SUPPORTED PERMISSIONS ===
        # Permissions that OID supports (including negative permissions)
        SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = frozenset(
            [
                # Standard RFC permissions
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                # Server-specific extended permissions
                "self_write",
                "proxy",
                "browse",
                "auth",
                "all",
                "none",
                # Negative permissions (OID-specific)
                "no_write",
                "no_add",
                "no_delete",
                "no_browse",
                "no_self_write",
            ],
        )

        # === ATTRIBUTE NAME TRANSFORMATIONS ===
        # OID→RFC attribute name transformations
        ATTRIBUTE_TRANSFORMATION_OID_TO_RFC: ClassVar[Mapping[str, str]] = {
            "orclguid": "entryUUID",  # Oracle GUID → RFC entryUUID
            "orclaci": "aci",  # Oracle ACL → RFC ACI
            "orclentrylevelaci": "aci",  # Oracle entry-level ACL → RFC ACI
        }

        # RFC→OID attribute name transformations (for reverse mapping)
        ATTRIBUTE_TRANSFORMATION_RFC_TO_OID: ClassVar[Mapping[str, str]] = {
            "entryUUID": "orclguid",
            "aci": "orclaci",
        }

        # === NESTED STRENUM DEFINITIONS ===
        # StrEnum definitions for type-safe permission, action, and encoding handling

        class AclPermission(enum_module.StrEnum):
            """OID-specific ACL permissions."""

            READ = "read"
            WRITE = "write"
            ADD = "add"
            DELETE = "delete"
            SEARCH = "search"
            COMPARE = "compare"
            SELF_WRITE = "self_write"
            PROXY = "proxy"
            BROWSE = "browse"
            AUTH = "auth"
            ALL = "all"
            NONE = "none"

        class AclAction(enum_module.StrEnum):
            """OID ACL action types."""

            ALLOW = "allow"
            DENY = "deny"

        class Encoding(enum_module.StrEnum):
            """OID-supported encodings."""

            UTF_8 = "utf-8"
            UTF_16 = "utf-16"
            ASCII = "ascii"
            LATIN_1 = "latin-1"
            ISO_8859_1 = "iso-8859-1"

    # =========================================================================
    # Server identification - accessed via Constants via properties in base.py
    # =========================================================================
    # NOTE: server_type and priority are accessed via properties in base.py
    # which read from Constants.SERVER_TYPE and Constants.PRIORITY

    # === PUBLIC INTERFACE FOR SCHEMA CONFIGURATION ===

    @classmethod
    def get_schema_filterable_fields(cls) -> frozenset[str]:
        """Get schema fields that support OID filtering.

        Returns:
            frozenset of schema field names (attributetypes, objectclasses, etc.)

        """
        return cls.Constants.SCHEMA_FILTERABLE_FIELDS

    @classmethod
    def get_schema_dn(cls) -> str:
        """Get the RFC-normalized schema DN (RFC 4512 standard).

        Returns:
            Schema DN in RFC format (cn=schema)
            OID's quirk DN (cn=subschemasubentry) is normalized during parsing

        """
        # Return RFC standard DN (inherited from parent)
        return FlextLdifServersRfc.Constants.SCHEMA_DN

    @classmethod
    def get_categorization_rules(cls) -> FlextLdifModels.CategoryRules:
        """Get categorization rules for entry classification.

        Returns CategoryRules model compatible with FlextLdif.migrate() parameter.

        Returns:
            CategoryRules model with OID server quirks

        """
        # Python 3.13: Dict comprehension with list comprehensions
        category_map = cls.Constants.CATEGORY_OBJECTCLASSES
        hierarchy_ocs = list(
            dict.fromkeys(
                list(category_map.get("hierarchy", frozenset()))
                + list(cls.Constants.HIERARCHY_PRIORITY_OBJECTCLASSES),
            ),
        )

        return FlextLdifModels.CategoryRules(
            hierarchy_objectclasses=hierarchy_ocs,
            user_objectclasses=list(category_map.get("users", frozenset())),
            group_objectclasses=list(category_map.get("groups", frozenset())),
            acl_attributes=list(cls.Constants.CATEGORIZATION_ACL_ATTRIBUTES),
        )

    def extract_schemas_from_ldif(
        self,
        ldif_content: str,
    ) -> FlextResult[dict[str, object]]:
        """Extract and parse all schema definitions from LDIF content.

        Delegates to the Schema nested class implementation.

        Returns:
            FlextResult containing extracted attributes and objectclasses

        """
        # Instantiate Schema nested class
        schema_class = getattr(type(self), "Schema", None)
        if not schema_class:
            return FlextResult[dict[str, object]].fail(
                "Schema nested class not available",
            )

        schema_quirk = schema_class()
        result: FlextResult[dict[str, list[str] | str]] = (
            schema_quirk.extract_schemas_from_ldif(ldif_content)
        )
        return result.map(lambda d: cast("dict[str, object]", d))

    class Schema(
        FlextLdifServersRfc.Schema,
    ):
        """Oracle OID schema quirks implementation.

        Inherits OID pattern detection from OidPatternMixin, which provides
        can_handle_attribute() and can_handle_objectclass() methods that
        automatically detect OID-specific attributes using the pattern
        defined in Constants.DETECTION_OID_PATTERN.
        """

        def __init__(
            self,
            schema_service: object | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize OID schema quirk.

            server_type and priority are obtained from parent class Constants.
            They are not passed as parameters anymore.

            Args:
                schema_service: Injected FlextLdifSchema service (optional)
                **kwargs: Passed to parent

            """
            super().__init__(schema_service=schema_service, **kwargs)

        # Schema parsing and conversion methods
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Schema)
        # These methods override the base class with Oracle OID-specific logic:
        # - _parse_attribute(): Custom parsing logic for Oracle OID schema with special OID replacements
        # - _parse_objectclass(): Custom parsing logic for Oracle OID schema with special OID replacements
        # - _write_attribute(): Uses RFC writer with OID error handling
        # - _write_objectclass(): Uses RFC writer with OID error handling
        # - should_filter_out_attribute(): Returns False (accept all in OID mode)
        # - should_filter_out_objectclass(): Returns False (accept all in OID mode)
        # - create_metadata(): Creates OID-specific metadata

        def _normalize_syntax_oid(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
            *,
            replacements: dict[str, str] | None = None,
        ) -> None:
            """Normalize syntax OIDs to RFC 4517 standard.

            OID server exports SYNTAX with single quotes: SYNTAX '1.3.6.1.4.1.1466.115.121.1.7'
            RFC 4512: SYNTAX OID must NOT be quoted

            Args:
                attr_data: Attribute data to normalize (modified in place)
                replacements: Optional OID→RFC replacements dict

            """
            if attr_data.syntax:
                attr_data.syntax = FlextLdifUtilities.Schema.normalize_syntax_oid(
                    str(attr_data.syntax),
                    replacements=replacements,
                )

        def _normalize_matching_rules(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> None:
            """Normalize matching rules to RFC 4517 standard.

            Uses utilities.py for normalization (DRY principle).

            Args:
                attr_data: Attribute data to normalize (modified in place)

            """
            # Python 3.13: Use utilities for matching rule normalization
            normalized_equality, normalized_substr = (
                FlextLdifUtilities.Schema.normalize_matching_rules(
                    attr_data.equality,
                    attr_data.substr,
                    replacements=FlextLdifServersOid.Constants.MATCHING_RULE_TO_RFC,
                    normalized_substr_values=FlextLdifServersOid.Constants.MATCHING_RULE_TO_RFC,
                )
            )

            # Update fields if normalized
            if normalized_equality != attr_data.equality:
                attr_data.equality = normalized_equality
            if normalized_substr != attr_data.substr:
                attr_data.substr = normalized_substr

            # Normalize ordering field if present
            if attr_data.ordering:
                normalized_ordering = (
                    FlextLdifServersOid.Constants.MATCHING_RULE_TO_RFC.get(
                        attr_data.ordering,
                    )
                )
                if normalized_ordering:
                    attr_data.ordering = normalized_ordering

        def _transform_case_ignore_substrings(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextLdifModels.SchemaAttribute:
            """Transform caseIgnoreSubstringsMatch from EQUALITY to SUBSTR.

            RFC 4517 compliance: caseIgnoreSubstringsMatch must be SUBSTR, not EQUALITY.
            Transform during parse so the model is correct from the start (OID → RFC).

            Args:
                attr_data: Attribute data to transform

            Returns:
                Transformed attribute data

            """
            # Use utilities to normalize matching rules (moves SUBSTR from EQUALITY to SUBSTR)
            normalized_equality, normalized_substr = (
                FlextLdifUtilities.Schema.normalize_matching_rules(
                    attr_data.equality,
                    attr_data.substr,
                    substr_rules_in_equality={
                        "caseIgnoreSubstringsMatch": "caseIgnoreMatch",
                        "caseIgnoreSubStringsMatch": "caseIgnoreMatch",
                    },
                )
            )

            # Only transform if values changed
            if (
                normalized_equality != attr_data.equality
                or normalized_substr != attr_data.substr
            ):
                logger.debug(
                    "Moved caseIgnoreSubstringsMatch from EQUALITY to SUBSTR",
                    attribute_name=attr_data.name,
                    original_equality=attr_data.equality,
                    normalized_substr=normalized_substr,
                )

                # Preserve original_format before transformation (Python 3.13: walrus operator)
                original_format: str | None = (
                    cast(
                        "str | None",
                        attr_data.metadata.extensions.get("original_format"),
                    )
                    if (
                        attr_data.metadata
                        and attr_data.metadata.extensions
                        and "original_format" in attr_data.metadata.extensions
                    )
                    else None
                )

                # Create new model with transformed values
                transformed = attr_data.model_copy(
                    update={
                        "equality": normalized_equality,
                        "substr": normalized_substr,
                    },
                )

                # Restore original_format in metadata after transformation
                if original_format and transformed.metadata:
                    transformed.metadata.extensions["original_format"] = original_format

                return transformed

            return attr_data

        def _capture_attribute_values(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> dict[str, str | None]:
            """Capture attribute values for metadata tracking.

            Used both before and after transformations to track source/target state.
            """
            return {
                "syntax_oid": str(attr_data.syntax) if attr_data.syntax else None,
                "equality": attr_data.equality,
                "substr": attr_data.substr,
                "ordering": attr_data.ordering,
                "name": attr_data.name,
            }

        def _apply_oid_transformations(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextLdifModels.SchemaAttribute:
            """Apply OID-specific transformations to attribute."""
            # Step 1: Clean syntax OID (remove quotes, no replacements)
            self._normalize_syntax_oid(attr_data, replacements=None)
            # Step 2: Normalize matching rules
            self._normalize_matching_rules(attr_data)
            # Step 3: Apply syntax OID replacements
            self._normalize_syntax_oid(
                attr_data,
                replacements=FlextLdifServersOid.Constants.SYNTAX_OID_TO_RFC,
            )
            # Step 4: Transform caseIgnoreSubstringsMatch (EQUALITY → SUBSTR)
            return self._transform_case_ignore_substrings(attr_data)

        def _add_source_metadata(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
            source_values: dict[str, str | None],
            _attr_definition: str,  # Unused but kept for API consistency
        ) -> None:
            """Add source metadata to attribute."""
            meta_keys = FlextLdifConstants.MetadataKeys
            if not attr_data.metadata:
                return

            # Preserve SOURCE (before transformation)
            if source_values["syntax_oid"]:
                attr_data.metadata.extensions[meta_keys.SCHEMA_SOURCE_SYNTAX_OID] = (
                    source_values["syntax_oid"]
                )
            if source_values["name"]:
                attr_data.metadata.extensions[
                    meta_keys.SCHEMA_SOURCE_ATTRIBUTE_NAME
                ] = source_values["name"]

            # Preserve SOURCE matching rules (before transformation)
            source_rules = {}
            if source_values["equality"]:
                source_rules["equality"] = source_values["equality"]
            if source_values["substr"]:
                source_rules["substr"] = source_values["substr"]
            if source_values["ordering"]:
                source_rules["ordering"] = source_values["ordering"]
            if source_rules:
                attr_data.metadata.extensions[
                    meta_keys.SCHEMA_SOURCE_MATCHING_RULES
                ] = source_rules

        def _add_target_metadata(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
            target_values: dict[str, str | None],
        ) -> None:
            """Add target metadata to attribute."""
            meta_keys = FlextLdifConstants.MetadataKeys
            if not attr_data.metadata:
                return

            # Preserve TARGET (after transformation)
            if target_values["syntax_oid"]:
                attr_data.metadata.extensions[meta_keys.SCHEMA_TARGET_SYNTAX_OID] = (
                    target_values["syntax_oid"]
                )
            if target_values["name"]:
                attr_data.metadata.extensions[
                    meta_keys.SCHEMA_TARGET_ATTRIBUTE_NAME
                ] = target_values["name"]

            # Preserve TARGET matching rules (after transformation)
            target_rules = {}
            if target_values["equality"]:
                target_rules["equality"] = target_values["equality"]
            if target_values["substr"]:
                target_rules["substr"] = target_values["substr"]
            if target_values["ordering"]:
                target_rules["ordering"] = target_values["ordering"]
            if target_rules:
                attr_data.metadata.extensions[
                    meta_keys.SCHEMA_TARGET_MATCHING_RULES
                ] = target_rules

            # Timestamp
            attr_data.metadata.extensions["parsed_timestamp"] = (
                FlextUtilities.Generators.generate_iso_timestamp()
            )

        def _parse_attribute(
            self,
            attr_definition: str,
            *,
            _case_insensitive: bool = True,
            _allow_syntax_quotes: bool = True,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse Oracle OID attribute definition.

            Uses RFC 4512 compliant baseline parser with lenient mode for OID quirks,
            then applies OID-specific enhancements like matching rule fixes and
            syntax OID replacements.

            Args:
                attr_definition: AttributeType definition string
                                (without "attributetypes:" prefix)
                _case_insensitive: OID uses case-insensitive NAME (default True, unused)
                _allow_syntax_quotes: OID allows 'OID' format for SYNTAX (default True)

            Returns:
                FlextResult with parsed OID attribute data with metadata

            """
            try:
                # Call parent RFC parser with OID-specific settings (lenient mode)
                result = super()._parse_attribute(
                    attr_definition,
                    _case_insensitive=_case_insensitive,
                    _allow_syntax_quotes=_allow_syntax_quotes,
                )

                if not result.is_success:
                    return result

                # Unwrap parsed attribute from RFC baseline
                attr_data = result.unwrap()

                # Preserve SOURCE values BEFORE transformations
                source_values = self._capture_attribute_values(attr_data)

                # Apply OID-specific enhancements
                attr_data = self._apply_oid_transformations(attr_data)

                # Preserve TARGET values AFTER transformations
                target_values = self._capture_attribute_values(attr_data)

                # Ensure metadata is preserved with GENERIC metadata (NO *_OID_* keys!)
                if not attr_data.metadata:
                    attr_data.metadata = self.create_metadata(attr_definition.strip())

                # Add GENERIC metadata keys for 100% bidirectional conversion
                if attr_data.metadata:
                    meta_keys = FlextLdifConstants.MetadataKeys
                    attr_data.metadata.extensions[meta_keys.SCHEMA_ORIGINAL_FORMAT] = (
                        attr_definition.strip()
                    )
                    attr_data.metadata.extensions[
                        meta_keys.SCHEMA_ORIGINAL_STRING_COMPLETE
                    ] = attr_definition  # Complete with ALL formatting
                    attr_data.metadata.extensions[meta_keys.SCHEMA_SOURCE_SERVER] = (
                        "oid"  # OID parsed this
                    )

                    # Preserve ALL schema formatting details for zero data loss
                    FlextLdifUtilities.Metadata.preserve_schema_formatting(
                        cast("FlextLdifModels.QuirkMetadata", attr_data.metadata),
                        attr_definition,
                    )

                    # Add source and target metadata
                    self._add_source_metadata(attr_data, source_values, attr_definition)
                    self._add_target_metadata(attr_data, target_values)

                return FlextResult[FlextLdifModels.SchemaAttribute].ok(attr_data)

            except Exception as e:
                logger.exception(
                    "OID attribute parsing failed",
                )
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"OID attribute parsing failed: {e}",
                )

        def _write_attribute(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[str]:
            """Write Oracle OID attribute definition with OID denormalization.

            Architecture: OID Writer = RFC Models → OID LDIF (ALWAYS denormalize)
            - Parser: OID LDIF → RFC Models (normalization)
            - Writer: RFC Models → OID LDIF (denormalization - restore OID quirks)

            For OID→OUD conversion (RFC format): Use RFC writer, NOT OID writer!

            Applies OID denormalizations:
            - Matching rule denormalization (RFC → OID native format)
            - Syntax OID denormalization (RFC → OID native format)
            - Uses INVERSE mappings (RFC_TO_OID)

            Args:
                attr_data: RFC SchemaAttribute model to write

            Returns:
                FlextResult with OID-formatted attribute string

            """
            # Create a copy to avoid mutating the original
            attr_copy = attr_data.model_copy(deep=True)

            meta_keys = FlextLdifConstants.MetadataKeys

            # ✅ STRICT RULE: OID Writer SEMPRE denormaliza RFC → OID LDIF
            # Não importa de onde veio (OID, OUD, OpenLDAP, etc.)
            # Se estamos escrevendo OID LDIF, SEMPRE aplicamos conversões OID!

            # Tentar restaurar valores SOURCE do metadata (para 100% fidelidade)
            source_rules = None
            source_syntax = None
            if attr_copy.metadata and attr_copy.metadata.extensions:
                source_rules = attr_copy.metadata.extensions.get(
                    meta_keys.SCHEMA_SOURCE_MATCHING_RULES,
                )
                source_syntax = attr_copy.metadata.extensions.get(
                    meta_keys.SCHEMA_SOURCE_SYNTAX_OID,
                )

            # 1. Denormalizar matching rules: RFC → OID
            if source_rules and FlextRuntime.is_dict_like(source_rules):
                # Preferir valores SOURCE do metadata (se vieram de OID originalmente)
                oid_equality = source_rules.get("equality", attr_copy.equality)
                oid_substr = source_rules.get("substr", attr_copy.substr)
                oid_ordering = source_rules.get("ordering", attr_copy.ordering)
            else:
                # Denormalizar valores atuais RFC → OID
                oid_equality, oid_substr = (
                    FlextLdifUtilities.Schema.normalize_matching_rules(
                        attr_copy.equality,
                        attr_copy.substr,
                        replacements=FlextLdifServersOid.Constants.MATCHING_RULE_RFC_TO_OID,
                        normalized_substr_values=FlextLdifServersOid.Constants.MATCHING_RULE_RFC_TO_OID,
                    )
                )
                oid_ordering = attr_copy.ordering
                if attr_copy.ordering:
                    mapped = FlextLdifServersOid.Constants.MATCHING_RULE_RFC_TO_OID.get(
                        attr_copy.ordering,
                    )
                    if mapped:
                        oid_ordering = mapped

            # 2. Denormalizar syntax OID: RFC → OID
            if source_syntax:
                # Preferir syntax SOURCE do metadata (se veio de OID originalmente)
                oid_syntax = source_syntax
            else:
                # Denormalizar syntax atual RFC → OID
                oid_syntax = attr_copy.syntax
                if attr_copy.syntax:
                    mapped = FlextLdifServersOid.Constants.SYNTAX_RFC_TO_OID.get(
                        str(attr_copy.syntax),
                    )
                    if mapped:
                        oid_syntax = mapped

            # Remove original_format from metadata (not used for writing)
            oid_metadata = attr_copy.metadata
            if attr_copy.metadata and attr_copy.metadata.extensions:
                keys_to_remove = {meta_keys.SCHEMA_ORIGINAL_FORMAT, "original_format"}
                new_extensions = {
                    k: v
                    for k, v in attr_copy.metadata.extensions.items()
                    if k not in keys_to_remove
                }
                oid_metadata = attr_copy.metadata.model_copy(
                    update={"extensions": new_extensions},
                )

            # Apply transformations with model_copy
            attr_copy = attr_copy.model_copy(
                update={
                    "equality": oid_equality,
                    "substr": oid_substr,
                    "ordering": oid_ordering,
                    "syntax": oid_syntax,
                    "metadata": oid_metadata,
                },
            )

            # Call parent RFC writer with OID-denormalized attribute
            return super()._write_attribute(attr_copy)

        def _normalize_sup_from_model(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> str | list[str] | None:
            """Normalize SUP from objectClass model.

            Fixes: SUP ( top ) → SUP top, SUP 'top' → SUP top

            Args:
                oc_data: ObjectClass data to check

            Returns:
                Normalized SUP value or None if no fix needed

            """
            if not oc_data.sup:
                return None

            # Python 3.13: Match/case for cleaner pattern matching
            # Set of SUP values that need normalization
            sup_normalize_set = {"( top )", "(top)", "'top'", '"top"'}

            match oc_data.sup:
                case sup_str if (
                    sup_clean := str(sup_str).strip()
                ) in sup_normalize_set:
                    logger.debug(
                        "OID→RFC transform: SUP normalization",
                        objectclass_name=oc_data.name,
                        objectclass_oid=oc_data.oid,
                        original_sup=sup_clean,
                        normalized_sup="top",
                    )
                    return "top"
                case [sup_item] if (
                    sup_clean := str(sup_item).strip()
                ) in sup_normalize_set:
                    logger.debug(
                        "OID→RFC transform: SUP normalization (list)",
                        objectclass_name=oc_data.name,
                        objectclass_oid=oc_data.oid,
                        original_sup=sup_clean,
                        normalized_sup="top",
                    )
                    return "top"
                case _:
                    return None

        def _normalize_sup_from_original_format(
            self,
            original_format_str: str,
        ) -> str | None:
            """Normalize SUP from original_format string.

            Args:
                original_format_str: Original format string to check

            Returns:
                Normalized SUP value or None if no fix needed

            """
            # Python 3.13: match/case for pattern matching (DRY: use set for patterns)
            sup_patterns = ("SUP 'top'", "SUP ( top )", "SUP (top)")
            match original_format_str:
                case s if any(pattern in s for pattern in sup_patterns):
                    logger.debug(
                        "OID→RFC transform: SUP normalization (from original_format)",
                        original_format_preview=s[
                            : FlextLdifServersOid.Constants.MAX_LOG_LINE_LENGTH
                        ],
                    )
                    return "top"
                case _:
                    return None

        def _normalize_auxiliary_typo(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
            original_format_str: str,
        ) -> str | None:
            """Normalize AUXILLARY typo to AUXILIARY.

            Args:
                oc_data: ObjectClass data to check
                original_format_str: Original format string to check

            Returns:
                Normalized kind value or None if no fix needed

            """
            # Python 3.13: match/case for cleaner pattern matching
            kind = getattr(oc_data, "kind", None)
            match (kind, original_format_str):
                case (k, _) if k and k.upper() == "AUXILLARY":
                    logger.debug(
                        "OID→RFC transform: AUXILLARY → AUXILIARY",
                        objectclass_name=oc_data.name,
                        objectclass_oid=oc_data.oid,
                        original_kind=k,
                        normalized_kind="AUXILIARY",
                    )
                    return "AUXILIARY"
                case (_, fmt) if fmt and "AUXILLARY" in fmt:
                    logger.debug(
                        "OID→RFC transform: AUXILLARY → AUXILIARY (from original_format)",
                        objectclass_name=getattr(oc_data, "name", None),
                        objectclass_oid=getattr(oc_data, "oid", None),
                        original_format_preview=fmt[
                            : FlextLdifServersOid.Constants.MAX_LOG_LINE_LENGTH
                        ],
                    )
                    return "AUXILIARY"
                case _:
                    return None

        def _normalize_attribute_names(
            self,
            attr_list: list[str] | None,
        ) -> list[str] | None:
            """Normalize attribute names using OID case mappings.

            OID exports objectClass MAY/MUST with lowercase attribute names,
            but attributeType definitions use CamelCase. This normalizes
            to RFC-correct case during parsing (OID → RFC transformation).

            Args:
                attr_list: List of attribute names from OID (may contain lowercase)

            Returns:
                List with normalized attribute names (RFC-correct case)
                None if input was None

            """
            if not attr_list:
                return attr_list

            # Python 3.13: List comprehension with walrus operator for case normalization
            case_map = FlextLdifServersOid.Constants.ATTR_NAME_CASE_MAP
            return [
                case_map.get(attr_name.lower(), attr_name) for attr_name in attr_list
            ]

        def _apply_objectclass_transforms(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
            original_format_str: str,
        ) -> FlextLdifModels.SchemaObjectClass:
            """Apply OID-specific transformations to objectClass data.

            Args:
                oc_data: Parsed objectClass from RFC baseline
                original_format_str: Original objectClass definition string

            Returns:
                Transformed objectClass data with OID-specific fixes applied

            """
            # Normalize SUP and AUXILIARY
            updated_sup = self._normalize_sup_from_model(oc_data)
            if updated_sup is None and original_format_str:
                updated_sup = self._normalize_sup_from_original_format(
                    original_format_str,
                )

            updated_kind = self._normalize_auxiliary_typo(
                oc_data,
                original_format_str,
            )

            # Normalize attribute names in MUST and MAY (OID → RFC case correction)
            normalized_must = self._normalize_attribute_names(oc_data.must)
            normalized_may = self._normalize_attribute_names(oc_data.may)

            # Apply transformations if needed (Python 3.13: dict comprehension)
            update_dict: dict[str, object] = {
                k: v
                for k, v in {
                    "sup": updated_sup,
                    "kind": updated_kind,
                    "must": normalized_must
                    if normalized_must != oc_data.must
                    else None,
                    "may": normalized_may if normalized_may != oc_data.may else None,
                }.items()
                if v
            }

            return oc_data.model_copy(update=update_dict) if update_dict else oc_data

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse Oracle OID objectClass definition.

            Uses RFC 4512 compliant baseline parser with lenient mode for OID quirks,
            then applies OID-specific enhancements.

            Args:
                oc_definition: ObjectClass definition string
                            (without "objectclasses:" prefix)

            Returns:
                FlextResult with parsed OID objectClass data with metadata

            """
            try:
                # Call parent RFC parser for objectClass parsing
                result = super()._parse_objectclass(oc_definition)

                if not result.is_success:
                    return result

                # Unwrap parsed objectClass from RFC baseline
                oc_data = result.unwrap()

                # Apply OID-specific enhancements on top of RFC baseline
                # Fix common ObjectClass issues (RFC 4512 compliance)
                FlextLdifUtilities.ObjectClass.ensure_sup_for_auxiliary(oc_data)
                FlextLdifUtilities.ObjectClass.align_kind_with_superior(oc_data, None)

                # Get original_format for transformations (Python 3.13: walrus operator)
                original_format_str = (
                    str(oc_data.metadata.extensions.get("original_format", ""))
                    if oc_data.metadata and oc_data.metadata.extensions
                    else ""
                )

                # Apply OID-specific transformations (extracted to reduce complexity)
                oc_data = self._apply_objectclass_transforms(
                    oc_data,
                    original_format_str,
                )

                # Ensure metadata is preserved with OID-specific information
                if not oc_data.metadata:
                    oc_data.metadata = self.create_metadata(oc_definition.strip())
                elif not oc_data.metadata.extensions.get("original_format"):
                    oc_data.metadata.extensions["original_format"] = (
                        oc_definition.strip()
                    )

                # Attach timestamp metadata (Python 3.13: type guard)
                if oc_data.metadata:
                    oc_data.metadata.extensions["parsed_timestamp"] = (
                        FlextUtilities.Generators.generate_iso_timestamp()
                    )

                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oc_data)

            except Exception as e:
                logger.exception(
                    "OID objectClass parsing failed",
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"OID objectClass parsing failed: {e}",
                )

        def _write_objectclass(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write Oracle OID objectClass definition with X-ORIGIN.

            Includes X-ORIGIN field from metadata if present, which is
            important for OID schema export and RFC-compliant schema interchange.

            X-ORIGIN is a server-specific extension that tracks the origin
            of objectClass definitions (e.g., "Oracle OID", "RFC 4519").

            Args:
                oc_data: Parsed schema objectClass model

            Returns:
                FlextResult with formatted LDIF objectClass definition string

            Example:
                Input: SchemaObjectClass with metadata.x_origin = "Oracle OID"
                Output: "( 2.5.6.6 NAME 'person' STRUCTURAL X-ORIGIN 'Oracle OID' )"

            """
            # Call parent RFC writer which already handles X-ORIGIN via metadata.extensions (Phase 5)
            # The parent implementation includes X-ORIGIN from metadata.extensions.get('x_origin')
            return super()._write_objectclass(oc_data)

        def _transform_attribute_for_write(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextLdifModels.SchemaAttribute:
            """Apply OID-specific attribute transformations before writing.

            IMPORTANT: Writer denormalization (RFC → OID) happens in _write_attribute.
            This hook should NOT re-normalize matching rules back to RFC.
            Only apply NAME normalization here.

            Args:
                attr_data: SchemaAttribute to transform (already denormalized in _write_attribute)

            Returns:
                Transformed SchemaAttribute with NAME fixes only

            """
            # Apply AttributeFixer transformations to NAME (use utilities.py)
            fixed_name = (
                FlextLdifUtilities.Schema.normalize_name(attr_data.name)
                or attr_data.name
            )

            # DO NOT re-normalize matching rules here!
            # Writer denormalization (RFC → OID) was already applied in _write_attribute
            # Re-normalizing here would undo the denormalization
            fixed_equality = attr_data.equality
            fixed_substr = attr_data.substr

            # Validate and enhance matching rules for OID
            # Check for invalid SUBSTR rules and apply INVALID_SUBSTR_RULES mappings
            invalid_substr_rules = FlextLdifServersOid.Constants.INVALID_SUBSTR_RULES

            if fixed_substr and fixed_substr in invalid_substr_rules:
                replacement = invalid_substr_rules[fixed_substr]
                if replacement:
                    logger.debug(
                        "Replacing invalid SUBSTR rule",
                        attribute_name=attr_data.name,
                        attribute_oid=attr_data.oid,
                        original_substr=fixed_substr,
                        replacement_substr=replacement,
                        equality_rule=attr_data.equality,
                    )
                    fixed_substr = replacement
                else:
                    logger.debug(
                        "Invalid SUBSTR rule has no replacement, keeping as-is",
                        attribute_name=attr_data.name,
                        attribute_oid=attr_data.oid,
                        invalid_substr=fixed_substr,
                        equality_rule=attr_data.equality,
                    )

            # Check if this is a boolean attribute for special handling during write
            # Python 3.13: Use set comprehension for efficient lookup
            boolean_attrs_lower = {
                attr.lower()
                for attr in FlextLdifServersOid.Constants.BOOLEAN_ATTRIBUTES
            }
            if fixed_name and fixed_name.lower() in boolean_attrs_lower:
                logger.debug(
                    "Identified boolean attribute",
                    attribute_name=fixed_name,
                    attribute_oid=attr_data.oid,
                    original_name=attr_data.name
                    if attr_data.name != fixed_name
                    else None,
                )

            # Extract x_origin from metadata.extensions (Python 3.13: match/case)
            x_origin_value: str | None = None
            if attr_data.metadata and attr_data.metadata.extensions:
                match attr_data.metadata.extensions.get("x_origin"):
                    case origin if isinstance(origin, str):
                        x_origin_value = origin
                    case None:
                        pass  # Already None
                    case x_origin_raw:
                        # Fast-fail: x_origin must be str or None
                        logger.warning(
                            "x_origin extension is not a string, ignoring",
                            extra={
                                "x_origin_type": type(x_origin_raw).__name__,
                                "x_origin_value": str(x_origin_raw)[:100],
                                "attribute_name": attr_data.name,
                                "attribute_oid": attr_data.oid,
                            },
                        )

            return FlextLdifModels.SchemaAttribute(
                oid=attr_data.oid,
                name=fixed_name,
                desc=attr_data.desc,
                sup=attr_data.sup,
                equality=fixed_equality,
                ordering=attr_data.ordering,
                substr=fixed_substr,
                syntax=attr_data.syntax,
                length=attr_data.length,
                usage=attr_data.usage,
                single_value=attr_data.single_value,
                no_user_modification=attr_data.no_user_modification,
                metadata=attr_data.metadata,
                x_origin=x_origin_value,
                x_file_ref=attr_data.x_file_ref,
                x_name=attr_data.x_name,
                x_alias=attr_data.x_alias,
                x_oid=attr_data.x_oid,
            )

        def _post_write_objectclass(self, written_str: str) -> str:
            """Fix known typos in written objectClass strings.

            Implements post-write hook from RFC base to fix:
            - AUXILLARY (double L) → AUXILIARY (single L) typo fix

            Args:
                written_str: RFC-formatted objectClass string from RFC base

            Returns:
                Potentially fixed objectClass string

            """
            # Fix AUXILLARY (double L) → AUXILIARY (single L) typo
            fixed = written_str.replace(
                FlextLdifServersOid.Constants.OBJECTCLASS_TYPO_AUXILLARY,
                FlextLdifServersOid.Constants.OBJECTCLASS_TYPO_AUXILIARY,
            )
            if fixed != written_str:
                # Extract objectClass name for better logging (Python 3.13: walrus operator)
                oc_name_match = (
                    m.group(1)
                    if "NAME" in written_str
                    and (m := re.search(r"NAME\s+['\"]?([^'\")]+)['\"]?", written_str))
                    else None
                )
                logger.debug(
                    "Fixed AUXILLARY typo in objectClass definition",
                    typo_found=FlextLdifServersOid.Constants.OBJECTCLASS_TYPO_AUXILLARY,
                    typo_corrected=FlextLdifServersOid.Constants.OBJECTCLASS_TYPO_AUXILIARY,
                    objectclass_name=oc_name_match,
                    definition_preview=written_str[
                        : FlextLdifServersOid.Constants.MAX_LOG_LINE_LENGTH
                    ],
                )
            return fixed

        def extract_schemas_from_ldif(
            self,
            ldif_content: str,
            *,  # keyword-only parameter
            validate_dependencies: bool = False,
        ) -> FlextResult[dict[str, object]]:
            """Extract and parse all schema definitions from LDIF content.

            OID-specific implementation: Uses base template method without dependency
            validation (OID has relaxed schema validation compared to RFC strict mode).

            Args:
                ldif_content: Raw LDIF content containing schema definitions
                validate_dependencies: Whether to validate attribute dependencies
                    (default False for OID as it has simpler schema)

            Returns:
                FlextResult containing extracted attributes and objectclasses
                as a dictionary with ATTRIBUTES and OBJECTCLASS lists.

            """
            return super().extract_schemas_from_ldif(
                ldif_content,
                validate_dependencies=validate_dependencies,
            )

    class Acl(FlextLdifServersRfc.Acl):
        """Oracle OID ACL quirk using universal parser with OID-specific configuration.

        Delegates to FlextLdifUtilities.ACL.parser() with OID server-specific patterns,
        permissions mapping, and subject transformations. This ensures DRY compliance
        while maintaining full OID feature support.

        OID-specific features supported:
        - orclaci: Oracle standard ACIs
        - orclentrylevelaci: Oracle entry-level ACIs
        - Complex filter expressions with balanced parentheses
        - OID-specific permissions (browse, auth, self_write, proxy)
        - Multi-subject ACLs
        - Entry-level constraints (added_object_constraint)
        """

        # ACL attribute name is obtained from Constants.ACL_ATTRIBUTE_NAME
        # No instance variable needed - use Constants directly

        # =====================================================================
        # PROTOCOL IMPLEMENTATION: FlextLdifProtocols.ServerAclProtocol
        # =====================================================================

        # RFC Foundation - Standard LDAP attributes (all servers start here)
        RFC_ACL_ATTRIBUTES: ClassVar[list[str]] = [
            "aci",  # Standard LDAP (RFC 4876)
            "acl",  # Alternative format
            "olcAccess",  # OpenLDAP
            "aclRights",  # Generic rights
            "aclEntry",  # ACL entry
        ]

        # OID-specific extensions
        OID_ACL_ATTRIBUTES: ClassVar[list[str]] = [
            "orclaci",  # OID-specific ACI
            "orclentrylevelaci",  # OID entry-level ACI
            "orclContainerLevelACL",  # OID container ACL
        ]

        def get_acl_attributes(self) -> list[str]:
            """Get RFC + OID extensions.

            Returns:
                List of ACL attribute names (RFC foundation + OID-specific)

            """
            return self.RFC_ACL_ATTRIBUTES + self.OID_ACL_ATTRIBUTES

        # is_acl_attribute inherited from base class (uses set for O(1) lookup)

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
        # These methods override the base class with Oracle OID-specific logic:
        # - can_handle_acl(): Detects orclaci/orclentrylevelaci formats
        # - parse_acl(): Normalizes Oracle OID ACL to RFC-compliant internal model
        # - write_acl(): Serializes RFC-compliant model to OID ACL format
        # - get_acl_attribute_name(): Returns "orclaci" (OID-specific, overridden)

        def can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
            """Check if this is an Oracle OID ACL.

            Detects Oracle OID ACL by checking for Oracle-specific ACL syntax patterns:
            - "access to <target> by <subject>" (Oracle OID ACL format)
            - "orclaci:" (LDIF attribute prefix)
            - "orclentrylevelaci:" (LDIF attribute prefix)

            Oracle OID ACL format: access to [entry|attr:<name>] by <subject> : <permissions>

            Args:
                acl_line: Raw ACL line from LDIF or Acl model

            Returns:
                True if this is Oracle OID ACL format

            """
            if isinstance(acl_line, FlextLdifModels.Acl):
                # Check metadata for OID server type
                if acl_line.metadata and acl_line.metadata.quirk_type:
                    return acl_line.metadata.quirk_type == self._get_server_type()
                return False
            if not acl_line:
                return False
            # Type narrowing: after checking for Acl, remaining is str
            # acl_line is str at this point (str | Acl, and Acl was already checked)
            acl_line_str: str = str(acl_line)
            acl_line_lower = acl_line_str.strip().lower()

            # Check for LDIF attribute prefix (when parsing from LDIF file)
            if acl_line_lower.startswith(
                (
                    f"{FlextLdifServersOid.Constants.ORCLACI}:",
                    f"{FlextLdifServersOid.Constants.ORCLENTRYLEVELACI}:",
                ),
            ):
                return True

            # Check for Oracle OID ACL content pattern (RFC 4876 compliant syntax)
            # Oracle format: "access to <target> by <subject> : <permissions>"
            return acl_line_lower.startswith("access to ")

        def _update_acl_with_oid_metadata(
            self,
            acl_data: FlextLdifModels.Acl,
            acl_line: str,
        ) -> FlextLdifModels.Acl:
            """Update ACL with OID server type and metadata."""
            server_type = FlextLdifServersOid.Constants.SERVER_TYPE
            updated_metadata = (
                acl_data.metadata.model_copy(update={"quirk_type": server_type})
                if acl_data.metadata
                else FlextLdifModels.QuirkMetadata.create_for(
                    server_type,
                    extensions={"original_format": acl_line.strip()},
                )
            )
            return acl_data.model_copy(
                update={
                    "server_type": server_type,
                    "metadata": updated_metadata,
                },
            )

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse Oracle OID ACL string to RFC-compliant internal model.

            Normalizes Oracle OID-specific ACL format (orclaci/orclentrylevelaci)
            to RFC-compliant internal representation using AclParser.

            OID-specific features normalized:
            - orclaci/orclentrylevelaci ACL types
            - Complex filter expressions with nested parentheses
            - Multi-subject bindings (dnattr, guidattr, groupattr)
            - Entry-level constraints (added_object_constraint)

            Args:
                acl_line: Oracle OID ACL definition line from LDIF

            Returns:
                FlextResult with RFC-compliant Acl model

            """
            # Always try parent's _parse_acl first (RFC format)
            parent_result = super()._parse_acl(acl_line)

            # If parent validation failed (empty string, etc.), return error immediately
            if parent_result.is_failure:
                return parent_result

            # Check if this is an OID ACL and parent parser populated it correctly
            if (
                parent_result.is_success
                and (acl_data := parent_result.unwrap())
                and self.can_handle_acl(acl_line)
                and any(
                    getattr(acl_data, field) is not None
                    for field in ("permissions", "target", "subject")
                )
            ):
                # Parent parser populated the model, use it with OID server_type
                updated_acl = self._update_acl_with_oid_metadata(acl_data, acl_line)
                return FlextResult[FlextLdifModels.Acl].ok(updated_acl)

            # Not an OID ACL or parent didn't parse well - use parent result or fall through
            if (
                parent_result.is_success
                and (acl_data := parent_result.unwrap())
                and not self.can_handle_acl(acl_line)
            ):
                return FlextResult[FlextLdifModels.Acl].ok(acl_data)

            # RFC parser failed - use OID-specific parsing
            return self._parse_oid_specific_acl(acl_line)

        def _map_oid_subject_to_rfc(
            self,
            oid_subject_type: str,
            oid_subject_value: str,
        ) -> tuple[str, str]:
            """Map OID subject types to RFC subject types."""
            if oid_subject_type == "self":
                return "self", "ldap:///self"
            if oid_subject_type in {"group_dn", "user_dn"}:
                return "bind_rules", oid_subject_value
            if oid_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
                return "bind_rules", oid_subject_value
            if oid_subject_type == "*" or oid_subject_value == "*":
                return "anonymous", "*"
            return "bind_rules", oid_subject_value

        def _build_oid_acl_metadata(
            self,
            acl_line: str,
            oid_subject_type: str,
            rfc_subject_type: str,
            oid_subject_value: str,
            perms_dict: dict[str, bool],
            target_dn: str,
            target_attrs: list[str] | None,
            acl_filter: str | None,
            acl_constraint: str | None,
        ) -> dict[str, object]:
            """Build metadata extensions for OID ACL."""
            extensions: dict[str, object] = {
                FlextLdifConstants.MetadataKeys.ACL_ORIGINAL_FORMAT: acl_line.strip(),
                FlextLdifConstants.MetadataKeys.ACL_SOURCE_SERVER: "oid",
                FlextLdifConstants.MetadataKeys.ACL_SOURCE_SUBJECT_TYPE: oid_subject_type,
                FlextLdifConstants.MetadataKeys.ACL_TARGET_SUBJECT_TYPE: rfc_subject_type,
                FlextLdifConstants.MetadataKeys.ACL_ORIGINAL_SUBJECT_VALUE: oid_subject_value,
                FlextLdifConstants.MetadataKeys.ACL_SOURCE_PERMISSIONS: perms_dict,
                "acl_source_target": {
                    "target_dn": target_dn,
                    "attributes": target_attrs or [],
                },
            }

            if acl_filter:
                extensions[FlextLdifConstants.MetadataKeys.ACL_FILTER] = acl_filter
            if acl_constraint:
                extensions[FlextLdifConstants.MetadataKeys.ACL_CONSTRAINT] = (
                    acl_constraint
                )

            return extensions

        def _parse_oid_specific_acl(
            self,
            acl_line: str,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Parse OID-specific ACL format when RFC parser fails."""
            # Parse OID ACL format: orclaci: access to [entry|attr=(...)] [by subject (permissions)] [filter=(...)] [added_object_constraint=(...)]
            try:
                # Extract target using DRY utility
                target_dn, target_attrs = FlextLdifUtilities.ACL.extract_oid_target(
                    acl_line,
                )

                # Detect subject using DRY utility with OID patterns
                subject_patterns: dict[str, tuple[str | None, str, str]] = (
                    FlextLdifServersOid.Constants.ACL_SUBJECT_PATTERNS
                )
                oid_subject_type, oid_subject_value = (
                    FlextLdifUtilities.ACL.detect_oid_subject(
                        acl_line,
                        subject_patterns,
                    )
                )

                # Map OID subject types to RFC subject types
                rfc_subject_type, rfc_subject_value = self._map_oid_subject_to_rfc(
                    oid_subject_type,
                    oid_subject_value,
                )

                # Parse permissions and extract filter/constraint
                perms_dict = FlextLdifUtilities.ACL.parse_oid_permissions(
                    acl_line,
                    FlextLdifServersOid.Constants.ACL_PERMISSION_MAPPING,
                )

                # Extract filter and constraint
                filter_match = re.search(
                    FlextLdifServersOid.Constants.ACL_FILTER_PATTERN,
                    acl_line,
                )
                acl_filter = filter_match.group(1) if filter_match else None

                constraint_match = re.search(
                    FlextLdifServersOid.Constants.ACL_CONSTRAINT_PATTERN,
                    acl_line,
                )
                acl_constraint = constraint_match.group(1) if constraint_match else None

                # Build metadata extensions
                extensions = self._build_oid_acl_metadata(
                    acl_line,
                    oid_subject_type,
                    rfc_subject_type,
                    oid_subject_value,
                    perms_dict,
                    target_dn,
                    target_attrs,
                    acl_filter,
                    acl_constraint,
                )

                # Create ACL model with parsed data (Python 3.13: cleaner dict creation)
                # Use RFC name (aci) for Entry model (OID → RFC conversion)
                server_type = cast(
                    "FlextLdifConstants.LiteralTypes.ServerType",
                    FlextLdifConstants.ServerTypes.OID,
                )
                acl_model = FlextLdifModels.Acl(
                    name=FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME,
                    target=FlextLdifModels.AclTarget(
                        target_dn=target_dn,
                        attributes=target_attrs or [],
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type=rfc_subject_type,
                        subject_value=rfc_subject_value,
                    ),
                    permissions=FlextLdifModels.AclPermissions(**perms_dict),
                    server_type=server_type,
                    metadata=FlextLdifModels.QuirkMetadata(
                        quirk_type=server_type,
                        extensions=extensions,
                    ),
                    raw_acl=acl_line,
                )
                return FlextResult[FlextLdifModels.Acl].ok(acl_model)
            except Exception as e:
                # Python 3.13: Walrus operator for cleaner code
                max_len = FlextLdifServersOid.Constants.MAX_LOG_LINE_LENGTH
                acl_preview = (
                    acl_line[:max_len] if len(acl_line) > max_len else acl_line
                )
                logger.debug(
                    "OID ACL parse failed",
                    error=str(e),
                    error_type=type(e).__name__,
                    acl_line=acl_preview,
                    acl_line_length=len(acl_line),
                )
                # Return error result
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"OID ACL parsing failed: {e}",
                )

        def _get_oid_patterns(self) -> dict[str, str]:
            """Get OID-specific regex patterns for ACL parsing.

            Returns:
                Dictionary of pattern names to regex patterns for ACL component extraction.
                Patterns support:
                - acl_type: Identifies orclaci vs orclentrylevelaci
                - target: Extracts target entry or attributes
                - subject: Matches subject bindings (group, dnattr, guidattr, etc.)
                - permissions: Extracts permission list in parentheses
                - filter: Handles nested parentheses in filter expressions
                - constraint: Extracts entry-level constraints

            """
            # Python 3.13: Dict from zip with strict=True for pattern mapping
            return dict(
                zip(
                    (
                        FlextLdifServersOid.Constants.ACL_PATTERN_KEY_TYPE,
                        FlextLdifServersOid.Constants.ACL_PATTERN_KEY_TARGET,
                        FlextLdifServersOid.Constants.ACL_PATTERN_KEY_SUBJECT,
                        FlextLdifServersOid.Constants.ACL_PATTERN_KEY_PERMISSIONS,
                        FlextLdifServersOid.Constants.ACL_PATTERN_KEY_FILTER,
                        FlextLdifServersOid.Constants.ACL_PATTERN_KEY_CONSTRAINT,
                    ),
                    (
                        FlextLdifServersOid.Constants.ACL_TYPE_PATTERN,
                        FlextLdifServersOid.Constants.ACL_TARGET_PATTERN,
                        FlextLdifServersOid.Constants.ACL_SUBJECT_PATTERN,
                        FlextLdifServersOid.Constants.ACL_PERMISSIONS_PATTERN,
                        FlextLdifServersOid.Constants.ACL_FILTER_PATTERN,
                        FlextLdifServersOid.Constants.ACL_CONSTRAINT_PATTERN,
                    ),
                    strict=True,
                ),
            )

        def convert_rfc_acl_to_aci(
            self,
            rfc_acl_attrs: dict[str, list[str]],
            _target_server: str,
        ) -> FlextResult[dict[str, list[str]]]:
            """Convert RFC ACL format to Oracle OID orclaci format.

            Returns RFC format unchanged (RFC ACLs are compatible with OID).

            Args:
                rfc_acl_attrs: ACL attributes in RFC format
                _target_server: Target server type (expected: "oid", unused in OID)

            Returns:
                FlextResult with RFC ACL attributes (unchanged, compatible with OID)

            """
            return FlextResult.ok(rfc_acl_attrs)

        def _write_acl(
            self,
            acl_data: FlextLdifModels.Acl,
            _format_option: str | None = None,
        ) -> FlextResult[str]:
            """Write ACL to OID orclaci format with formatting options.

            Serializes the RFC-compliant internal model to Oracle OID orclaci format string.

            Args:
                acl_data: Acl model to write
                _format_option: Formatting option (unused, OID uses standard format)

            Returns:
                FlextResult with OID orclaci formatted string

            """
            # If raw_acl is available and already in OID format, use it
            if acl_data.raw_acl and acl_data.raw_acl.startswith(
                FlextLdifServersOid.Constants.ORCLACI + ":",
            ):
                return FlextResult[str].ok(acl_data.raw_acl)

            # Build orclaci format using DRY utilities (Python 3.13: list building)
            acl_parts = [
                FlextLdifServersOid.Constants.ORCLACI + ":",
                FlextLdifServersOid.Constants.ACL_ACCESS_TO,
                FlextLdifUtilities.ACL.format_oid_target(
                    cast("FlextLdifModels.AclTarget", acl_data.target)
                    if acl_data.target
                    else None,
                ),
            ]

            # Format subject and permissions if available
            if acl_data.subject:
                # Cast to avoid mypy type checking issues (FlextLdifModels.AclSubject is alias)
                oid_subject_type_for_write = self._map_rfc_subject_to_oid(
                    cast("FlextLdifModels.AclSubject", acl_data.subject),
                    cast("FlextLdifModels.QuirkMetadata | None", acl_data.metadata),
                )

                # Prepare subject_value for OID-specific types
                subject_value = acl_data.subject.subject_value
                # Subject value should already have format "attribute#SUFFIX"
                # If it doesn't have suffix, add it
                if (
                    oid_subject_type_for_write in {"dn_attr", "guid_attr", "group_attr"}
                    and "#" not in subject_value
                ):
                    type_suffix = {
                        "dn_attr": "LDAPURL",
                        "guid_attr": "USERDN",
                        "group_attr": "GROUPDN",
                    }
                    subject_value = (
                        f"{subject_value}#{type_suffix[oid_subject_type_for_write]}"
                    )
                    # Otherwise use as-is (already has suffix)

                # Criar subject temporário com tipo OID para formatar
                oid_subject = FlextLdifModels.AclSubject(
                    subject_type=oid_subject_type_for_write,
                    subject_value=subject_value,
                )

                acl_parts.extend(
                    [
                        FlextLdifServersOid.Constants.ACL_BY,
                        FlextLdifUtilities.ACL.format_oid_subject(
                            oid_subject,
                            FlextLdifServersOid.Constants.ACL_SUBJECT_FORMATTERS,
                        ),
                        FlextLdifUtilities.ACL.format_oid_permissions(
                            acl_data.permissions,
                            FlextLdifServersOid.Constants.ACL_PERMISSION_NAMES,
                        ),
                    ],
                )

            # Add filter if present in metadata (Python 3.13: walrus operator, standardized key from constants.py)
            if (
                acl_data.metadata
                and acl_data.metadata.extensions
                and (
                    acl_filter := acl_data.metadata.extensions.get(
                        FlextLdifConstants.MetadataKeys.ACL_FILTER,
                    )
                )
            ):
                acl_parts.append(f"filter={acl_filter}")

            # Add constraint if present in metadata (Python 3.13: walrus operator, standardized key from constants.py)
            if (
                acl_data.metadata
                and acl_data.metadata.extensions
                and (
                    acl_constraint := acl_data.metadata.extensions.get(
                        FlextLdifConstants.MetadataKeys.ACL_CONSTRAINT,
                    )
                )
            ):
                acl_parts.append(f"added_object_constraint=({acl_constraint})")

            # Join parts (both formats use same join - DRY)
            orclaci_str = " ".join(acl_parts)
            return FlextResult[str].ok(orclaci_str)

        def _get_source_subject_type(
            self,
            metadata: FlextLdifModels.QuirkMetadata | None,
        ) -> str | None:
            """Get source subject type from metadata."""
            if not metadata or not metadata.extensions:
                return None

            meta_keys = FlextLdifConstants.MetadataKeys
            return cast(
                "str | None",
                metadata.extensions.get(meta_keys.ACL_SOURCE_SUBJECT_TYPE),
            )

        def _map_bind_rules_to_oid(
            self,
            rfc_subject_value: str,
            source_subject_type: str | None,
        ) -> str:
            """Map bind_rules/group to OID subject type."""
            # Check for attribute-based subject types from source metadata
            if source_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
                return source_subject_type
            # Determine if it's group_dn or user_dn based on value
            if source_subject_type in {"group_dn", "user_dn"}:
                return source_subject_type
            # OUD uses "group" as subject_type for groupdn - map to group_dn for OID
            if source_subject_type == "group":
                return "group_dn"
            if (
                "group=" in rfc_subject_value.lower()
                or "groupdn" in rfc_subject_value.lower()
            ):
                return "group_dn"
            return "user_dn"

        def _map_rfc_subject_to_oid(
            self,
            rfc_subject: FlextLdifModels.AclSubject,
            metadata: FlextLdifModels.QuirkMetadata | None,
        ) -> str:
            """Map RFC subject type to OID subject type for writing.

            Args:
                rfc_subject: RFC-compliant subject model
                metadata: ACL metadata with original OID subject type

            Returns:
                OID subject type for writing

            """
            rfc_subject_type = rfc_subject.subject_type
            rfc_subject_value = rfc_subject.subject_value

            # Read source subject type from GENERIC metadata
            source_subject_type = self._get_source_subject_type(metadata)

            # Mapear RFC → OID para write (usando GENERIC source_subject_type)
            if rfc_subject_type == "self":
                return "self"
            if rfc_subject_type == "anonymous" or rfc_subject_value == "*":
                return "*"
            # If already an attribute-based type, return as-is
            if rfc_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
                return rfc_subject_type
            # If already group_dn or user_dn (from test or conversion), return as-is
            if rfc_subject_type in {"group_dn", "user_dn"}:
                return rfc_subject_type
            if rfc_subject_type in {"bind_rules", "group"}:
                return self._map_bind_rules_to_oid(
                    rfc_subject_value,
                    source_subject_type,
                )
            return source_subject_type or "user_dn"

        def write(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL data to OID orclaci format.

            Routes to _write_acl() internally.

            Args:
                acl_data: Acl model

            Returns:
                FlextResult with OID orclaci formatted string

            """
            return self._write_acl(acl_data)

        def can_handle_attribute(
            self,
            attribute: FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """Check if this ACL quirk should be aware of a specific attribute definition."""
            _ = attribute
            return False

        def can_handle_objectclass(
            self,
            objectclass: FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Check if this ACL quirk should be aware of a specific objectClass definition."""
            _ = objectclass
            return False

    class Entry(FlextLdifServersRfc.Entry):
        """Oracle OID Entry Quirk - Transforms OID-specific boolean values to RFC format.

        Handles OID-specific entry transformations:
        - Converts boolean attribute values from OID format ("0"/"1") to RFC format ("TRUE"/"FALSE")
        - Stores conversion metadata for audit
        - Converts OID-specific attribute names to RFC-canonical format (orclaci → aci)
        """

        def _normalize_attribute_name(self, attr_name: str) -> str:
            """Normalize OID attribute names to RFC-canonical format.

            Converts Oracle OID-specific attribute names to RFC standard equivalents.
            This transformation happens during the PARSING phase (Phase 1) to create
            RFC-canonical entries that can be processed uniformly by downstream logic.

            Transformations:
            - orclaci → aci: OID access control list to RFC ACI
            - orclentrylevelaci → aci: OID entry-level ACL to RFC ACI

            All other attributes are delegated to the RFC base implementation for
            standard normalization (e.g., objectclass → objectClass).

            Args:
                attr_name: Raw attribute name from LDIF

            Returns:
                RFC-canonical attribute name

            """
            # Python 3.13 match/case: Optimize ACL attribute normalization (DRY)
            match attr_name.lower():
                case attr_lower if attr_lower in {
                    FlextLdifServersOid.Constants.ORCLACI.lower(),
                    FlextLdifServersOid.Constants.ORCLENTRYLEVELACI.lower(),
                }:
                    # Oracle OID ACL attributes → RFC standard ACI
                    return FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME
                case _:
                    # Delegate to RFC for standard normalization (objectclass, etc.)
                    return super()._normalize_attribute_name(attr_name)

        def _convert_boolean_attributes_to_rfc(
            self,
            entry_attributes: dict[str, list[str]],
        ) -> tuple[
            dict[str, list[str]],
            set[str],
            dict[str, dict[str, list[str] | str]],
        ]:
            """Convert OID boolean attribute values to RFC format.

            OID uses "0"/"1" for boolean values, RFC4517 requires "TRUE"/"FALSE".
            Uses utilities.py for conversion (DRY principle).

            Args:
                entry_attributes: Entry attributes mapping

            Returns:
                Tuple of (converted_attributes, converted_attrs_set, boolean_conversions)

            """
            boolean_attributes = FlextLdifServersOid.Constants.BOOLEAN_ATTRIBUTES
            boolean_attr_names = {attr.lower() for attr in boolean_attributes}

            # Use utilities.py for conversion (OID→RFC: "0/1" → "TRUE/FALSE")
            # Cast to match utilities signature (accepts dict[str, list[str] | list[bytes] | bytes | str])
            converted_attributes = FlextLdifUtilities.Entry.convert_boolean_attributes(
                cast(
                    "dict[str, list[str] | list[bytes] | bytes | str]",
                    entry_attributes,
                ),
                boolean_attr_names,
                source_format="0/1",
                target_format="TRUE/FALSE",
            )

            # Track conversions for metadata
            converted_attrs: set[str] = set()
            boolean_conversions: dict[str, dict[str, list[str] | str]] = {}

            for attr_name, attr_values in entry_attributes.items():
                if attr_name.lower() in boolean_attr_names:
                    original_values = list(attr_values)
                    converted_values = converted_attributes.get(
                        attr_name,
                        original_values,
                    )

                    if converted_values != original_values:
                        converted_attrs.add(attr_name)
                        # CRITICAL: Track conversion with complete details for perfect round-trip
                        boolean_conversions[attr_name] = {
                            "original": original_values,
                            "converted": converted_values,
                            "conversion_type": "boolean_oid_to_rfc",
                            "original_format": "0/1",
                            "converted_format": "TRUE/FALSE",
                        }
                        logger.debug(
                            "Converted boolean attribute OID→RFC",
                            attribute_name=attr_name,
                        )

            return converted_attributes, converted_attrs, boolean_conversions

        def _detect_entry_acl_transformations(
            self,
            entry_attrs: Mapping[str, object],
            converted_attributes: dict[str, list[str]],
        ) -> dict[str, FlextLdifModels.AttributeTransformation]:
            """Detect ACL attribute transformations (orclaci→aci).

            Args:
                entry_attrs: Original raw attributes from LDIF
                converted_attributes: Converted attributes mapping

            Returns:
                Dictionary of ACL transformations

            """
            # Python 3.13: Dict comprehension for original_attr_names mapping
            original_attr_names: dict[str, str] = {
                normalized.lower(): str(raw_attr_name)
                for raw_attr_name in entry_attrs
                if (
                    normalized := self._normalize_attribute_name(str(raw_attr_name))
                ).lower()
                != str(raw_attr_name).lower()
            }

            # Python 3.13: Dict comprehension for ACL transformations
            acl_transformations: dict[str, FlextLdifModels.AttributeTransformation] = {
                original_name: FlextLdifModels.AttributeTransformation(
                    original_name=original_name,
                    target_name=attr_name,
                    original_values=attr_values,
                    target_values=attr_values,
                    transformation_type="renamed",
                    reason=f"OID proprietary ACL ({original_name}) → RFC 2256 standard (aci)",
                )
                for attr_name, attr_values in converted_attributes.items()
                if attr_name.lower() in original_attr_names
                and (original_name := original_attr_names[attr_name.lower()]).lower()
                in {"orclaci", "orclentrylevelaci"}
            }

            return acl_transformations

        def _detect_rfc_violations(
            self,
            converted_attributes: dict[str, list[str]],
        ) -> tuple[list[str], list[dict[str, object]]]:
            """Detect RFC compliance violations in entry.

            Args:
                converted_attributes: Entry attributes

            Returns:
                Tuple of (rfc_violations, attribute_conflicts)

            """
            object_classes = converted_attributes.get("objectClass", [])
            object_classes_lower = {oc.lower() for oc in object_classes}

            # Python 3.13: Set operations and list comprehensions
            structural_classes = {
                "domain",
                "organization",
                "organizationalunit",
                "person",
                "groupofuniquenames",
                "groupofnames",
                "orclsubscriber",
                "orclgroup",
                "customsistemas",
                "customuser",
            }
            found_structural = object_classes_lower & structural_classes

            rfc_violations: list[str] = (
                [
                    f"Multiple structural objectClasses: {', '.join(sorted(found_structural))}",
                ]
                if len(found_structural) > 1
                else []
            )

            # Python 3.13: List comprehension for attribute conflicts
            domain_invalid_attrs = {
                "cn",
                "uniquemember",
                "member",
                "orclsubscriberfullname",
                "orclversion",
                "orclgroupcreatedate",
            }
            attribute_conflicts: list[dict[str, object]] = [
                {
                    "attribute": attr_name,
                    "values": converted_attributes[attr_name],
                    "reason": f"Attribute '{attr_name}' not allowed by RFC 4519 domain objectClass",
                    "conflicting_objectclass": "domain",
                }
                for attr_name in converted_attributes
                if "domain" in object_classes_lower
                and attr_name.lower() in domain_invalid_attrs
            ]

            return rfc_violations, attribute_conflicts

        def normalize_schema_strings_inline(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Normalize schema attribute strings inline (attributetypes, objectclasses, etc.).

            Applies OID-specific normalizations to schema definition strings stored
            as attribute values. This fixes typos and normalizes matching rules
            in schema entries before they are parsed into SchemaAttribute/SchemaObjectClass models.

            Normalizations applied:
            - Matching rule typos: caseIgnoreSubStringsMatch → caseIgnoreSubstringsMatch
            - Other OID proprietary → RFC 4517 standard mappings

            Args:
                entry: Entry with potential schema attributes to normalize

            Returns:
                Entry with normalized schema attribute strings

            """
            if not entry.attributes:
                return entry

            # Schema attribute names (case-insensitive)
            schema_attrs = {
                FlextLdifServersOid.Constants.SCHEMA_FIELD_ATTRIBUTE_TYPES.lower(),
                FlextLdifServersOid.Constants.SCHEMA_FIELD_OBJECT_CLASSES.lower(),
                FlextLdifServersOid.Constants.SCHEMA_FIELD_MATCHING_RULES.lower(),
                FlextLdifServersOid.Constants.SCHEMA_FIELD_LDAP_SYNTAXES.lower(),
            }

            # Check if entry has schema attributes (Python 3.13: early return)
            if not any(
                attr_name.lower() in schema_attrs
                for attr_name in entry.attributes.attributes
            ):
                return entry

            # Get matching rule replacements from constants (DRY: Python 3.13)
            replacements = FlextLdifServersOid.Constants.MATCHING_RULE_TO_RFC

            # Normalize schema attribute values (DRY: Python 3.13 optimized)
            # Python 3.13: Dict comprehension with conditional
            new_attributes: dict[str, list[str]] = {
                attr_name: (
                    [
                        reduce(
                            lambda val, pair: val.replace(pair[0], pair[1]),
                            replacements.items(),
                            value,
                        )
                        for value in attr_values
                    ]
                    if attr_name.lower() in schema_attrs
                    else attr_values
                )
                for attr_name, attr_values in entry.attributes.attributes.items()
            }

            # Only create new entry if attributes changed
            if new_attributes == entry.attributes.attributes:
                return entry

            return entry.model_copy(
                update={
                    "attributes": FlextLdifModels.LdifAttributes(
                        attributes=new_attributes,
                    ),
                },
            )

        def _denormalize_attribute_name(self, attr_name: str) -> str:
            """Denormalize RFC attribute names to OID format.

            Converts RFC-canonical attribute names back to OID-specific format.
            This transformation happens during the WRITING phase (Phase 2) to convert
            RFC-canonical entries back to OID format for output.

            Transformations:
            - aci → orclaci: RFC ACI to Oracle OID ACL
            - (aci was normalized from orclaci during parsing)

            All other attributes are delegated to the RFC base implementation.

            Args:
                attr_name: RFC-canonical attribute name

            Returns:
                OID-specific attribute name

            """
            # Python 3.13 match/case: Optimize ACL attribute denormalization (DRY)
            match attr_name.lower():
                case attr_lower if (
                    attr_lower
                    == FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME.lower()
                ):
                    # RFC standard ACI → Oracle OID ACL
                    return FlextLdifServersOid.Constants.ORCLACI
                case _:
                    # Delegate to RFC for standard handling (no denormalization needed)
                    return attr_name

        def _convert_boolean_attributes_to_oid(
            self,
            entry_attributes: dict[str, list[str]],
        ) -> dict[str, list[str]]:
            """Convert RFC boolean attribute values to OID format.

            RFC4517 uses "TRUE"/"FALSE" for boolean values, OID requires "0"/"1".
            Uses utilities.py for conversion (DRY principle).

            Args:
                entry_attributes: Entry attributes mapping (in RFC format)

            Returns:
                Converted attributes mapping (in OID format)

            """
            boolean_attributes = FlextLdifServersOid.Constants.BOOLEAN_ATTRIBUTES
            boolean_attr_names = {attr.lower() for attr in boolean_attributes}

            # Use utilities.py for conversion (RFC→OID: "TRUE/FALSE" → "0/1")
            # Cast to match utilities signature (accepts dict[str, list[str] | list[bytes] | bytes | str])
            return FlextLdifUtilities.Entry.convert_boolean_attributes(
                cast(
                    "dict[str, list[str] | list[bytes] | bytes | str]",
                    entry_attributes,
                ),
                boolean_attr_names,
                source_format="TRUE/FALSE",
                target_format="0/1",
            )

        # ===== _write_entry HELPER METHODS (DRY refactoring) =====

        def _restore_oid_boolean_values(
            self,
            attributes: dict[str, list[str]],
            metadata: FlextLdifModels.QuirkMetadata | None,
        ) -> dict[str, list[str]]:
            """Restore original OID boolean values from metadata.

            Args:
                attributes: Current attributes
                metadata: Entry metadata with boolean conversions

            Returns:
                Attributes with restored boolean values

            """
            if not (metadata and metadata.boolean_conversions):
                return attributes

            restored_attrs = dict(attributes)
            for attr_name, conversion in metadata.boolean_conversions.items():
                if attr_name in restored_attrs:
                    original_val = conversion.get("original", "")
                    if original_val:
                        restored_attrs[attr_name] = [original_val]
                        logger.debug(
                            "Restored original OID boolean value from metadata",
                            attribute_name=attr_name,
                        )
            return restored_attrs

        def _denormalize_oid_attributes(
            self,
            oid_attributes: dict[str, list[str]],
            metadata: FlextLdifModels.QuirkMetadata | None,
        ) -> dict[str, list[str]]:
            """Denormalize attributes from RFC to OID format.

            Args:
                oid_attributes: Attributes with OID boolean format
                metadata: Entry metadata with original attributes

            Returns:
                Denormalized attributes with original names restored

            """
            original_attrs = None
            if metadata and metadata.extensions:
                original_attrs = metadata.extensions.get("original_attributes_complete")

            denormalized: dict[str, list[str]] = {}
            for attr_name, attr_values in oid_attributes.items():
                if original_attrs and FlextRuntime.is_dict_like(original_attrs):
                    # Try to find original attribute name
                    for orig_name, orig_values in original_attrs.items():
                        if self._normalize_attribute_name(str(orig_name)) == attr_name:
                            denormalized[str(orig_name)] = cast(
                                "list[str]",
                                orig_values
                                if FlextRuntime.is_list_like(orig_values)
                                else [str(orig_values)],
                            )
                            break
                    else:
                        denormalized[self._denormalize_attribute_name(attr_name)] = (
                            attr_values
                        )
                else:
                    denormalized[self._denormalize_attribute_name(attr_name)] = (
                        attr_values
                    )
            return denormalized

        def _restore_oid_original_dn(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextLdifModels.DistinguishedName:
            """Restore original OID DN from metadata.

            Args:
                entry_data: Entry with metadata

            Returns:
                Original or denormalized DN

            """
            meta_keys = FlextLdifConstants.MetadataKeys
            # Ensure we use the correct type from models.py
            oid_dn = (
                FlextLdifModels.DistinguishedName(value=entry_data.dn.value)
                if entry_data.dn
                else FlextLdifModels.DistinguishedName(value="")
            )

            if entry_data.metadata and entry_data.metadata.extensions:
                original_dn = entry_data.metadata.extensions.get("original_dn_complete")
                if original_dn and isinstance(original_dn, str):
                    oid_dn = FlextLdifModels.DistinguishedName(value=original_dn)
                else:
                    source_dn = entry_data.metadata.extensions.get(
                        meta_keys.ENTRY_SOURCE_DN_CASE,
                    )
                    if source_dn:
                        oid_dn = FlextLdifModels.DistinguishedName(
                            value=cast("str", source_dn),
                        )

            # Denormalize schema DN if needed
            if (
                entry_data.dn
                and entry_data.dn.value.lower()
                == FlextLdifServersRfc.Constants.SCHEMA_DN.lower()
            ):
                oid_dn = FlextLdifModels.DistinguishedName(
                    value=FlextLdifServersOid.Constants.SCHEMA_DN_QUIRK,
                )

            return oid_dn

        def _write_entry(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[str]:
            """Write Entry model to OID LDIF format.

            CRITICAL: Uses metadata to restore original OID formatting for perfect round-trip.
            Restores DN, attributes, boolean values, case, spacing, punctuation, etc. from metadata.

            Converts Entry model (stored in RFC format) to OID LDIF format.
            This method performs RFC→OID conversions:
            - Boolean attributes: "TRUE"/"FALSE" → "0"/"1" (restored from metadata)
            - ACL attribute name: "aci" → "orclaci" (restored from metadata)

            Args:
                entry_data: Entry model (in RFC format with complete metadata)

            Returns:
                FlextResult with OID-formatted LDIF string (with original formatting restored when possible)

            """
            if not entry_data.attributes:
                # No attributes - delegate to RFC writer
                return super()._write_entry(entry_data)

            logger.debug(
                "Writing OID entry",
                entry_dn=entry_data.dn.value[:50] if entry_data.dn else None,
            )

            # Restore original boolean values using helper (DRY refactoring)
            # Convert metadata to correct type from models.py if needed
            metadata = (
                entry_data.metadata
                if isinstance(entry_data.metadata, FlextLdifModels.QuirkMetadata)
                else None
            )
            attributes_to_convert = self._restore_oid_boolean_values(
                entry_data.attributes.attributes,
                metadata,
            )

            # Convert boolean attributes RFC→OID
            oid_attributes = self._convert_boolean_attributes_to_oid(
                attributes_to_convert,
            )

            # Denormalize attributes using helper (DRY refactoring)
            denormalized_attributes = self._denormalize_oid_attributes(
                oid_attributes,
                metadata,
            )

            # Restore original DN using helper (DRY refactoring)
            oid_dn = self._restore_oid_original_dn(entry_data)

            # Create entry copy with OID-formatted attributes and DN
            oid_entry = entry_data.model_copy(
                update={
                    "dn": oid_dn,
                    "attributes": FlextLdifModels.LdifAttributes(
                        attributes=denormalized_attributes,
                    ),
                },
            )

            # Delegate to RFC writer (which handles LDIF formatting)
            return super()._write_entry(oid_entry)

        # =====================================================================
        # METADATA BUILDER HELPERS (DRY refactoring)
        # =====================================================================

        def _build_conversion_metadata(
            self,
            cleaned_dn: str,
            converted_attrs: set[str],
            boolean_conversions: dict[str, dict[str, list[str] | str]],
        ) -> dict[str, object]:
            """Build boolean conversion metadata."""
            if not converted_attrs:
                return {}
            logger.debug(
                "Converted OID boolean attributes to RFC format",
                entry_dn=cleaned_dn,
                attributes_count=len(converted_attrs),
                attributes=list(converted_attrs),
                conversions=boolean_conversions,
            )
            return {"boolean_attributes_converted": list(converted_attrs)}

        def _build_dn_metadata(
            self,
            original_dn: str,
            cleaned_dn: str,
            dn_stats: FlextLdifModels.DNStatistics,
        ) -> dict[str, object]:
            """Build DN cleaning metadata."""
            if original_dn == cleaned_dn:
                return {}
            logger.debug(
                "Cleaned OID DN quirks",
                original_dn=original_dn,
                cleaned_dn=cleaned_dn,
                transformations=dn_stats.transformations,
                had_tab_chars=dn_stats.had_tab_chars,
                had_extra_spaces=dn_stats.had_extra_spaces,
                had_utf8_chars=dn_stats.had_utf8_chars,
                had_escape_sequences=dn_stats.had_escape_sequences,
                validation_status=dn_stats.validation_status,
                validation_warnings=dn_stats.validation_warnings or None,
                validation_errors=dn_stats.validation_errors or None,
            )
            return {
                "original_dn": original_dn,
                "cleaned_dn": cleaned_dn,
                "dn_was_cleaned": True,
            }

        def _build_generic_metadata(
            self,
            original_dn: str,
            cleaned_dn: str,
            converted_attrs: set[str],
            boolean_conversions: dict[str, dict[str, list[str] | str]],
            converted_attributes: dict[str, list[str]],
            original_entry: FlextLdifModels.Entry,
        ) -> dict[str, object]:
            """Build generic metadata for bidirectional conversion."""
            meta_keys = FlextLdifConstants.MetadataKeys
            return {
                meta_keys.ENTRY_SOURCE_SERVER: "oid",
                meta_keys.ENTRY_ORIGINAL_FORMAT: f"OID Entry with {len(converted_attrs)} boolean conversions",
                meta_keys.ENTRY_SOURCE_DN_CASE: original_dn,
                meta_keys.ENTRY_SOURCE_ATTRIBUTES: list(
                    original_entry.attributes.attributes.keys(),
                )
                if original_entry.attributes
                else [],
                meta_keys.ENTRY_SOURCE_OBJECTCLASSES: original_entry.attributes.attributes.get(
                    "objectClass",
                    [],
                )
                if original_entry.attributes
                else [],
                meta_keys.ENTRY_TARGET_DN_CASE: cleaned_dn,
                meta_keys.ENTRY_TARGET_ATTRIBUTES: list(converted_attributes.keys()),
                meta_keys.ENTRY_TARGET_OBJECTCLASSES: converted_attributes.get(
                    "objectClass",
                    [],
                ),
                meta_keys.ENTRY_SOURCE_OPERATIONAL_ATTRS: [
                    attr
                    for attr in (
                        original_entry.attributes.attributes.keys()
                        if original_entry.attributes
                        else []
                    )
                    if attr.lower()
                    in {
                        a.lower()
                        for a in FlextLdifServersOid.Constants.OPERATIONAL_ATTRIBUTES
                    }
                ],
                meta_keys.CONVERTED_ATTRIBUTES: {
                    "boolean_conversions": boolean_conversions,
                    "attribute_name_conversions": {"orclaci": "aci"}
                    if "aci" in converted_attributes
                    and "orclaci"
                    in (
                        original_entry.attributes.attributes.keys()
                        if original_entry.attributes
                        else []
                    )
                    else {},
                },
            }

        def _build_original_format_details(
            self,
            original_dn: str,
            cleaned_dn: str,
            converted_attrs: set[str],
            boolean_conversions: dict[str, dict[str, list[str] | str]],
            converted_attributes: dict[str, list[str]],
            original_entry: FlextLdifModels.Entry,
        ) -> dict[str, object]:
            """Build original format details for round-trip support."""
            # Preserve original lines from RFC parser
            original_dn_line = None
            original_attr_lines: list[str] = []
            if (
                original_entry.metadata
                and original_entry.metadata.original_format_details
            ):
                original_dn_line = original_entry.metadata.original_format_details.get(
                    "original_dn_line",
                )
                orig_attr_lines = original_entry.metadata.original_format_details.get(
                    "original_attr_lines",
                    [],
                )
                if FlextRuntime.is_list_like(orig_attr_lines):
                    original_attr_lines = cast("list[str]", orig_attr_lines)

            return {
                "dn_spacing": original_dn,
                "dn_cleaned": cleaned_dn,
                "dn_was_modified": original_dn != cleaned_dn,
                "boolean_format": "0/1" if boolean_conversions else "RFC",
                "server_type": "oid",
                "original_dn_line": original_dn_line,
                "original_attr_lines": original_attr_lines,
                "original_attributes_dict": {
                    k: list(v)
                    if isinstance(v, (list, tuple))
                    else [str(v)]
                    if v is not None
                    else []
                    for k, v in (
                        original_entry.attributes.attributes.items()
                        if original_entry.attributes
                        else {}
                    )
                },
                "converted_attributes_dict": converted_attributes,
                "all_conversions": {
                    "boolean_attributes": list(converted_attrs),
                    "boolean_conversions": boolean_conversions,
                    "attribute_name_conversions": {
                        "orclaci": "aci"
                        if "aci" in converted_attributes
                        and "orclaci"
                        in (
                            original_entry.attributes.attributes.keys()
                            if original_entry.attributes
                            else []
                        )
                        else None,
                    },
                },
                "removed_attributes": [],
                "removed_attributes_count": 0,
            }

        def _create_entry_result_with_metadata(
            self,
            _entry: FlextLdifModels.Entry,  # Unused: kept for signature
            cleaned_dn: str,
            original_dn: str,
            dn_stats: FlextLdifModels.DNStatistics,
            converted_attrs: set[str],
            boolean_conversions: dict[str, dict[str, list[str] | str]],
            acl_transformations: dict[str, FlextLdifModels.AttributeTransformation],
            rfc_violations: list[str],
            attribute_conflicts: list[dict[str, object]],
            converted_attributes: dict[str, list[str]],
            original_entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Create entry result with complete metadata.

            Args:
                _entry: Base RFC entry (unused - kept for signature)
                cleaned_dn: Cleaned DN
                original_dn: Original DN
                dn_stats: DN cleaning statistics
                converted_attrs: Set of converted boolean attributes
                boolean_conversions: Boolean conversion details
                acl_transformations: ACL transformations
                rfc_violations: RFC violations list
                attribute_conflicts: Attribute conflicts list
                converted_attributes: Converted attributes mapping
                original_entry: Original entry before conversions

            Returns:
                FlextResult with Entry including metadata

            """
            # Build metadata using helper methods (DRY refactoring)
            conversion_metadata = self._build_conversion_metadata(
                cleaned_dn,
                converted_attrs,
                boolean_conversions,
            )
            dn_metadata = self._build_dn_metadata(original_dn, cleaned_dn, dn_stats)

            # Build RFC compliance metadata using helper (DRY refactoring)
            rfc_compliance_metadata = self._build_rfc_compliance_metadata(
                rfc_violations,
                attribute_conflicts,
                boolean_conversions,
                converted_attributes,
                original_entry,
                cleaned_dn,
            )

            # Build generic metadata using helper
            generic_metadata = self._build_generic_metadata(
                original_dn,
                cleaned_dn,
                converted_attrs,
                boolean_conversions,
                converted_attributes,
                original_entry,
            )

            # Merge extensions from original_entry.metadata if it exists
            original_extensions: dict[str, object] = {}
            if original_entry.metadata and original_entry.metadata.extensions:
                original_extensions = original_entry.metadata.extensions.copy()

            # Create metadata using domain class, then ensure correct type from models.py
            domain_metadata = FlextLdifModels.QuirkMetadata.create_for(
                self._get_server_type(),
                extensions={
                    **conversion_metadata,
                    **dn_metadata,
                    **rfc_compliance_metadata,
                    **generic_metadata,  # Add GENERIC metadata
                    **original_extensions,  # Include original extensions (original_dn_complete, etc.)
                    "original_entry": original_entry,
                },
            )
            # Convert to models.py type (QuirkMetadata in models.py inherits from domain)
            metadata = FlextLdifModels.QuirkMetadata.model_validate(
                domain_metadata.model_dump(),
            )

            # =====================================================================
            # ZERO DATA LOSS: Populate dedicated metadata fields for round-trip
            # =====================================================================

            # Track boolean conversions using helper (DRY refactoring)
            self._track_boolean_conversions_in_metadata(metadata, boolean_conversions)

            # Build original_format_details using helper
            metadata.original_format_details = self._build_original_format_details(
                original_dn,
                cleaned_dn,
                converted_attrs,
                boolean_conversions,
                converted_attributes,
                original_entry,
            )

            # Track schema quirk if schema DN was normalized
            if (
                original_dn != cleaned_dn
                and original_dn.lower()
                == FlextLdifServersOid.Constants.SCHEMA_DN_QUIRK.lower()
            ):
                metadata.schema_quirks_applied.append("schema_dn_normalization")

            # Add ACL transformations
            if acl_transformations:
                metadata.attribute_transformations.update(acl_transformations)

            # Create final Entry (use cleaned_dn which is normalized_dn at this point)
            # Use converted_attributes parameter (which contains normalized_attributes with RFC names)
            ldif_attrs = FlextLdifModels.LdifAttributes(attributes=converted_attributes)
            entry_with_conversions = FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value=cleaned_dn),
                attributes=ldif_attrs,
                metadata=metadata,
            )

            return FlextResult[FlextLdifModels.Entry].ok(entry_with_conversions)

        # ===== _create_entry_result_with_metadata HELPER METHODS (DRY refactoring) =====

        def _build_rfc_compliance_metadata(
            self,
            rfc_violations: list[str],
            attribute_conflicts: list[dict[str, object]],
            boolean_conversions: dict[str, dict[str, list[str] | str]],
            converted_attributes: dict[str, list[str]],
            original_entry: FlextLdifModels.Entry,
            cleaned_dn: str,
        ) -> dict[str, object]:
            """Build RFC compliance metadata with violation details.

            Args:
                rfc_violations: List of RFC violations
                attribute_conflicts: List of attribute conflicts
                boolean_conversions: Boolean conversion details
                converted_attributes: Converted attributes mapping
                original_entry: Original entry before conversions
                cleaned_dn: Cleaned DN for logging

            Returns:
                RFC compliance metadata dictionary

            """
            if not (rfc_violations or attribute_conflicts or boolean_conversions):
                return {}

            rfc_compliance_metadata: dict[str, object] = {
                "rfc_violations": rfc_violations,
                "attribute_conflicts": attribute_conflicts,
                "has_rfc_violations": True,
                "attribute_value_changes": boolean_conversions or {},
                "attribute_value_changes_count": len(boolean_conversions),
            }

            if rfc_violations or attribute_conflicts:
                # Build detailed violation information
                violation_details: list[dict[str, object]] = [
                    {
                        "type": "rfc_violation",
                        "description": violation,
                        "severity": "warning",
                    }
                    for violation in rfc_violations
                ]

                for conflict in attribute_conflicts:
                    attr_name = str(conflict.get("attribute", "unknown"))
                    original_values = (
                        original_entry.attributes.attributes.get(attr_name, [])
                        if original_entry.attributes
                        else []
                    )
                    conflict_values = conflict.get("values", [])
                    was_removed = attr_name not in converted_attributes

                    violation_details.append(
                        {
                            "type": "attribute_conflict",
                            "attribute": attr_name,
                            "reason": str(conflict.get("reason", "Unknown conflict")),
                            "conflicting_objectclass": str(
                                conflict.get("conflicting_objectclass", ""),
                            ),
                            "original_values": original_values,
                            "conflict_values": conflict_values,
                            "was_removed": was_removed,
                            "action_taken": "removed"
                            if was_removed
                            else "kept_with_warning",
                            "original_values_string": str(original_values),
                            "conflict_values_string": str(conflict_values),
                        },
                    )

                # Calculate attribute changes for logging
                original_attr_set = set(
                    original_entry.attributes.attributes.keys()
                    if original_entry.attributes
                    else [],
                )
                final_attr_set = set(converted_attributes.keys())
                removed_attrs = list(original_attr_set - final_attr_set)

                logger.debug(
                    "OID entry converted with RFC adjustments",
                    entry_dn=cleaned_dn,
                    violations_count=len(rfc_violations),
                    violations=rfc_violations or None,
                    attributes_removed=removed_attrs or None,
                    boolean_conversions=len(boolean_conversions),
                )

            return rfc_compliance_metadata

        def _track_boolean_conversions_in_metadata(
            self,
            metadata: FlextLdifModels.QuirkMetadata,
            boolean_conversions: dict[str, dict[str, list[str] | str]],
        ) -> None:
            """Track boolean conversions in metadata for round-trip support.

            Args:
                metadata: QuirkMetadata to update
                boolean_conversions: Boolean conversion details

            """
            if not boolean_conversions:
                return

            for attr_name, conv_data in boolean_conversions.items():
                original_vals = conv_data.get("original", [])
                converted_vals = conv_data.get("converted", [])

                if original_vals and converted_vals:
                    original_val = (
                        original_vals[0]
                        if len(original_vals) == 1
                        else str(original_vals)
                    )
                    converted_val = (
                        converted_vals[0]
                        if len(converted_vals) == 1
                        else str(converted_vals)
                    )

                    FlextLdifUtilities.Metadata.track_boolean_conversion(
                        metadata=metadata,
                        attr_name=attr_name,
                        original_value=original_val,
                        converted_value=converted_val,
                        format_direction="OID->RFC",
                    )

                    logger.debug(
                        "Boolean conversion tracked in metadata",
                        operation="_create_entry_result_with_metadata",
                        attribute_name=attr_name,
                        original_value=original_val,
                        converted_value=converted_val,
                    )

        # ===== _parse_entry HELPER METHODS (DRY refactoring) =====

        def _analyze_oid_entry_differences(
            self,
            entry_attrs: Mapping[str, object],
            normalized_attributes: dict[str, list[str]],
            original_dn: str,
            normalized_dn: str,
        ) -> tuple[dict[str, object], dict[str, dict[str, object]], dict[str, object]]:
            """Analyze DN and attribute differences for OID entries.

            Args:
                entry_attrs: Original raw attributes
                normalized_attributes: Normalized attributes after conversion
                original_dn: Original DN string
                normalized_dn: Normalized DN after cleaning

            Returns:
                Tuple of (dn_differences, attribute_differences, original_attrs_complete)

            """
            # Analyze DN differences
            dn_differences = FlextLdifUtilities.Metadata.analyze_minimal_differences(
                original=original_dn,
                converted=normalized_dn if normalized_dn != original_dn else None,
                context="dn",
            )

            # Analyze attribute differences
            attribute_differences: dict[str, dict[str, object]] = {}
            original_attributes_complete: dict[str, object] = {}

            for attr_name, attr_values in entry_attrs.items():
                original_attr_name = str(attr_name)
                normalized_name = self._normalize_attribute_name(original_attr_name)

                # Preserve original values
                original_values = (
                    list(attr_values)
                    if isinstance(attr_values, (list, tuple))
                    else [attr_values]
                    if attr_values is not None
                    else []
                )
                original_attributes_complete[original_attr_name] = original_values

                converted_values = normalized_attributes.get(normalized_name, [])

                # Build string representations
                original_str = f"{original_attr_name}: {', '.join(str(v) for v in original_values)}"
                converted_str = (
                    f"{normalized_name}: {', '.join(str(v) for v in converted_values)}"
                    if converted_values
                    else None
                )

                # Analyze differences
                attr_diff = FlextLdifUtilities.Metadata.analyze_minimal_differences(
                    original=original_str,
                    converted=converted_str if converted_str != original_str else None,
                    context="attribute",
                )
                attribute_differences[normalized_name] = attr_diff

            return dn_differences, attribute_differences, original_attributes_complete

        def _store_oid_minimal_differences(
            self,
            metadata: FlextLdifModels.QuirkMetadata,
            dn_differences: dict[str, object],
            attribute_differences: dict[str, dict[str, object]],
            original_dn: str,
            normalized_dn: str,
            original_attributes_complete: dict[str, object],
            original_dn_line: str | None = None,
            original_attr_lines: list[str] | None = None,
        ) -> None:
            """Store minimal differences in OID entry metadata.

            Args:
                metadata: QuirkMetadata to update
                dn_differences: DN difference analysis
                attribute_differences: Attribute difference analysis
                original_dn: Original DN string
                normalized_dn: Normalized DN string
                original_attributes_complete: Complete original attributes
                original_dn_line: Original DN line from LDIF (optional)
                original_attr_lines: Original attribute lines from LDIF (optional)

            """
            if not metadata.extensions:
                metadata.extensions = {}

            # Store in extensions
            metadata.extensions["minimal_differences_dn"] = dn_differences
            metadata.extensions["minimal_differences_attributes"] = (
                attribute_differences
            )
            metadata.extensions["original_dn_complete"] = original_dn
            metadata.extensions["original_attributes_complete"] = (
                original_attributes_complete
            )
            # Store original lines if provided
            if original_dn_line is not None:
                metadata.extensions["original_dn_line_complete"] = original_dn_line
            if original_attr_lines is not None:
                metadata.extensions["original_attr_lines_complete"] = (
                    original_attr_lines
                )

            # Track DN differences
            if dn_differences.get("has_differences"):
                FlextLdifUtilities.Metadata.track_minimal_differences_in_metadata(
                    metadata=metadata,
                    original=original_dn,
                    converted=normalized_dn if normalized_dn != original_dn else None,
                    context="dn",
                    attribute_name="dn",
                )

            # Track attribute differences
            for attr_name, attr_diff in attribute_differences.items():
                if attr_diff.get("has_differences", False):
                    original_attr_str = attr_diff.get("original", "")
                    converted = attr_diff.get("converted")
                    converted_attr_str = str(converted) if converted else None
                    if isinstance(original_attr_str, str):
                        FlextLdifUtilities.Metadata.track_minimal_differences_in_metadata(
                            metadata=metadata,
                            original=original_attr_str,
                            converted=converted_attr_str,
                            context="attribute",
                            attribute_name=attr_name,
                        )

        def _parse_entry(
            self,
            entry_dn: str,
            entry_attrs: Mapping[str, object],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Parse OID entry and convert boolean attributes to RFC format.

            Args:
                entry_dn: Entry distinguished name
                entry_attrs: Raw attribute mapping from LDIF parser

            Returns:
                FlextResult with Entry model with conversions applied

            """
            original_dn = entry_dn
            cleaned_dn, dn_stats = FlextLdifUtilities.DN.clean_dn_with_statistics(
                entry_dn,
            )

            # Normalize OID schema DN to RFC format (OID → RFC conversion)
            # OID uses "cn=subschemasubentry", RFC uses "cn=schema"
            normalized_dn = cleaned_dn
            if (
                cleaned_dn.lower()
                == FlextLdifServersOid.Constants.SCHEMA_DN_QUIRK.lower()
            ):
                normalized_dn = FlextLdifServersRfc.Constants.SCHEMA_DN
                logger.debug(
                    "OID→RFC transform: Normalizing schema DN",
                    original_dn=cleaned_dn,
                    normalized_dn=normalized_dn,
                )

            result = super()._parse_entry(normalized_dn, entry_attrs)
            if result.is_failure:
                logger.debug(
                    "OID parser rejected entry",
                    original_dn=original_dn[: FlextLdifConstants.DN_TRUNCATE_LENGTH],
                )
                return result

            entry = result.unwrap()
            original_entry = entry.model_copy(deep=True)

            # ZERO DATA LOSS: Preserve original lines from RFC parser
            # RFC parser already captured original_dn_line and original_attr_lines
            # These are stored in metadata.original_format_details for round-trip support
            # Access via: entry.metadata.original_format_details.get("original_dn_line")
            # Access via: entry.metadata.original_format_details.get("original_attr_lines", [])

            if not entry.attributes or not entry.dn:
                return result

            # Apply OID-specific conversions
            # Step 1: Convert boolean attributes OID → RFC
            converted_attributes, converted_attrs, boolean_conversions = (
                self._convert_boolean_attributes_to_rfc(entry.attributes.attributes)
            )

            # Step 2: Normalize attribute names OID → RFC (orclaci → aci)
            normalized_attributes: dict[str, list[str]] = {}
            for attr_name, attr_values in converted_attributes.items():
                normalized_name = self._normalize_attribute_name(attr_name)
                normalized_attributes[normalized_name] = attr_values

            # Step 3: Detect ACL transformations for metadata
            acl_transformations = self._detect_entry_acl_transformations(
                entry_attrs,
                normalized_attributes,
            )

            rfc_violations, attribute_conflicts = self._detect_rfc_violations(
                normalized_attributes,
            )

            # Analyze differences using helper (DRY refactoring)
            dn_differences, attribute_differences, original_attributes_complete_dict = (
                self._analyze_oid_entry_differences(
                    entry_attrs,
                    normalized_attributes,
                    original_dn,
                    normalized_dn,
                )
            )

            # Store minimal differences using helper (DRY refactoring)
            if not original_entry.metadata:
                domain_metadata = FlextLdifModels.QuirkMetadata.create_for(
                    self._get_server_type(),
                    extensions={},
                )
                original_entry.metadata = FlextLdifModels.QuirkMetadata.model_validate(
                    domain_metadata.model_dump(),
                )
            # Ensure metadata is the correct type from models.py
            entry_metadata = (
                original_entry.metadata
                if isinstance(original_entry.metadata, FlextLdifModels.QuirkMetadata)
                else (
                    FlextLdifModels.QuirkMetadata.model_validate(
                        original_entry.metadata.model_dump(),
                    )
                    if original_entry.metadata
                    else FlextLdifModels.QuirkMetadata.model_validate(
                        FlextLdifModels.QuirkMetadata.create_for(
                            self._get_server_type(),
                            extensions={},
                        ).model_dump(),
                    )
                )
            )
            # Extract original lines from metadata for round-trip support
            original_dn_line: str | None = None
            original_attr_lines: list[str] | None = None
            if entry.metadata and entry.metadata.original_format_details:
                original_dn_line_raw = entry.metadata.original_format_details.get(
                    "original_dn_line",
                )
                original_dn_line = (
                    str(original_dn_line_raw)
                    if original_dn_line_raw is not None
                    else None
                )
                orig_attr_lines = entry.metadata.original_format_details.get(
                    "original_attr_lines",
                )
                if FlextRuntime.is_list_like(orig_attr_lines):
                    original_attr_lines = cast("list[str]", orig_attr_lines)
            # Store minimal differences in metadata
            self._store_oid_minimal_differences(
                metadata=entry_metadata,
                dn_differences=dn_differences,
                attribute_differences=attribute_differences,
                original_dn=original_dn,
                normalized_dn=normalized_dn,
                original_attributes_complete=original_attributes_complete_dict,
                original_dn_line=original_dn_line,
                original_attr_lines=original_attr_lines,
            )

            # Ensure entry uses the modified metadata
            original_entry.metadata = entry_metadata

            logger.debug(
                "OID entry parsed with complete minimal differences analysis",
                entry_dn=original_dn[:50] if original_dn else None,
                # Before/After comparison
                original_dn=original_dn,
                normalized_dn=normalized_dn,
                original_attributes_count=len(entry_attrs),
                normalized_attributes_count=len(normalized_attributes),
                # What was preserved
                minimal_differences_dn_captured=bool(
                    dn_differences.get("has_differences", False),
                ),
                minimal_differences_attributes_captured=len(attribute_differences) > 0,
                boolean_conversions_count=len(boolean_conversions),
                acl_transformations_count=len(acl_transformations),
                # Status
                metadata_preserved=True,
                all_data_preserved=True,
                operation="_parse_entry",
            )

            # Create result with metadata (use normalized_dn for RFC format)
            # Original_entry.metadata now contains minimal differences from _store_oid_minimal_differences
            return self._create_entry_result_with_metadata(
                entry,
                normalized_dn,
                original_dn,
                dn_stats,
                converted_attrs,
                boolean_conversions,
                acl_transformations,
                rfc_violations,
                attribute_conflicts,
                normalized_attributes,
                original_entry,
            )

        def _inject_validation_rules(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Inject OID-specific validation rules into Entry metadata via DI."""
            server_type = FlextLdifConstants.ServerTypes.OID

            # Build validation rules dictionary (Python 3.13: dict comprehension)
            validation_rules: dict[str, object] = {
                "requires_objectclass": (
                    server_type
                    in FlextLdifConstants.ServerValidationRules.OBJECTCLASS_REQUIRED_SERVERS
                ),
                "requires_naming_attr": (
                    server_type
                    in FlextLdifConstants.ServerValidationRules.NAMING_ATTR_REQUIRED_SERVERS
                ),
                "requires_binary_option": (
                    server_type
                    in FlextLdifConstants.ServerValidationRules.BINARY_OPTION_REQUIRED_SERVERS
                ),
                "encoding_rules": {
                    "default_encoding": FlextLdifServersOid.Constants.Encoding.UTF_8.value,
                    # Python 3.13: List comprehension for encoding values
                    "allowed_encodings": [
                        encoding.value
                        for encoding in (
                            FlextLdifServersOid.Constants.Encoding.UTF_8,
                            FlextLdifServersOid.Constants.Encoding.UTF_16,
                            FlextLdifServersOid.Constants.Encoding.ASCII,
                            FlextLdifServersOid.Constants.Encoding.LATIN_1,
                            FlextLdifServersOid.Constants.Encoding.ISO_8859_1,
                        )
                    ],
                },
                "dn_case_rules": {
                    "preserve_case": True,
                    "normalize_to": None,
                },
                "acl_format_rules": {
                    "format": FlextLdifServersOid.Constants.ACL_FORMAT,
                    "attribute_name": FlextLdifServersOid.Constants.ACL_ATTRIBUTE_NAME,
                    "requires_target": True,
                    "requires_subject": True,
                },
                "track_deletions": True,
                "track_modifications": True,
                "track_conversions": True,
            }

            # Ensure entry has metadata
            if entry.metadata is None:
                entry = entry.model_copy(
                    update={
                        "metadata": FlextLdifModels.QuirkMetadata.create_for(
                            server_type,
                            extensions={},
                        ),
                    },
                )

            # Python 3.13: Type guard with walrus operator
            if entry.metadata and (entry_dn := entry.dn.value if entry.dn else None):
                entry.metadata.extensions["validation_rules"] = validation_rules
                logger.debug(
                    "Injected OID validation rules into Entry metadata",
                    entry_dn=entry_dn,
                    server_type=server_type,
                )

            return entry
