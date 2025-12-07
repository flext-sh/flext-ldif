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

from collections.abc import Mapping
from typing import ClassVar

from flext_core import FlextLogger

from flext_ldif.constants import c
from flext_ldif.servers.rfc import FlextLdifServersRfc

logger = FlextLogger(__name__)


class FlextLdifServersOidConstants(FlextLdifServersRfc.Constants):
    r"""Oracle Internet Directory (OID) constants for LDIF processing.

    OID vs RFC Constant Differences
    ================================
    This class extends RFC baseline constants with OID-specific values
    for detection, ACL format, schema processing, and attribute mappings.

    1. BOOLEAN FORMAT
    -----------------
    RFC 4517 Section 3.3.3:
        BOOLEAN = "TRUE" / "FALSE"

    OID Proprietary:
        BOOLEAN = "1" / "0"

    Constants:
        ONE_OID = "1"          # OID true
        ZERO_OID = "0"         # OID false
        OID_TO_RFC = {"1": "TRUE", "0": "FALSE"}
        RFC_TO_OID = {"TRUE": "1", "FALSE": "0"}

    Boolean Attributes (BOOLEAN_ATTRIBUTES):
        - orcldasenableproductlogo, orcldasenablesubscriberlogo
        - orcldasshowproductlogo, orcldasenablebranding
        - orcldasisenabled, orcldasismandatory, orcldasispersonal
        - pwdlockout, pwdmustchange, pwdallowuserchange

    2. ACL FORMAT
    -------------
    RFC 4876 (Standard ACI):
        Attribute: aci
        Format: (target)(version; acl "name"; action;)

    OID Proprietary:
        Attributes:
            - orclaci: Subtree scope (inherited by children)
            - orclentrylevelaci: Entry-level scope (not inherited)

        Format:
            access to <target> by <subject> (<permissions>)

        Target Types:
            - entry: Entire entry
            - attr=(*): All attributes
            - attr=(cn,sn): Specific attributes

        Subject Types:
            - *: Anonymous
            - self: The entry itself
            - "dn": Specific DN (quoted)
            - group="dn": Group DN
            - dnattr=(attr): DN from attribute

        Permissions:
            - browse, read, write, add, delete, search, compare
            - auth, selfwrite, proxy, all
            - Negations: noread, nowrite, noadd, nodelete, nosearch

    Constants:
        ORCLACI = "orclaci"
        ORCLENTRYLEVELACI = "orclentrylevelaci"
        ACL_TYPE_PATTERN = r"^(Union[orclaci, orclentrylevelaci]):"
        ACL_TARGET_PATTERN = r"access to (Union[entry, attr]=\(([^)]+)\))"
        ACL_SUBJECT_PATTERN = r"by\s+(group=\"...\"|...)"
        ACL_PERMISSIONS_PATTERN = r"\(([^)]+)\)(?:\s*$)"

    3. MATCHING RULES
    -----------------
    RFC 4517 Section 4.2 (Case-Ignore Matching):
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch  # lowercase 's'

    OID Bug (Typo):
        SUBSTR caseIgnoreSubStringsMatch  # uppercase 'S'

    Constants:
        MATCHING_RULE_TO_RFC = {
            "caseIgnoreSubStringsMatch": "caseIgnoreSubstringsMatch"
        }
        MATCHING_RULE_RFC_TO_OID = {
            "caseIgnoreSubstringsMatch": "caseIgnoreSubStringsMatch"
        }

    4. SYNTAX OIDs
    --------------
    RFC 4517 Syntaxes:
        1.3.6.1.4.1.1466.115.121.1.15 = Directory String

    OID Proprietary Syntaxes:
        1.3.6.1.4.1.1466.115.121.1.1 = OID ACI List Syntax

    Constants:
        SYNTAX_OID_TO_RFC = {
            "1.3.6.1.4.1.1466.115.121.1.1": "1.3.6.1.4.1.1466.115.121.1.15"
        }
        SYNTAX_RFC_TO_OID = {
            "1.3.6.1.4.1.1466.115.121.1.15": "1.3.6.1.4.1.1466.115.121.1.1"
        }

    5. SCHEMA DN
    ------------
    RFC 4512 Section 4.2:
        Recommended: cn=schema or cn=Subschema

    OID Proprietary:
        cn=subschemasubentry

    Constants:
        SCHEMA_DN_QUIRK = "cn=subschemasubentry"

    6. DETECTION PATTERNS
    ---------------------
    OID Server Detection (DETECTION_PATTERN):
        Pattern: r"2\.16\.840\.1\.113894\.|orcl"

        Matches:
        - Oracle OID namespace: 2.16.840.1.113894.*
        - Oracle attributes: orcl* prefix

    Detection Attributes (DETECTION_ATTRIBUTES):
        orclOID, orclGUID, orclPassword, orclaci, orclentrylevelaci, orcldaslov

    Detection ObjectClasses (DETECTION_OBJECTCLASS_NAMES):
        orcldirectory, orcldomain, orcldirectoryserverconfig, orclcontainer

    7. OPERATIONAL ATTRIBUTES
    -------------------------
    OID extends RFC operational attributes:
        RFC: createTimestamp, modifyTimestamp, creatorsName, modifiersName, ...

        OID additions:
        - orclguid: Oracle GUID (128-bit identifier)
        - orclobjectguid: Object GUID
        - orclentryid: Entry identifier
        - orclaccount: Account information
        - pwdChangedTime: Password change timestamp
        - pwdHistory: Password history
        - pwdFailureTime: Failed auth timestamps

    Constants:
        OPERATIONAL_ATTRIBUTES = RFC.OPERATIONAL_ATTRIBUTES | {orclguid, ...}

    8. CATEGORIZATION
    -----------------
    OID entry categorization for migration:

    Priority Order (CATEGORIZATION_PRIORITY):
        1. acl - Entries with ACL attributes
        2. users - User accounts (person, inetOrgPerson, orclUser)
        3. hierarchy - Structural containers (ou, o, orclContainer)
        4. groups - Group entries (groupOfNames, orclGroup)

    OID-specific ObjectClasses (CATEGORY_OBJECTCLASSES):
        - users: orclUser, orclUserV2
        - hierarchy: orclContainer, orclContainerOC, orclContext,
                    orclApplicationEntity, orclConfigSet, orclDASAttrCategory
        - groups: orclGroup, orclPrivilegeGroup

    Oracle Documentation References
    ================================
    - Oracle Fusion Middleware Administrator's Guide for Oracle Internet Directory:
      https://docs.oracle.com/cd/E29127_01/doc.111170/e28967/toc.htm
    - Oracle Directory Services Schema Reference:
      https://docs.oracle.com/cd/E28280_01/REDACTED_LDAP_BIND_PASSWORD.1111/e10029/oid_schema_elements.htm
    - Oracle Internet Directory Attribute Reference:
      https://docs.oracle.com/cd/E28280_01/REDACTED_LDAP_BIND_PASSWORD.1111/e10029/oid_attr_ref.htm

    """

    # Server identity and priority (defined at Constants level)
    SERVER_TYPE: ClassVar[c.Ldif.LiteralTypes.ServerTypeLiteral] = "oid"
    PRIORITY: ClassVar[int] = 10

    # NOTE: DEFAULT_PORT, DEFAULT_SSL_PORT, DEFAULT_PAGE_SIZE
    # inherited from RFC.Constants

    # Logging configuration
    MAX_LOG_LINE_LENGTH: ClassVar[int] = 200  # Maximum length for log line excerpts

    # Oracle OID ACL attribute names
    ORCLACI: ClassVar[str] = "orclaci"  # Standard Oracle OID ACL
    ORCLENTRYLEVELACI: ClassVar[str] = "orclentrylevelaci"  # Entry-level ACI
    ACL_FORMAT: ClassVar[str] = "orclaci"  # OID ACL format
    ACL_ATTRIBUTE_NAME: ClassVar[str] = "orclaci"  # ACL attribute name

    # NOTE: ACL metadata keys removed - use c.MetadataKeys
    # Servers communicate via GENERIC metadata keys (not server-specific)

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
    # OID exports MAY/MUST lowercase but attributeTypes use CamelCase
    ATTR_NAME_CASE_MAP: ClassVar[dict[str, str]] = {
        "middlename": "middleName",  # RFC 4519 standard
        # Oracle 'orcl*' attrs handled by ATTRIBUTE_TRANSFORMATION below
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
    # NOTE: Use DETECTION_PATTERN (defined below) for server auto-discovery
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
    # Use c.SchemaKeys for field names
    # SCHEMA_FILTERABLE_FIELDS: fields processed with OID filtering
    SCHEMA_FILTERABLE_FIELDS: ClassVar[frozenset[str]] = frozenset(
        [
            "attributetypes",
            "objectclasses",
            "matchingrules",
            "ldapsyntaxes",
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
            # Oracle user/account boolean attributes
            "orclisenabled",
            "orclaccountlocked",
            "orclpwdmustchange",
            "orclpasswordverify",
            "orclisvisible",
            "orclsamlenable",
            "orclsslenable",
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

    # NOTE: VARIANTS removed - use ALIASES instead
    # (defined below in auto-discovery section)

    # Schema attribute fields that are server-specific
    ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset(["usage", "x_origin"])

    # ObjectClass requirements (extends RFC - allows multiple SUP)
    OBJECTCLASS_REQUIREMENTS: ClassVar[Mapping[str, bool]] = {
        "requires_sup_for_auxiliary": True,
        "allows_multiple_sup": True,  # OID allows multiple SUP
        "requires_explicit_structural": False,
    }

    # Oracle OID specific attributes (consolidated operational + categorization)
    OID_SPECIFIC_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
        [
            "orclaci",  # OID access control
            "orclentrylevelaci",  # OID entry-level ACI
            "orclguid",  # Oracle GUID
            "orcloid",  # Oracle OID identifier
            "orclpassword",  # Oracle password
            "orcldaslov",  # Oracle DASLOV configuration
            "orclmailaddr",  # Mail address
            "orcluseractivefrom",  # User active from date
            "orcluserinactivefrom",  # User inactive from date
        ],
    )

    # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
    CANONICAL_NAME: ClassVar[str] = "oid"
    ALIASES: ClassVar[frozenset[str]] = frozenset(["oid", "oracle_oid"])
    CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["oid"])
    CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["oid", "rfc"])

    # Server detection patterns and weights
    # Oracle OID pattern: 2.16.840.1.113894.* namespace or orcl* attributes
    DETECTION_PATTERN: ClassVar[str] = r"2\.16\.840\.1\.113894\.|orcl"
    # Pattern used by detector service for OID namespace matching
    DETECTION_OID_PATTERN: ClassVar[str] = r"2\.16\.840\.1\.113894\.|orcl"
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
    # Increased to ensure OID detection wins over other servers
    # when OID-specific attributes/objectClasses are present
    DETECTION_WEIGHT: ClassVar[int] = 12

    # Oracle OID metadata keys (for ACL processing)
    OID_SPECIFIC_RIGHTS: ClassVar[str] = "oid_specific_rights"
    RFC_NORMALIZED: ClassVar[str] = "rfc_normalized"
    ORIGINAL_OID_PERMS: ClassVar[str] = "original_oid_perms"

    # Oracle OID metadata keys (for ACL target/source)
    OID_ACL_SOURCE_TARGET: ClassVar[str] = "acl_source_target"

    # All OID metadata keys
    # NOTE: Entry metadata keys (CONVERTED_ATTRIBUTES, ORIGINAL_ATTRIBUTES_COMPLETE, etc.)
    # are defined in c.MetadataKeys and should be used directly.
    ALL_OID_KEYS: ClassVar[frozenset[str]] = frozenset(
        [
            OID_SPECIFIC_RIGHTS,
            RFC_NORMALIZED,
            ORIGINAL_OID_PERMS,
            OID_ACL_SOURCE_TARGET,
            # Entry metadata keys from c.MetadataKeys:
            # CONVERTED_ATTRIBUTES, ORIGINAL_ATTRIBUTES_COMPLETE, etc.
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

    # Permission names inherited from RFC.Constants:
    # PERMISSION_READ, PERMISSION_WRITE, PERMISSION_ADD,
    # PERMISSION_DELETE, PERMISSION_SEARCH, PERMISSION_COMPARE

    # ACL subject types
    ACL_SUBJECT_TYPE_USER: ClassVar[str] = "user"
    ACL_SUBJECT_TYPE_GROUP: ClassVar[str] = "group"
    ACL_SUBJECT_TYPE_ROLE: ClassVar[str] = "role"
    ACL_SUBJECT_TYPE_SELF: ClassVar[str] = "self"
    ACL_SUBJECT_TYPE_ANONYMOUS: ClassVar[str] = "anonymous"

    # ACL parsing patterns
    ACL_TYPE_PATTERN: ClassVar[str] = r"^(Union[orclaci, orclentrylevelaci]):"
    ACL_TARGET_PATTERN: ClassVar[str] = r"access to (Union[entry, attr]=\(([^)]+)\))"
    ACL_SUBJECT_PATTERN: ClassVar[str] = (
        r"by\s+(group=\"[^\"]+\"|dnattr=\([^)]+\)|guidattr=\([^)]+\"|groupattr=\([^)]+\"|\"[^\"]+\"|self|\*)"
    )
    ACL_PERMISSIONS_PATTERN: ClassVar[str] = r"\(([^)]+)\)(?:\s*$)"
    ACL_FILTER_PATTERN: ClassVar[str] = r"filter=(\([^)]*(?:\([^)]*\)[^)]*)*\))"
    ACL_CONSTRAINT_PATTERN: ClassVar[str] = r"added_object_constraint=\(([^)]+)\)"

    # ACL parsing patterns for OID-specific extensions
    # (validated against Oracle OID documentation)
    ACL_BINDMODE_PATTERN: ClassVar[str] = r"(?i)bindmode\s*=\s*\(([^)]+)\)"
    ACL_DENY_GROUP_OVERRIDE_PATTERN: ClassVar[str] = r"DenyGroupOverride"
    ACL_APPEND_TO_ALL_PATTERN: ClassVar[str] = r"AppendToAll"
    ACL_BIND_IP_FILTER_PATTERN: ClassVar[str] = r"(?i)bindipfilter\s*=\s*\(([^)]+)\)"
    ACL_CONSTRAIN_TO_ADDED_PATTERN: ClassVar[str] = (
        r"(?i)constraintonaddedobject\s*=\s*\(([^)]+)\)"
    )

    # ACL extraction patterns for _extract_oid_target method
    ACL_TARGET_DN_EXTRACT: ClassVar[str] = r'target\s*=\s*"([^"]*)"'
    ACL_TARGET_ATTR_EXTRACT: ClassVar[str] = r'targetattr\s*=\s*"([^"]*)"'
    # OID-specific pattern to extract attributes from attr=(cn,sn,mail) format
    ACL_TARGET_ATTR_OID_EXTRACT: ClassVar[str] = r"attr\s*=\s*\(([^)]+)\)"

    # ACL subject detection patterns for _detect_oid_subject method
    ACL_SUBJECT_USER_DETECT: ClassVar[str] = r'subject\s*=\s*"[^"]*userdn'
    ACL_SUBJECT_GROUP_DETECT: ClassVar[str] = r'subject\s*=\s*"[^"]*groupdn'
    ACL_SUBJECT_ROLE_DETECT: ClassVar[str] = r'subject\s*=\s*"[^"]*roledn'

    # ACL permissions extraction patterns for _parse_oid_permissions method
    # RFC format patterns (legacy - kept for reference)
    ACL_ALLOW_PERMS_EXTRACT: ClassVar[str] = r"\(allow\s+\(([^)]*)\)"
    ACL_DENY_PERMS_EXTRACT: ClassVar[str] = r"\(deny\s+\(([^)]*)\)"
    # OID format: Extract permissions from final parentheses before filter/constraint/end
    ACL_PERMS_EXTRACT_OID: ClassVar[str] = (
        r"\s\(([^()]+)\)(?:\s*(?:filter=|Union[added_object, bindmode]|Union[Deny, Append]|Union[bindip, constrain]|$))"
    )

    # ACL pattern dictionary keys (used in _get_oid_patterns)
    ACL_PATTERN_KEY_TYPE: ClassVar[str] = "acl_type"
    ACL_PATTERN_KEY_TARGET: ClassVar[str] = "target"
    ACL_PATTERN_KEY_SUBJECT: ClassVar[str] = "subject"
    ACL_PATTERN_KEY_PERMISSIONS: ClassVar[str] = "permissions"
    ACL_PATTERN_KEY_FILTER: ClassVar[str] = "filter"
    ACL_PATTERN_KEY_CONSTRAINT: ClassVar[str] = "constraint"

    # NOTE: OBJECTCLASS_TYPO_* constants removed - unused, use inline literals
    # NOTE: MATCHING_RULE_CASE_IGNORE_* constants removed - use
    # MATCHING_RULE_TO_RFC dict instead

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

    # NOTE: Transformation mappings removed - not used
    # Conversions handled by services/conversion.py

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

    # NOTE: AclPermission and AclAction StrEnums REMOVED - unused dead code
    # Use SUPPORTED_PERMISSIONS frozenset and ACL_PERMISSION_MAPPING dict instead
    # NOTE: Encoding enum removed - use c.Encoding instead
