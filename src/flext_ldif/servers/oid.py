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

import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import reduce
from typing import ClassVar, Union

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
        SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.OID
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

        # NOTE: ACL metadata keys removed - use FlextLdifConstants.MetadataKeys
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
        # Use FlextLdifConstants.SchemaKeys for field names
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
        # are defined in FlextLdifConstants.MetadataKeys and should be used directly.
        ALL_OID_KEYS: ClassVar[frozenset[str]] = frozenset(
            [
                OID_SPECIFIC_RIGHTS,
                RFC_NORMALIZED,
                ORIGINAL_OID_PERMS,
                OID_ACL_SOURCE_TARGET,
                # Entry metadata keys from FlextLdifConstants.MetadataKeys:
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
        ACL_TARGET_PATTERN: ClassVar[str] = (
            r"access to (Union[entry, attr]=\(([^)]+)\))"
        )
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
        ACL_BIND_IP_FILTER_PATTERN: ClassVar[str] = (
            r"(?i)bindipfilter\s*=\s*\(([^)]+)\)"
        )
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
        # NOTE: Encoding enum removed - use FlextLdifConstants.Encoding instead

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

    # REMOVED: get_categorization_rules (25 lines dead code - never called)
    # Categorization rules are passed via FlextLdif.migrate() directly

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
        result = schema_quirk.extract_schemas_from_ldif(ldif_content)
        # Type narrowing: convert Union[dict[str, list[str], str]] to dict[str, object]
        if result.is_success:
            data = result.unwrap()
            # Return schema extraction result with metadata
            converted_data: dict[str, object] = {
                "attributes": data.get("attributes", {}),
                "objectclasses": data.get("objectclasses", {}),
                "total_attributes": len(data.get("attributes", {})),
                "total_objectclasses": len(data.get("objectclasses", {})),
            }
            return FlextResult[dict[str, object]].ok(converted_data)
        return FlextResult[dict[str, object]].fail(
            result.error or "Failed to extract schemas",
        )

    class Schema(
        FlextLdifServersRfc.Schema,
    ):
        """Oracle Internet Directory (OID) schema quirks implementation.

        OID vs RFC Differences
        ======================
        Oracle OID exports schema in a format that deviates from RFC 4512 in
        several ways. This class normalizes OID-specific formats to RFC-compliant
        structures during parsing, and denormalizes back to OID format when writing.

        1. MATCHING RULE CASE SENSITIVITY
        ---------------------------------
        OID Bug: Uses 'caseIgnoreSubStringsMatch' (capital S) instead of
        RFC 4517 compliant 'caseIgnoreSubstringsMatch' (lowercase s).

        - OID exports:   EQUALITY caseIgnoreSubStringsMatch
        - RFC standard:  SUBSTR caseIgnoreSubstringsMatch (note: SUBSTR not EQUALITY)

        This quirk normalizes:
        - 'caseIgnoreSubStringsMatch' → 'caseIgnoreSubstringsMatch'
        - Moves from EQUALITY to SUBSTR field (per RFC 4517 Section 4.2.2)

        See: Oracle Fusion Middleware Admin Guide, Chapter "Schema Management"

        2. SYNTAX OID QUIRKS
        --------------------
        OID uses proprietary syntax OIDs that must be mapped to RFC 4517:

        - OID ACI List Syntax (1.3.6.1.4.1.1466.115.121.1.1)
          → RFC Directory String (1.3.6.1.4.1.1466.115.121.1.15)

        3. ORACLE-SPECIFIC ATTRIBUTES
        -----------------------------
        OID defines proprietary attributes in the 2.16.840.1.113894.* namespace:

        - orclGUID: Oracle GUID (maps to RFC entryUUID conceptually)
        - orclPassword: Oracle password storage
        - orclaci: Oracle Access Control Information
        - orclentrylevelaci: Entry-level ACI

        See: Oracle Fusion Middleware Reference for OID Schema

        4. OBJECTCLASS SUP QUIRKS
        -------------------------
        OID allows multiple SUP values in objectClass definitions, which is
        technically RFC-compliant but less common. Format normalization handles:

        - SUP ( top person ) → list ['top', 'person']
        - SUP top → list ['top']

        5. AUXILLARY TYPO
        -----------------
        OID exports sometimes contain typo 'AUXILLARY' instead of 'AUXILIARY'.
        This quirk normalizes the typo during parsing.

        6. BOOLEAN ATTRIBUTE FORMAT
        ---------------------------
        OID uses '0'/'1' for boolean attributes instead of RFC 4517 'TRUE'/'FALSE':

        - orcldasenableproductlogo: 1 → TRUE
        - pwdlockout: 0 → FALSE

        Detection Pattern
        =================
        OID schemas are detected by:
        - OID namespace: 2.16.840.1.113894.*
        - Attribute prefix: orcl*
        - ObjectClasses: orclContext, orclContainer, etc.

        References
        ----------
        - RFC 4512: LDAP Directory Information Models (Schema)
        - RFC 4517: LDAP Syntaxes and Matching Rules
        - Oracle Fusion Middleware Administrator's Guide for OID
        - Oracle Fusion Middleware Reference for OID Schema Objects

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
        # These methods override base class with Oracle OID-specific logic:
        # - _parse_attribute(): OID schema parsing with OID replacements
        # - _parse_objectclass(): OID schema parsing with OID replacements
        # - _write_attribute(): RFC writer with OID error handling
        # - _write_objectclass(): RFC writer with OID error handling
        # - should_filter_out_attribute(): Returns False (accept all)
        # - should_filter_out_objectclass(): Returns False (accept all)
        # - create_metadata(): Creates OID-specific metadata

        def _hook_post_parse_attribute(
            self,
            attr: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Hook: Transform parsed attribute using OID-specific normalizations.

            Called by RFC._parse_attribute() after RFC 4512 baseline parsing.
            Applies OID → RFC transformations to normalize Oracle-specific
            schema formats to RFC-compliant structures.

            OID-Specific Transformations Applied
            ====================================

            Step 1: Syntax OID Cleanup
            --------------------------
            Remove quotes from syntax OID values. OID sometimes exports:
                SYNTAX '1.3.6.1.4.1.1466.115.121.1.15'
            RFC 4512 requires unquoted:
                SYNTAX 1.3.6.1.4.1.1466.115.121.1.15

            Step 2: Matching Rule Normalization
            -----------------------------------
            Fix OID's case sensitivity bug and incorrect field placement:

            Input (OID export):
                EQUALITY caseIgnoreSubStringsMatch  (wrong: capital S, wrong field)

            Output (RFC 4517 compliant):
                EQUALITY caseIgnoreMatch
                SUBSTR caseIgnoreSubstringsMatch  (lowercase s, correct)

            Uses Constants.MATCHING_RULE_TO_RFC mapping:
                'caseIgnoreSubStringsMatch' → 'caseIgnoreSubstringsMatch'
                'accessDirectiveMatch' → 'caseIgnoreMatch'

            Step 3: Syntax OID Replacement
            ------------------------------
            Map OID proprietary syntax OIDs to RFC 4517 standard:

            Uses Constants.SYNTAX_OID_TO_RFC mapping:
                '1.3.6.1.4.1.1466.115.121.1.1' (OID ACI List)
                → '1.3.6.1.4.1.1466.115.121.1.15' (RFC Directory String)

            Step 4: SUBSTR Field Correction
            -------------------------------
            Move caseIgnoreSubstringsMatch from EQUALITY to SUBSTR field
            per RFC 4517 Section 4.2.2 (Substring Matching Rules).

            Example LDIF Input (OID)
            ========================
            attributetypes: ( 2.16.840.1.113894.1.1.5 NAME 'orclDbType'
              EQUALITY caseIgnoreSubStringsMatch
              SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{128}' )

            Example Output (RFC Normalized)
            ===============================
            SchemaAttribute(
                oid='2.16.840.1.113894.1.1.5',
                name='orclDbType',
                equality='caseIgnoreMatch',
                substr='caseIgnoreSubstringsMatch',
                syntax='1.3.6.1.4.1.1466.115.121.1.15',
                length=128
            )

            Args:
                attr: Parsed attribute from RFC baseline parser

            Returns:
                FlextResult with OID-normalized SchemaAttribute

            """
            try:
                # Step 1: Clean syntax OID (remove quotes, no replacements)
                if attr.syntax:
                    attr.syntax = FlextLdifUtilities.Schema.normalize_syntax_oid(
                        str(attr.syntax),
                    )

                # Step 2: Normalize matching rules using Constants
                normalized_equality, normalized_substr = (
                    FlextLdifUtilities.Schema.normalize_matching_rules(
                        attr.equality,
                        attr.substr,
                        replacements=FlextLdifServersOid.Constants.MATCHING_RULE_TO_RFC,
                        normalized_substr_values=FlextLdifServersOid.Constants.MATCHING_RULE_TO_RFC,
                    )
                )
                if normalized_equality != attr.equality:
                    attr.equality = normalized_equality
                if normalized_substr != attr.substr:
                    attr.substr = normalized_substr
                # Normalize ordering field if present
                if attr.ordering:
                    normalized_ordering = (
                        FlextLdifServersOid.Constants.MATCHING_RULE_TO_RFC.get(
                            attr.ordering,
                        )
                    )
                    if normalized_ordering:
                        attr.ordering = normalized_ordering

                # Step 3: Apply syntax OID→RFC replacements
                if attr.syntax:
                    attr.syntax = FlextLdifUtilities.Schema.normalize_syntax_oid(
                        str(attr.syntax),
                        replacements=FlextLdifServersOid.Constants.SYNTAX_OID_TO_RFC,
                    )

                # Step 4: Transform caseIgnoreSubstringsMatch (EQUALITY → SUBSTR)
                attr = self._transform_case_ignore_substrings(attr)

                return FlextResult.ok(attr)

            except Exception as e:
                logger.exception(
                    "OID post-parse attribute hook failed",
                )
                return FlextResult.fail(
                    f"OID post-parse attribute hook failed: {e}",
                )

        def _hook_post_parse_objectclass(
            self,
            oc: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Hook: Transform parsed objectClass using OID-specific normalizations.

            Called by RFC._parse_objectclass() after RFC 4512 baseline parsing.
            Applies OID → RFC transformations to normalize Oracle-specific
            objectClass definitions.

            OID-Specific Transformations Applied
            ====================================

            Step 1: SUP Normalization
            -------------------------
            OID exports SUP in various formats that need normalization:

            Input formats (OID):
                SUP top                    → ['top']
                SUP ( top person )         → ['top', 'person']
                SUP 'top'                  → ['top']

            Output (RFC normalized list):
                sup=['top', 'person']

            Multiple SUP is RFC-compliant (RFC 4512 Section 4.1.1) but less common.

            Step 2: AUXILLARY Typo Fix
            --------------------------
            OID sometimes exports typo 'AUXILLARY' instead of 'AUXILIARY':

            Input (OID with typo):
                objectClasses: ( ... AUXILLARY ... )

            Output (RFC corrected):
                kind='AUXILIARY'

            Step 3: Attribute Name Case Normalization
            -----------------------------------------
            OID exports MUST/MAY attributes with inconsistent case:

            Input (OID lowercase):
                MUST ( middlename $ mail )

            Output (RFC CamelCase):
                must=['middleName', 'mail']

            Uses Constants.ATTR_NAME_CASE_MAP for corrections:
                'middlename' → 'middleName' (per RFC 4519)

            Example LDIF Input (OID)
            ========================
            objectClasses: ( 2.16.840.1.113894.1.0.5
              NAME 'orclUserV2'
              SUP ( top person inetOrgPerson )
              AUXILLARY
              MUST ( middlename )
              MAY ( orclPassword ) )

            Example Output (RFC Normalized)
            ===============================
            SchemaObjectClass(
                oid='2.16.840.1.113894.1.0.5',
                name='orclUserV2',
                sup=['top', 'person', 'inetOrgPerson'],
                kind='AUXILIARY',
                must=['middleName'],
                may=['orclPassword']
            )

            Args:
                oc: Parsed objectClass from RFC baseline parser

            Returns:
                FlextResult with OID-normalized SchemaObjectClass

            """
            try:
                # Get original format for transformations
                meta_keys = FlextLdifConstants.MetadataKeys
                key = meta_keys.SCHEMA_ORIGINAL_FORMAT
                original_format_str = (
                    str(oc.metadata.extensions.get(key, ""))
                    if oc.metadata and oc.metadata.extensions
                    else ""
                )

                # Normalize SUP and AUXILIARY
                updated_sup = self._normalize_sup_from_model(oc)
                if updated_sup is None and original_format_str:
                    updated_sup = self._normalize_sup_from_original_format(
                        original_format_str,
                    )

                updated_kind = self._normalize_auxiliary_typo(
                    oc,
                    original_format_str,
                )

                # Normalize attribute names in MUST and MAY (OID → RFC case correction)
                normalized_must = self._normalize_attribute_names(oc.must)
                normalized_may = self._normalize_attribute_names(oc.may)

                # Apply transformations if needed
                update_dict: dict[str, str | list[str] | None] = {
                    k: v
                    for k, v in {
                        "sup": updated_sup,
                        "kind": updated_kind,
                        "must": normalized_must if normalized_must != oc.must else None,
                        "may": normalized_may if normalized_may != oc.may else None,
                    }.items()
                    if v
                }

                if update_dict:
                    oc = oc.model_copy(update=update_dict)

                return FlextResult.ok(oc)

            except Exception as e:
                logger.exception(
                    "OID post-parse objectclass hook failed",
                )
                return FlextResult.fail(
                    f"OID post-parse objectclass hook failed: {e}",
                )

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
            # Use utilities to normalize matching rules
            # (moves SUBSTR from EQUALITY to SUBSTR)
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

                # Preserve original_format before transformation
                original_format: str | None = None
                meta_keys = FlextLdifConstants.MetadataKeys
                key = meta_keys.SCHEMA_ORIGINAL_FORMAT
                if (
                    attr_data.metadata
                    and attr_data.metadata.extensions
                    and key in attr_data.metadata.extensions
                ):
                    original_format_raw = attr_data.metadata.extensions.get(
                        meta_keys.SCHEMA_ORIGINAL_FORMAT,
                    )
                    if original_format_raw is None or isinstance(
                        original_format_raw,
                        str,
                    ):
                        original_format = original_format_raw
                    else:
                        msg = f"Expected Optional[str], got {type(original_format_raw)}"
                        raise TypeError(msg)

                # Create new model with transformed values
                transformed = attr_data.model_copy(
                    update={
                        "equality": normalized_equality,
                        "substr": normalized_substr,
                    },
                )

                # Restore original_format in metadata after transformation
                if original_format and transformed.metadata:
                    transformed.metadata.extensions[
                        meta_keys.SCHEMA_ORIGINAL_FORMAT
                    ] = original_format

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

        # REMOVED: _add_source_metadata (34 lines dead code - never called)
        # SOURCE metadata is populated in _parse_attribute via source_values capture

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
            attr_data.metadata.extensions[
                FlextLdifConstants.Rfc.META_TRANSFORMATION_TIMESTAMP
            ] = FlextUtilities.Generators.generate_iso_timestamp()

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            r"""Parse Oracle OID attribute definition (Phase 1: Normalization).

            OID vs RFC Attribute Parsing
            ============================
            This method extends RFC's `_parse_attribute()` to handle OID-specific
            schema attribute formats while normalizing to RFC 4512 structures.

            Parsing Pipeline
            ----------------
            1. Call RFC base parser with lenient mode
            2. RFC parser calls `_hook_post_parse_attribute()` hook
            3. Hook applies OID→RFC transformations:
               - Fix matching rule typo (SubStrings → Substrings)
               - Normalize syntax OIDs (OID → RFC 4517)
            4. Add OID-specific metadata for round-trip support
            5. Capture target values for bidirectional conversion

            OID-Specific Input Handling
            ---------------------------
            a) SYNTAX with Quotes:
               OID exports: SYNTAX '1.3.6.1.4.1.1466.115.121.1.15'
               RFC 4512:    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15

            b) Case-Insensitive Matching:
               OID uses case-insensitive NAME matching
               RFC 4512 is case-sensitive

            c) Matching Rule Typos:
               OID: SUBSTR caseIgnoreSubStringsMatch (uppercase S)
               RFC: SUBSTR caseIgnoreSubstringsMatch (lowercase s)

            Example Input (OID)
            -------------------
            ( 2.16.840.1.113894.1.1.123
              NAME 'orclPassword'
              SYNTAX '1.3.6.1.4.1.1466.115.121.1.40'{128}
              EQUALITY octetStringMatch
              SINGLE-VALUE
              X-ORIGIN 'Oracle' )

            Example Output (RFC-normalized)
            -------------------------------
            SchemaAttribute(
                oid='2.16.840.1.113894.1.1.123',
                names=['orclPassword'],
                syntax='1.3.6.1.4.1.1466.115.121.1.40',  # Quotes removed
                syntax_length=128,
                equality='octetStringMatch',
                single_value=True,
                x_origin=['Oracle'],
                metadata=FlextLdifModels.QuirkMetadata(
                    server_type='oid',
                    extensions={
                        FlextLdifConstants.MetadataKeys.SCHEMA_ORIGINAL_FORMAT: '( 2.16.840.1.113894... )',
                        FlextLdifConstants.MetadataKeys.SCHEMA_ORIGINAL_STRING_COMPLETE: '...',
                        FlextLdifConstants.MetadataKeys.SCHEMA_SOURCE_SERVER: 'oid',
                    }
                )
            )

            Metadata for Round-Trip
            -----------------------
            Uses FlextLdifConstants.MetadataKeys:
            - SCHEMA_ORIGINAL_FORMAT: Stripped definition string
            - SCHEMA_ORIGINAL_STRING_COMPLETE: Complete with all formatting
            - SCHEMA_SOURCE_SERVER: "oid"
            - META_TRANSFORMATION_TIMESTAMP: ISO timestamp

            Args:
                attr_definition: AttributeType definition string
                                (without "attributetypes:" prefix)

            Returns:
                FlextResult with RFC-normalized SchemaAttribute

            """
            try:
                # Parse RFC baseline - hook _hook_post_parse_attribute() applies
                # OID-specific transformations (matching rules, syntax normalization)
                result = super()._parse_attribute(attr_definition)

                if not result.is_success:
                    return result

                # Unwrap parsed attribute (already has OID transformations via hook)
                attr_data = result.unwrap()

                # Preserve TARGET values AFTER transformations (applied by hook)
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
                    # Convert internal QuirkMetadata to public QuirkMetadata if needed
                    metadata_public = FlextLdifModels.QuirkMetadata.model_validate(
                        attr_data.metadata.model_dump(),
                    )
                    FlextLdifUtilities.Metadata.preserve_schema_formatting(
                        metadata_public,
                        attr_definition,
                    )

                    # Add target metadata (transformations applied by hook)
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
            r"""Write Oracle OID attribute definition (Phase 2: Denormalization).

            OID vs RFC Attribute Writing
            ============================
            This method converts RFC-normalized SchemaAttribute models back to
            Oracle OID format for LDIF output.

            Architecture Principle
            ----------------------
            - Parser: OID LDIF → RFC Models (normalization)
            - Writer: RFC Models → OID LDIF (denormalization)

            The OID writer ALWAYS denormalizes to OID format, regardless of
            the source server. For OID→OUD conversion, use RFC writer instead.

            Denormalization Pipeline
            ------------------------
            1. Copy model to avoid mutation
            2. Restore SOURCE values from metadata if available
            3. If no SOURCE metadata, apply RFC→OID mappings:
               a) Matching rules: caseIgnoreSubstringsMatch → caseIgnoreSubStringsMatch
               b) Syntax OIDs: RFC → OID proprietary
            4. Call RFC base writer with denormalized values

            Denormalization Rules
            ---------------------
            a) Matching Rules (Constants.MATCHING_RULE_RFC_TO_OID):
               RFC:  caseIgnoreSubstringsMatch (lowercase s)
               OID:  caseIgnoreSubStringsMatch (uppercase S)

            b) Syntax OIDs (Constants.SYNTAX_RFC_TO_OID):
               RFC:  1.3.6.1.4.1.1466.115.121.1.15 (Directory String)
               OID:  1.3.6.1.4.1.1466.115.121.1.1 (OID ACI List)

            Metadata Usage for Perfect Round-Trip
            -------------------------------------
            If metadata.extensions contains SOURCE values:
            - SCHEMA_SOURCE_MATCHING_RULES: {equality, substr, ordering}
            - SCHEMA_SOURCE_SYNTAX_OID: Original OID syntax

            These are used to restore exact original format.

            Example Input (RFC-normalized)
            ------------------------------
            SchemaAttribute(
                oid='2.16.840.1.113894.1.1.123',
                names=['orclTest'],
                syntax='1.3.6.1.4.1.1466.115.121.1.15',
                substr='caseIgnoreSubstringsMatch',  # RFC format
                metadata=FlextLdifModels.QuirkMetadata(
                    extensions={
                        FlextLdifConstants.MetadataKeys.SCHEMA_SOURCE_MATCHING_RULES: {
                            'substr': 'caseIgnoreSubStringsMatch'
                        },
                    }
                )
            )

            Example Output (OID Format)
            ---------------------------
            ( 2.16.840.1.113894.1.1.123
              NAME 'orclTest'
              SYNTAX 1.3.6.1.4.1.1466.115.121.1.1
              SUBSTR caseIgnoreSubStringsMatch )

            Args:
                attr_data: RFC-normalized SchemaAttribute model to write

            Returns:
                FlextResult with OID-formatted attribute definition string

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
                # Use constant for metadata key (DRY: avoid hardcoding)
                keys_to_remove = {meta_keys.SCHEMA_ORIGINAL_FORMAT}
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
        ) -> Union[str, list[str] | None]:
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
                        "OID→RFC: AUXILLARY → AUXILIARY (original_format)",
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

            # List comprehension with case normalization
            case_map = FlextLdifServersOid.Constants.ATTR_NAME_CASE_MAP
            return [
                case_map.get(attr_name.lower(), attr_name) for attr_name in attr_list
            ]

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
                # Hook _hook_post_parse_objectclass() called by RFC
                # Transforms: SUP/AUXILIARY, attribute name normalization

                # Ensure metadata is preserved with OID-specific information
                meta_keys = FlextLdifConstants.MetadataKeys
                key = meta_keys.SCHEMA_ORIGINAL_FORMAT
                if not oc_data.metadata:
                    oc_data.metadata = self.create_metadata(oc_definition.strip())
                elif not oc_data.metadata.extensions.get(key):
                    oc_data.metadata.extensions[key] = oc_definition.strip()

                # Attach timestamp metadata
                if oc_data.metadata:
                    oc_data.metadata.extensions[
                        FlextLdifConstants.Rfc.META_TRANSFORMATION_TIMESTAMP
                    ] = FlextUtilities.Generators.generate_iso_timestamp()

                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oc_data)

            except Exception as e:
                logger.exception(
                    "OID objectClass parsing failed",
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"OID objectClass parsing failed: {e}",
                )

        def _transform_attribute_for_write(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextLdifModels.SchemaAttribute:
            """Apply OID-specific attribute transformations before writing.

            IMPORTANT: Writer denormalization (RFC → OID) happens in _write_attribute.
            This hook should NOT re-normalize matching rules back to RFC.
            Only apply NAME normalization here.

            Args:
                attr_data: SchemaAttribute to transform (denormalized)

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

            # Apply invalid SUBSTR rule replacements using utility
            original_substr = fixed_substr
            fixed_substr = FlextLdifUtilities.Schema.replace_invalid_substr_rule(
                fixed_substr,
                FlextLdifServersOid.Constants.INVALID_SUBSTR_RULES,
            )
            if fixed_substr != original_substr:
                logger.debug(
                    "Replaced invalid SUBSTR rule",
                    attribute_name=attr_data.name,
                    attribute_oid=attr_data.oid,
                    original_substr=original_substr,
                    replacement_substr=fixed_substr,
                )

            # Check if this is a boolean attribute using utility
            is_boolean = FlextLdifUtilities.Schema.is_boolean_attribute(
                fixed_name,
                set(FlextLdifServersOid.Constants.BOOLEAN_ATTRIBUTES),
            )
            if is_boolean:
                logger.debug(
                    "Identified boolean attribute",
                    attribute_name=fixed_name,
                    attribute_oid=attr_data.oid,
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

        # REMOVED: _post_write_objectclass (36 lines dead code - never called)
        # Typo fix is handled in _normalize_auxiliary_typo during parsing

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
        r"""Oracle Internet Directory (OID) ACL implementation.

        OID vs RFC ACL Differences
        ==========================
        Oracle OID uses a proprietary ACL format (orclaci/orclentrylevelaci)
        that differs significantly from RFC 4876 (LDAP Access Control Model).
        This class parses OID ACLs and normalizes them to a common model.

        1. ACL ATTRIBUTE NAMES
        ----------------------
        RFC 4876 Standard:
            aci: access to ... by ...

        OID Proprietary:
            orclaci: access to Union[entry, attr]=(...) by subject (permissions)
            orclentrylevelaci: (same format, entry-level scope)

        2. ACL FORMAT STRUCTURE
        -----------------------
        OID ACL Syntax (from Oracle Fusion Middleware documentation):

            orclaci: access to <target> by <subject> (<permissions>)
            orclentrylevelaci: access to <target> by <subject> (<permissions>)

        Target Types:
            - entry: Entire entry
            - attr=(*): All attributes
            - attr=(cn,sn,mail): Specific attributes

        Subject Types:
            - *: Everyone (anonymous)
            - self: The entry itself
            - "dn": Specific user DN (quoted)
            - group="dn": Group DN
            - dnattr=(attrname): DN from attribute
            - guidattr=(attrname): GUID from attribute
            - groupattr=(attrname): Group from attribute

        3. OID-SPECIFIC PERMISSIONS
        ---------------------------
        Standard permissions (RFC-like):
            read, write, add, delete, search, compare

        OID extensions:
            browse: Combination of read + search
            auth: Authentication permission
            selfwrite: Self-modification permission
            proxy: Proxy access permission
            all: All permissions combined

        Negative permissions (deny specific rights):
            noread, nowrite, noadd, nodelete, nosearch, nocompare,
            nobrowse, noselfwrite

        4. ENTRY-LEVEL vs SUBTREE ACL
        -----------------------------
        OID distinguishes between:
            - orclaci: Applies to subtree (inherited)
            - orclentrylevelaci: Applies only to entry (not inherited)

        5. ACL PARSING PATTERNS
        -----------------------
        Constants.ACL_TYPE_PATTERN:
            r"^(Union[orclaci, orclentrylevelaci]):"

        Constants.ACL_TARGET_PATTERN:
            r"access to (Union[entry, attr]=\\(([^)]+)\\))"

        Constants.ACL_SUBJECT_PATTERN:
            r"by\\s+(group=\"[^\"]+\"|...)"

        Constants.ACL_PERMISSIONS_PATTERN:
            r"\\(([^)]+)\\)(?:\\s*$)"

        Example LDIF Input (OID)
        ========================
        dn: ou=People,dc=example,dc=com
        orclaci: access to entry by group="cn=Admins" (browse,add,delete)
        orclaci: access to attr=(*) by * (read,search)
        orclaci: access to attr=(userpassword) by self (write)
        orclentrylevelaci: access to entry by * (browse)

        Example Parsed Model
        ====================
        Acl(
            target_type='entry',
            target_attrs=None,
            subject_type='group_dn',
            subject='cn=Admins,dc=example,dc=com',
            permissions=['browse', 'add', 'delete'],
            scope='subtree',  # from orclaci
            metadata={FlextLdifConstants.MetadataKeys.ACL_ORIGINAL_FORMAT: '...', FlextLdifConstants.MetadataKeys.ACL_SOURCE_SERVER: 'oid'}
        )

        Acl(
            target_type='attr',
            target_attrs=['userpassword'],
            subject_type='self',
            subject='self',
            permissions=['write', 'compare'],
            scope='subtree',
            metadata={...}
        )

        References
        ----------
        - RFC 4876: A Configuration Profile Schema for LDAP Access Control
        - Oracle Fusion Middleware Administrator's Guide for OID
        - Oracle Directory Server Enterprise Edition Reference, Chapter "Access Control"

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

        # =====================================================================
        # METADATA CONFIGURATION
        # =====================================================================
        # Dataclass to consolidate _build_oid_acl_metadata parameters
        # Reduces 15 individual parameters to single config object
        @dataclass(frozen=True)
        class OidAclMetadataConfig:
            """Configuration for building OID ACL metadata.

            Consolidates 15 parameters into single dataclass for reduced complexity
            and improved parameter passing (Parameter Object pattern).

            Attributes:
                acl_line: Original ACL line
                oid_subject_type: OID subject type (user, group, dn_attr, etc.)
                rfc_subject_type: RFC-normalized subject type
                oid_subject_value: Original subject value
                target_dn: Target DN
                perms_dict: Permissions dictionary
                target_attrs: Target attributes (optional)
                acl_filter: OID filter expression (optional)
                acl_constraint: OID added_object_constraint (optional)
                bindmode: OID BINDMODE - auth/encryption (optional)
                deny_group_override: OID DenyGroupOverride flag (optional)
                append_to_all: OID AppendToAll flag (optional)
                bind_ip_filter: OID BINDIPFILTER expression (optional)
                constrain_to_added_object: OID constraintonaddedobject filter (optional)

            """

            acl_line: str
            oid_subject_type: str
            rfc_subject_type: str
            oid_subject_value: str
            target_dn: str
            perms_dict: dict[str, bool]
            target_attrs: list[str] | None = None
            acl_filter: str | None = None
            acl_constraint: str | None = None
            bindmode: str | None = None
            deny_group_override: bool | None = None
            append_to_all: bool | None = None
            bind_ip_filter: str | None = None
            constrain_to_added_object: str | None = None

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
        # These methods override the base class with Oracle OID-specific logic:
        # - can_handle_acl(): Detects orclaci/orclentrylevelaci formats
        # - parse_acl(): Normalizes Oracle OID ACL to RFC-compliant internal model
        # - write_acl(): Serializes RFC-compliant model to OID ACL format
        # - get_acl_attribute_name(): Returns "orclaci" (OID-specific, overridden)

        def can_handle_acl(self, acl_line: Union[str, FlextLdifModels].Acl) -> bool:
            """Check if this is an Oracle OID ACL.

            Detects Oracle OID ACL by checking for Oracle-specific ACL syntax patterns:
            - "access to <target> by <subject>" (Oracle OID ACL format)
            - "orclaci:" (LDIF attribute prefix)
            - "orclentrylevelaci:" (LDIF attribute prefix)

            OID ACL: access to [Union[entry, attr]] by <subject> (<perms>)

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
            # acl_line is str at this point (Union[str, Acl], and Acl was already checked)
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
                    extensions={
                        FlextLdifConstants.MetadataKeys.ACL_ORIGINAL_FORMAT: acl_line.strip(),
                    },
                )
            )
            return acl_data.model_copy(
                update={
                    "server_type": server_type,
                    "metadata": updated_metadata,
                },
            )

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            r"""Parse Oracle OID ACL string to RFC-compliant internal model.

            OID vs RFC ACL Parsing
            ======================
            This method extends RFC's `_parse_acl()` to handle OID-specific
            ACL formats while maintaining RFC compatibility.

            Parsing Strategy
            ----------------
            1. Try RFC parent parser first (handles standard ACIs)
            2. If OID-specific format detected, enhance with OID metadata
            3. Fall back to OID-specific parser for proprietary formats

            OID ACL Format (Input)
            ----------------------
            orclaci: access to <target> by <subject> (<permissions>)
            orclentrylevelaci: access to <target> by <subject> (<permissions>)

            Example Input:
                orclaci: access to entry by group="cn=Admins" (browse)
                orclaci: access to attr=(userpassword) by self (write)
                orclentrylevelaci: access to entry by * (browse)

            OID-Specific Features Parsed
            ----------------------------
            1. ACL Type Detection:
               - orclaci: Subtree scope (inherited)
               - orclentrylevelaci: Entry-level scope (not inherited)

            2. Target Extraction:
               - entry: Entire entry
               - attr=(*): All attributes
               - attr=(cn,sn,mail): Specific attributes

            3. Subject Detection:
               - *: Anonymous (everyone)
               - self: The entry itself
               - "dn": Specific user DN (quoted)
               - group="dn": Group membership
               - dnattr=(attr): DN from entry attribute
               - guidattr=(attr): GUID from entry attribute
               - groupattr=(attr): Group from entry attribute

            4. Permission Parsing:
               - Standard: browse, read, write, add, delete, search, compare
               - Extended: auth, selfwrite, proxy, all
               - Negations: noread, nowrite, noadd, nodelete, nosearch

            5. Filter Extraction:
               - filter=(objectClass=person)
               - Complex nested filters supported

            6. Constraint Extraction:
               - added_object_constraint=(objectClass=...)

            Output Model (RFC-normalized)
            -----------------------------
            Acl(
                permissions={'browse': True, 'add': True, 'delete': True},
                target='entry',
                target_attrs=None,
                subject='group',
                subject_dn='cn=Admins,dc=example,dc=com',
                scope='subtree',
                metadata=FlextLdifModels.QuirkMetadata(
                    server_type='oid',
                    extensions={
                        FlextLdifConstants.MetadataKeys.ACL_ORIGINAL_FORMAT: 'orclaci: access to entry by...',
                        'acl_type': 'orclaci',
                        ...
                    }
                )
            )

            Args:
                acl_line: Oracle OID ACL definition line from LDIF

            Returns:
                FlextResult with RFC-normalized Acl model

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

            # Not an OID ACL - use parent result or fall through
            if (
                parent_result.is_success
                and (acl_data := parent_result.unwrap())
                and not self.can_handle_acl(acl_line)
            ):
                return FlextResult[FlextLdifModels.Acl].ok(acl_data)

            # RFC parser failed - use OID-specific parsing
            return self._parse_oid_specific_acl(acl_line)

        # =====================================================================
        # OID-SPECIFIC ACL PARSING/FORMATTING METHODS
        # These methods contain OID server knowledge and MUST stay in this class
        # =====================================================================

        @staticmethod
        def _extract_oid_target(content: str) -> tuple[str | None, list[str]]:
            """Extract target DN and attributes from OID ACL.

            Args:
                content: OID ACL content string

            Returns:
                Tuple of (target_dn, attribute_list)

            """
            target_dn: str | None = None
            attributes: list[str] = []
            patterns = FlextLdifServersOid.Constants

            # Extract target DN using constant pattern
            target_match = re.search(
                patterns.ACL_TARGET_DN_EXTRACT,
                content,
                re.IGNORECASE,
            )
            if target_match:
                target_dn = target_match.group(1)

            # Extract target attributes using OID-specific pattern (attr=(...) format)
            # Try OID format first (attr=(cn,sn,mail))
            attr_match = re.search(
                patterns.ACL_TARGET_ATTR_OID_EXTRACT,
                content,
                re.IGNORECASE,
            )
            if attr_match:
                attr_str = attr_match.group(1)
                attributes = [a.strip() for a in attr_str.split(",")]

            return target_dn, attributes

        @staticmethod
        def _detect_oid_subject(content: str) -> str | None:
            """Detect OID ACL subject type by matching ACL_SUBJECT_PATTERNS.

            Args:
                content: OID ACL content string

            Returns:
                Subject type ("self", "user_dn", "group_dn", "dn_attr", "guid_attr", "group_attr") or None

            """
            if not content:
                return None

            const = FlextLdifServersOid.Constants

            # Check for subject type by matching ACL_SUBJECT_PATTERNS keys
            # This identifies what kind of subject is present in the OID ACL
            for pattern_key, (_, subject_type, _) in const.ACL_SUBJECT_PATTERNS.items():
                # Check if the pattern key (literal substring) is present in content
                if pattern_key.lower() in content.lower():
                    return subject_type

            return None

        @staticmethod
        def _parse_oid_permissions(content: str) -> dict[str, bool]:
            """Parse OID ACL permissions clause.

            Extracts OID permissions from ACL string and normalizes them using
            ACL_PERMISSION_MAPPING. Handles compound permissions (e.g., browse→read+search)
            and permission negation (e.g., nowrite→no_write).

            Args:
                content: OID ACL content string (e.g., "access to ... (read,write)")

            Returns:
                Permissions dict: normalized name → True (allow) / False (deny)
                E.g., {"read": True, "search": True, "browse": False}

            """
            permissions: dict[str, bool] = {}
            const = FlextLdifServersOid.Constants

            # Use OID-specific pattern to extract permissions from parentheses
            # OID format: (read,write) or (read,write,self_write)
            perm_match = re.search(const.ACL_PERMS_EXTRACT_OID, content, re.IGNORECASE)
            if perm_match:
                perms_str = perm_match.group(1)
                # Split by comma for OID format (not space-separated like RFC)
                raw_perms = [p.strip() for p in perms_str.split(",")]

                # Process each permission
                for raw_perm in raw_perms:
                    if not raw_perm:
                        continue

                    # Check for negative permission prefix
                    is_negative = raw_perm.lower().startswith("no")
                    perm_name = raw_perm

                    # Normalize using ACL_PERMISSION_MAPPING
                    if perm_name.lower() in const.ACL_PERMISSION_MAPPING:
                        # Get normalized permission names from mapping
                        mapped_names = const.ACL_PERMISSION_MAPPING[perm_name.lower()]
                        for mapped_name in mapped_names:
                            # Compound permissions map to multiple entries
                            # (e.g., browse → [read, search])
                            permissions[mapped_name] = not is_negative
                    else:
                        # Unknown permission - store as-is
                        # This preserves any server-specific extensions
                        permissions[perm_name.lower()] = not is_negative

            return permissions

        @staticmethod
        def _format_oid_target(target_dn: str, attributes: list[str]) -> str:
            r"""Format OID ACL target clause.

            Generates OID orclaci format: "entry" or "attr=(...)"
            NOT RFC format: "target=\"*\" targetattr=\"...\""

            Args:
                target_dn: Target DN string ("entry", "*", etc.)
                attributes: List of target attributes

            Returns:
                Formatted OID target clause (e.g. "entry" or "attr=(cn,mail)")

            """
            # Handle entry-level targets
            if not attributes or target_dn == "entry":
                return "entry"
            # Handle all-attributes target
            if len(attributes) == 1 and attributes[0] == "*":
                return "attr=(*)"
            # Handle specific attributes
            attrs_str = ",".join(attributes)
            return f"attr=({attrs_str})"

        @staticmethod
        def _clean_subject_value(subject_value: str) -> str:
            """Clean OID subject value by removing ldap:/// prefix and parser suffixes.

            Args:
                subject_value: Subject value with possible prefixes/suffixes

            Returns:
                Cleaned subject value

            """
            clean_value = subject_value

            # Strip ldap:/// prefix if present (comes from internal RFC storage)
            if clean_value.startswith("ldap:///"):
                clean_value = clean_value[8:]  # Remove "ldap:///" prefix
                # Also remove LDAP URL query parameters (e.g., ?scope=base, ?scope=sub)
                if "?" in clean_value:
                    clean_value = clean_value.split("?")[0]

            # Strip parser-added suffixes (#GROUPDN, #LDAPURL, #USERDN)
            if "#" in clean_value:
                # Remove any suffix after # that matches known parser suffixes
                suffixes_to_strip = {"#GROUPDN", "#LDAPURL", "#USERDN"}
                for suffix in suffixes_to_strip:
                    if clean_value.endswith(suffix):
                        clean_value = clean_value[: -len(suffix)]
                        break

            return clean_value

        @staticmethod
        def _format_oid_subject(subject_type: str, subject_value: str) -> str:
            r"""Format OID ACL subject clause in orclaci format.

            Generates OID orclaci format: "self", "*", "group=\"DN\"", "dnattr=(attr)", etc.
            NOT RFC format: "subject=\"userdn=*\""

            Args:
                subject_type: Subject type ("self", "anonymous", "group_dn", "dn_attr", etc.)
                subject_value: Subject value (DN, attribute name, etc., may have ldap:/// prefix or #SUFFIX from internal storage)

            Returns:
                Formatted OID subject clause (e.g. "self", "*", "group=\"cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com\"")

            """
            clean_value = FlextLdifServersOid._clean_subject_value(subject_value)

            match subject_type.lower():
                case "self":
                    return "self"
                case "anonymous" | "*":
                    return "*"
                case "group_dn" | "group":
                    # OID format: by group="DN"
                    return f'group="{clean_value}"'
                case "user_dn" | "user":
                    # OID format: by "DN"
                    return f'"{clean_value}"'
                case "dn_attr":
                    # OID format: by dnattr=(attribute)
                    return f"dnattr=({clean_value})"
                case "guid_attr":
                    # OID format: by guidattr=(attribute)
                    return f"guidattr=({clean_value})"
                case "group_attr":
                    # OID format: by groupattr=(attribute)
                    return f"groupattr=({clean_value})"
                case _:
                    # Default to user_dn style
                    return f'"{clean_value}"' if clean_value else "*"

        @staticmethod
        def _format_oid_permissions(permissions: dict[str, object]) -> str:
            """Format OID ACL permissions clause.

            OID uses simple comma-separated format: (write,compare,browse)
            NOT RFC format with allow/deny keywords.

            Args:
                permissions: Permissions dictionary (name -> True/False)

            Returns:
                Formatted OID permissions clause (e.g., "(write,compare)")

            """
            # Permission name mapping for OID format output
            # Maps internal names (with underscores) to OID format names
            permission_names = {
                "read": "read",
                "write": "write",
                "add": "add",
                "delete": "delete",
                "search": "search",
                "compare": "compare",
                "self_write": "selfwrite",
                "proxy": "proxy",
                "browse": "browse",
                "auth": "auth",
                "all": "all",
                "no_write": "nowrite",
                "no_add": "noadd",
                "no_delete": "nodelete",
                "no_browse": "nobrowse",
                "no_self_write": "noselfwrite",
            }

            # Collect only allowed permissions, mapping to OID format
            allowed_perms: list[str] = []
            for perm, allowed in permissions.items():
                if allowed:
                    # Map internal name to OID format name
                    oid_perm_name = permission_names.get(perm, perm)
                    allowed_perms.append(oid_perm_name)

            # Generate simple OID format: (perm1,perm2,perm3)
            if allowed_perms:
                return f"({','.join(allowed_perms)})"
            # Default if no permissions allowed - this shouldn't normally happen
            return "(none)"

        def _build_metadata_extensions(
            self,
            metadata: object | None,  # Accepts both domain and public types
        ) -> list[str]:
            """Build OID ACL extension clauses from metadata.

            Consolidates formatting of OID-specific metadata extensions:
            - Generic: filter, added_object_constraint
            - OID-specific: bindmode, DenyGroupOverride, AppendToAll, etc.

            Args:
                metadata: ACL metadata with extensions (domain or public model)

            Returns:
                List of formatted extension clauses

            """
            extensions: list[str] = []

            if not metadata:
                return extensions

            meta_extensions = getattr(metadata, "extensions", None)
            if not meta_extensions:
                return extensions

            meta_keys = FlextLdifConstants.MetadataKeys

            # Generic extensions (filter, constraint)
            if acl_filter := meta_extensions.get(meta_keys.ACL_FILTER):
                extensions.append(f"filter={acl_filter}")

            if acl_constraint := meta_extensions.get(meta_keys.ACL_CONSTRAINT):
                extensions.append(f"added_object_constraint=({acl_constraint})")

            # OID-specific extensions (validated against Oracle OID documentation)
            # BINDMODE: Authentication/encryption requirements
            if bindmode := meta_extensions.get(meta_keys.ACL_BINDMODE):
                extensions.append(f"bindmode=({bindmode})")

            # DenyGroupOverride: Prevents override by higher ACPs
            if meta_extensions.get(meta_keys.ACL_DENY_GROUP_OVERRIDE):
                extensions.append("DenyGroupOverride")

            # AppendToAll: Adds subject to all other ACIs
            if meta_extensions.get(meta_keys.ACL_APPEND_TO_ALL):
                extensions.append("AppendToAll")

            # BINDIPFILTER: IP-based access restriction
            if bind_ip_filter := meta_extensions.get(meta_keys.ACL_BIND_IP_FILTER):
                extensions.append(f"bindipfilter=({bind_ip_filter})")

            # constraintonaddedobject: Entry type constraints
            if constrain_to_added := meta_extensions.get(
                meta_keys.ACL_CONSTRAIN_TO_ADDED_OBJECT,
            ):
                extensions.append(f"constraintonaddedobject=({constrain_to_added})")

            return extensions

        @staticmethod
        def _normalize_to_dict(value: object) -> dict[str, str | int | bool]:
            """Normalize value to dict for model validation.

            Args:
                value: Pydantic model, dict, or other object

            Returns:
                Dictionary representation of value

            """
            if isinstance(value, dict):
                return value
            if hasattr(value, "model_dump") and callable(
                getattr(value, "model_dump", None),
            ):
                return value.model_dump()
            return {"subject_type": str(value)} if value else {}

        @staticmethod
        def _normalize_permissions_to_dict(
            permissions: object | None,
        ) -> dict[str, object]:
            """Normalize permissions to dict for formatting.

            Args:
                permissions: Permissions model, dict, or None

            Returns:
                Dictionary representation of permissions

            """
            if not permissions:
                return {}
            if isinstance(permissions, dict):
                # Convert dict to normalized format
                return {
                    "read": bool(permissions.get("read", False)),
                    "write": bool(permissions.get("write", False)),
                    "add": bool(permissions.get("add", False)),
                    "delete": bool(permissions.get("delete", False)),
                    "search": bool(permissions.get("search", False)),
                    "compare": bool(permissions.get("compare", False)),
                    "self_write": bool(permissions.get("self_write", False)),
                    "proxy": bool(permissions.get("proxy", False)),
                    "browse": bool(permissions.get("browse", False)),
                    "auth": bool(permissions.get("auth", False)),
                    "all": bool(permissions.get("all", False)),
                }
            if FlextRuntime.is_dict_like(permissions):
                raw_perms = dict(permissions)
                return {
                    "read": bool(raw_perms.get("read")),
                    "write": bool(raw_perms.get("write")),
                    "add": bool(raw_perms.get("add")),
                    "delete": bool(raw_perms.get("delete")),
                    "search": bool(raw_perms.get("search")),
                    "compare": bool(raw_perms.get("compare")),
                    "self_write": bool(raw_perms.get("self_write")),
                    "proxy": bool(raw_perms.get("proxy")),
                    "browse": bool(raw_perms.get("browse")),
                    "auth": bool(raw_perms.get("auth")),
                    "all": bool(raw_perms.get("all")),
                }
            if hasattr(permissions, "model_dump") and callable(
                getattr(permissions, "model_dump", None),
            ):
                raw_perms = permissions.model_dump()
                return {
                    "read": bool(raw_perms.get("read", False)),
                    "write": bool(raw_perms.get("write", False)),
                    "add": bool(raw_perms.get("add", False)),
                    "delete": bool(raw_perms.get("delete", False)),
                    "search": bool(raw_perms.get("search", False)),
                    "compare": bool(raw_perms.get("compare", False)),
                    "self_write": bool(raw_perms.get("self_write", False)),
                    "proxy": bool(raw_perms.get("proxy", False)),
                    "browse": bool(raw_perms.get("browse", False)),
                    "auth": bool(raw_perms.get("auth", False)),
                    "all": bool(raw_perms.get("all", False)),
                }
            return {}

        def _prepare_subject_value_with_suffix(
            self,
            subject_value: str,
            oid_subject_type: str,
        ) -> str:
            """Prepare subject value with OID-specific suffix if needed.

            Args:
                subject_value: Original subject value
                oid_subject_type: OID subject type

            Returns:
                Subject value with suffix if applicable

            """
            if (
                oid_subject_type in {"dn_attr", "guid_attr", "group_attr"}
                and "#" not in subject_value
            ):
                type_suffix = {
                    "dn_attr": "LDAPURL",
                    "guid_attr": "USERDN",
                    "group_attr": "GROUPDN",
                }
                return f"{subject_value}#{type_suffix[oid_subject_type]}"
            return subject_value

        def _prepare_subject_and_permissions_for_write(
            self,
            acl_subject: object,  # Accepts both domain and public types
            acl_permissions: object | None,  # Accepts both domain and public types
            metadata: object | None,  # Accepts both domain and public types
        ) -> tuple[str, str]:
            """Prepare OID subject and permissions clauses for ACL write.

            Consolidates subject mapping, suffix handling, permissions formatting.

            Args:
                acl_subject: RFC-compliant subject (domain or public model)
                acl_permissions: Permissions model, dict, or None
                metadata: ACL metadata for source subject type (domain or public)

            Returns:
                Tuple of (subject_clause, permissions_clause)

            """
            # Convert to public models using helper
            subject_dict = self._normalize_to_dict(acl_subject)
            subject_public = FlextLdifModels.AclSubject.model_validate(subject_dict)

            # Normalize metadata
            metadata_public: FlextLdifModels.QuirkMetadata | None = None
            if metadata:
                metadata_dict = self._normalize_to_dict(metadata)
                metadata_public = FlextLdifModels.QuirkMetadata.model_validate(
                    metadata_dict,
                )

            # Map RFC subject to OID subject type
            oid_subject_type = self._map_rfc_subject_to_oid(
                subject_public,
                metadata_public,
            )

            # Prepare subject value with suffix if needed
            subject_value = self._prepare_subject_value_with_suffix(
                subject_public.subject_value,
                oid_subject_type,
            )

            # Format subject clause
            subject_clause = self._format_oid_subject(
                oid_subject_type,
                subject_value,
            )

            # Convert and format permissions
            permissions_dict = self._normalize_permissions_to_dict(acl_permissions)
            permissions_clause = self._format_oid_permissions(permissions_dict)

            return subject_clause, permissions_clause

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
            config: FlextLdifServersOid.Acl.OidAclMetadataConfig,
        ) -> dict[str, str | int | bool]:
            """Build metadata extensions for OID ACL with Oracle-specific features.

            Delegates to FlextLdifUtilities.Metadata.build_acl_metadata_complete()
            for unified ACL metadata construction.

            Args:
                config: OidAclMetadataConfig with all ACL metadata parameters

            Returns:
                Metadata extensions dict for zero-data-loss preservation

            """
            return FlextLdifUtilities.Metadata.build_acl_metadata_complete(
                acl_line=config.acl_line,
                server_type="oid",
                subject_type=config.oid_subject_type,
                subject_value=config.oid_subject_value,
                target_dn=config.target_dn,
                target_attrs=config.target_attrs,
                permissions=config.perms_dict,
                target_subject_type=config.rfc_subject_type,
                acl_filter=config.acl_filter,
                acl_constraint=config.acl_constraint,
                bindmode=config.bindmode,
                deny_group_override=config.deny_group_override is True,
                append_to_all=config.append_to_all is True,
                bind_ip_filter=config.bind_ip_filter,
                constrain_to_added_object=config.constrain_to_added_object,
                target_key=FlextLdifServersOid.Constants.OID_ACL_SOURCE_TARGET,
            )

        def _parse_oid_specific_acl(
            self,
            acl_line: str,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Parse OID-specific ACL format when RFC parser fails."""
            # OID ACL format: orclaci: access to [Union[entry, attr]=(...)]
            #   [by subject (permissions)] [filter=(...)] [added_object_constraint=()]
            try:
                # Extract target using OID-specific method
                target_dn, target_attrs = self._extract_oid_target(acl_line)
                # Default to "entry" if no explicit target DN specified
                if not target_dn:
                    target_dn = "entry"

                # Detect subject using OID-specific method
                oid_subject_type = self._detect_oid_subject(acl_line)
                # Extract subject value using DRY utility (OUD pattern)
                oid_subject_value: str | None = None
                if oid_subject_type:
                    for (
                        regex,
                        subj_type,
                        _,
                    ) in FlextLdifServersOid.Constants.ACL_SUBJECT_PATTERNS.values():
                        if subj_type == oid_subject_type and regex:
                            oid_subject_value = (
                                FlextLdifUtilities.ACL.extract_component(
                                    acl_line,
                                    regex,
                                    group=1,
                                )
                            )
                            if oid_subject_value:
                                break
                    oid_subject_value = oid_subject_value or "*"
                else:
                    oid_subject_type = "self"
                    oid_subject_value = "self"

                # Map OID subject types to RFC subject types
                rfc_subject_type, rfc_subject_value = self._map_oid_subject_to_rfc(
                    oid_subject_type,
                    oid_subject_value,
                )

                # Parse permissions using OID-specific method
                perms_dict = self._parse_oid_permissions(acl_line)

                # Extract filter and constraint using DRY utility (OUD pattern)
                acl_filter = FlextLdifUtilities.ACL.extract_component(
                    acl_line,
                    FlextLdifServersOid.Constants.ACL_FILTER_PATTERN,
                    group=1,
                )
                acl_constraint = FlextLdifUtilities.ACL.extract_component(
                    acl_line,
                    FlextLdifServersOid.Constants.ACL_CONSTRAINT_PATTERN,
                    group=1,
                )

                # Extract OID-specific extensions using DRY utility
                bindmode = FlextLdifUtilities.ACL.extract_component(
                    acl_line,
                    FlextLdifServersOid.Constants.ACL_BINDMODE_PATTERN,
                    group=1,
                )
                deny_group_override = (
                    FlextLdifUtilities.ACL.extract_component(
                        acl_line,
                        FlextLdifServersOid.Constants.ACL_DENY_GROUP_OVERRIDE_PATTERN,
                    )
                    is not None
                )
                append_to_all = (
                    FlextLdifUtilities.ACL.extract_component(
                        acl_line,
                        FlextLdifServersOid.Constants.ACL_APPEND_TO_ALL_PATTERN,
                    )
                    is not None
                )
                bind_ip_filter = FlextLdifUtilities.ACL.extract_component(
                    acl_line,
                    FlextLdifServersOid.Constants.ACL_BIND_IP_FILTER_PATTERN,
                    group=1,
                )
                constrain_to_added_object = FlextLdifUtilities.ACL.extract_component(
                    acl_line,
                    FlextLdifServersOid.Constants.ACL_CONSTRAIN_TO_ADDED_PATTERN,
                    group=1,
                )

                # Build metadata extensions using config object
                config = self.OidAclMetadataConfig(
                    acl_line=acl_line,
                    oid_subject_type=oid_subject_type,
                    rfc_subject_type=rfc_subject_type,
                    oid_subject_value=oid_subject_value,
                    perms_dict=perms_dict,
                    target_dn=target_dn,
                    target_attrs=target_attrs,
                    acl_filter=acl_filter,
                    acl_constraint=acl_constraint,
                    bindmode=bindmode,
                    deny_group_override=deny_group_override,
                    append_to_all=append_to_all,
                    bind_ip_filter=bind_ip_filter,
                    constrain_to_added_object=constrain_to_added_object,
                )
                extensions = self._build_oid_acl_metadata(config)

                # Create ACL model with parsed data (Python 3.13: cleaner dict creation)
                # Use RFC name (aci) for Entry model (OID → RFC conversion)
                # Type narrowing: ServerTypes.OID is already ServerType
                server_type = FlextLdifConstants.ServerTypes.OID

                # Architecture: Filter permissions to RFC-compliant only
                # Server-specific permissions (like OID's "none") are preserved in metadata.extensions
                # via build_acl_metadata_complete(permissions=config.perms_dict) above
                rfc_compliant_perms = (
                    FlextLdifModels.AclPermissions.get_rfc_compliant_permissions(
                        perms_dict
                    )
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
                    permissions=FlextLdifModels.AclPermissions(**rfc_compliant_perms),
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

        # REMOVED: _get_oid_patterns (36 lines dead code - never called)
        # Constants.ACL_*_PATTERN are used directly where needed

        def convert_rfc_acl_to_aci(
            self,
            rfc_acl_attrs: dict[str, list[str]],
        ) -> FlextResult[dict[str, list[str]]]:
            """Convert RFC ACL format to Oracle OID orclaci format.

            Returns RFC format unchanged (RFC ACLs are compatible with OID).

            Args:
                rfc_acl_attrs: ACL attributes in RFC format

            Returns:
                FlextResult with RFC ACL attributes (unchanged, compatible with OID)

            """
            return FlextResult.ok(rfc_acl_attrs)

        def _write_acl(
            self,
            acl_data: FlextLdifModels.Acl,
            _format_option: str | None = None,
        ) -> FlextResult[str]:
            r"""Write ACL to OID orclaci format (Phase 2: Denormalization).

            OID vs RFC ACL Writing
            ======================
            This method converts RFC-normalized Acl models back to Oracle OID
            orclaci format for LDIF output.

            Output Format (OID)
            -------------------
            orclaci: access to <target> by <subject> (<permissions>)

            Writing Strategy
            ----------------
            1. If raw_acl in OID format exists, use it directly (round-trip)
            2. Otherwise, build OID format from RFC-normalized model:
               a) Add ACL type prefix (orclaci:)
               b) Format target clause
               c) Format subject clause
               d) Format permissions clause
               e) Add metadata extensions

            Input Model (RFC-normalized)
            ----------------------------
            Acl(
                permissions={'browse': True, 'add': True},
                target=AclTarget(target_dn='entry', attributes=None),
                subject=AclSubject(type='group', dn='cn=Admins,...'),
                scope='subtree',
                metadata=FlextLdifModels.QuirkMetadata(server_type='oid', ...)
            )

            Output (OID Format)
            -------------------
            orclaci: access to entry by group="cn=Admins,dc=example,dc=com" (browse,add)

            Format Components
            -----------------
            1. ACL Type: orclaci: | orclentrylevelaci:
            2. Access To: "access to"
            3. Target:
               - entry → "entry"
               - attr=(*) → "attr=(*)"
               - attr=(cn,sn) → "attr=(cn,sn)"
            4. By: "by"
            5. Subject:
               - * → "*"
               - self → "self"
               - user DN → "\"cn=user,...\""
               - group → "group=\"cn=group,...\""
            6. Permissions: "(browse,add,delete)"

            Metadata Restoration
            --------------------
            If metadata.extensions contains original OID format details,
            they are used to reconstruct the exact original format:
            - acl_type: orclaci vs orclentrylevelaci
            - original_permissions: Original permission order
            - filter: Original filter expression
            - constraint: Original constraint expression

            Args:
                acl_data: RFC-normalized Acl model to write
                _format_option: Formatting option (unused, OID uses standard format)

            Returns:
                FlextResult with OID orclaci formatted string

            """
            # If raw_acl is available and already in OID format, use it
            if acl_data.raw_acl and acl_data.raw_acl.startswith(
                FlextLdifServersOid.Constants.ORCLACI + ":",
            ):
                return FlextResult[str].ok(acl_data.raw_acl)

            # Build orclaci format using consolidated helpers
            acl_parts = [
                FlextLdifServersOid.Constants.ORCLACI + ":",
                FlextLdifServersOid.Constants.ACL_ACCESS_TO,
            ]

            # Add target if available
            if acl_data.target:
                target_public = FlextLdifModels.AclTarget.model_validate(
                    acl_data.target.model_dump(),
                )
                acl_parts.append(
                    self._format_oid_target(
                        target_public.target_dn,
                        target_public.attributes or [],
                    ),
                )

            # Format subject and permissions if available (consolidated in helper)
            if acl_data.subject:
                subject_clause, permissions_clause = (
                    self._prepare_subject_and_permissions_for_write(
                        acl_data.subject,
                        acl_data.permissions,
                        acl_data.metadata,
                    )
                )
                acl_parts.extend(
                    [
                        FlextLdifServersOid.Constants.ACL_BY,
                        subject_clause,
                        permissions_clause,
                    ],
                )

            # Add metadata extensions (consolidated in helper)
            acl_parts.extend(self._build_metadata_extensions(acl_data.metadata))

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
            source_subject_type_raw = metadata.extensions.get(
                meta_keys.ACL_SOURCE_SUBJECT_TYPE,
            )
            if source_subject_type_raw is None or isinstance(
                source_subject_type_raw,
                str,
            ):
                return source_subject_type_raw
            msg = f"Expected Optional[str], got {type(source_subject_type_raw)}"
            raise TypeError(msg)

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
            # Detect group DN by checking if DN path contains "cn=groups"
            # (e.g., cn=REDACTED_LDAP_BIND_PASSWORDs,cn=groups,dc=example,dc=com indicates a group)
            if "cn=groups" in rfc_subject_value.lower():
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

            # Map RFC → OID for write (using match/case for clarity)
            match rfc_subject_type:
                case "self":
                    return "self"
                case "anonymous":
                    return "*"
                case rfc_type if rfc_subject_value == "*":
                    return "*"
                case rfc_type if rfc_type in {
                    "dn_attr",
                    "guid_attr",
                    "group_attr",
                    "group_dn",
                    "user_dn",
                }:
                    # Return attribute-based types as-is
                    return rfc_type
                case "bind_rules" | "group":
                    # Map bind_rules/group to OID-specific type
                    return self._map_bind_rules_to_oid(
                        rfc_subject_value,
                        source_subject_type,
                    )
                case _:
                    # Default fallback
                    return source_subject_type or "user_dn"

    class Entry(FlextLdifServersRfc.Entry):
        r"""Oracle Internet Directory (OID) Entry implementation.

        OID vs RFC Entry Differences
        ============================
        Oracle OID exports entries in a format that deviates from RFC 2849/4517
        in several ways. This class normalizes OID-specific formats to
        RFC-compliant structures during parsing (Phase 1), and denormalizes
        back to OID format when writing (Phase 2).

        1. BOOLEAN ATTRIBUTE FORMAT
        ---------------------------
        RFC 4517 Section 3.3.3 (Boolean):
            Boolean = "TRUE" / "FALSE"

        OID Proprietary Format (Oracle Fusion Middleware):
            Boolean = "0" / "1"
            - "0" = FALSE
            - "1" = TRUE

        OID Boolean Attributes (Constants.BOOLEAN_ATTRIBUTES):
            - orclIsEnabled: Account enabled flag
            - orclSAMLEnable: SAML authentication enabled
            - orclSSLEnable: SSL/TLS enabled
            - orclIsVisible: Entry visibility
            - orclPasswordVerify: Password verification
            - orclAccountLocked: Account lockout status
            - orclPwdMustChange: Force password change

        Transformation Example:
            Input (OID LDIF):
                orclIsEnabled: 1
                orclAccountLocked: 0

            Output (RFC-normalized):
                orclIsEnabled: TRUE
                orclAccountLocked: FALSE

        2. ACL ATTRIBUTE NAMES
        ----------------------
        RFC 4876 / Draft-ietf-ldapext-aci (Standard ACI):
            aci: (target) (version X.X; acl "name"; action;)

        OID Proprietary Names (Oracle Internet Directory):
            orclaci: access to <target> by <subject> (<perms>)
            orclentrylevelaci: access to <target> by <subject> (<perms>)

        Transformation (Parsing):
            orclaci → aci
            orclentrylevelaci → aci

        Both OID ACL attributes are normalized to RFC "aci" during parsing.
        Original names are preserved in metadata for round-trip support.

        3. SCHEMA DN NORMALIZATION
        --------------------------
        RFC 4512 Section 4.2 (Subschema Subentry):
            Recommended DN: cn=schema (or cn=Subschema)

        OID Proprietary Schema DN:
            cn=subschemasubentry

        Transformation:
            cn=subschemasubentry → cn=schema

        This enables cross-server schema comparison and migration.

        4. OID-SPECIFIC OPERATIONAL ATTRIBUTES
        --------------------------------------
        OID adds proprietary operational attributes not in RFC 4512:
            - orclguid: Oracle-generated GUID (128-bit)
            - orclnormdn: Normalized DN (internal use)
            - orclaci: Access control list (subtree scope)
            - orclentrylevelaci: Entry-level ACL (no inheritance)
            - orclmodifiersname: Last modifier DN
            - orclmodifytimestamp: Modification timestamp (OID format)
            - orclcreatorsname: Creator DN
            - orclcreatetimestamp: Creation timestamp (OID format)

        These are preserved during parsing but flagged as operational
        in metadata for filtering during migration.

        5. RFC COMPLIANCE VALIDATION
        ----------------------------
        OID allows configurations that violate RFC 4512:

        a) Multiple Structural ObjectClasses:
            RFC 4512 Section 2.4.1:
                "An entry's objectClasses form a hierarchy..."
                "Exactly one structural objectClass chain must exist"

            OID allows (non-RFC):
                objectClass: person
                objectClass: organizationalUnit
                (Two structural classes = RFC violation)

            This class detects and flags such violations in metadata.

        b) Invalid Attributes for ObjectClass:
            RFC 4519 defines allowed attributes per objectClass.

            OID allows (non-RFC):
                objectClass: domain
                cn: Example    (cn not allowed by RFC 4519 domain)

            Such conflicts are detected and stored in metadata.

        6. DN CLEANING AND NORMALIZATION
        --------------------------------
        OID DNs may contain non-RFC characters or spacing:
            Input:  "cn= John Doe , ou=People,dc=example,dc=com"
            Output: "cn=John Doe,ou=People,dc=example,dc=com"

        Cleaning operations (via FlextLdifUtilities.DN):
            - Remove extra whitespace around RDN separators
            - Normalize attribute name casing (CN → cn)
            - Remove trailing separators

        7. METADATA TRACKING (ROUND-TRIP SUPPORT)
        -----------------------------------------
        All transformations are tracked in Entry.metadata for perfect
        round-trip support (OID → RFC → OID):

        metadata.extensions:
            - original_attributes_complete: Raw attributes before conversion
            - boolean_conversions: {attr: {original: [...], converted: [...]}}
            - oid_converted_attrs: List of converted attribute names
            - attribute_name_conversions: {orclaci: aci, ...}

        metadata.original_format_details:
            - original_dn: Raw DN before cleaning
            - original_dn_line: Raw "dn:" line from LDIF
            - original_attr_lines: Raw attribute lines from LDIF
            - boolean_format: "0/1"
            - server_type: "oid"

        Example LDIF Input (OID)
        ========================
        dn: cn=REDACTED_LDAP_BIND_PASSWORD,ou=People,dc=example,dc=com
        objectClass: person
        objectClass: organizationalPerson
        objectClass: orcluser
        cn: REDACTED_LDAP_BIND_PASSWORD
        sn: Administrator
        orclIsEnabled: 1
        orclAccountLocked: 0
        orclaci: access to entry by self (write)
        orclguid: 1234567890ABCDEF

        Example Parsed Entry (RFC-normalized)
        =====================================
        Entry(
            dn=DistinguishedName(value="cn=REDACTED_LDAP_BIND_PASSWORD,ou=People,dc=example,dc=com"),
            attributes=LdifAttributes(
                attributes={
                    "objectClass": ["person", "organizationalPerson", "orcluser"],
                    "cn": ["REDACTED_LDAP_BIND_PASSWORD"],
                    "sn": ["Administrator"],
                    "orclIsEnabled": ["TRUE"],      # Converted from "1"
                    "orclAccountLocked": ["FALSE"], # Converted from "0"
                    "aci": ["access to entry by self (write)"],  # Renamed
                    "orclguid": ["1234567890ABCDEF"],
                }
            ),
            metadata=QuirkMetadata(
                server_type="oid",
                extensions={
                    FlextLdifConstants.MetadataKeys.CONVERSION_BOOLEAN_CONVERSIONS: {
                        "orclIsEnabled": {FlextLdifConstants.MetadataKeys.CONVERSION_ORIGINAL_VALUE: ["1"], FlextLdifConstants.MetadataKeys.CONVERSION_CONVERTED_VALUE: ["TRUE"]},
                        "orclAccountLocked": {FlextLdifConstants.MetadataKeys.CONVERSION_ORIGINAL_VALUE: ["0"], FlextLdifConstants.MetadataKeys.CONVERSION_CONVERTED_VALUE: ["FALSE"]},
                    },
                    FlextLdifConstants.MetadataKeys.CONVERSION_ATTRIBUTE_NAME_CONVERSIONS: {"orclaci": "aci"},
                    ...
                }
            )
        )

        Oracle Documentation References
        ================================
        - Oracle Fusion Middleware Administrator's Guide for Oracle Internet Directory:
          https://docs.oracle.com/cd/E29127_01/doc.111170/e28967/toc.htm
        - Oracle Directory Services LDIF Export Guide:
          https://docs.oracle.com/cd/E28280_01/REDACTED_LDAP_BIND_PASSWORD.1111/e10029/export_ldif.htm
        - Oracle Internet Directory Attribute Reference:
          https://docs.oracle.com/cd/E28280_01/REDACTED_LDAP_BIND_PASSWORD.1111/e10029/oid_schema_elements.htm

        """

        def _hook_transform_entry_raw(
            self,
            dn: str,
            attrs: dict[str, list[str]],
        ) -> FlextResult[tuple[str, dict[str, list[str]]]]:
            """Transform OID-specific DN and attributes before RFC parsing.

            OID-Specific Transformations:
            1. Schema DN: cn=subschemasubentry → cn=schema (RFC standard)
            2. DN cleaning: Normalize whitespace and RDN separators

            This hook enables OID entries to be parsed using RFC's generic
            _parse_entry without requiring a full method override.

            Args:
                dn: Original OID distinguished name
                attrs: Original OID attributes dictionary

            Returns:
                FlextResult with tuple of (normalized_dn, attrs)

            """
            # Clean DN using utility
            cleaned_dn, _ = FlextLdifUtilities.DN.clean_dn_with_statistics(dn)

            # Normalize OID schema DN to RFC format
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

            return FlextResult.ok((normalized_dn, attrs))

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
            Union[dict[str, dict[str, list[str], str]]],
        ]:
            """Convert OID boolean attribute values to RFC format.

            OID uses "0"/"1" for boolean values, RFC4517 requires "TRUE"/"FALSE".
            Uses utilities.py for conversion (DRY principle).

            Args:
                entry_attributes: Entry attributes mapping

            Returns:
                Tuple: (converted_attrs, converted_set, boolean_conversions)

            """
            boolean_attributes = FlextLdifServersOid.Constants.BOOLEAN_ATTRIBUTES
            boolean_attr_names = {attr.lower() for attr in boolean_attributes}

            # Use utilities.py for conversion (OID→RFC: "0/1" → "TRUE/FALSE")
            # Type narrowing: convert dict[str, list[str]] to compatible type
            # The utility accepts Union[dict[str, list[str], list[bytes]] | Union[bytes, str]]
            # and dict[str, list[str]] is compatible (list[str] is a subtype)
            converted_attrs_for_util: Union[
                dict[str, list[str], list[bytes]] | Union[bytes, str],
            ] = dict(entry_attributes.items())
            # Use constants for boolean format strings (DRY: avoid hardcoding)
            source_format = f"{FlextLdifServersOid.Constants.ZERO_OID}/{FlextLdifServersOid.Constants.ONE_OID}"
            target_format = f"{FlextLdifConstants.BooleanFormats.FALSE_RFC}/{FlextLdifConstants.BooleanFormats.TRUE_RFC}"
            converted_attributes = FlextLdifUtilities.Entry.convert_boolean_attributes(
                converted_attrs_for_util,
                boolean_attr_names,
                source_format=source_format,
                target_format=target_format,
            )

            # Track conversions for metadata
            converted_attrs: set[str] = set()
            boolean_conversions: Union[dict[str, dict[str, list[str], str]]] = {}

            for attr_name, attr_values in entry_attributes.items():
                if attr_name.lower() in boolean_attr_names:
                    original_values = list(attr_values)
                    converted_values = converted_attributes.get(
                        attr_name,
                        original_values,
                    )

                    if converted_values != original_values:
                        converted_attrs.add(attr_name)
                        # Track conversion for perfect round-trip
                        # Use constants for format strings (DRY: avoid hardcoding)
                        original_format_str = f"{FlextLdifServersOid.Constants.ZERO_OID}/{FlextLdifServersOid.Constants.ONE_OID}"
                        converted_format_str = f"{FlextLdifConstants.BooleanFormats.FALSE_RFC}/{FlextLdifConstants.BooleanFormats.TRUE_RFC}"
                        # Use standardized nested metadata keys (DRY: avoid hardcoding)
                        mk_conv = FlextLdifConstants.MetadataKeys
                        boolean_conversions[attr_name] = {
                            mk_conv.CONVERSION_ORIGINAL_VALUE: original_values,
                            mk_conv.CONVERSION_CONVERTED_VALUE: converted_values,
                            "conversion_type": "boolean_oid_to_rfc",
                            FlextLdifConstants.MetadataKeys.ORIGINAL_FORMAT: original_format_str,
                            "converted_format": converted_format_str,
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
                    reason=f"OID ACL ({original_name}) → RFC 2256 (aci)",
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
        ) -> tuple[list[str], list[dict[str, str | int]]]:
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

            structural_str = ", ".join(sorted(found_structural))
            rfc_violations: list[str] = (
                [f"Multiple structural objectClasses: {structural_str}"]
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
            attribute_conflicts: list[dict[str, str]] = [
                {
                    "attribute": attr_name,
                    "values": converted_attributes[attr_name],
                    "reason": f"'{attr_name}' not allowed by RFC 4519 domain",
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
            """Normalize schema attribute strings (attributetypes, objectclasses).

            Applies OID-specific normalizations to schema definition strings stored
            as attribute values. Fixes typos and normalizes matching rules in schema
            entries before they are parsed into SchemaAttribute/SchemaObjectClass.

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
            # Use SCHEMA_FILTERABLE_FIELDS which already contains lowercase names
            schema_attrs = FlextLdifServersOid.Constants.SCHEMA_FILTERABLE_FIELDS

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

        # ===== PHASE 2: DENORMALIZATION VIA HOOK OVERRIDE =====
        # ARCHITECTURE: Override RFC's _restore_entry_from_metadata() hook
        # to apply OID-specific denormalization. Keeps code in RFC base class,
        # OID only provides OID-specific behavior via override.

        def _restore_single_attribute(
            self,
            attr_name: str,
            attr_values: list[str],
            original_attrs: object | None,
        ) -> tuple[str, list[str]]:
            """Restore attribute from metadata or apply denormalization.

            Attempts to find original attribute name/values from metadata. If not found,
            applies OID denormalization rule (aci → orclaci).

            Args:
                attr_name: Current (normalized) attribute name
                attr_values: Current attribute values
                original_attrs: Original attributes dict from metadata (optional)

            Returns:
                Tuple of (restored_attr_name, restored_attr_values)

            """
            # Try to find original attribute in metadata
            if original_attrs and FlextRuntime.is_dict_like(original_attrs):
                for orig_name, orig_values in original_attrs.items():
                    if self._normalize_attribute_name(str(orig_name)) == attr_name:
                        # Found original - restore it
                        if FlextRuntime.is_list_like(orig_values):
                            # Type narrowing: is_list_like guarantees it's iterable
                            restored_values = [str(v) for v in orig_values]
                        else:
                            restored_values = [str(orig_values)]
                        return str(orig_name), restored_values

            # Not in metadata - apply denormalization rule
            denorm_name = (
                FlextLdifServersOid.Constants.ORCLACI
                if attr_name.lower()
                == FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME.lower()
                else attr_name
            )
            return denorm_name, attr_values

        def _denormalize_oid_attributes_for_output(
            self,
            attrs: dict[str, list[str]],
            metadata: FlextLdifModels.QuirkMetadata | None,
        ) -> dict[str, list[str]]:
            """Denormalize RFC attributes to OID format.

            Restores original attribute names from metadata if available,
            otherwise applies OID denormalization rules (e.g., aci → orclaci).

            Uses FlextLdifConstants.MetadataKeys.ORIGINAL_ATTRIBUTES_COMPLETE
            for metadata key standardization.
            """
            mk = FlextLdifConstants.MetadataKeys
            original_attrs = (
                metadata.extensions.get(mk.ORIGINAL_ATTRIBUTES_COMPLETE)
                if metadata and metadata.extensions
                else None
            )
            denormalized: dict[str, list[str]] = {}
            for attr_name, attr_values in attrs.items():
                restored_name, restored_values = self._restore_single_attribute(
                    attr_name,
                    attr_values,
                    original_attrs,
                )
                denormalized[restored_name] = restored_values
            return denormalized

        def _extract_boolean_conversions_from_metadata(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> Union[dict[str, dict[str, list[str], str]]]:
            """Extract boolean conversions from entry metadata.

            Extracts from nested structure: CONVERTED_ATTRIBUTES[CONVERSION_BOOLEAN_CONVERSIONS].

            Args:
                entry_data: Entry model with metadata

            Returns:
                Dictionary of boolean conversions by attribute name

            """
            mk = FlextLdifConstants.MetadataKeys
            boolean_conversions: Union[dict[str, dict[str, list[str], str]]] = {}

            if not (entry_data.metadata and entry_data.metadata.extensions):
                return boolean_conversions

            converted_attrs_data = entry_data.metadata.extensions.get(
                mk.CONVERTED_ATTRIBUTES,
            )
            # Extract from nested structure: CONVERTED_ATTRIBUTES[CONVERSION_BOOLEAN_CONVERSIONS]
            if isinstance(converted_attrs_data, dict):
                boolean_conversions_obj = converted_attrs_data.get(
                    mk.CONVERSION_BOOLEAN_CONVERSIONS,
                    {},
                )
                if isinstance(boolean_conversions_obj, dict):
                    boolean_conversions = boolean_conversions_obj

            return boolean_conversions

        def _restore_boolean_attribute_from_metadata(
            self,
            attr_name: str,
            conv_data: Union[dict[str, list[str], str]],
            restored_attrs: dict[str, list[str]],
        ) -> bool:
            """Restore single boolean attribute from conversion metadata.

            Args:
                attr_name: Attribute name to restore
                conv_data: Conversion metadata for the attribute
                restored_attrs: Dictionary to update with restored value

            Returns:
                True if restoration was successful, False otherwise

            """
            mk = FlextLdifConstants.MetadataKeys

            converted_val_list = conv_data.get(mk.CONVERSION_CONVERTED_VALUE, [])
            if not converted_val_list:
                return False

            # Map RFC boolean (TRUE/FALSE) → OID format (1/0)
            rfc_value = converted_val_list[0] if converted_val_list else ""
            oid_value = FlextLdifServersOid.Constants.RFC_TO_OID.get(
                rfc_value,
                rfc_value,  # Fallback to RFC value if not in map
            )
            restored_attrs[attr_name] = [oid_value]
            logger.debug(
                "Restored OID boolean format from metadata",
                attribute_name=attr_name,
                rfc_value=rfc_value,
                oid_value=oid_value,
                operation="_restore_boolean_values_to_oid",
            )
            return True

        def _restore_boolean_values_to_oid(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Restore OID boolean format from RFC format (RFC → OID: TRUE/FALSE → 0/1).

            Overrides RFC's _restore_boolean_values() to convert RFC 4517 boolean format
            ("TRUE"/"FALSE") back to OID format ("1"/"0") during write.

            Uses FlextLdifServersOid.Constants for boolean format constants.
            Uses FlextLdifUtilities.Entry for conversion (DRY principle).

            Args:
                entry_data: Entry model with RFC-formatted boolean attributes

            Returns:
                Entry with OID-formatted boolean attributes if conversions exist

            """
            if not entry_data.attributes:
                return entry_data

            # Extract boolean conversions from metadata
            boolean_conversions = self._extract_boolean_conversions_from_metadata(
                entry_data,
            )
            if not boolean_conversions:
                return entry_data

            # Boolean attribute names for matching
            boolean_attr_names = {
                attr.lower()
                for attr in FlextLdifServersOid.Constants.BOOLEAN_ATTRIBUTES
            }

            # Restore boolean attributes from metadata
            restored_attrs = dict(entry_data.attributes.attributes)
            for attr_name in list(restored_attrs.keys()):
                if attr_name.lower() not in boolean_attr_names:
                    continue

                # Restore from metadata (required - should always be present)
                conv_data = boolean_conversions.get(attr_name, {})
                # Type guard: ensure conv_data is dict and restore
                if isinstance(conv_data, dict):
                    self._restore_boolean_attribute_from_metadata(
                        attr_name,
                        conv_data,
                        restored_attrs,
                    )

            if restored_attrs == entry_data.attributes.attributes:
                return entry_data

            # Return entry with restored attributes
            return entry_data.model_copy(
                update={
                    "attributes": FlextLdifModels.LdifAttributes(
                        attributes=restored_attrs,
                        attribute_metadata=(
                            entry_data.attributes.attribute_metadata
                            if entry_data.attributes
                            else {}
                        ),
                        metadata=(
                            entry_data.attributes.metadata
                            if entry_data.attributes
                            else {}
                        ),
                    ),
                },
            )

        def _restore_entry_from_metadata(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Restore OID-specific formats from metadata (RFC → OID denormalization).

            Overrides RFC's _restore_entry_from_metadata() to apply OID-specific
            denormalization during write phase. Restores:
            - Boolean format: "TRUE"/"FALSE" → "0"/"1" (RFC 4517 → OID)
            - ACL attribute names: aci → orclaci (RFC → OID)
            - Schema DN: cn=schema → cn=subschemasubentry (RFC → OID)

            This hook is called by RFC._write_entry() before formatting the entry
            for LDIF output. Enables perfect round-trip OID→RFC→OID conversion.

            Uses FlextLdifConstants.MetadataKeys for standardized metadata keys.

            Args:
                entry_data: RFC-normalized Entry model to restore

            Returns:
                Entry with OID-specific formats restored from metadata

            """
            # Chain: DN → Attributes → Booleans (OID-specific)
            # Step 1: Restore DN (delegate to RFC - handles schema DN normalization)
            # Step 2: Restore attributes (delegate to RFC - handles attribute names)
            # Step 3: Restore OID boolean format (OID-specific override)
            return self._restore_boolean_values_to_oid(
                super()._restore_original_attributes(
                    super()._restore_original_dn(entry_data),
                ),
            )

        # =====================================================================
        # METADATA BUILDER HELPERS (DRY refactoring)
        # =====================================================================

        # REMOVED: _build_conversion_metadata, _build_dn_metadata, etc.
        # CONSOLIDATED into FlextLdifUtilities.Metadata (DRY: 118→1 call)

        def _create_entry_result_with_metadata(
            self,
            _entry: FlextLdifModels.Entry,  # Unused: kept for signature
            cleaned_dn: str,
            original_dn: str,
            _dn_stats: FlextLdifModels.DNStatistics,
            converted_attrs: set[str],
            boolean_conversions: Union[dict[str, dict[str, list[str], str]]],
            acl_transformations: dict[str, FlextLdifModels.AttributeTransformation],
            rfc_violations: list[str],
            attribute_conflicts: list[dict[str, str]],
            converted_attributes: dict[str, list[str]],
            original_entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Create entry result with complete metadata.

            CONSOLIDATED: Uses FlextLdifUtilities.Metadata utilities for DRY code.
            Previous helper methods (_build_*) replaced by utility calls.

            """
            # Get original attributes once
            original_attrs = (
                original_entry.attributes.attributes
                if original_entry.attributes
                else {}
            )

            # INLINE: _build_conversion_metadata (18 lines → 2 lines)
            # Use constants for metadata keys (DRY: avoid hardcoding)
            mk = FlextLdifConstants.MetadataKeys
            conversion_metadata: dict[str, list[str]] = (
                {mk.CONVERSION_CONVERTED_ATTRIBUTE_NAMES: list(converted_attrs)}
                if converted_attrs
                else {}
            )

            # INLINE: _build_dn_metadata (27 lines → 3 lines)
            # Use constants for metadata keys (DRY: avoid hardcoding)
            mk = FlextLdifConstants.MetadataKeys
            dn_metadata: dict[str, str] = (
                {
                    mk.ORIGINAL_DN_COMPLETE: original_dn,
                    mk.ORIGINAL_DN_LINE_COMPLETE: cleaned_dn,  # cleaned_dn is the processed DN
                    mk.HAS_DIFFERENCES: True,  # DN was cleaned/modified
                }
                if original_dn != cleaned_dn
                else {}
            )

            # UTILITY: build_rfc_compliance_metadata (93 lines → 1 call)
            rfc_compliance_metadata = (
                FlextLdifUtilities.Metadata.build_rfc_compliance_metadata(
                    rfc_violations=rfc_violations,
                    attribute_conflicts=attribute_conflicts,
                    boolean_conversions=boolean_conversions,
                    converted_attributes=converted_attributes,
                    original_entry=original_entry,
                    entry_dn=cleaned_dn,
                )
            )

            # UTILITY: build_entry_metadata_extensions (58 lines → 10 lines)
            generic_metadata = (
                FlextLdifUtilities.Metadata.build_entry_metadata_extensions(
                    entry_dn=original_dn,
                    original_attributes=original_attrs,
                    processed_attributes=converted_attributes,
                    server_type="oid",
                    metadata_keys=FlextLdifConstants.MetadataKeys,
                    operational_attributes=list(
                        FlextLdifServersOid.Constants.OPERATIONAL_ATTRIBUTES,
                    ),
                )
            )
            # OID-specific: conversions, target DN, format message
            mk = FlextLdifConstants.MetadataKeys
            # Store boolean conversions and attribute name conversions
            # Use standardized nested metadata keys (DRY: avoid hardcoding)
            generic_metadata[mk.CONVERTED_ATTRIBUTES] = {
                mk.CONVERSION_BOOLEAN_CONVERSIONS: boolean_conversions,
                mk.CONVERSION_ATTRIBUTE_NAME_CONVERSIONS: {
                    FlextLdifServersOid.Constants.ORCLACI: FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME,
                }
                if (
                    FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME
                    in converted_attributes
                    and FlextLdifServersOid.Constants.ORCLACI in original_attrs
                )
                else {},
            }
            generic_metadata[FlextLdifConstants.MetadataKeys.ENTRY_TARGET_DN_CASE] = (
                cleaned_dn
            )
            generic_metadata[FlextLdifConstants.MetadataKeys.ENTRY_ORIGINAL_FORMAT] = (
                f"OID Entry with {len(converted_attrs)} boolean conversions"
            )

            # Merge extensions from original_entry.metadata if it exists
            original_extensions: dict[str, str | int | bool] = (
                original_entry.metadata.extensions.copy()
                if original_entry.metadata and original_entry.metadata.extensions
                else {}
            )

            # Create metadata using domain class (create_for returns validated instance)
            metadata = FlextLdifModels.QuirkMetadata.create_for(
                self._get_server_type(),
                extensions={
                    **conversion_metadata,
                    **dn_metadata,
                    **rfc_compliance_metadata,
                    **generic_metadata,
                    **original_extensions,
                    FlextLdifConstants.MetadataKeys.ORIGINAL_ENTRY: original_entry,
                },
            )

            # INLINE: _track_boolean_conversions_in_metadata (47 lines → 10 lines)
            # Use standardized nested metadata keys (DRY: avoid hardcoding)
            for attr_name, conv_data in boolean_conversions.items():
                original_vals = conv_data.get(mk.CONVERSION_ORIGINAL_VALUE, [])
                converted_vals = conv_data.get(mk.CONVERSION_CONVERTED_VALUE, [])
                if original_vals and converted_vals:
                    FlextLdifUtilities.Metadata.track_boolean_conversion(
                        metadata=metadata,
                        attr_name=attr_name,
                        original_value=original_vals[0]
                        if len(original_vals) == 1
                        else str(original_vals),
                        converted_value=converted_vals[0]
                        if len(converted_vals) == 1
                        else str(converted_vals),
                        format_direction="OID->RFC",
                    )

            # UTILITY: build_original_format_details (70 lines → 1 call)
            # Extract original lines from RFC parser metadata
            orig_dn_line: str | None = None
            orig_attr_lines: list[str] = []
            if (
                original_entry.metadata
                and original_entry.metadata.original_format_details
            ):
                raw_dn_line = original_entry.metadata.original_format_details.get(
                    "original_dn_line",
                )
                orig_dn_line = str(raw_dn_line) if raw_dn_line is not None else None
                raw_lines = original_entry.metadata.original_format_details.get(
                    "original_attr_lines",
                    [],
                )
                if FlextRuntime.is_list_like(raw_lines):
                    orig_attr_lines = [str(line) for line in list(raw_lines)]

            metadata.original_format_details = (
                FlextLdifUtilities.Metadata.build_original_format_details(
                    original_dn=original_dn,
                    cleaned_dn=cleaned_dn,
                    converted_attrs=converted_attrs,
                    boolean_conversions=boolean_conversions,
                    converted_attributes=converted_attributes,
                    original_attributes=original_attrs,
                    server_type="oid",
                    original_dn_line=orig_dn_line,
                    original_attr_lines=orig_attr_lines,
                )
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

            # Create final Entry
            ldif_attrs = FlextLdifModels.LdifAttributes(attributes=converted_attributes)
            return FlextResult[FlextLdifModels.Entry].ok(
                FlextLdifModels.Entry(
                    dn=FlextLdifModels.DistinguishedName(value=cleaned_dn),
                    attributes=ldif_attrs,
                    metadata=metadata,
                ),
            )

        # ===== _parse_entry HELPER METHODS (DRY refactoring) =====
        # REMOVED: _analyze_oid_entry_differences (63 lines → utility)
        # Now uses: FlextLdifUtilities.Entry.analyze_differences()
        # REMOVED: _store_oid_minimal_differences (68 lines → utility)
        # Now uses: FlextLdifUtilities.Metadata.store_minimal_differences()

        def _hook_post_parse_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            r"""Hook: Transform parsed entry using OID-specific enhancements.

            OID vs RFC Transformations Applied
            ==================================
            This hook extends RFC's `_hook_post_parse_entry()` to apply
            OID-specific normalizations during Phase 1 (parsing).

            Step 1: Boolean Attribute Conversion
            ------------------------------------
            RFC 4517 Section 3.3.3:
                Boolean = "TRUE" / "FALSE"

            OID Format:
                Boolean = "0" / "1"

            Transformation:
                "0" → "FALSE"
                "1" → "TRUE"

            Applies to attributes in Constants.BOOLEAN_ATTRIBUTES:
                orclIsEnabled, orclAccountLocked, orclPwdMustChange, etc.

            Step 2: Attribute Name Normalization
            ------------------------------------
            RFC 4876 (ACI):
                aci: <acl-definition>

            OID Proprietary:
                orclaci: <acl-definition>
                orclentrylevelaci: <acl-definition>

            Transformation:
                orclaci → aci
                orclentrylevelaci → aci

            Metadata Tracking
            -----------------
            All transformations are stored in `entry.metadata.extensions`:
                - oid_converted_attrs: List of converted boolean attributes
                - oid_boolean_conversions: Dict mapping attr → {original, converted}

            This metadata enables perfect round-trip support in Phase 2 (writing).

            Args:
                entry: RFC-parsed Entry model (from RFC._parse_entry)

            Returns:
                FlextResult with transformed Entry model

            """
            try:
                if not entry.attributes or not entry.dn:
                    return FlextResult.ok(entry)

                # Step 1: Convert boolean attributes OID → RFC
                converted_attributes, converted_attrs, boolean_conversions = (
                    self._convert_boolean_attributes_to_rfc(entry.attributes.attributes)
                )

                # Step 2: Normalize attribute names OID → RFC (orclaci → aci)
                normalized_attributes: dict[str, list[str]] = {}
                for attr_name, attr_values in converted_attributes.items():
                    normalized_name = self._normalize_attribute_name(attr_name)
                    normalized_attributes[normalized_name] = attr_values

                # Update entry attributes with transformed values
                entry.attributes.attributes = normalized_attributes

                # Store transformation metadata for later use in _parse_entry()
                mk = FlextLdifConstants.MetadataKeys
                if entry.metadata:
                    if not entry.metadata.extensions:
                        entry.metadata.extensions = {}
                    # Store converted attributes using standardized metadata keys
                    entry.metadata.extensions[mk.CONVERTED_ATTRIBUTES] = list(
                        converted_attrs,
                    )
                    # Store boolean conversions in standardized structure under CONVERTED_ATTRIBUTES
                    # This follows the pattern: CONVERTED_ATTRIBUTES contains nested metadata
                    # Structure: CONVERTED_ATTRIBUTES = {
                    #   CONVERSION_BOOLEAN_CONVERSIONS: {...},
                    #   CONVERSION_ATTRIBUTE_NAME_CONVERSIONS: {...},
                    #   CONVERSION_CONVERTED_ATTRIBUTE_NAMES: [...]
                    # }
                    if boolean_conversions:
                        # Initialize CONVERTED_ATTRIBUTES as dict if it's currently a list
                        converted_attrs_dict = entry.metadata.extensions.get(
                            mk.CONVERTED_ATTRIBUTES,
                            {},
                        )
                        # Python 3.13: Use match/case for type dispatching
                        match converted_attrs_dict:
                            case list():
                                # Convert list to dict structure for nested metadata
                                entry.metadata.extensions[mk.CONVERTED_ATTRIBUTES] = {
                                    mk.CONVERSION_CONVERTED_ATTRIBUTE_NAMES: converted_attrs_dict,
                                    mk.CONVERSION_BOOLEAN_CONVERSIONS: dict(
                                        boolean_conversions,
                                    ),
                                }
                            case dict():
                                # Add to existing dict structure
                                converted_attrs_dict[
                                    mk.CONVERSION_BOOLEAN_CONVERSIONS
                                ] = dict(boolean_conversions)

                return FlextResult.ok(entry)
            except Exception as e:
                logger.exception("OID post-parse entry hook failed")
                return FlextResult.fail(f"OID post-parse entry hook failed: {e}")

        def _hook_finalize_entry_parse(
            self,
            entry: FlextLdifModels.Entry,
            original_dn: str,
            entry_attrs: Mapping[str, object],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Finalize OID entry with ACL and RFC violation metadata.

            This hook adds OID-specific metadata without duplicating the
            difference analysis already performed by RFC base class.

            OID-Specific Additions:
            - ACL transformations (orclaci → aci renames detected)
            - RFC violations (multiple structural objectClasses, etc.)
            - Attribute conflicts for invalid combinations

            The RFC base class already handles:
            - Difference analysis (DN and attribute changes)
            - Minimal differences storage
            - Original format preservation

            Args:
                entry: Parsed entry from RFC with all hooks applied
                original_dn: Original DN before transformation
                entry_attrs: Original attributes for comparison

            Returns:
                FlextResult with entry containing OID-specific metadata

            """
            _ = original_dn  # Used for logging if needed

            if not entry.attributes:
                return FlextResult.ok(entry)

            normalized_attrs = entry.attributes.attributes

            # OID-specific: Detect ACL attribute transformations
            acl_transformations = self._detect_entry_acl_transformations(
                entry_attrs,
                normalized_attrs,
            )

            # OID-specific: Detect RFC compliance violations
            rfc_violations, attribute_conflicts = self._detect_rfc_violations(
                normalized_attrs,
            )

            # Add OID-specific metadata to extensions
            if entry.metadata and (
                acl_transformations or rfc_violations or attribute_conflicts
            ):
                extensions = dict(entry.metadata.extensions or {})

                # Use string keys directly (OID-specific metadata)
                if acl_transformations:
                    extensions["acl_transformations"] = acl_transformations
                if rfc_violations:
                    extensions["rfc_violations"] = rfc_violations
                if attribute_conflicts:
                    extensions["attribute_conflicts"] = attribute_conflicts

                entry.metadata = entry.metadata.model_copy(
                    update={"extensions": extensions},
                )

                logger.debug(
                    "OID finalize: Added server-specific metadata",
                    acl_count=len(acl_transformations),
                    violations_count=len(rfc_violations),
                    conflicts_count=len(attribute_conflicts),
                )

            return FlextResult.ok(entry)
