"""Test constants organized in namespaces for maximum reuse.

Provides structured constants for all test domains with proper namespacing.
Organized by domain (OIDs, Names, DNs, Syntax, Values, Errors) for better reuse.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar


class FixturePaths:
    """Paths to test fixture files organized by server type."""

    ACL_FIXTURES: ClassVar[dict[str, str]] = {
        "oid": "oid/oid_acl_fixtures.ldif",
        "oud": "oud/oud_acl_fixtures.ldif",
    }


class OIDs:
    """LDAP object identifier constants."""

    # Common attribute OIDs
    CN = "2.5.4.3"
    SN = "2.5.4.4"
    OBJECTCLASS = "2.5.4.0"

    # Common objectClass OIDs
    PERSON = "2.5.6.6"
    ORGANIZATIONAL_PERSON = "2.5.6.7"
    INET_ORG_PERSON = "2.5.6.6"  # Same as person for inetOrgPerson

    # Common syntax OIDs
    DIRECTORY_STRING = "1.3.6.1.4.1.1466.115.115.121.1.15"
    BOOLEAN = "1.3.6.1.4.1.1466.115.121.1.7"
    INTEGER = "1.3.6.1.4.1.1466.115.121.1.27"
    OCTET_STRING = "1.3.6.1.4.1.1466.115.121.1.40"


class Names:
    """LDAP attribute and objectClass name constants."""

    # Common attribute names
    CN = "cn"
    SN = "sn"
    OBJECTCLASS = "objectClass"
    MAIL = "mail"
    UID = "uid"
    DN = "dn"

    # Common objectClass names
    PERSON = "person"
    ORGANIZATIONAL_PERSON = "organizationalPerson"
    INET_ORG_PERSON = "inetOrgPerson"
    TOP = "top"


class DNs:
    """Distinguished name constants for testing."""

    # Base DNs
    EXAMPLE = "dc=example,dc=com"
    SCHEMA = "cn=schema"

    # Test entries
    TEST_USER = f"cn=test,{EXAMPLE}"
    TEST_USER1 = f"cn=user1,{EXAMPLE}"
    TEST_USER2 = f"cn=user2,{EXAMPLE}"
    TEST_GROUP = f"cn=testgroup,{EXAMPLE}"

    # Deep DN for testing
    DEEP = "cn=level1,ou=level2,ou=level3,ou=level4,ou=level5,ou=level6,ou=level7,ou=level8,ou=level9,ou=level10,ou=level11,ou=level12,dc=example,dc=com"


class Syntax:
    """LDAP syntax OID constants."""

    DIRECTORY_STRING = OIDs.DIRECTORY_STRING
    BOOLEAN = OIDs.BOOLEAN
    INTEGER = OIDs.INTEGER
    OCTET_STRING = OIDs.OCTET_STRING


class Values:
    """Common test values."""

    # User values
    TEST = "test"
    USER = "user"
    USER1 = "user1"
    USER2 = "user2"
    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"

    # Email patterns
    EMAIL_BASE = "@example.com"
    TEST_EMAIL = f"{TEST}{EMAIL_BASE}"
    USER1_EMAIL = f"{USER1}{EMAIL_BASE}"
    USER2_EMAIL = f"{USER2}{EMAIL_BASE}"

    # Multi-value examples
    MAIL_VALUES: ClassVar[list[str]] = [
        "user1@example.com",
        "user1@company.com",
        "user1@personal.net",
    ]


class Errors:
    """Common error message patterns."""

    MISSING_OID = "Missing OID"
    INVALID_FORMAT = "Invalid format"
    PARSE_FAILED = "Parse failed"
    VALIDATION_FAILED = "Validation failed"
    SCHEMA_ERROR = "Schema error"
    DN_INVALID = "Invalid DN"


class RFC:
    """RFC-specific constants."""

    # Attribute definitions
    ATTR_DEF_CN = "( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
    ATTR_DEF_CN_COMPLETE = "( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
    ATTR_DEF_CN_MINIMAL = "( 2.5.4.3 )"
    ATTR_DEF_SN = (
        "( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{255} )"
    )
    ATTR_DEF_ST = "( 2.5.4.8 NAME 'st' DESC 'State or Province Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch )"
    ATTR_DEF_MAIL = (
        "( 0.9.2342.19200300.100.1.3 NAME 'mail' SUP name DESC 'Email address' )"
    )
    ATTR_DEF_MODIFY_TIMESTAMP = "( 2.5.18.2 NAME 'modifyTimestamp' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )"
    ATTR_DEF_OBSOLETE = "( 2.5.4.10 NAME 'o' DESC 'Organization Name' OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
    ATTR_DEF_OBJECTCLASS = "( 2.5.4.0 NAME 'objectClass' DESC 'Object Class' SYNTAX '1.3.6.1.4.1.1466.115.121.1.38' )"

    # ObjectClass definitions
    OC_DEF_PERSON = "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) )"
    OC_DEF_PERSON_BASIC = (
        "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL )"
    )
    OC_DEF_PERSON_MINIMAL = "( 2.5.6.6 NAME 'person' STRUCTURAL )"

    # LDIF content samples
    SAMPLE_LDIF_BASIC = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user
"""
    SAMPLE_LDIF_MULTIPLE = """dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1

dn: cn=user2,dc=example,dc=com
objectClass: person
cn: user2
"""
    SAMPLE_LDIF_BINARY = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
photo:: UGhvdG8gZGF0YQ==
"""
    SAMPLE_SCHEMA_CONTENT = """dn: cn=subschema
objectClass: top
objectClass: subentry
objectClass: subschema
cn: subschema
attributeTypes: ( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
objectClasses: ( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) )
"""

    # Invalid definitions
    INVALID_ATTR_DEF = "NAME 'cn' DESC 'Common Name'"
    INVALID_OC_DEF = "invalid objectclass definition"

    # ACL samples
    ACL_SAMPLE_BROWSE = "access to entry by * (browse)"
    ACL_SAMPLE_READ = "access to entry by * (read)"


class Fixtures:
    """Fixture-related constants."""

    # Fixture categories
    RFC = "rfc"
    SERVERS = "servers"
    EDGE_CASES = "edge_cases"
    BROKEN = "broken"

    # Server types
    OID = "oid"
    OUD = "oud"
    OPENLDAP = "openldap"
    AD = "ad"
    DS389 = "ds389"

    # Fixture types
    ENTRY = "entry"
    MODIFY = "modify"
    DELETE = "delete"
    MODRDN = "modrdn"
    ACL = "acl"

    # Subcategories
    VALID = "valid"
    VIOLATIONS = "violations"
    BOUNDARY = "boundary"


class SortingCases:
    """Sorting test case definitions and expected results."""

    @staticmethod
    def hierarchy_entries() -> list[dict[str, str | list[str]]]:
        """Create test entries in random order for hierarchy sorting."""
        return [
            {
                "dn": "cn=john,ou=users,dc=example,dc=com",
                "objectClass": [Names.PERSON],
                "cn": ["john"],
                "sn": ["doe"],
            },
            {
                "dn": "dc=example,dc=com",
                "objectClass": [Names.TOP, "domain"],
                "dc": ["example"],
            },
            {
                "dn": "ou=users,dc=example,dc=com",
                "objectClass": [Names.TOP, "organizationalUnit"],
                "ou": ["users"],
            },
        ]

    @staticmethod
    def expected_hierarchy_dns() -> list[str]:
        """Expected DN order for hierarchy sorting (shallowest first)."""
        return [
            "dc=example,dc=com",
            "ou=users,dc=example,dc=com",
            "cn=john,ou=users,dc=example,dc=com",
        ]

    @staticmethod
    def expected_alphabetical_dns() -> list[str]:
        """Expected DN order for alphabetical sorting."""
        return [
            "cn=john,ou=users,dc=example,dc=com",
            "dc=example,dc=com",
            "ou=users,dc=example,dc=com",
        ]

    @staticmethod
    def get_expected_order(strategy: str) -> list[str]:
        """Get expected DN order for given sorting strategy."""
        if strategy == "hierarchy":
            return SortingCases.expected_hierarchy_dns()
        if strategy == "alphabetical":
            return SortingCases.expected_alphabetical_dns()
        raise ValueError(f"Unknown sorting strategy: {strategy}")


class Filters:
    """Filter service test constants organized in namespaces."""

    # Filter criteria
    CRITERIA_DN = "dn"
    CRITERIA_OBJECTCLASS = "objectclass"
    CRITERIA_ATTRIBUTES = "attributes"
    CRITERIA_BASE_DN = "base_dn"

    # Filter modes
    MODE_INCLUDE = "include"
    MODE_EXCLUDE = "exclude"

    # DN patterns for testing
    DN_PATTERN_USERS = "*,ou=users,*"
    DN_PATTERN_ADMINS = "*,ou=REDACTED_LDAP_BIND_PASSWORDs,*"
    DN_PATTERN_GROUPS = "*,ou=groups,*"
    DN_PATTERN_ALL = "*"
    DN_PATTERN_OU = "*,ou=*"

    # ObjectClass values
    OC_PERSON = Names.PERSON
    OC_ORGANIZATIONAL_UNIT = "organizationalUnit"
    OC_GROUP_OF_NAMES = "groupOfNames"
    OC_GROUP = "group"
    OC_DOMAIN = "domain"
    OC_TOP = Names.TOP
    OC_INET_ORG_PERSON = Names.INET_ORG_PERSON

    # Attribute names
    ATTR_CN = Names.CN
    ATTR_MAIL = Names.MAIL
    ATTR_OBJECTCLASS = Names.OBJECTCLASS
    ATTR_SN = Names.SN
    ATTR_UID = Names.UID

    # Server types
    SERVER_RFC = "rfc"
    SERVER_OID = "oid"
    SERVER_OUD = "oud"

    # Categories
    CATEGORY_USERS = "users"
    CATEGORY_GROUPS = "groups"
    CATEGORY_HIERARCHY = "hierarchy"
    CATEGORY_SCHEMA = "schema"
    CATEGORY_ACL = "acl"
    CATEGORY_REJECTED = "rejected"

    # Test entry DNs
    DN_USER_JOHN = f"cn=john,ou=users,{DNs.EXAMPLE}"
    DN_USER_JANE = f"cn=jane,ou=users,{DNs.EXAMPLE}"
    DN_USER_ADMIN = f"cn=REDACTED_LDAP_BIND_PASSWORD,ou=REDACTED_LDAP_BIND_PASSWORDs,{DNs.EXAMPLE}"
    DN_OU_USERS = f"ou=users,{DNs.EXAMPLE}"
    DN_OU_GROUPS = f"ou=groups,{DNs.EXAMPLE}"
    DN_ACL_POLICY = f"cn=acl-policy,{DNs.EXAMPLE}"
    DN_REJECTED = f"cn=rejected,{DNs.EXAMPLE}"

    # OID patterns for schema filtering
    OID_PATTERN_CN = "2.5.4.*"
    OID_PATTERN_PERSON = "2.5.6.*"


class Statistics:
    """Statistics service test constants."""

    # Categories
    CATEGORY_USERS = "users"
    CATEGORY_GROUPS = "groups"
    CATEGORY_ROLES = "roles"
    CATEGORY_VALID = "valid"
    CATEGORY_REJECTED = "rejected"
    CATEGORY_ENTRIES = "entries"

    # Rejection reasons
    REJECTION_MISSING_ATTRIBUTE = "Missing required attribute"
    REJECTION_INVALID_DN = "Invalid DN format"
    REJECTION_SCHEMA_VIOLATION = "Schema violation"
    REJECTION_DUPLICATE_DN = "Duplicate DN"
    REJECTION_INVALID_ATTRIBUTES = "Invalid attributes"
    REJECTION_INVALID_FORMAT = "Invalid format"

    # Output paths
    OUTPUT_DIR_TMP = "/tmp"
    OUTPUT_DIR_LDIF = "/tmp/ldif"
    OUTPUT_DIR_EXPORT = "/output/ldif"
    OUTPUT_DIR_BASE = "/output"

    # File names
    FILE_USERS = "users.ldif"
    FILE_GROUPS = "groups.ldif"
    FILE_ROLES = "roles.ldif"
    FILE_REJECTED = "rejected.ldif"
    FILE_USERS_EXPORT = "users_export.ldif"
    FILE_GROUPS_EXPORT = "groups_export.ldif"
    FILE_EXPORTED_USERS = "exported_users.ldif"

    # Service status
    SERVICE_NAME = "StatisticsService"
    STATUS_OPERATIONAL = "operational"
    CAPABILITY_GENERATE = "generate_statistics"
    CAPABILITY_COUNT = "count_entries"
    CAPABILITY_ANALYZE = "analyze_rejections"
    VERSION = "1.0.0"


class EntryTestConstants:
    """Entry service test constants organized in namespaces."""

    # Operational attributes for testing
    OPERATIONAL_ATTRS: ClassVar[list[str]] = [
        "createTimestamp",
        "modifyTimestamp",
        "creatorsName",
        "modifiersName",
        "entryCSN",
        "entryUUID",
    ]

    # Common test attributes
    COMMON_ATTRS: ClassVar[list[str]] = [
        Names.CN,
        Names.SN,
        Names.MAIL,
        Names.UID,
        Names.OBJECTCLASS,
    ]

    # Edge case values
    LONG_VALUE_LENGTH: ClassVar[int] = 10000
    MANY_ATTRS_COUNT: ClassVar[int] = 100
    MANY_ATTRS_REMOVE_COUNT: ClassVar[int] = 50

    # Unicode test values
    UNICODE_DN: ClassVar[str] = "cn=日本語,dc=example,dc=com"
    UNICODE_VALUE: ClassVar[str] = "日本語"

    # Validation test values
    VALID_ATTR_NAMES: ClassVar[list[str]] = [
        Names.CN,
        Names.MAIL,
        Names.OBJECTCLASS,
        "user-account",
        "extensionAttribute123",
    ]
    INVALID_ATTR_NAMES: ClassVar[list[str]] = [
        "2invalid",
        "user name",
        "",
        "user@name",
    ]

    # Syntax test values
    BOOLEAN_OID: ClassVar[str] = OIDs.BOOLEAN
    BOOLEAN_NAME: ClassVar[str] = "boolean"

    # DN cleaning test cases
    DN_CLEANING_CASES: ClassVar[dict[str, tuple[str, str | None, str | None]]] = {
        "with_spaces": (
            "cn = John Doe , ou = users , dc = example , dc = com",
            "cn=",
            " = ",
        ),
        "already_clean": (
            "cn=john,ou=users,dc=example,dc=com",
            "cn=john",
            None,
        ),
        "with_escaped_chars": (
            r"cn=John\, Doe,ou=users,dc=example,dc=com",
            None,
            None,
        ),
    }


class TestData:
    """Structured test data builders."""

    @staticmethod
    def user_entry(
        dn: str = DNs.TEST_USER,
        **overrides: str | list[str],
    ) -> dict[str, str | list[str]]:
        """Create user entry test data."""
        base: dict[str, str | list[str]] = {
            "dn": dn,
            "objectClass": [
                Names.INET_ORG_PERSON,
                Names.ORGANIZATIONAL_PERSON,
                Names.PERSON,
                Names.TOP,
            ],
            "cn": [Values.TEST],
            "sn": [Values.TEST],
            "mail": [Values.TEST_EMAIL],
            "uid": [Values.TEST],
        }
        # Filter overrides to only include compatible types
        compatible_overrides = {
            k: v for k, v in overrides.items() if isinstance(v, (str, list))
        }
        base.update(compatible_overrides)
        return base

    @staticmethod
    def multivalue_entry(
        dn: str = DNs.TEST_USER,
        **overrides: str | list[str],
    ) -> dict[str, str | list[str]]:
        """Create multivalue attribute entry test data."""
        base: dict[str, str | list[str]] = {
            "dn": dn,
            "objectClass": [Names.INET_ORG_PERSON],
            "cn": [Values.TEST],
            "mail": Values.MAIL_VALUES,
        }
        # Filter overrides to only include compatible types
        compatible_overrides = {
            k: v for k, v in overrides.items() if isinstance(v, (str, list))
        }
        base.update(compatible_overrides)
        return base

    @staticmethod
    def schema_attribute(
        oid: str = OIDs.CN,
        name: str = Names.CN,
        **overrides: str,
    ) -> dict[str, str]:
        """Create schema attribute test data."""
        base: dict[str, str] = {
            "oid": oid,
            "name": name,
            "syntax": Syntax.DIRECTORY_STRING,
        }
        # Filter overrides to only include string values
        compatible_overrides = {
            k: v for k, v in overrides.items() if isinstance(v, str)
        }
        base.update(compatible_overrides)
        return base

    @staticmethod
    def categorized_entry(
        dn: str,
        category: str = Statistics.CATEGORY_USERS,
        rejection_reason: str | None = None,
    ) -> dict[str, object]:
        """Create categorized entry for statistics testing."""
        entry: dict[str, object] = {"dn": dn, "attributes": {}}
        if rejection_reason:
            entry["attributes"] = {"rejectionReason": rejection_reason}
        return entry

    @staticmethod
    def categorized_batch(
        category: str,
        count: int,
        base_dn: str = DNs.EXAMPLE,
        prefix: str = "user",
        rejection_reason: str | None = None,
    ) -> list[dict[str, object]]:
        """Create batch of categorized entries."""
        return [
            TestData.categorized_entry(
                dn=f"cn={prefix}{i},{base_dn}",
                category=category,
                rejection_reason=rejection_reason,
            )
            for i in range(1, count + 1)
        ]


class Writer:
    """Constants for writer tests organized by category."""

    # Test DNs
    LONG_DN = (
        "cn=Very Long Common Name That Exceeds Normal Length,"
        "ou=Very Long Organizational Unit Name,"
        "o=Very Long Organization Name,dc=example,dc=com"
    )

    # Line widths for testing
    LINE_WIDTHS: ClassVar[list[int]] = [50, 76, 120]
    MIN_LINE_WIDTH: ClassVar[int] = 1

    # Output targets
    OUTPUT_TARGET_STRING: ClassVar[str] = "string"
    OUTPUT_TARGET_FILE: ClassVar[str] = "file"
    OUTPUT_TARGET_LDAP3: ClassVar[str] = "ldap3"
    OUTPUT_TARGET_MODEL: ClassVar[str] = "model"

    # Patterns for assertions
    PATTERN_VERSION: ClassVar[str] = "version: 1"
    PATTERN_TIMESTAMP_REGEX: ClassVar[str] = (
        r"# Generated on: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    )
    PATTERN_TIMESTAMP_PREFIX: ClassVar[str] = "# Generated on:"
    PATTERN_HIDDEN_ATTR: ClassVar[str] = "# telephoneNumber:"
    PATTERN_EMPTY_ATTR: ClassVar[str] = "emptyAttr:"
    PATTERN_DN_COMMENT: ClassVar[str] = "# Complex DN:"
    PATTERN_ENTRY_METADATA: ClassVar[str] = "# Entry Metadata:"

    # Regex special characters for pattern detection
    REGEX_SPECIAL_CHARS: ClassVar[set[str]] = {
        "\\d",
        "\\w",
        "\\s",
        ".*",
        ".+",
        "^",
        "$",
        "[",
        "]",
        "(",
        ")",
        "?",
        "*",
        "+",
        "|",
    }


class OidTestConstants:
    """OID-specific test constants for Oracle Internet Directory (OID) testing.

    Consolidates Oracle OID namespace OIDs, boolean conversions, schema definitions,
    and ACL-related constants used across OID test suite.
    """

    # ═══════════════════════════════════════════════════════════════════════════
    # ORACLE OID NAMESPACE CONSTANTS
    # ═══════════════════════════════════════════════════════════════════════════

    # Oracle namespace: 2.16.840.1.113894.*
    ORACLE_NAMESPACE = "2.16.840.1.113894"
    ORACLE_ATTRIBUTE_OID = "2.16.840.1.113894.1.1.1"
    ORACLE_OBJECTCLASS_OID = "2.16.840.1.113894.2.1.1"
    ORACLE_ACL_OID = "2.16.840.1.113894.1.1.2"
    ORACLE_GUID_OID = "2.16.840.1.113894.1.1.1"
    ORACLE_CONTEXT_OID = "2.16.840.1.113894.2.1.1"

    # OID namespace pattern for detection
    ORACLE_OID_PATTERN = r"2\.16\.840\.1\.113894\."
    ORACLE_OR_NOVELL_PATTERN = r"2\.16\.840\.1\.11(3894|3719)\."

    # ═══════════════════════════════════════════════════════════════════════════
    # BOOLEAN VALUE MAPPINGS (OID ↔ RFC)
    # ═══════════════════════════════════════════════════════════════════════════

    OID_TO_RFC_BOOLEAN: ClassVar[dict[str, str]] = {"0": "FALSE", "1": "TRUE"}
    RFC_TO_OID_BOOLEAN: ClassVar[dict[str, str]] = {"TRUE": "1", "FALSE": "0"}
    BOOLEAN_VALUES_OID: ClassVar[list[str]] = ["0", "1"]
    BOOLEAN_VALUES_RFC: ClassVar[list[str]] = ["TRUE", "FALSE"]

    # ═══════════════════════════════════════════════════════════════════════════
    # SCHEMA DEFINITIONS
    # ═══════════════════════════════════════════════════════════════════════════

    # Basic Oracle attribute
    ORACLE_ATTR_GUID = (
        "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' "
        "DESC 'Oracle GUID' "
        "EQUALITY caseIgnoreMatch "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
    )

    # Basic Oracle objectClass
    ORACLE_OC_CONTEXT = (
        "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' "
        "DESC 'Oracle Context' "
        "SUP top STRUCTURAL "
        "MUST cn "
        "MAY ( orclguid ) )"
    )

    # Complex Oracle attribute with all options
    ORACLE_ATTR_COMPLEX = (
        "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
        "DESC 'Oracle GUID' "
        "EQUALITY caseIgnoreMatch "
        "ORDERING caseIgnoreOrderingMatch "
        "SUBSTR caseIgnoreSubstringsMatch "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
        "SINGLE-VALUE )"
    )

    # Oracle attributes with special syntax (CASE-IGNORE-SUBSTRINGS)
    ORACLE_ATTR_WITH_SUBSTR = (
        "( 2.16.840.1.113894.1.1.1 NAME 'orclAttr' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
        "SUBSTR caseIgnoreSubstringsMatch )"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # ACL CONSTANTS
    # ═══════════════════════════════════════════════════════════════════════════

    # ACL subject types (Oracle OID specific)
    ACL_SUBJECT_TYPES: ClassVar[list[str]] = ["PUBLIC", "BIND_RULE"]
    ACL_PERMISSION_NAMES: ClassVar[list[str]] = [
        "read",
        "write",
        "delete",
        "search",
        "add",
        "modifyrdn",
    ]

    # Sample Oracle ACL
    ORACLE_ACL_SAMPLE = "PUBLIC/2=allow;/2=allow;PUBLIC/2=allow"

    # ═══════════════════════════════════════════════════════════════════════════
    # BOOLEAN ATTRIBUTE NAMES
    # ═══════════════════════════════════════════════════════════════════════════

    BOOLEAN_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
        "pwdlockout",
        "pwdAllowUserChange",
        "pwdMustChange",
        "pwdSafeModify",
        "pwdInHistory",
        "orclAccountStatus",
    ])

    # ═══════════════════════════════════════════════════════════════════════════
    # ENTRY TEST DATA
    # ═══════════════════════════════════════════════════════════════════════════

    ORACLE_ENTRY_DN = "cn=test,dc=oracle,dc=com"
    ORACLE_ENTRY_OBJECTCLASS: ClassVar[list[str]] = ["top", "person", "orclContext"]
    ORACLE_ENTRY_ATTRS: ClassVar[dict[str, list[str]]] = {
        "cn": ["test"],
        "sn": ["user"],
        "orclguid": ["oracle-guid-123"],
    }


# Re-export for backward compatibility and convenience
General = type(
    "General",
    (),
    {
        **{k: v for k, v in OIDs.__dict__.items() if not k.startswith("_")},
        **{k: v for k, v in Names.__dict__.items() if not k.startswith("_")},
        **{k: v for k, v in DNs.__dict__.items() if not k.startswith("_")},
        **{k: v for k, v in Syntax.__dict__.items() if not k.startswith("_")},
        **{k: v for k, v in Values.__dict__.items() if not k.startswith("_")},
        **{k: v for k, v in Errors.__dict__.items() if not k.startswith("_")},
        **{k: v for k, v in RFC.__dict__.items() if not k.startswith("_")},
        **{k: v for k, v in SortingCases.__dict__.items() if not k.startswith("_")},
        **{k: v for k, v in Statistics.__dict__.items() if not k.startswith("_")},
        **{k: v for k, v in Filters.__dict__.items() if not k.startswith("_")},
        **{k: v for k, v in Writer.__dict__.items() if not k.startswith("_")},
        **{k: v for k, v in OidTestConstants.__dict__.items() if not k.startswith("_")},
    },
)
