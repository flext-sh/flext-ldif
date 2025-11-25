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
    ADMIN = "admin"

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


class TestData:
    """Structured test data builders."""

    @staticmethod
    def user_entry(
        dn: str = DNs.TEST_USER, **overrides: str | list[str]
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
        dn: str = DNs.TEST_USER, **overrides: str | list[str]
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
        oid: str = OIDs.CN, name: str = Names.CN, **overrides: str
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
    },
)
