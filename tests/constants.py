"""Test constant definitions extending src constants for centralized test constants.

This module provides test-specific constants that complement but do not duplicate
src/flext_ldif/constants.py. These constants are used exclusively in tests for:
- Test data generation
- Test fixtures
- Test assertions
- Mock data

Important: This module should NOT duplicate constants from src/constants.py.
Instead, it should import and reuse them when possible, or define test-specific
constants that are not part of the production codebase.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Mapping,
    Sequence,
)
from enum import StrEnum, unique
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Final

from flext_ldap import c
from flext_tests import FlextTestsConstants
from frozenlist import FrozenList

from tests import m

if TYPE_CHECKING:
    from tests import t


class TestsFlextLdifConstants(FlextTestsConstants, c):
    """Constants for flext-ldif tests using COMPOSITION INHERITANCE."""

    class Ldif(c.Ldif):
        """Domain namespace for flext-ldif test constants."""

        class Tests:
            """Flat test-only constants consumed from `?.Ldif.Tests.*`."""

            class _Paths:
                """Test directory path constants."""

                FIXTURES_DIR: Final[Path] = Path(__file__).parent / "fixtures"
                OID_FIXTURES_DIR: Final[Path] = (
                    Path(__file__).parent / "fixtures" / "oid"
                )
                WORKSPACE_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

            FIXTURES_DIR: Final[Path] = Path(__file__).parent / "fixtures"
            PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
            WORKSPACE_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

            RFC: Final[t.Ldif.Tests.FixtureServer] = "rfc"
            OID: Final[t.Ldif.Tests.FixtureServer] = "oid"
            OUD: Final[t.Ldif.Tests.FixtureServer] = "oud"
            OPENLDAP: Final[t.Ldif.Tests.FixtureServer] = "openldap"
            OPENLDAP1: Final[t.Ldif.Tests.FixtureServer] = "openldap1"
            DS389: Final[t.Ldif.Tests.FixtureServer] = "ds389"
            APACHE: Final[t.Ldif.Tests.FixtureServer] = "apache"
            NOVELL: Final[t.Ldif.Tests.FixtureServer] = "novell"
            TIVOLI: Final[t.Ldif.Tests.FixtureServer] = "tivoli"
            AD: Final[t.Ldif.Tests.FixtureServer] = "ad"

            SCHEMA: Final[t.Ldif.Tests.FixtureKind] = "schema"
            ACL: Final[t.Ldif.Tests.FixtureKind] = "acl"
            ENTRIES: Final[t.Ldif.Tests.FixtureKind] = "entries"
            INTEGRATION: Final[t.Ldif.Tests.FixtureKind] = "integration"

            class _Docker:
                """Docker container infrastructure constants for integration tests.

                Mirrors c.Ldap.Tests.Docker from flext-ldap tests to avoid
                cross-project test imports while keeping values in sync.
                """

                CONTAINER_NAME: Final[str] = "flext-openldap-test"
                COMPOSE_FILE_REL: Final[str] = "docker/docker-compose.openldap.yml"
                SERVICE_NAME: Final[str] = "openldap"
                PORT: Final[int] = 3390
                BASE_DN: Final[str] = "dc=flext,dc=local"
                ADMIN_DN: Final[str] = "cn=admin,dc=flext,dc=local"
                ADMIN_PASSWORD: Final[str] = "admin123"
                LEGACY_ADMIN_DN: Final[str] = (
                    "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
                )
                LEGACY_ADMIN_PASSWORD: Final[str] = "REDACTED_LDAP_BIND_PASSWORD123"

            class _Schema:
                """Schema constants wrapper for test convenience."""

                STRUCTURAL: str = c.Ldif.SchemaKind.STRUCTURAL
                AUXILIARY: str = c.Ldif.SchemaKind.AUXILIARY
                ABSTRACT: str = c.Ldif.SchemaKind.ABSTRACT
                ACTIVE: str = "ACTIVE"
                DEPRECATED: str = "DEPRECATED"

            class _Names:
                """Standard LDAP attribute names for test fixtures."""

                CN: Final[str] = "cn"
                SN: Final[str] = "sn"
                GIVEN_NAME: Final[str] = "givenName"
                MAIL: Final[str] = "mail"
                OBJECT_CLASS: Final[str] = "objectClass"
                OBJECTCLASS: Final[str] = OBJECT_CLASS
                DESCRIPTION: Final[str] = "description"
                TELEPHONE_NUMBER: Final[str] = "telephoneNumber"
                STREET: Final[str] = "street"
                LOCALITY: Final[str] = "l"
                STATE_OR_PROVINCE: Final[str] = "st"
                POSTAL_CODE: Final[str] = "postalCode"
                ORGANIZATION: Final[str] = "o"
                ORGANIZATIONAL_UNIT: Final[str] = "ou"
                ORGANIZATIONAL_PERSON: Final[str] = "organizationalPerson"
                USER_PASSWORD: Final[str] = "userPassword"
                JPEG_PHOTO: Final[str] = "jpegPhoto"
                EMPLOYEE_ID: Final[str] = "employeeID"
                DN: Final[str] = "dn"
                UID: Final[str] = "uid"
                PERSON: Final[str] = "person"
                TOP: Final[str] = "top"
                INETORGPERSON: Final[str] = "inetOrgPerson"
                INET_ORG_PERSON: Final[str] = INETORGPERSON
                MODIFY_TIMESTAMP: Final[str] = "modifyTimestamp"

            class _Fixtures:
                """Test fixture directory names used in tests/fixtures/."""

                OID: Final[str] = "oid"
                OUD: Final[str] = "oud"
                OPENLDAP: Final[str] = "openldap"
                OPENLDAP2: Final[str] = "openldap2"
                RFC: Final[str] = "rfc"

            class _Dns:
                """Canonical DN constants for testing."""

                EXAMPLE: Final[str] = "dc=example,dc=com"
                BASE: Final[str] = EXAMPLE
                TEST: Final[str] = "cn=test,dc=example,dc=com"
                TEST_USER: Final[str] = "cn=testuser,dc=example,dc=com"
                TEST_GROUP: Final[str] = "cn=testgroup,dc=example,dc=com"
                TEST_USER1: Final[str] = "cn=user1,dc=example,dc=com"
                TEST_USER2: Final[str] = "cn=user2,dc=example,dc=com"
                TEST_USER_FULL: Final[str] = "cn=Test User,dc=example,dc=com"
                TEST1: Final[str] = "cn=test1,dc=example,dc=com"
                TEST2: Final[str] = "cn=test2,dc=example,dc=com"
                SCHEMA: Final[str] = "cn=schema"
                SUBSCHEMA: Final[str] = "cn=subschema"
                SCHEMA_SYSTEM: Final[str] = "cn=schema,o=system"
                INVALID: Final[str] = "invalid-dn-format"

            class _Oids:
                """Canonical OID constants for testing.

                Attribute OIDs, ObjectClass OIDs, and Syntax OIDs.
                """

                # Attribute OIDs
                CN: Final[str] = "2.5.4.3"
                SN: Final[str] = "2.5.4.4"
                ST: Final[str] = "2.5.4.8"
                MAIL: Final[str] = "0.9.2342.19200300.100.1.3"
                MODIFY_TIMESTAMP: Final[str] = "2.5.18.2"
                ORGANIZATION: Final[str] = "2.5.4.10"
                OBJECTCLASS: Final[str] = "2.5.4.0"
                # ObjectClass OIDs
                PERSON: Final[str] = "2.5.6.6"
                # Syntax OIDs
                DIRECTORY_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.15"
                BOOLEAN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.7"
                INTEGER: Final[str] = "1.3.6.1.4.1.1466.115.121.1.27"
                IA5_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.26"
                GENERALIZED_TIME: Final[str] = "1.3.6.1.4.1.1466.115.121.1.24"
                OID: Final[str] = "1.3.6.1.4.1.1466.115.121.1.38"
                OCTET_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.40"

            class _Rfc:
                """RFC test constants for schema and entry testing."""

                ATTR_DEF_CN: Final[str] = (
                    "( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
                )
                ATTR_DEF_CN_COMPLETE: Final[str] = ATTR_DEF_CN
                ATTR_DEF_CN_MINIMAL: Final[str] = "( 2.5.4.3 )"
                ATTR_DEF_SN: Final[str] = (
                    "( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{255} )"
                )
                ATTR_DEF_ST: Final[str] = (
                    "( 2.5.4.8 NAME 'st' DESC 'State or Province Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch )"
                )
                ATTR_DEF_MAIL: Final[str] = (
                    "( 0.9.2342.19200300.100.1.3 NAME 'mail' SUP name DESC 'Email address' )"
                )
                ATTR_DEF_MODIFY_TIMESTAMP: Final[str] = (
                    "( 2.5.18.2 NAME 'modifyTimestamp' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )"
                )
                ATTR_DEF_OBSOLETE: Final[str] = (
                    "( 2.5.4.10 NAME 'o' DESC 'Organization Name' OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
                )
                ATTR_DEF_OBJECTCLASS: Final[str] = (
                    "( 2.5.4.0 NAME 'objectClass' DESC 'Object Class' SYNTAX '1.3.6.1.4.1.1466.115.121.1.38' )"
                )
                ATTR_OID_CN: Final[str] = "2.5.4.3"
                ATTR_OID_SN: Final[str] = "2.5.4.4"
                ATTR_OID_ST: Final[str] = "2.5.4.8"
                ATTR_OID_MAIL: Final[str] = "0.9.2342.19200300.100.1.3"
                ATTR_OID_MODIFY_TIMESTAMP: Final[str] = "2.5.18.2"
                ATTR_OID_O: Final[str] = "2.5.4.10"
                ATTR_OID_OBJECTCLASS: Final[str] = "2.5.4.0"
                ATTR_NAME_CN: Final[str] = "cn"
                ATTR_NAME_SN: Final[str] = "sn"
                ATTR_NAME_ST: Final[str] = "st"
                ATTR_NAME_MAIL: Final[str] = "mail"
                ATTR_NAME_MODIFY_TIMESTAMP: Final[str] = "modifyTimestamp"
                ATTR_NAME_O: Final[str] = "o"
                ATTR_NAME_OBJECTCLASS: Final[str] = "objectClass"
                SYNTAX_OID_DIRECTORY_STRING: Final[str] = (
                    "1.3.6.1.4.1.1466.115.121.1.15"
                )
                SYNTAX_OID_BOOLEAN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.7"
                SYNTAX_OID_INTEGER: Final[str] = "1.3.6.1.4.1.1466.115.121.1.27"
                SYNTAX_OID_IA5_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.26"
                SYNTAX_OID_GENERALIZED_TIME: Final[str] = (
                    "1.3.6.1.4.1.1466.115.121.1.24"
                )
                SYNTAX_OID_OID: Final[str] = "1.3.6.1.4.1.1466.115.121.1.38"
                OC_DEF_PERSON: Final[str] = (
                    "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) )"
                )
                OC_DEF_PERSON_FULL: Final[str] = OC_DEF_PERSON
                OC_DEF_PERSON_BASIC: Final[str] = (
                    "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL )"
                )
                OC_DEF_PERSON_MINIMAL: Final[str] = (
                    "( 2.5.6.6 NAME 'person' STRUCTURAL )"
                )
                OC_OID_PERSON: Final[str] = "2.5.6.6"
                OC_NAME_PERSON: Final[str] = "person"
                SCHEMA_DN_SUBSCHEMA: Final[str] = "cn=subschema"
                SCHEMA_DN_SCHEMA: Final[str] = "cn=schema"
                SCHEMA_DN_SCHEMA_SYSTEM: Final[str] = "cn=schema,o=system"
                TEST_DN: Final[str] = "cn=test,dc=example,dc=com"
                TEST_DN_USER1: Final[str] = "cn=user1,dc=example,dc=com"
                TEST_DN_USER2: Final[str] = "cn=user2,dc=example,dc=com"
                TEST_DN_TEST_USER: Final[str] = "cn=Test User,dc=example,dc=com"
                INVALID_DN: Final[str] = "invalid-dn-format"
                SAMPLE_DN: Final[str] = "cn=test,dc=example,dc=com"
                SAMPLE_DN_USER1: Final[str] = "cn=user1,dc=example,dc=com"
                SAMPLE_DN_USER2: Final[str] = "cn=user2,dc=example,dc=com"
                SAMPLE_ATTRIBUTE_CN: Final[str] = "cn"
                SAMPLE_ATTRIBUTE_SN: Final[str] = "sn"
                SAMPLE_LDIF_BASIC: Final[str] = (
                    "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: user\n"
                )
                SAMPLE_LDIF_MULTIPLE: Final[str] = (
                    "dn: cn=user1,dc=example,dc=com\nobjectClass: person\ncn: user1\n\ndn: cn=user2,dc=example,dc=com\nobjectClass: person\ncn: user2\n"
                )
                SAMPLE_LDIF_BINARY: Final[str] = (
                    "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nphoto:: UGhvdG8gZGF0YQ==\n"
                )
                SAMPLE_SCHEMA_CONTENT: Final[str] = (
                    "dn: cn=subschema\nobjectClass: top\nobjectClass: subentry\nobjectClass: subschema\ncn: subschema\nattributeTypes: ( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )\nobjectClasses: ( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) )\n"
                )
                INVALID_ATTR_DEF: Final[str] = "NAME 'cn' DESC 'Common Name'"
                INVALID_OC_DEF: Final[str] = "invalid objectclass definition"
                ACL_SAMPLE_BROWSE: Final[str] = "access to entry by * (browse)"
                ACL_SAMPLE_READ: Final[str] = "access to entry by * (read)"

            class _TestData:
                """Test data generation constants."""

                SAMPLE_BASE_DN: Final[str] = "dc=test,dc=local"
                SAMPLE_USER_DN: Final[str] = "cn=testuser,dc=test,dc=local"
                SAMPLE_GROUP_DN: Final[str] = "cn=testgroup,dc=test,dc=local"
                SAMPLE_OU_DN: Final[str] = "ou=testou,dc=test,dc=local"
                SAMPLE_ATTRIBUTES: Final[Mapping[str, t.StrSequence]] = {
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                    "cn": ["Test User"],
                    "sn": ["User"],
                    "mail": ["test@example.com"],
                    "uid": ["testuser"],
                }
                SAMPLE_LDIF_ENTRY: Final[str] = (
                    "dn: cn=Test User,dc=test,dc=local\nobjectClass: inetOrgPerson\nobjectClass: organizationalPerson\nobjectClass: person\nobjectClass: top\ncn: Test User\nsn: User\nmail: test@example.com\nuid: testuser\n"
                )

                class Relaxed:
                    """Test data for relaxed quirks tests."""

                    ATTRIBUTE_DEFINITIONS: Final[
                        Mapping[
                            str,
                            tuple[str, bool],
                        ]
                    ] = {
                        "valid": (
                            "( 1.2.3.4 NAME 'testAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                            True,
                        ),
                        "malformed": (
                            "( 2.5.4.3 NAME 'broken'",
                            True,
                        ),
                        "missing_name": (
                            "( 1.2.3.4 )",
                            True,
                        ),
                        "no_oid": (
                            "NAME 'onlyName'",
                            False,
                        ),
                        "empty": ("", False),
                        "whitespace": (
                            "   ",
                            False,
                        ),
                        "binary_data": (
                            "( 1.2.3.4 NAME 'test' \x00\x01 )".encode("latin1").decode(
                                "latin1"
                            ),
                            True,
                        ),
                        "unicode": (
                            "( 1.2.3.4 NAME 'тест' 😀 )",
                            True,
                        ),
                        "long_definition": (
                            "( 1.2.3.4 " + "NAME 'test' " * 100 + ")",
                            True,
                        ),
                    }
                    OBJECTCLASS_DEFINITIONS: Final[
                        Mapping[
                            str,
                            tuple[str, bool],
                        ]
                    ] = {
                        "valid": (
                            "( 1.2.3 NAME 'testOc' STRUCTURAL )",
                            True,
                        ),
                        "malformed": (
                            "( 2.5.6.0 NAME 'broken'",
                            True,
                        ),
                        "missing_name": (
                            "( 1.2.3.4 STRUCTURAL )",
                            True,
                        ),
                        "no_oid": (
                            "BROKEN CLASS",
                            False,
                        ),
                        "empty": ("", False),
                        "whitespace": (
                            "   ",
                            False,
                        ),
                        "unicode": (
                            "( 1.2.3.4 NAME 'тест' 😀 )",
                            True,
                        ),
                    }
                    NAME_FORMAT_VARIATIONS: Final[Sequence[tuple[str, bool]]] = [
                        ("( 1.2.3.4 NAME 'quoted' )", True),
                        ("( 1.2.3.4 NAME unquoted )", True),
                        ('( 1.2.3.4 NAME "doublequoted" )', True),
                    ]
                    ACL_DEFINITIONS: Final[Mapping[str, tuple[str, bool]]] = {
                        "valid": (
                            '(targetentry="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")(version 3.0;acl "REDACTED_LDAP_BIND_PASSWORD";allow(all)',
                            True,
                        ),
                        "malformed": ("(targetentry incomplete", True),
                        "broken": ("(targetentry invalid) broken", True),
                    }

                class AclRegistry:
                    """Test data for ACL registry tests."""

                    GET_ACL_ATTRIBUTES_DATA: Final[
                        Mapping[
                            str,
                            tuple[
                                str,
                                str | None,
                                t.StrSequence,
                                t.StrSequence,
                            ],
                        ]
                    ] = {
                        "get_acl_attributes_rfc_foundation": (
                            "rfc",
                            None,
                            ["aci", "acl", "olcAccess", "aclRights", "aclEntry"],
                            list[str](),
                        ),
                        "get_acl_attributes_oid_quirks": (
                            "oid",
                            "oid",
                            ["orclaci", "orclentrylevelaci", "aci", "acl"],
                            list[str](),
                        ),
                        "get_acl_attributes_oud_quirks": (
                            "oud",
                            "oud",
                            ["orclaci", "orclentrylevelaci", "aci"],
                            list[str](),
                        ),
                        "get_acl_attributes_ad_quirks": (
                            "ad",
                            "ad",
                            ["nTSecurityDescriptor", "aci"],
                            list[str](),
                        ),
                        "get_acl_attributes_generic": (
                            "generic",
                            "generic",
                            ["aci", "acl"],
                            ["orclaci", "nTSecurityDescriptor"],
                        ),
                        "get_acl_attributes_unknown": (
                            "unknown_server",
                            "unknown_server",
                            ["aci", "acl"],
                            ["orclaci", "nTSecurityDescriptor"],
                        ),
                        "get_acl_attributes_none": (
                            "none",
                            None,
                            ["aci", "acl"],
                            ["orclaci"],
                        ),
                    }
                    IS_ACL_ATTRIBUTE_DATA: Final[
                        Mapping[
                            str,
                            tuple[
                                str,
                                str,
                                str | None,
                                bool,
                            ],
                        ]
                    ] = {
                        "is_acl_attribute_rfc_aci": (
                            "valid_rfc",
                            "aci",
                            None,
                            True,
                        ),
                        "is_acl_attribute_rfc_acl": (
                            "valid_rfc",
                            "acl",
                            None,
                            True,
                        ),
                        "is_acl_attribute_rfc_olcAccess": (
                            "valid_rfc",
                            "olcAccess",
                            None,
                            True,
                        ),
                        "is_acl_attribute_oid_orclaci": (
                            "valid_server_specific",
                            "orclaci",
                            "oid",
                            True,
                        ),
                        "is_acl_attribute_oud_orclaci": (
                            "valid_server_specific",
                            "orclaci",
                            "oud",
                            True,
                        ),
                        "is_acl_attribute_invalid_cn": (
                            "invalid",
                            "cn",
                            None,
                            False,
                        ),
                        "is_acl_attribute_invalid_uid": (
                            "invalid",
                            "uid",
                            None,
                            False,
                        ),
                        "is_acl_attribute_case_insensitive_aci": (
                            "case_insensitive",
                            "ACI",
                            None,
                            True,
                        ),
                        "is_acl_attribute_case_insensitive_acl": (
                            "case_insensitive",
                            "Acl",
                            None,
                            True,
                        ),
                        "is_acl_attribute_case_insensitive_olcAccess": (
                            "case_insensitive",
                            "OLCACCESS",
                            None,
                            True,
                        ),
                        "is_acl_attribute_case_insensitive_orclaci": (
                            "case_insensitive",
                            "OrclAci",
                            "oid",
                            True,
                        ),
                    }

                class Typings:
                    """Test data for typings tests."""

                    SAMPLE_ATTR_DICT: Final[dict[str, list[str]]] = {
                        "cn": ["John Doe"],
                        "sn": ["Doe"],
                        "mail": ["john@example.com", "john.doe@example.com"],
                        "objectClass": ["person", "inetOrgPerson"],
                    }
                    SAMPLE_DISTRIBUTION: Final[dict[str, int]] = {
                        "inetOrgPerson": 1245,
                        "groupOfNames": 89,
                        "organizationalUnit": 34,
                        "domain": 1,
                        "country": 1,
                        "dcObject": 1,
                    }
                    REMOVED_NAMESPACES: Final[Sequence[str]] = [
                        "Parser",
                        "Writer",
                        "LdifValidation",
                        "LdifProcessing",
                        "Analytics",
                        "ServerTypes",
                        "Functional",
                        "Streaming",
                        "AnnotatedLdif",
                        "ModelAliases",
                        "LdifProject",
                        "Project",
                    ]
                    REMOVED_COMMON_DICT: Final[Sequence[str]] = [
                        "ChangeDict",
                        "CategorizedDict",
                        "TreeDict",
                        "HierarchyDict",
                    ]
                    REMOVED_ENTRY: Final[Sequence[str]] = [
                        "EntryConfiguration",
                        "EntryValidation",
                        "EntryTransformation",
                        "EntryProcessing",
                    ]

            class _General:
                """General test constants (from fixtures/general_constants.py)."""

                SAMPLE_DN: Final[str] = "cn=test,dc=example,dc=com"
                SAMPLE_DN_1: Final[str] = "cn=test1,dc=example,dc=com"
                SAMPLE_DN_2: Final[str] = "cn=test2,dc=example,dc=com"
                SAMPLE_SCHEMA_DN: Final[str] = "cn=schema"
                SAMPLE_USER_DN: Final[str] = "uid=testuser,ou=people,dc=example,dc=com"
                SAMPLE_SUBSCHEMA_DN: Final[str] = "cn=subschema"
                SAMPLE_LDIF_ENTRY: Final[str] = (
                    "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: user\n"
                )
                SAMPLE_LDIF_TWO_ENTRIES: Final[str] = (
                    "dn: cn=test1,dc=example,dc=com\ncn: test1\n\ndn: cn=test2,dc=example,dc=com\ncn: test2\n"
                )
                WRITER_FAILED_MSG: Final[str] = "Writer failed"
                PARSER_ERROR_MSG: Final[str] = "Parser error"
                DN_ERROR_MSG: Final[str] = "DN error"
                INVALID_ENTRY_MSG: Final[str] = "Invalid entry"
                PARSE_FAILED_MSG: Final[str] = "Parse failed"
                WRITE_FAILED_MSG: Final[str] = "Write failed"
                INVALID_ATTRIBUTE: Final[str] = (
                    "this is not a valid attribute definition"
                )
                INVALID_DN: Final[str] = "invalid-dn-format"
                INVALID_DATA_TYPE: Final[str] = "invalid_type"
                ATTR_NAME_CN: Final[str] = "cn"
                ATTR_NAME_SN: Final[str] = "sn"
                ATTR_NAME_OBJECTCLASS: Final[str] = "objectClass"
                ATTR_VALUE_TEST: Final[str] = "test"
                ATTR_VALUE_TEST1: Final[str] = "test1"
                ATTR_VALUE_TEST2: Final[str] = "test2"
                ATTR_VALUE_USER: Final[str] = "user"
                OC_NAME_PERSON: Final[str] = "person"
                OC_NAME_TOP: Final[str] = "top"

            class _RfcServer:
                """RFC server test constants (from fixtures/rfc_constants.py)."""

                ATTR_DEF_CN: Final[str] = "( 2.5.4.3 NAME 'cn' )"
                ATTR_DEF_CN_FULL: Final[str] = (
                    "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch )"
                )
                ATTR_DEF_CN_COMPLETE: Final[str] = (
                    "( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
                )
                ATTR_DEF_SN: Final[str] = (
                    "( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )"
                )
                ATTR_DEF_OBJECTCLASS: Final[str] = (
                    "( 2.5.4.0 NAME 'objectClass' DESC 'Object Class' SYNTAX '1.3.6.1.4.1.1466.115.121.1.38' )"
                )
                ATTR_OID_CN: Final[str] = "2.5.4.3"
                ATTR_OID_OBJECTCLASS: Final[str] = "2.5.4.0"
                ATTR_NAME_CN: Final[str] = "cn"
                ATTR_OID_SN: Final[str] = "2.5.4.4"
                ATTR_NAME_SN: Final[str] = "sn"
                OC_DEF_PERSON: Final[str] = "( 2.5.6.6 NAME 'person' STRUCTURAL )"
                OC_DEF_PERSON_FULL: Final[str] = (
                    "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) )"
                )
                OC_DEF_PERSON_BASIC: Final[str] = (
                    "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL )"
                )
                OC_OID_PERSON: Final[str] = "2.5.6.6"
                OC_NAME_PERSON: Final[str] = "person"
                TEST_DN: Final[str] = "cn=test,dc=example,dc=com"
                TEST_ORIGIN: Final[str] = "test.ldif"
                SCHEMA_DN_SUBSCHEMA: Final[str] = "cn=subschema"
                SCHEMA_DN_SCHEMA: Final[str] = "cn=schema"
                SCHEMA_DN_SCHEMA_SYSTEM: Final[str] = "cn=schema,o=system"
                ATTR_DEF_CN_MINIMAL: Final[str] = "( 2.5.4.3 )"
                ATTR_DEF_ST: Final[str] = (
                    "( 2.5.4.8 NAME 'st' DESC 'State or Province Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch )"
                )
                ATTR_DEF_MAIL: Final[str] = (
                    "( 0.9.2342.19200300.100.1.3 NAME 'mail' SUP name DESC 'Email address' )"
                )
                ATTR_OID_MAIL: Final[str] = "0.9.2342.19200300.100.1.3"
                ATTR_NAME_MAIL: Final[str] = "mail"
                ATTR_DEF_MODIFY_TIMESTAMP: Final[str] = (
                    "( 2.5.18.2 NAME 'modifyTimestamp' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )"
                )
                ATTR_DEF_OBSOLETE: Final[str] = (
                    "( 2.5.4.10 NAME 'o' DESC 'Organization Name' OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
                )
                ATTR_OID_O: Final[str] = "2.5.4.10"
                ATTR_NAME_O: Final[str] = "o"
                SYNTAX_OID_DIRECTORY_STRING: Final[str] = (
                    "1.3.6.1.4.1.1466.115.121.1.15"
                )
                SYNTAX_OID_BOOLEAN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.7"
                SYNTAX_OID_INTEGER: Final[str] = "1.3.6.1.4.1.1466.115.121.1.27"
                INVALID_ATTR_DEF: Final[str] = "NAME 'cn' DESC 'Common Name'"
                INVALID_OC_DEF: Final[str] = "invalid objectclass definition"
                SAMPLE_LDIF_CONTENT: Final[str] = (
                    "dn: cn=schema\nattributeTypes: ( 2.5.4.3 NAME 'cn' )\nobjectClasses: ( 2.5.6.6 NAME 'person' STRUCTURAL )\n"
                )
                SAMPLE_SCHEMA_CONTENT: Final[str] = (
                    "dn: cn=subschema\nobjectClass: top\nobjectClass: subentry\nobjectClass: subschema\ncn: subschema\nattributeTypes: ( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )\nobjectClasses: ( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) )\n"
                )
                SAMPLE_DN: Final[str] = "cn=test,dc=example,dc=com"
                SAMPLE_DN_USER1: Final[str] = "cn=user1,dc=example,dc=com"
                SAMPLE_DN_USER2: Final[str] = "cn=user2,dc=example,dc=com"
                SAMPLE_DN_TEST_USER: Final[str] = "cn=Test User,dc=example,dc=com"
                INVALID_DN: Final[str] = "invalid-dn-format"
                SAMPLE_LDIF_BASIC: Final[str] = (
                    "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: user\n"
                )
                SAMPLE_LDIF_MULTIPLE: Final[str] = (
                    "dn: cn=user1,dc=example,dc=com\nobjectClass: person\ncn: user1\n\ndn: cn=user2,dc=example,dc=com\nobjectClass: person\ncn: user2\n"
                )
                SAMPLE_LDIF_BINARY: Final[str] = (
                    "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nphoto:: UGhvdG8gZGF0YQ==\n"
                )
                SAMPLE_ATTRIBUTE_CN: Final[str] = "cn"
                SAMPLE_ATTRIBUTE_SN: Final[str] = "sn"
                SAMPLE_ATTRIBUTE_PHOTO: Final[str] = "photo"
                SAMPLE_VALUE_TEST: Final[str] = "test"
                SAMPLE_VALUE_USER: Final[str] = "user"
                SAMPLE_VALUE_USER1: Final[str] = "user1"
                SAMPLE_VALUE_USER2: Final[str] = "user2"
                SAMPLE_OBJECTCLASS_PERSON: Final[str] = "person"
                BASE64_PHOTO_DATA: Final[str] = "UGhvdG8gZGF0YQ=="
                ACL_LINE_SAMPLE: Final[str] = (
                    '(targetattr="*")(version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
                )
                ACL_LINE_EMPTY_OID: Final[str] = ""
                ACL_LINE_INVALID_OID: Final[str] = "invalid.oid.format"

            class _OidServer:
                """OID server test constants (from fixtures/oid_constants.py)."""

                ORACLE_OID_NAMESPACE: Final[str] = "2.16.840.1.113894"
                ATTRIBUTE_ORCLGUID: Final[str] = (
                    "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
                )
                ATTRIBUTE_ORCLDBNAME: Final[str] = (
                    "( 2.16.840.1.113894.1.1.2 NAME 'orclDBName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
                )
                ATTRIBUTE_ORCLGUID_COMPLEX: Final[str] = (
                    "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' DESC 'Oracle Global Unique Identifier' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )"
                )
                OBJECTCLASS_ORCLCONTEXT: Final[str] = (
                    "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
                )
                OBJECTCLASS_ORCLCONTAINER: Final[str] = (
                    "( 2.16.840.1.113894.1.2.2 NAME 'orclContainer' SUP top STRUCTURAL MUST cn )"
                )
                OBJECTCLASS_ORCLCONTEXT_WITH_MAY: Final[str] = (
                    "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn MAY ( description $ orclVersion ) )"
                )
                ATTRIBUTE_NAME_ORCLGUID: Final[str] = "orclGUID"
                ATTRIBUTE_NAME_ORCLDBNAME: Final[str] = "orclDBName"
                OBJECTCLASS_NAME_ORCLCONTEXT: Final[str] = "orclContext"
                OBJECTCLASS_NAME_ORCLCONTAINER: Final[str] = "orclContainer"

            class _OudServer:
                """OUD server test constants (from fixtures/oud_constants.py)."""

                SCHEMA_DN: Final[str] = "cn=schema"
                SCHEMA_DN_SUBSCHEMA: Final[str] = "cn=subschemasubentry"

            class _Values:
                """Value constants for testing."""

                TEST: Final[str] = "test"
                USER: Final[str] = "user"
                USER1: Final[str] = "user1"
                USER2: Final[str] = "user2"
                ADMIN: Final[str] = "REDACTED_LDAP_BIND_PASSWORD"
                EXAMPLE: Final[str] = "example"
                USER1_EMAIL: Final[str] = "user1@example.com"
                USER2_EMAIL: Final[str] = "user2@example.com"
                ATTRIBUTE_ORCLGUID: Final[str] = (
                    "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
                )
                ATTRIBUTE_ORCLGUID_WITH_X_ORIGIN: Final[str] = (
                    "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 X-ORIGIN 'Oracle' )"
                )
                ATTRIBUTE_ORCLGUID_WITH_X_EXTENSIONS: Final[str] = (
                    "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 X-ORIGIN 'Oracle' X-FILE-REF '99-user.ldif' X-NAME 'TestName' X-ALIAS 'testAlias' X-OID '1.2.3.5' )"
                )
                ATTRIBUTE_SYNTAX_WITH_QUOTES: Final[str] = (
                    "( 1.2.3.4 NAME 'testAttr' SYNTAX '1.3.6.1.4.1.1466.115.121.1.7' )"
                )
                ATTRIBUTE_SYNTAX_WITHOUT_QUOTES: Final[str] = (
                    "( 1.2.3.4 NAME 'testAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )"
                )
                ATTRIBUTE_INVALID_OID: Final[str] = (
                    "( invalid@oid!format NAME 'testAttr' )"
                )
                OBJECTCLASS_ORCLCONTEXT: Final[str] = (
                    "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
                )
                OBJECTCLASS_MULTIPLE_SUP: Final[str] = (
                    "( 1.2.3.4 NAME 'testOC' SUP ( top $ person ) STRUCTURAL )"
                )
                OBJECTCLASS_SINGLE_SUP: Final[str] = (
                    "( 1.2.3.4 NAME 'testOC' SUP top STRUCTURAL )"
                )
                SAMPLE_ATTRIBUTE_OID: Final[str] = "1.2.3.4"
                SAMPLE_ATTRIBUTE_OID_2: Final[str] = "1.2.3.5"
                SAMPLE_OBJECTCLASS_OID: Final[str] = "1.2.3.6"
                SAMPLE_SYNTAX_OID: Final[str] = "1.3.6.1.4.1.1466.115.121.1.15"
                SAMPLE_SYNTAX_OID_QUOTED: Final[str] = "1.3.6.1.4.1.1466.115.121.1.7"
                SAMPLE_ATTRIBUTE_NAME: Final[str] = "testAttr"
                SAMPLE_ATTRIBUTE_NAME_2: Final[str] = "testAttr2"
                SAMPLE_OBJECTCLASS_NAME: Final[str] = "testOC"
                SAMPLE_ATTRIBUTE_DEF: Final[str] = (
                    "( 1.2.3.4 NAME 'testAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
                )
                SAMPLE_ATTRIBUTE_DEF_2: Final[str] = (
                    "( 1.2.3.5 NAME 'testAttr2' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
                )
                SAMPLE_OBJECTCLASS_DEF: Final[str] = (
                    "( 1.2.3.6 NAME 'testOC' SUP top STRUCTURAL )"
                )
                SAMPLE_DN: Final[str] = "cn=test,dc=example,dc=com"
                SAMPLE_SCHEMA_DN: Final[str] = "cn=schema"
                SAMPLE_ACI: Final[str] = (
                    '(targetattr="*")(version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
                )
                SAMPLE_ACI_WITH_MACRO_SUBJECT: Final[str] = (
                    '(targetattr="*")(version 3.0; acl "test"; allow (read) userdn="ldap:///($dn)";)'
                )
                SAMPLE_ACI_WITH_MACRO_TARGET: Final[str] = (
                    '(target="($dn)")(version 3.0; acl "test"; allow (read) userdn="ldap:///($dn)";)'
                )
                SAMPLE_ACI_WITH_MACRO_SUBJECT_NO_TARGET: Final[str] = (
                    '(targetattr="*")(version 3.0; acl "test"; allow (read) userdn="ldap:///[$dn]";)'
                )
                ACL_ATTRIBUTE_ACI: Final[str] = "aci"
                ACL_ATTRIBUTE_ORCLACI: Final[str] = "orclaci"
                MATCHING_RULE_DEF: Final[str] = (
                    "( 1.2.3.7 NAME 'testMR' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
                )
                MATCHING_RULE_USE_DEF: Final[str] = (
                    "( 1.2.3.8 NAME 'testMRU' APPLIES testAttr )"
                )

            class _Conversion:
                """Conversion test constants (from conftest ConversionTestConstants)."""

                OID_ATTRIBUTE_ORCLGUID: Final[str] = (
                    "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
                )
                OID_ATTRIBUTE_ORCLDBNAME: Final[str] = (
                    "( 2.16.840.1.113894.1.1.2 NAME 'orclDBName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
                )
                OID_ATTRIBUTE_ORCLGUID_COMPLEX: Final[str] = (
                    "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' DESC 'Oracle Global Unique Identifier' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )"
                )
                OUD_ATTRIBUTE_ORCLGUID: Final[str] = (
                    "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
                )
                OID_OBJECTCLASS_ORCLCONTEXT: Final[str] = (
                    "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
                )
                OID_OBJECTCLASS_ORCLCONTAINER: Final[str] = (
                    "( 2.16.840.1.113894.1.2.2 NAME 'orclContainer' SUP top STRUCTURAL MUST cn )"
                )
                OID_OBJECTCLASS_ORCLCONTEXT_WITH_MAY: Final[str] = (
                    "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn MAY ( description $ orclVersion ) )"
                )
                OUD_OBJECTCLASS_ORCLCONTEXT: Final[str] = (
                    "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
                )

            class _Migration:
                """Migration pipeline test constants."""

                class Oid:
                    """Constants for OID boolean conversion tests."""

                    RFC_TO_OID_BOOLEAN: Final[Mapping[str, str]] = {
                        "TRUE": "1",
                        "FALSE": "0",
                    }
                    OID_TO_RFC_BOOLEAN: Final[Mapping[str, str]] = {
                        "1": "TRUE",
                        "0": "FALSE",
                    }

            class _ProtocolTest:
                """Protocol test constants."""

                ATTR_PARSE: str = "parse_attribute"
                ATTR_WRITE: str = "write"
                ATTR_SERVER_TYPE: str = "server_type"
                ATTR_PRIORITY: str = "priority"
                ATTR_CAN_HANDLE_ATTRIBUTE: str = "can_handle_attribute"
                ATTR_CAN_HANDLE_OBJECTCLASS: str = "can_handle_objectclass"
                ATTR_SCHEMA: str = "schema"
                ATTR_ACL: str = "acl"
                ATTR_ENTRY: str = "entry"
                ATTR_IS_SUCCESS: str = "is_success"
                SAMPLE_ATTR_DEF: str = (
                    "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
                )
                SAMPLE_ATTR_DEF_SIMPLE: str = "( 2.5.4.3 NAME 'cn' )"
                SAMPLE_OC_DEF: str = "( 2.5.6.0 NAME 'top' ABSTRACT )"

            class _CrossQuirk:
                """Cross-quirk conversion test constants."""

                OID_ATTRIBUTE_ORCLGUID: Final[str] = (
                    "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' DESC 'Oracle GUID' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
                )
                OID_OBJECTCLASS_ORCLCONTAINER: Final[str] = (
                    "( 2.16.840.1.113894.2.1.1 NAME 'orclContainer' DESC 'Oracle Container' SUP top STRUCTURAL MUST cn MAY description )"
                )
                OID_ACL_ANONYMOUS: Final[str] = "orclaci: access to entry by * (browse)"
                OUD_ACI_ANONYMOUS: Final[str] = (
                    'aci: (targetattr="*")(version 3.0; acl "Test ACL"; allow (read,search) userdn="ldap:///anyone";)'
                )
                OUD_ATTRIBUTE_ORCLGUID: Final[str] = (
                    "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
                )
                OID_OBJECTCLASS_ORCLCONTEXT: Final[str] = (
                    "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
                )

            class _ConfigIntegration:
                """Config integration test constants."""

                SERVER_TYPES: ClassVar[t.StrSequence] = (
                    "oid",
                    "oud",
                    "openldap",
                    "rfc",
                )
                BASIC_ENTRY: Final[str] = (
                    "dn: cn=Test,dc=example,dc=com\ncn: Test\nobjectClass: person\n"
                )
                MULTIPLE_ENTRIES: Final[str] = (
                    "dn: cn=User1,dc=example,dc=com\ncn: User1\nobjectClass: person\n\n"
                    "dn: cn=User2,dc=example,dc=com\ncn: User2\nobjectClass: person\n\n"
                    "dn: cn=User3,dc=example,dc=com\ncn: User3\nobjectClass: person\n"
                )
                SERVER_CONTENT: ClassVar[t.StrMapping] = {
                    "oid": "dn: cn=OID Test,dc=example,dc=com\ncn: OID Test\nobjectClass: person\n",
                    "oud": "dn: cn=OUD Test,dc=example,dc=com\ncn: OUD Test\nobjectClass: person\n",
                    "openldap": "dn: cn=OpenLDAP Test,dc=example,dc=com\ncn: OpenLDAP Test\nobjectClass: person\n",
                    "rfc": "dn: cn=RFC Test,dc=example,dc=com\ncn: RFC Test\nobjectClass: person\n",
                }

            class _ConftestFactory:
                """Constants for FlextLdifTestConftest factory."""

                SAMPLE_LDIF_FILE: Final[str] = "tests/fixtures/sample_basic.ldif"
                COMPLEX_LDIF_FILE: Final[str] = "tests/fixtures/sample_complex.ldif"
                INVALID_LDIF_FILE: Final[str] = "tests/fixtures/sample_invalid.ldif"
                SAMPLE_DN: Final[str] = "cn=test,ou=users,dc=example,dc=com"
                SAMPLE_ATTRIBUTE: Final[str] = "cn"
                SAMPLE_VALUE: Final[str] = "test user"
                MAX_TEST_ENTRIES: Final[int] = 100
                MAX_TEST_ATTRIBUTES: Final[int] = 50
                MAX_TEST_VALUES: Final[int] = 20
                DEFAULT_TIMEOUT_MS: Final[int] = 5000
                MAX_PARSE_TIME_PER_ENTRY: Final[int] = 1000

                TEST_USERS: Final[Sequence[Mapping[str, str]]] = [
                    {"name": "Test User 1", "email": "user1@example.com"},
                    {"name": "Test User 2", "email": "user2@example.com"},
                    {"name": "Test User 3", "email": "user3@example.com"},
                ]

            class _Scenarios:
                """Scenario enums used by parametrized tests."""

                class Relaxed:
                    """Relaxed quirk scenarios."""

                    @unique
                    class Parse(StrEnum):
                        VALID = "valid"
                        MALFORMED = "malformed"
                        MISSING_NAME = "missing_name"
                        NO_OID = "no_oid"
                        EMPTY = "empty"
                        WHITESPACE = "whitespace"
                        BINARY_DATA = "binary_data"
                        UNICODE = "unicode"
                        LONG_DEFINITION = "long_definition"

                class Api:
                    """API integration scenarios."""

                    @unique
                    class Scenario(StrEnum):
                        SIMPLE_LDIF = "simple_ldif"
                        BUILD_ENTRY = "build_entry"
                        VALIDATE_ENTRIES = "validate_entries"
                        MULTIPLE_INSTANCES = "multiple_instances"
                        API_FACADE_PROPERTIES = "api_facade_properties"
                        END_TO_END_WORKFLOW = "end_to_end_workflow"

                class AclRegistry:
                    """ACL registry scenarios."""

                    @unique
                    class GetAclAttributes(StrEnum):
                        RFC = "rfc"
                        OID = "oid"
                        OUD = "oud"
                        AD = "ad"
                        GENERIC = "generic"
                        UNKNOWN = "unknown_server"
                        NONE = "none"

                    @unique
                    class IsAclAttribute(StrEnum):
                        VALID_RFC = "valid_rfc"
                        VALID_SERVER_SPECIFIC = "valid_server_specific"
                        INVALID = "invalid"
                        CASE_INSENSITIVE = "case_insensitive"

                class Protocol:
                    """Protocol test scenarios."""

                    @unique
                    class Names(StrEnum):
                        SCHEMA = "SchemaQuirk"
                        ACL = "AclQuirk"
                        ENTRY = "EntryQuirk"

            class _TestCases:
                """Parametrized test case data for quirk server tests."""

                class Apache:
                    """Apache quirk test cases."""

                    ATTRIBUTE_TEST_CASES = (
                        m.Ldif.Tests.AttributeTestCase(
                            scenario="apache_oid",
                            attr_definition="( 1.3.6.1.4.1.18060.0.4.1.2.100 NAME 'ads-enabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
                            expected_can_handle=True,
                            expected_name="ads-enabled",
                        ),
                        m.Ldif.Tests.AttributeTestCase(
                            scenario="ads_prefix",
                            attr_definition="( 2.16.840.1.113730.3.1.1 NAME 'ads-searchBaseDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
                            expected_can_handle=True,
                            expected_name="ads-searchBaseDN",
                        ),
                        m.Ldif.Tests.AttributeTestCase(
                            scenario="apacheds_name",
                            attr_definition="( 1.2.3.4 NAME 'apachedsSystemId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                            expected_can_handle=True,
                            expected_name="apachedsSystemId",
                        ),
                        m.Ldif.Tests.AttributeTestCase(
                            scenario="standard_rfc",
                            attr_definition="( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                            expected_can_handle=False,
                            expected_name="cn",
                        ),
                    )
                    OBJECTCLASS_TEST_CASES = (
                        m.Ldif.Tests.ObjectClassTestCase(
                            scenario="apache_oid",
                            oc_definition="( 1.3.6.1.4.1.18060.0.4.1.3.100 NAME 'ads-directoryService' SUP top STRUCTURAL )",
                            expected_can_handle=True,
                            expected_name="ads-directoryService",
                        ),
                        m.Ldif.Tests.ObjectClassTestCase(
                            scenario="ads_name",
                            oc_definition="( 2.5.6.0 NAME 'ads-base' SUP top ABSTRACT )",
                            expected_can_handle=True,
                            expected_name="ads-base",
                        ),
                        m.Ldif.Tests.ObjectClassTestCase(
                            scenario="standard_rfc",
                            oc_definition="( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )",
                            expected_can_handle=False,
                            expected_name="posixAccount",
                        ),
                    )
                    ENTRY_TEST_CASES = (
                        m.Ldif.Tests.EntryTestCase(
                            scenario="ou_config",
                            entry_dn="ou=config,dc=example,dc=com",
                            attributes={"objectClass": ["organizationalUnit"]},
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="ou_services",
                            entry_dn="ou=services,dc=example,dc=com",
                            attributes={"objectClass": ["organizationalUnit"]},
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="ou_system",
                            entry_dn="ou=system,dc=example,dc=com",
                            attributes={"objectClass": ["organizationalUnit"]},
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="ou_partitions",
                            entry_dn="ou=partitions,dc=example,dc=com",
                            attributes={"objectClass": ["organizationalUnit"]},
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="ads_attribute",
                            entry_dn="cn=test,dc=example,dc=com",
                            attributes={
                                "ads-enabled": ["TRUE"],
                                "objectClass": ["top"],
                            },
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="apacheds_attribute",
                            entry_dn="cn=test,dc=example,dc=com",
                            attributes={
                                "apachedsSystemId": ["test"],
                                "objectClass": ["top"],
                            },
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="ads_objectclass",
                            entry_dn="cn=test,dc=example,dc=com",
                            attributes={"objectClass": ["top", "ads-directory"]},
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="standard_rfc",
                            entry_dn="cn=user,dc=example,dc=com",
                            attributes={"objectClass": ["person"], "cn": ["user"]},
                            expected_can_handle=True,
                        ),
                    )

                class Ds389:
                    """DS389 quirk test cases."""

                    ATTRIBUTE_TEST_CASES = (
                        m.Ldif.Tests.AttributeTestCase(
                            scenario="ds389_oid",
                            attr_definition="( 2.16.840.1.113730.3.1.1 NAME 'nsslapd-suffix' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
                            expected_can_handle=True,
                            expected_oid="2.16.840.1.113730.3.1.1",
                            expected_name="nsslapd-suffix",
                        ),
                        m.Ldif.Tests.AttributeTestCase(
                            scenario="nsslapd_prefix",
                            attr_definition="( 1.2.3.4 NAME 'nsslapd-port' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
                            expected_can_handle=True,
                            expected_name="nsslapd-port",
                        ),
                        m.Ldif.Tests.AttributeTestCase(
                            scenario="nsds_prefix",
                            attr_definition="( 1.2.3.4 NAME 'nsds5ReplicaId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
                            expected_can_handle=True,
                            expected_name="nsds5ReplicaId",
                        ),
                        m.Ldif.Tests.AttributeTestCase(
                            scenario="nsuniqueid_prefix",
                            attr_definition="( 1.2.3.4 NAME 'nsuniqueid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                            expected_can_handle=True,
                            expected_name="nsuniqueid",
                        ),
                        m.Ldif.Tests.AttributeTestCase(
                            scenario="standard_rfc",
                            attr_definition="( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                            expected_can_handle=False,
                        ),
                    )
                    OBJECTCLASS_TEST_CASES = (
                        m.Ldif.Tests.ObjectClassTestCase(
                            scenario="ds389_oid",
                            oc_definition="( 2.16.840.1.113730.3.2.1 NAME 'nscontainer' SUP top STRUCTURAL )",
                            expected_can_handle=True,
                            expected_oid="2.16.840.1.113730.3.2.1",
                            expected_name="nscontainer",
                            expected_kind="STRUCTURAL",
                        ),
                        m.Ldif.Tests.ObjectClassTestCase(
                            scenario="ns_name",
                            oc_definition="( 2.5.6.0 NAME 'nsperson' SUP top STRUCTURAL )",
                            expected_can_handle=True,
                            expected_name="nsperson",
                        ),
                        m.Ldif.Tests.ObjectClassTestCase(
                            scenario="standard_rfc",
                            oc_definition="( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )",
                            expected_can_handle=False,
                        ),
                    )
                    ENTRY_TEST_CASES = (
                        m.Ldif.Tests.EntryTestCase(
                            scenario="cn_config",
                            entry_dn="cn=config",
                            attributes={c.Ldif.DictKeys.OBJECTCLASS: ["nscontainer"]},
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="cn_monitor",
                            entry_dn="cn=monitor",
                            attributes={c.Ldif.DictKeys.OBJECTCLASS: ["top"]},
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="cn_changelog",
                            entry_dn="cn=changelog",
                            attributes={c.Ldif.DictKeys.OBJECTCLASS: ["top"]},
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="nsslapd_attribute",
                            entry_dn="cn=test,dc=example,dc=com",
                            attributes={
                                "nsslapd-port": ["389"],
                                "objectclass": ["top"],
                            },
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="nsds_attribute",
                            entry_dn="cn=test,dc=example,dc=com",
                            attributes={
                                "nsds5ReplicaId": ["1"],
                                "objectclass": ["top"],
                            },
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="nsuniqueid_attribute",
                            entry_dn="cn=test,dc=example,dc=com",
                            attributes={
                                "nsuniqueid": ["12345"],
                                "objectclass": ["top"],
                            },
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="ns_objectclass",
                            entry_dn="cn=test,dc=example,dc=com",
                            attributes={
                                c.Ldif.DictKeys.OBJECTCLASS: [
                                    "top",
                                    "nscontainer",
                                ],
                            },
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="standard_rfc",
                            entry_dn="cn=user,dc=example,dc=com",
                            attributes={
                                c.Ldif.DictKeys.OBJECTCLASS: ["person"],
                                "cn": ["user"],
                            },
                            expected_can_handle=False,
                        ),
                    )

                class Novell:
                    """Novell quirk test cases."""

                    ATTRIBUTE_TEST_CASES = (
                        m.Ldif.Tests.AttributeTestCase(
                            scenario="novell_oid",
                            attr_definition="( 2.16.840.1.113719.1.1.4.1.501 NAME 'nspmPasswordPolicyDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
                            expected_can_handle=True,
                            expected_oid="2.16.840.1.113719.1.1.4.1.501",
                            expected_name="nspmPasswordPolicyDN",
                        ),
                        m.Ldif.Tests.AttributeTestCase(
                            scenario="nspm_prefix",
                            attr_definition="( 1.2.3.4 NAME 'nspmPasswordPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                            expected_can_handle=True,
                            expected_name="nspmPasswordPolicy",
                        ),
                        m.Ldif.Tests.AttributeTestCase(
                            scenario="login_prefix",
                            attr_definition="( 1.2.3.4 NAME 'loginDisabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
                            expected_can_handle=True,
                            expected_name="loginDisabled",
                        ),
                        m.Ldif.Tests.AttributeTestCase(
                            scenario="dirxml_prefix",
                            attr_definition="( 1.2.3.4 NAME 'dirxml-associations' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                            expected_can_handle=True,
                            expected_name="dirxml-associations",
                        ),
                        m.Ldif.Tests.AttributeTestCase(
                            scenario="standard_rfc",
                            attr_definition="( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                            expected_can_handle=False,
                        ),
                    )
                    OBJECTCLASS_TEST_CASES = (
                        m.Ldif.Tests.ObjectClassTestCase(
                            scenario="novell_oid",
                            oc_definition="( 2.16.840.1.113719.2.2.6.1 NAME 'ndsPerson' SUP top STRUCTURAL )",
                            expected_can_handle=True,
                            expected_oid="2.16.840.1.113719.2.2.6.1",
                            expected_name="ndsPerson",
                        ),
                        m.Ldif.Tests.ObjectClassTestCase(
                            scenario="nds_name",
                            oc_definition="( 2.5.6.0 NAME 'ndsserver' SUP top STRUCTURAL )",
                            expected_can_handle=True,
                            expected_name="ndsserver",
                        ),
                        m.Ldif.Tests.ObjectClassTestCase(
                            scenario="standard_rfc",
                            oc_definition="( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )",
                            expected_can_handle=False,
                        ),
                    )
                    ENTRY_TEST_CASES = (
                        m.Ldif.Tests.EntryTestCase(
                            scenario="ou_services",
                            entry_dn="ou=services,o=Example",
                            attributes={"objectClass": ["organizationalUnit"]},
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="ou_apps",
                            entry_dn="ou=apps,o=Example",
                            attributes={"objectClass": ["organizationalUnit"]},
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="ou_system",
                            entry_dn="ou=system,o=Example",
                            attributes={"objectClass": ["organizationalUnit"]},
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="nspm_attribute",
                            entry_dn="cn=user,o=Example",
                            attributes={
                                "nspmpasswordpolicy": ["policy1"],
                                "objectClass": ["top"],
                            },
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="login_attribute",
                            entry_dn="cn=user,o=Example",
                            attributes={
                                "logindisabled": ["TRUE"],
                                "objectClass": ["top"],
                            },
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="nds_objectclass",
                            entry_dn="cn=user,o=Example",
                            attributes={"objectClass": ["top", "ndsperson"]},
                            expected_can_handle=True,
                        ),
                        m.Ldif.Tests.EntryTestCase(
                            scenario="standard_rfc",
                            entry_dn="cn=user,dc=example,dc=com",
                            attributes={"objectClass": ["person"], "cn": ["user"]},
                            expected_can_handle=False,
                        ),
                    )

            @unique
            class _ServerType(StrEnum):
                """Canonical server identifiers for tests."""

                RFC = "rfc"
                OID = "oid"
                OUD = "oud"
                OPENLDAP = "openldap"
                OPENLDAP1 = "openldap1"
                DS389 = "ds389"
                APACHE = "apache"
                NOVELL = "novell"
                TIVOLI = "tivoli"
                AD = "ad"

            @unique
            class _FixtureType(StrEnum):
                """Canonical fixture categories for tests."""

                SCHEMA = "schema"
                ACL = "acl"
                ENTRIES = "entries"
                INTEGRATION = "integration"

            DOCKER_CONTAINER_NAME: Final[str] = _Docker.CONTAINER_NAME
            DOCKER_COMPOSE_FILE_REL: Final[str] = _Docker.COMPOSE_FILE_REL
            DOCKER_SERVICE_NAME: Final[str] = _Docker.SERVICE_NAME
            DOCKER_PORT: Final[int] = _Docker.PORT
            DOCKER_BASE_DN: Final[str] = _Docker.BASE_DN
            DOCKER_ADMIN_DN: Final[str] = _Docker.ADMIN_DN
            DOCKER_ADMIN_PASSWORD: Final[str] = _Docker.ADMIN_PASSWORD
            DOCKER_LEGACY_ADMIN_DN: Final[str] = _Docker.LEGACY_ADMIN_DN
            DOCKER_LEGACY_ADMIN_PASSWORD: Final[str] = _Docker.LEGACY_ADMIN_PASSWORD

            SCHEMA_STRUCTURAL: Final[str] = _Schema.STRUCTURAL
            SCHEMA_AUXILIARY: Final[str] = _Schema.AUXILIARY
            SCHEMA_ABSTRACT: Final[str] = _Schema.ABSTRACT

            NAME_CN: Final[str] = _Names.CN
            NAME_SN: Final[str] = _Names.SN
            NAME_MAIL: Final[str] = _Names.MAIL
            NAME_UID: Final[str] = _Names.UID
            NAME_OBJECTCLASS: Final[str] = _Names.OBJECTCLASS
            NAME_PERSON: Final[str] = _Names.PERSON
            NAME_TOP: Final[str] = _Names.TOP
            NAME_INETORGPERSON: Final[str] = _Names.INETORGPERSON

            DN_TEST: Final[str] = _Dns.TEST
            DN_TEST_USER: Final[str] = _Dns.TEST_USER

            OID_CN: Final[str] = _Oids.CN

            RFC_SAMPLE_LDIF_BASIC: Final[str] = _Rfc.SAMPLE_LDIF_BASIC
            RFC_SAMPLE_LDIF_MULTIPLE: Final[str] = _Rfc.SAMPLE_LDIF_MULTIPLE
            RFC_TEST_DN: Final[str] = _Rfc.TEST_DN

            ATTR_VALUE_TEST: Final[str] = _General.ATTR_VALUE_TEST
            ATTR_VALUE_USER: Final[str] = _General.ATTR_VALUE_USER

            CONFIG_BASIC_ENTRY: Final[str] = _ConfigIntegration.BASIC_ENTRY
            CONFIG_MULTIPLE_ENTRIES: Final[str] = _ConfigIntegration.MULTIPLE_ENTRIES

            CROSS_QUIRK_OID_ATTRIBUTE_ORCLGUID: Final[str] = (
                _CrossQuirk.OID_ATTRIBUTE_ORCLGUID
            )
            CROSS_QUIRK_OID_OBJECTCLASS_ORCLCONTAINER: Final[str] = (
                _CrossQuirk.OID_OBJECTCLASS_ORCLCONTAINER
            )
            CROSS_QUIRK_OID_OBJECTCLASS_ORCLCONTEXT: Final[str] = (
                _CrossQuirk.OID_OBJECTCLASS_ORCLCONTEXT
            )
            CROSS_QUIRK_OID_ACL_ANONYMOUS: Final[str] = _CrossQuirk.OID_ACL_ANONYMOUS
            CROSS_QUIRK_OUD_ACI_ANONYMOUS: Final[str] = _CrossQuirk.OUD_ACI_ANONYMOUS
            CROSS_QUIRK_OUD_ATTRIBUTE_ORCLGUID: Final[str] = (
                _CrossQuirk.OUD_ATTRIBUTE_ORCLGUID
            )

            FIXTURE_SERVERS = FrozenList(
                [
                    _ServerType.OID,
                    _ServerType.OUD,
                    _ServerType.OPENLDAP,
                    _ServerType.OPENLDAP1,
                    _ServerType.DS389,
                    _ServerType.APACHE,
                    _ServerType.NOVELL,
                    _ServerType.TIVOLI,
                    _ServerType.AD,
                    _ServerType.RFC,
                ],
            )
            FIXTURE_SERVERS.freeze()

            FIXTURE_TYPES = FrozenList(
                [
                    _FixtureType.SCHEMA,
                    _FixtureType.ACL,
                    _FixtureType.ENTRIES,
                    _FixtureType.INTEGRATION,
                ],
            )
            FIXTURE_TYPES.freeze()

            CONFIG_SERVER_TYPES: Final[Sequence[str]] = tuple(
                value.value for value in FIXTURE_SERVERS
            )
            CONFIG_SERVER_CONTENT: Final[Mapping[str, str]] = MappingProxyType(
                dict(_ConfigIntegration.SERVER_CONTENT),
            )
            BOOLEAN_RFC_TO_OID: Final[Mapping[str, str]] = MappingProxyType(
                dict(_Migration.Oid.RFC_TO_OID_BOOLEAN),
            )
            BOOLEAN_OID_TO_RFC: Final[Mapping[str, str]] = MappingProxyType(
                dict(_Migration.Oid.OID_TO_RFC_BOOLEAN),
            )

            TEST_USERS = FrozenList(list(_ConftestFactory.TEST_USERS))
            TEST_USERS.freeze()

            RELAXED_PARSE_VALID: Final[str] = _Scenarios.Relaxed.Parse.VALID
            RELAXED_PARSE_MALFORMED: Final[str] = _Scenarios.Relaxed.Parse.MALFORMED
            API_SCENARIO_SIMPLE_LDIF: Final[str] = _Scenarios.Api.Scenario.SIMPLE_LDIF
            API_SCENARIO_MULTIPLE_INSTANCES: Final[str] = (
                _Scenarios.Api.Scenario.MULTIPLE_INSTANCES
            )
            PROTOCOL_NAME_SCHEMA: Final[str] = _Scenarios.Protocol.Names.SCHEMA
            PROTOCOL_NAME_ACL: Final[str] = _Scenarios.Protocol.Names.ACL
            PROTOCOL_NAME_ENTRY: Final[str] = _Scenarios.Protocol.Names.ENTRY
            ACL_REGISTRY_GET_ACL_ATTRIBUTES_DATA = (
                _TestData.AclRegistry.GET_ACL_ATTRIBUTES_DATA
            )
            ACL_REGISTRY_IS_ACL_ATTRIBUTE_DATA = (
                _TestData.AclRegistry.IS_ACL_ATTRIBUTE_DATA
            )

            RELAXED_ATTRIBUTE_DEFINITIONS = _TestData.Relaxed.ATTRIBUTE_DEFINITIONS
            RELAXED_OBJECTCLASS_DEFINITIONS = _TestData.Relaxed.OBJECTCLASS_DEFINITIONS
            RELAXED_NAME_FORMAT_VARIATIONS = FrozenList(
                list(_TestData.Relaxed.NAME_FORMAT_VARIATIONS),
            )
            RELAXED_NAME_FORMAT_VARIATIONS.freeze()
            RELAXED_ACL_DEFINITIONS = _TestData.Relaxed.ACL_DEFINITIONS

            SAMPLE_USER_DN = _TestData.SAMPLE_USER_DN
            TYPINGS_SAMPLE_ATTR_DICT = _TestData.Typings.SAMPLE_ATTR_DICT
            TYPINGS_SAMPLE_DISTRIBUTION = _TestData.Typings.SAMPLE_DISTRIBUTION
            TYPINGS_REMOVED_NAMESPACES = FrozenList(
                list(_TestData.Typings.REMOVED_NAMESPACES),
            )
            TYPINGS_REMOVED_NAMESPACES.freeze()
            TYPINGS_REMOVED_COMMON_DICT = FrozenList(
                list(_TestData.Typings.REMOVED_COMMON_DICT),
            )
            TYPINGS_REMOVED_COMMON_DICT.freeze()
            TYPINGS_REMOVED_ENTRY = FrozenList(list(_TestData.Typings.REMOVED_ENTRY))
            TYPINGS_REMOVED_ENTRY.freeze()

            PROTOCOL_ATTR_PARSE = _ProtocolTest.ATTR_PARSE
            PROTOCOL_ATTR_WRITE = _ProtocolTest.ATTR_WRITE
            PROTOCOL_ATTR_CAN_HANDLE_ATTRIBUTE = _ProtocolTest.ATTR_CAN_HANDLE_ATTRIBUTE
            PROTOCOL_ATTR_CAN_HANDLE_OBJECTCLASS = (
                _ProtocolTest.ATTR_CAN_HANDLE_OBJECTCLASS
            )
            PROTOCOL_ATTR_SCHEMA = _ProtocolTest.ATTR_SCHEMA
            PROTOCOL_ATTR_ACL = _ProtocolTest.ATTR_ACL
            PROTOCOL_ATTR_ENTRY = _ProtocolTest.ATTR_ENTRY
            PROTOCOL_SAMPLE_ATTR_DEF = _ProtocolTest.SAMPLE_ATTR_DEF

            APACHE_ATTRIBUTE_TEST_CASES = FrozenList(
                list(_TestCases.Apache.ATTRIBUTE_TEST_CASES),
            )
            APACHE_ATTRIBUTE_TEST_CASES.freeze()
            APACHE_OBJECTCLASS_TEST_CASES = FrozenList(
                list(_TestCases.Apache.OBJECTCLASS_TEST_CASES),
            )
            APACHE_OBJECTCLASS_TEST_CASES.freeze()
            APACHE_ENTRY_TEST_CASES = FrozenList(
                list(_TestCases.Apache.ENTRY_TEST_CASES)
            )
            APACHE_ENTRY_TEST_CASES.freeze()

            DS389_ATTRIBUTE_TEST_CASES = FrozenList(
                list(_TestCases.Ds389.ATTRIBUTE_TEST_CASES),
            )
            DS389_ATTRIBUTE_TEST_CASES.freeze()
            DS389_OBJECTCLASS_TEST_CASES = FrozenList(
                list(_TestCases.Ds389.OBJECTCLASS_TEST_CASES),
            )
            DS389_OBJECTCLASS_TEST_CASES.freeze()
            DS389_ENTRY_TEST_CASES = FrozenList(list(_TestCases.Ds389.ENTRY_TEST_CASES))
            DS389_ENTRY_TEST_CASES.freeze()

            NOVELL_ATTRIBUTE_TEST_CASES = FrozenList(
                list(_TestCases.Novell.ATTRIBUTE_TEST_CASES),
            )
            NOVELL_ATTRIBUTE_TEST_CASES.freeze()
            NOVELL_OBJECTCLASS_TEST_CASES = FrozenList(
                list(_TestCases.Novell.OBJECTCLASS_TEST_CASES),
            )
            NOVELL_OBJECTCLASS_TEST_CASES.freeze()
            NOVELL_ENTRY_TEST_CASES = FrozenList(
                list(_TestCases.Novell.ENTRY_TEST_CASES),
            )
            NOVELL_ENTRY_TEST_CASES.freeze()


c = TestsFlextLdifConstants

__all__ = ["TestsFlextLdifConstants", "c"]
