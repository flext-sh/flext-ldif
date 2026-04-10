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
    Callable,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
    Sized,
)
from enum import StrEnum, unique
from pathlib import Path
from typing import ClassVar, Final

from flext_tests import FlextTestsConstants
from pydantic import BaseModel

from flext_ldif import (
    FlextLdif,
    FlextLdifConstants,
    FlextLdifEntries,
    FlextLdifParser,
    FlextLdifServersBaseSchema,
    FlextLdifServersBaseSchemaAcl,
    FlextLdifWriter,
    ldif,
    m,
    p,
    r,
    t,
)
from tests import TestsFlextLdifModels, u


class TestsFlextLdifConstants(FlextTestsConstants):
    """Constants for flext-ldif tests using COMPOSITION INHERITANCE."""

    class Ldif(FlextLdifConstants.Ldif):
        """Domain namespace for flext-ldif test constants."""

        class Paths:
            """Test directory path constants."""

            FIXTURES_DIR: Final[Path] = Path(__file__).parent / "fixtures"
            OID_FIXTURES_DIR: Final[Path] = Path(__file__).parent / "fixtures" / "oid"
            WORKSPACE_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

        class Docker:
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

        class Schema:
            """Schema constants wrapper for test convenience."""

            STRUCTURAL: str = FlextLdifConstants.Ldif.SchemaKind.STRUCTURAL
            AUXILIARY: str = FlextLdifConstants.Ldif.SchemaKind.AUXILIARY
            ABSTRACT: str = FlextLdifConstants.Ldif.SchemaKind.ABSTRACT
            ACTIVE: str = "ACTIVE"
            DEPRECATED: str = "DEPRECATED"

        class Names:
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

        class Fixtures:
            """Test fixture directory names used in tests/fixtures/."""

            OID: Final[str] = "oid"
            OUD: Final[str] = "oud"
            OPENLDAP: Final[str] = "openldap"
            OPENLDAP2: Final[str] = "openldap2"
            RFC: Final[str] = "rfc"

        class DNs:
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

        class OIDs:
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

        class Rfc:
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
            SYNTAX_OID_DIRECTORY_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.15"
            SYNTAX_OID_BOOLEAN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.7"
            SYNTAX_OID_INTEGER: Final[str] = "1.3.6.1.4.1.1466.115.121.1.27"
            SYNTAX_OID_IA5_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.26"
            SYNTAX_OID_GENERALIZED_TIME: Final[str] = "1.3.6.1.4.1.1466.115.121.1.24"
            SYNTAX_OID_OID: Final[str] = "1.3.6.1.4.1.1466.115.121.1.38"
            OC_DEF_PERSON: Final[str] = (
                "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) )"
            )
            OC_DEF_PERSON_FULL: Final[str] = OC_DEF_PERSON
            OC_DEF_PERSON_BASIC: Final[str] = (
                "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL )"
            )
            OC_DEF_PERSON_MINIMAL: Final[str] = "( 2.5.6.6 NAME 'person' STRUCTURAL )"
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

        class TestData:
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

        class General:
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
            INVALID_ATTRIBUTE: Final[str] = "this is not a valid attribute definition"
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

        class RFC:
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
            SYNTAX_OID_DIRECTORY_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.15"
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

        class OidServer:
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

        class OUD:
            """OUD server test constants (from fixtures/oud_constants.py)."""

            SCHEMA_DN: Final[str] = "cn=schema"
            SCHEMA_DN_SUBSCHEMA: Final[str] = "cn=subschemasubentry"

        class Values:
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
            ATTRIBUTE_INVALID_OID: Final[str] = "( invalid@oid!format NAME 'testAttr' )"
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

        class Conversion:
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

        class Migration:
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

        class ProtocolTest:
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

        class CrossQuirk:
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

        class ConfigIntegration:
            """Config integration test constants."""

            SERVER_TYPES: ClassVar[t.StrSequence] = ("oid", "oud", "openldap", "rfc")
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

        class RfcTestHelpers:
            """RFC test helper utilities for LDIF testing."""

            @staticmethod
            def test_parse_ldif_content(
                parser_service: FlextLdifParser,
                content: str,
                expected_count: int,
                server_type: str = "rfc",
            ) -> Sequence[m.Ldif.Entry]:
                """Parse LDIF content and return entries.

                Args:
                    parser_service: The parser service instance
                    content: LDIF content to parse
                    expected_count: Expected number of entries (for validation)
                    server_type: Server type for parsing

                Returns:
                    List of parsed entries

                """
                parse_response: m.Ldif.ParseResponse = u.expect_success(
                    parser_service.parse_string(
                        content=content,
                        server_type=server_type,
                    ),
                    message="Parsing failed",
                )
                entries = parse_response.entries
                if len(entries) != expected_count:
                    raise AssertionError(
                        f"Expected {expected_count} entries, got {len(entries)}",
                    )
                return entries

            @staticmethod
            def test_entry_create_and_unwrap(
                dn: str,
                attributes: t.MutableAttributeMapping,
            ) -> m.Ldif.Entry:
                """Create an entry and unwrap the result.

                Args:
                    dn: Distinguished Name for the entry
                    attributes: Dictionary of attributes for the entry

                Returns:
                    The unwrapped Entry instance

                Raises:
                    AssertionError: If entry creation fails

                """
                entry: m.Ldif.Entry = u.expect_success(
                    m.Ldif.Entry.create(dn=dn, attributes=attributes),
                    message="Entry creation failed",
                )
                return entry

            @staticmethod
            def test_quirk_schema_parse_and_assert_properties(
                quirk: p.Ldif.SchemaQuirk | FlextLdifServersBaseSchema,
                schema_def: str,
                *,
                expected_oid: str | None = None,
                expected_name: str | None = None,
                expected_desc: str | None = None,
                expected_syntax: str | None = None,
                expected_single_value: bool | None = None,
                expected_length: int | None = None,
                expected_kind: str | None = None,
                expected_sup: str | None = None,
                expected_must: t.StrSequence | None = None,
                expected_may: t.StrSequence | None = None,
            ) -> p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass | None:
                """Parse schema definition and assert properties.

                Args:
                    quirk: Schema quirk instance
                    schema_def: Schema definition string (attribute or objectClass)
                    expected_oid: Expected OID
                    expected_name: Expected NAME
                    expected_desc: Expected DESC
                    expected_syntax: Expected SYNTAX (without length)
                    expected_single_value: Expected SINGLE-VALUE flag
                    expected_length: Expected syntax length (e.g., 256 from {256})
                    expected_kind: Expected KIND (STRUCTURAL, AUXILIARY, ABSTRACT)
                    expected_sup: Expected SUP (superior class)
                    expected_must: Expected MUST attributes
                    expected_may: Expected MAY attributes

                Returns:
                    The parsed schema t.NormalizedValue

                Raises:
                    AssertionError: If parsing fails or properties don't match

                """
                if (
                    "STRUCTURAL" in schema_def
                    or "AUXILIARY" in schema_def
                    or "ABSTRACT" in schema_def
                ):
                    parse_method = getattr(quirk, "parse_objectclass", None)
                else:
                    parse_method = getattr(quirk, "parse_attribute", None)
                if parse_method is None:
                    parse_method = getattr(quirk, "parse", None)
                if parse_method is None:
                    msg = "Quirk has no suitable parse method"
                    raise AssertionError(msg)
                result = parse_method(schema_def)
                if hasattr(result, "is_failure") and result.is_failure:
                    raise AssertionError(f"Parsing failed: {result.error}")
                value: p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass = (
                    result.value if hasattr(result, "value") else result
                )
                if expected_oid is not None:
                    actual_oid = getattr(value, "oid", None)
                    if actual_oid != expected_oid:
                        raise AssertionError(
                            f"Expected OID '{expected_oid}', got '{actual_oid}'",
                        )
                if expected_name is not None:
                    actual_name = getattr(value, "name", None)
                    if actual_name != expected_name:
                        raise AssertionError(
                            f"Expected NAME '{expected_name}', got '{actual_name}'",
                        )
                if expected_desc is not None:
                    actual_desc = getattr(value, "desc", None)
                    if actual_desc != expected_desc:
                        raise AssertionError(
                            f"Expected DESC '{expected_desc}', got '{actual_desc}'",
                        )
                if expected_syntax is not None:
                    actual_syntax = getattr(value, "syntax", None)
                    if actual_syntax != expected_syntax:
                        raise AssertionError(
                            f"Expected SYNTAX '{expected_syntax}', got '{actual_syntax}'",
                        )
                if expected_single_value is not None:
                    actual_sv = getattr(value, "single_value", None)
                    if actual_sv != expected_single_value:
                        raise AssertionError(
                            f"Expected SINGLE-VALUE {expected_single_value}, got {actual_sv}",
                        )
                if expected_length is not None:
                    actual_length = getattr(value, "length", None)
                    if actual_length != expected_length:
                        raise AssertionError(
                            f"Expected length {expected_length}, got {actual_length}",
                        )
                if expected_kind is not None:
                    actual_kind = getattr(value, "kind", None)
                    if actual_kind != expected_kind:
                        raise AssertionError(
                            f"Expected KIND '{expected_kind}', got '{actual_kind}'",
                        )
                if expected_sup is not None:
                    actual_sup = getattr(value, "sup", None)
                    if actual_sup != expected_sup:
                        raise AssertionError(
                            f"Expected SUP '{expected_sup}', got '{actual_sup}'",
                        )
                if expected_must is not None:
                    actual_must: t.StrSequence = (
                        list(value.must or [])
                        if isinstance(value, m.Ldif.SchemaObjectClass)
                        else []
                    )
                    if actual_must != list(expected_must):
                        raise AssertionError(
                            f"Expected MUST {expected_must}, got {actual_must}",
                        )
                if expected_may is not None:
                    actual_may: t.StrSequence = (
                        list(value.may or [])
                        if isinstance(value, m.Ldif.SchemaObjectClass)
                        else []
                    )
                    if actual_may != list(expected_may):
                        raise AssertionError(
                            f"Expected MAY {expected_may}, got {actual_may}",
                        )
                return value

            @staticmethod
            def test_result_success_and_unwrap(
                result: r[t.Ldif.RecursiveContainer],
                expected_type: type | None = None,
                expected_count: int | None = None,
            ) -> t.Ldif.RecursiveContainer | None:
                """Assert result is successful and unwrap its value.

                Args:
                    result: r instance to check
                    expected_type: Optional expected type for the unwrapped value
                    expected_count: Optional expected count if value is a sequence

                Returns:
                    The unwrapped value from the result

                Raises:
                    AssertionError: If result is failure or type mismatch

                """
                value = u.expect_success(result, message="Result is failure")
                if expected_type is not None and (not isinstance(value, expected_type)):
                    raise AssertionError(
                        f"Expected {expected_type.__name__}, got {type(value).__name__}",
                    )
                if expected_count is not None:
                    if not isinstance(value, Sized):
                        raise AssertionError(
                            f"Cannot check count on {type(value).__name__} - not a sequence",
                        )
                    sized_value: Sized = value
                    if len(sized_value) != expected_count:
                        raise AssertionError(
                            f"Expected count {expected_count}, got {len(sized_value)}",
                        )
                return value

            @staticmethod
            def test_create_entry_and_unwrap(
                dn: str,
                attributes: t.MutableAttributeMapping | None = None,
            ) -> m.Ldif.Entry:
                """Create an entry and unwrap the result.

                Alias for test_entry_create_and_unwrap for naming consistency.

                Args:
                    dn: Distinguished Name for the entry
                    attributes: Dictionary of attributes for the entry

                Returns:
                    The unwrapped Entry instance

                Raises:
                    AssertionError: If entry creation fails

                """
                if attributes is None:
                    attributes = {}
                entry: m.Ldif.Entry = u.expect_success(
                    m.Ldif.Entry.create(dn=dn, attributes=attributes),
                    message="Entry creation failed",
                )
                return entry

            @staticmethod
            def test_create_schema_attribute_and_unwrap(
                oid: str,
                name: str,
                desc: str | None = None,
                syntax: str | None = None,
                *,
                single_value: bool = False,
            ) -> m.Ldif.SchemaAttribute:
                """Create a schema attribute and unwrap the result.

                Args:
                    oid: Object Identifier
                    name: Attribute name
                    desc: Description
                    syntax: Syntax OID
                    single_value: Single value flag

                Returns:
                    The unwrapped SchemaAttribute instance

                Raises:
                    AssertionError: If creation fails

                """
                return m.Ldif.SchemaAttribute(
                    oid=oid,
                    name=name,
                    desc=desc,
                    syntax=syntax,
                    single_value=single_value,
                )

            @staticmethod
            def test_create_schema_objectclass_and_unwrap(
                oid: str,
                name: str,
                desc: str | None = None,
                kind: str = "STRUCTURAL",
                sup: str | None = None,
                must: MutableSequence[str] | None = None,
                may: MutableSequence[str] | None = None,
            ) -> m.Ldif.SchemaObjectClass:
                """Create a schema objectClass and unwrap the result.

                Args:
                    oid: Object Identifier
                    name: ObjectClass name
                    desc: Description
                    kind: Kind (STRUCTURAL, AUXILIARY, ABSTRACT)
                    sup: Superior class
                    must: Required attributes
                    may: Optional attributes

                Returns:
                    The unwrapped SchemaObjectClass instance

                Raises:
                    AssertionError: If creation fails

                """
                return m.Ldif.SchemaObjectClass(
                    oid=oid,
                    name=name,
                    desc=desc,
                    kind=kind,
                    sup=sup,
                    must=must or [],
                    may=may or [],
                )

            @staticmethod
            def test_quirk_parse_success_and_unwrap(
                quirk: (p.Ldif.SchemaQuirk | p.Ldif.AclQuirk | p.Ldif.EntryQuirk),
                content: str,
                parse_method: str | None = None,
            ) -> object | None:
                """Parse using quirk and assert success.

                Args:
                    quirk: Schema quirk instance
                    content: Content to parse
                    parse_method: Optional specific parse method name

                Returns:
                    The parsed value

                Raises:
                    AssertionError: If parsing fails

                """
                method_name = parse_method or "parse"
                parse_fn: Callable[[str], object] | None = getattr(
                    quirk,
                    method_name,
                    None,
                )
                if parse_fn is None or not callable(parse_fn):
                    raise AssertionError(f"Quirk has no method '{method_name}'")
                raw_res: object = parse_fn(content)
                is_failure: object = getattr(raw_res, "is_failure", None)
                if isinstance(is_failure, bool) and is_failure:
                    error: object = getattr(raw_res, "error", "Unknown error")
                    raise AssertionError(f"Parsing failed: {error}")
                return getattr(raw_res, "value", raw_res)

            @staticmethod
            def test_schema_quirk_parse_and_assert(
                quirk: p.Ldif.SchemaQuirk,
                content: str,
                expected_oid: str | None = None,
                expected_name: str | None = None,
                expected_desc: str | None = None,
                expected_sup: str | None = None,
                expected_kind: str | None = None,
                expected_must: t.StrSequence | None = None,
                expected_may: t.StrSequence | None = None,
                expected_syntax: str | None = None,
                expected_equality: str | None = None,
                expected_single_value: bool | None = None,
            ) -> p.Ldif.SchemaAttribute | None:
                """Parse schema content and assert properties.

                Args:
                    quirk: Schema quirk instance
                    content: Schema definition content
                    expected_oid: Expected OID
                    expected_name: Expected name

                Returns:
                    The parsed schema t.NormalizedValue

                Raises:
                    AssertionError: If parsing fails or properties don't match

                """
                if (
                    "STRUCTURAL" in content
                    or "AUXILIARY" in content
                    or "ABSTRACT" in content
                ):
                    parse_method = getattr(quirk, "parse_objectclass", None)
                else:
                    parse_method = getattr(quirk, "parse_attribute", None)
                if parse_method is None:
                    parse_method = getattr(quirk, "parse", None)
                if parse_method is None:
                    msg = "Quirk has no suitable parse method"
                    raise AssertionError(msg)
                result = parse_method(content)
                if hasattr(result, "is_failure") and result.is_failure:
                    raise AssertionError(f"Parsing failed: {result.error}")
                value = result.value if hasattr(result, "value") else result
                if expected_oid is not None:
                    actual_oid = getattr(value, "oid", None)
                    if actual_oid != expected_oid:
                        raise AssertionError(
                            f"Expected OID '{expected_oid}', got '{actual_oid}'",
                        )
                if expected_name is not None:
                    actual_name = getattr(value, "name", None)
                    if actual_name != expected_name:
                        raise AssertionError(
                            f"Expected name '{expected_name}', got '{actual_name}'",
                        )
                if expected_desc is not None:
                    actual_desc = getattr(value, "desc", None)
                    if actual_desc != expected_desc:
                        raise AssertionError(
                            f"Expected desc '{expected_desc}', got '{actual_desc}'",
                        )
                if expected_sup is not None:
                    actual_sup = getattr(value, "sup", None)
                    if actual_sup != expected_sup:
                        raise AssertionError(
                            f"Expected sup '{expected_sup}', got '{actual_sup}'",
                        )
                if expected_kind is not None:
                    actual_kind = getattr(value, "kind", None)
                    if actual_kind != expected_kind:
                        raise AssertionError(
                            f"Expected kind '{expected_kind}', got '{actual_kind}'",
                        )
                if expected_must is not None:
                    actual_must = getattr(value, "must", None)
                    if actual_must != expected_must:
                        raise AssertionError(
                            f"Expected must '{expected_must}', got '{actual_must}'",
                        )
                if expected_may is not None:
                    actual_may = getattr(value, "may", None)
                    if actual_may != expected_may:
                        raise AssertionError(
                            f"Expected may '{expected_may}', got '{actual_may}'",
                        )
                if expected_syntax is not None:
                    actual_syntax = getattr(value, "syntax", None)
                    if actual_syntax != expected_syntax:
                        raise AssertionError(
                            f"Expected syntax '{expected_syntax}', got '{actual_syntax}'",
                        )
                if expected_equality is not None:
                    actual_equality = getattr(value, "equality", None)
                    if actual_equality != expected_equality:
                        raise AssertionError(
                            f"Expected equality '{expected_equality}', got '{actual_equality}'",
                        )
                if expected_single_value is not None:
                    actual_single_value = getattr(value, "single_value", None)
                    if actual_single_value != expected_single_value:
                        raise AssertionError(
                            f"Expected single_value '{expected_single_value}', got '{actual_single_value}'",
                        )
                return value

            @staticmethod
            def test_create_schema_attribute_from_dict(
                data: t.ContainerMapping,
            ) -> m.Ldif.SchemaAttribute:
                """Create a schema attribute from dictionary.

                Args:
                    data: Dictionary with attribute properties

                Returns:
                    The SchemaAttribute instance

                """
                desc_value = data.get("desc")
                syntax_value = data.get("syntax")
                return m.Ldif.SchemaAttribute(
                    oid=str(data.get("oid", "")),
                    name=str(data.get("name", "")),
                    desc=desc_value if isinstance(desc_value, str) else None,
                    syntax=syntax_value if isinstance(syntax_value, str) else None,
                    single_value=bool(data.get("single_value")),
                )

            @staticmethod
            def test_create_schema_objectclass_from_dict(
                data: t.ContainerMapping,
            ) -> m.Ldif.SchemaObjectClass:
                """Create a schema objectClass from dictionary.

                Args:
                    data: Dictionary with objectClass properties

                Returns:
                    The SchemaObjectClass instance

                """
                must = data.get("must", [])
                may = data.get("may", [])
                desc_value = data.get("desc")
                sup_value = data.get("sup")
                must_list = (
                    [item for item in must if isinstance(item, str)]
                    if isinstance(must, list)
                    else []
                )
                may_list = (
                    [item for item in may if isinstance(item, str)]
                    if isinstance(may, list)
                    else []
                )
                return m.Ldif.SchemaObjectClass(
                    oid=str(data.get("oid", "")),
                    name=str(data.get("name", "")),
                    desc=desc_value if isinstance(desc_value, str) else None,
                    kind=str(data.get("kind", "STRUCTURAL")),
                    sup=sup_value if isinstance(sup_value, str) else None,
                    must=must_list,
                    may=may_list,
                )

            @staticmethod
            def test_schema_parse_attribute(
                schema_quirk: p.Ldif.SchemaQuirk,
                attr_def: str,
                expected_oid: str,
                expected_name: str,
            ) -> m.Ldif.SchemaAttribute:
                """Parse attribute definition and validate expected properties.

                Args:
                    schema_quirk: Schema quirk instance
                    attr_def: Attribute definition string
                    expected_oid: Expected OID
                    expected_name: Expected name

                Returns:
                    The parsed SchemaAttribute instance

                Raises:
                    AssertionError: If parsing fails or properties don't match

                """
                parse_method = getattr(schema_quirk, "_parse_attribute", None)
                if parse_method is None:
                    parse_method = getattr(schema_quirk, "parse_attribute", None)
                if parse_method is None:
                    msg = "Schema quirk has no attribute parse method"
                    raise AssertionError(msg)
                result = parse_method(attr_def)
                if hasattr(result, "is_failure") and result.is_failure:
                    raise AssertionError(f"Attribute parsing failed: {result.error}")
                value = result.value if hasattr(result, "value") else result
                actual_oid = getattr(value, "oid", None)
                if actual_oid != expected_oid:
                    raise AssertionError(
                        f"Expected OID '{expected_oid}', got '{actual_oid}'",
                    )
                actual_name = getattr(value, "name", None)
                if actual_name != expected_name:
                    raise AssertionError(
                        f"Expected name '{expected_name}', got '{actual_name}'",
                    )
                return value

            @staticmethod
            def test_schema_parse_objectclass(
                schema_quirk: p.Ldif.SchemaQuirk,
                oc_def: str,
                expected_oid: str,
                expected_name: str,
            ) -> m.Ldif.SchemaObjectClass:
                """Parse objectClass definition and validate expected properties.

                Args:
                    schema_quirk: Schema quirk instance
                    oc_def: ObjectClass definition string
                    expected_oid: Expected OID
                    expected_name: Expected name

                Returns:
                    The parsed SchemaObjectClass instance

                Raises:
                    AssertionError: If parsing fails or properties don't match

                """
                parse_method = getattr(schema_quirk, "_parse_objectclass", None)
                if parse_method is None:
                    parse_method = getattr(schema_quirk, "parse_objectclass", None)
                if parse_method is None:
                    msg = "Schema quirk has no objectClass parse method"
                    raise AssertionError(msg)
                result = parse_method(oc_def)
                if hasattr(result, "is_failure") and result.is_failure:
                    raise AssertionError(f"ObjectClass parsing failed: {result.error}")
                value = result.value if hasattr(result, "value") else result
                actual_oid = getattr(value, "oid", None)
                if actual_oid != expected_oid:
                    raise AssertionError(
                        f"Expected OID '{expected_oid}', got '{actual_oid}'",
                    )
                actual_name = getattr(value, "name", None)
                if actual_name != expected_name:
                    raise AssertionError(
                        f"Expected name '{expected_name}', got '{actual_name}'",
                    )
                return value

            @staticmethod
            def test_schema_write_attribute_with_metadata(
                schema_quirk: p.Ldif.SchemaQuirk,
                attr_def: str,
                expected_oid: str,
                expected_name: str,
                must_contain: t.StrSequence | None = None,
            ) -> tuple[m.Ldif.SchemaAttribute, str]:
                """Parse attribute definition, write it back, and validate output.

                Args:
                    schema_quirk: Schema quirk instance
                    attr_def: Attribute definition string to parse
                    expected_oid: Expected OID in the parsed attribute
                    expected_name: Expected name in the parsed attribute
                    must_contain: List of strings that must appear in written output

                Returns:
                    Tuple of (parsed attribute, written string)

                Raises:
                    AssertionError: If parsing/writing fails or validations don't pass

                """
                attr = TestsFlextLdifConstants.Ldif.RfcTestHelpers.test_schema_parse_attribute(
                    schema_quirk,
                    attr_def,
                    expected_oid,
                    expected_name,
                )
                write_method = getattr(schema_quirk, "write_attribute", None)
                if write_method is None:
                    msg = "Schema quirk has no write_attribute method"
                    raise AssertionError(msg)
                result = write_method(attr)
                if hasattr(result, "is_failure") and result.is_failure:
                    raise AssertionError(f"Attribute writing failed: {result.error}")
                written_raw = result.value if hasattr(result, "value") else result
                written: str = (
                    written_raw if isinstance(written_raw, str) else str(written_raw)
                )
                if must_contain:
                    for element in must_contain:
                        if element not in written:
                            raise AssertionError(
                                f"Expected '{element}' in written output: {written}",
                            )
                return (attr, written)

            @staticmethod
            def test_parse_and_assert_entry_structure(
                parser_service: FlextLdifParser,
                content: str,
                expected_dn: str,
                expected_attributes: t.StrSequence,
                expected_count: int = 1,
            ) -> Sequence[m.Ldif.Entry]:
                """Parse LDIF content and assert entry structure.

                Args:
                    parser_service: The parser service instance
                    content: LDIF content to parse
                    expected_dn: Expected DN of first entry
                    expected_attributes: Expected attribute names
                    expected_count: Expected number of entries

                Returns:
                    List of parsed entries

                Raises:
                    AssertionError: If parsing fails or structure doesn't match

                """
                parse_response: m.Ldif.ParseResponse = u.expect_success(
                    parser_service.parse_string(content=content, server_type="rfc"),
                    message="Parsing failed",
                )
                entries = parse_response.entries
                if len(entries) != expected_count:
                    raise AssertionError(
                        f"Expected {expected_count} entries, got {len(entries)}",
                    )
                if entries and expected_dn:
                    actual_dn = getattr(entries[0], "dn", None)
                    if str(actual_dn) != expected_dn:
                        raise AssertionError(
                            f"Expected DN '{expected_dn}', got '{actual_dn}'",
                        )
                if entries and expected_attributes:
                    entry = entries[0]
                    attrs = getattr(entry, "attributes", {})
                    for attr_name in expected_attributes:
                        if attr_name not in attrs:
                            raise AssertionError(
                                f"Expected attribute '{attr_name}' not found in entry",
                            )
                return entries

            @staticmethod
            def test_parse_and_assert_multiple_entries(
                parser_service: FlextLdifParser,
                content: str,
                expected_dns: t.StrSequence,
                expected_count: int,
            ) -> Sequence[m.Ldif.Entry]:
                """Parse LDIF content with multiple entries and assert structure.

                Args:
                    parser_service: The parser service instance
                    content: LDIF content to parse
                    expected_dns: Expected DNs of entries (in order)
                    expected_count: Expected number of entries

                Returns:
                    List of parsed entries

                Raises:
                    AssertionError: If parsing fails or structure doesn't match

                """
                parse_response: m.Ldif.ParseResponse = u.expect_success(
                    parser_service.parse_string(content=content, server_type="rfc"),
                    message="Parsing failed",
                )
                entries = parse_response.entries
                if len(entries) != expected_count:
                    raise AssertionError(
                        f"Expected {expected_count} entries, got {len(entries)}",
                    )
                for i, expected_dn in enumerate(expected_dns):
                    if i < len(entries):
                        actual_dn = getattr(entries[i], "dn", None)
                        if str(actual_dn) != expected_dn:
                            raise AssertionError(
                                f"Entry {i}: Expected DN '{expected_dn}', got '{actual_dn}'",
                            )
                return entries

            @staticmethod
            def test_create_entry(
                dn: str,
                attributes: t.MutableAttributeMapping,
            ) -> m.Ldif.Entry:
                """Create an entry for testing.

                Args:
                    dn: Distinguished Name for the entry
                    attributes: Dictionary of attributes for the entry

                Returns:
                    Entry instance

                Raises:
                    AssertionError: If entry creation fails

                """
                entry: m.Ldif.Entry = u.expect_success(
                    m.Ldif.Entry.create(dn=dn, attributes=attributes),
                    message="Entry creation failed",
                )
                return entry

            @staticmethod
            def test_write_entries_to_string(
                writer_service: FlextLdifWriter,
                entries: MutableSequence[m.Ldif.Entry],
                expected_content: t.StrSequence | None = None,
            ) -> str:
                """Write entries to LDIF string.

                Args:
                    writer_service: The writer service instance
                    entries: List of entries to write
                    expected_content: Optional list of strings that must appear in output

                Returns:
                    LDIF string

                Raises:
                    AssertionError: If writing fails or expected content not found

                """
                ldif_string = u.expect_success(
                    writer_service.write_to_string(entries=entries),
                    message="Writing failed",
                )
                if expected_content:
                    for substring in expected_content:
                        if substring not in ldif_string:
                            raise AssertionError(
                                f"'{substring}' not found in LDIF output",
                            )
                return ldif_string

            @staticmethod
            def test_write_entries_to_file(
                writer_service: FlextLdifWriter,
                entries: MutableSequence[m.Ldif.Entry],
                file_path: str | Path,
                expected_content: t.StrSequence | None = None,
            ) -> None:
                """Write entries to LDIF file.

                Args:
                    writer_service: The writer service instance
                    entries: List of entries to write
                    file_path: Path to write to
                    expected_content: Optional list of strings that must appear in output

                Raises:
                    AssertionError: If writing fails or expected content not found

                """
                if not isinstance(file_path, Path):
                    raise TypeError(f"Expected Path, got {type(file_path)}")
                result = writer_service.write_to_file(entries=entries, path=file_path)
                if result.is_failure:
                    raise AssertionError(f"Writing to file failed: {result.error}")
                if not file_path.exists():
                    raise AssertionError(f"Output file {file_path} was not created")
                if expected_content:
                    content = file_path.read_text()
                    for substring in expected_content:
                        if substring not in content:
                            raise AssertionError(
                                f"'{substring}' not found in file content",
                            )

            @staticmethod
            def test_parse_edge_case(
                parser_service: FlextLdifParser,
                content: str,
                should_succeed: bool | None = None,
            ) -> Sequence[m.Ldif.Entry] | None:
                """Parse edge case LDIF content.

                Args:
                    parser_service: The parser service instance
                    content: LDIF content to parse
                    should_succeed: Expected success state (None = either outcome acceptable)

                Returns:
                    Parse result value if successful, None otherwise

                Raises:
                    AssertionError: If should_succeed specified and result doesn't match

                """
                result = parser_service.parse_string(content=content, server_type="rfc")
                if should_succeed is True and result.is_failure:
                    raise AssertionError(
                        f"Expected success but got failure: {result.error}",
                    )
                if should_succeed is False and result.is_success:
                    msg = "Expected failure but got success"
                    raise AssertionError(msg)
                if result.is_failure:
                    return None
                parse_response: m.Ldif.ParseResponse = u.expect_success(
                    result,
                    message="Parsing failed",
                )
                return parse_response.entries

            @staticmethod
            def test_write_entry_variations(
                writer_service: FlextLdifWriter,
                entry_data: Mapping[
                    str,
                    Mapping[str, str | Mapping[str, t.StrSequence]],
                ],
            ) -> None:
                """Test writing entries with various data types.

                Args:
                    writer_service: The writer service instance
                    entry_data: Dict mapping test case names to entry data

                Raises:
                    AssertionError: If any write operation fails

                """
                for test_name, data in entry_data.items():
                    dn = str(data.get("dn", ""))
                    raw_attributes = data.get("attributes", {})
                    if not isinstance(raw_attributes, dict):
                        attributes: t.MutableAttributeMapping = {}
                    else:
                        attributes = {
                            str(k): (
                                [str(i) for i in v] if isinstance(v, list) else [str(v)]
                            )
                            for k, v in raw_attributes.items()
                        }
                    entry: m.Ldif.Entry = u.expect_success(
                        m.Ldif.Entry.create(dn=dn, attributes=attributes),
                        message=f"Entry creation failed for {test_name}",
                    )
                    write_result = writer_service.write_to_string(
                        entries=[entry],
                    )
                    if write_result.is_failure:
                        raise AssertionError(
                            f"Write failed for {test_name}: {write_result.error}",
                        )
                    written_content = u.expect_success(
                        write_result,
                        message=f"Write failed for {test_name}",
                    )
                    if dn and dn not in written_content:
                        raise AssertionError(
                            f"DN '{dn}' not found in output for {test_name}",
                        )

            @staticmethod
            def test_entry_quirk_can_handle(
                entry_quirk: p.Ldif.EntryQuirk,
                entry: m.Ldif.Entry,
                expected: bool,
            ) -> None:
                """Test Entry quirk can_handle method.

                Args:
                    entry_quirk: Entry quirk instance
                    entry: Entry to test
                    expected: Expected result from can_handle

                Raises:
                    AssertionError: If can_handle returns unexpected result

                """
                can_handle_method = getattr(entry_quirk, "can_handle", None)
                if can_handle_method is None:
                    msg = "Entry quirk has no can_handle method"
                    raise AssertionError(msg)
                attributes = getattr(entry, "attributes", {})
                result = can_handle_method(
                    entry.dn.value if entry.dn is not None else "",
                    attributes,
                )
                if result != expected:
                    raise AssertionError(
                        f"Expected can_handle to return {expected}, got {result}",
                    )

            @staticmethod
            def test_acl_quirk_parse_and_verify(
                acl_quirk: p.Ldif.AclQuirk,
                acl_line: str,
                expected_raw_acl: str | None = None,
            ) -> m.Ldif.Acl | None:
                """Parse ACL and verify result.

                Args:
                    acl_quirk: ACL quirk instance
                    acl_line: ACL line to parse
                    expected_raw_acl: Expected raw ACL value

                Returns:
                    Parsed ACL t.NormalizedValue

                Raises:
                    AssertionError: If parsing fails or verification fails

                """
                parse_method = getattr(acl_quirk, "parse", None)
                if parse_method is None:
                    msg = "ACL quirk has no parse method"
                    raise AssertionError(msg)
                result = parse_method(acl_line)
                if hasattr(result, "is_failure") and result.is_failure:
                    raise AssertionError(f"ACL parsing failed: {result.error}")
                value = result.value if hasattr(result, "value") else result
                if expected_raw_acl is not None:
                    raw_acl = getattr(value, "raw_acl", None)
                    if raw_acl != expected_raw_acl:
                        raise AssertionError(
                            f"Expected raw_acl '{expected_raw_acl}', got '{raw_acl}'",
                        )
                return value

            @staticmethod
            def test_acl_quirk_write_and_verify(
                acl_quirk: p.Ldif.AclQuirk,
                acl: m.Ldif.Acl,
                expected_content: str | None = None,
            ) -> str:
                """Write ACL and verify result.

                Args:
                    acl_quirk: ACL quirk instance
                    acl: ACL t.NormalizedValue to write
                    expected_content: Expected content in output

                Returns:
                    Written ACL string

                Raises:
                    AssertionError: If writing fails or verification fails

                """
                write_method = getattr(acl_quirk, "write", None)
                if write_method is None:
                    msg = "ACL quirk has no write method"
                    raise AssertionError(msg)
                result = write_method(acl)
                if hasattr(result, "is_failure") and result.is_failure:
                    raise AssertionError(f"ACL writing failed: {result.error}")
                output_raw = result.value if hasattr(result, "value") else result
                output = output_raw if isinstance(output_raw, str) else str(output_raw)
                if expected_content is not None and expected_content not in output:
                    raise AssertionError(
                        f"Expected '{expected_content}' not found in output",
                    )
                return output

            @staticmethod
            def test_parse_error_handling(
                schema_quirk: p.Ldif.SchemaQuirk,
                invalid_def: str,
                *,
                should_fail: bool = True,
            ) -> m.Ldif.SchemaAttribute | None:
                """Test parsing error handling for invalid definitions.

                Args:
                    schema_quirk: Schema quirk instance
                    invalid_def: Invalid attribute/objectClass definition string
                    should_fail: Whether parsing should fail (default True)

                Returns:
                    Parse result value if successful, None otherwise

                Raises:
                    AssertionError: If should_fail and parsing succeeds,
                                or if not should_fail and parsing fails

                """
                parse_method = getattr(schema_quirk, "_parse_attribute", None)
                if parse_method is None:
                    parse_method = getattr(schema_quirk, "parse_attribute", None)
                if parse_method is None:
                    msg = "Schema quirk has no attribute parse method"
                    raise AssertionError(msg)
                result = parse_method(invalid_def)
                if hasattr(result, "is_failure"):
                    is_failure = result.is_failure
                else:
                    is_failure = result is None
                if should_fail and (not is_failure):
                    msg = "Expected parsing to fail but it succeeded"
                    raise AssertionError(msg)
                if not should_fail and is_failure:
                    error_msg = (
                        result.error if hasattr(result, "error") else "Unknown error"
                    )
                    raise AssertionError(
                        f"Expected parsing to succeed but got: {error_msg}",
                    )
                if is_failure:
                    return None
                return result.value if hasattr(result, "value") else result

        class TestDeduplicationHelpers:
            """Test helpers for deduplication functionality."""

            @staticmethod
            def create_entries_batch(
                entries_data: Sequence[t.ContainerMapping],
                *,
                validate_all: bool = True,
            ) -> Sequence[m.Ldif.Entry]:
                """Create multiple entries from data dictionaries.

                Args:
                    entries_data: List of dicts with 'dn' and 'attributes' keys
                    validate_all: Whether to validate all entries (currently unused)

                Returns:
                    List of created Entry instances

                """
                service = FlextLdifEntries()
                entries: MutableSequence[m.Ldif.Entry] = []
                for entry_data in entries_data:
                    dn_raw = entry_data.get("dn")
                    attrs_raw = entry_data.get("attributes")
                    if not isinstance(dn_raw, str):
                        msg = "Entry data must include string 'dn'"
                        raise AssertionError(msg)
                    if not isinstance(attrs_raw, dict):
                        msg = "Entry data must include dict 'attributes'"
                        raise AssertionError(msg)
                    normalized_attrs: MutableMapping[
                        str, str | MutableSequence[str]
                    ] = {}
                    for attr_name_raw, attr_value_raw in attrs_raw.items():
                        if isinstance(attr_value_raw, str):
                            normalized_attrs[attr_name_raw] = attr_value_raw
                            continue
                        if isinstance(attr_value_raw, list):
                            string_values: MutableSequence[str] = [
                                item for item in attr_value_raw if isinstance(item, str)
                            ]
                            if len(string_values) == len(attr_value_raw):
                                normalized_attrs[attr_name_raw] = string_values
                    result = service.create_entry(
                        dn=dn_raw,
                        attributes=normalized_attrs,
                    )
                    if result.is_success:
                        entry: m.Ldif.Entry = u.expect_success(result)
                        entries.append(entry)
                return entries

            @staticmethod
            def batch_parse_and_assert(
                parser_service: FlextLdifParser,
                test_cases: Sequence[t.ContainerMapping],
                *,
                validate_all: bool = True,
            ) -> Sequence[r[m.Ldif.ParseResponse]]:
                """Batch parse LDIF content and assert results.

                Args:
                    parser_service: The parser service instance
                    test_cases: List of dicts with 'ldif_content', 'should_succeed',
                            and optionally 'server_type' keys
                    validate_all: Whether to validate all results strictly

                Returns:
                    List of parse results

                Raises:
                    AssertionError: If validation fails when validate_all is True

                """
                results: MutableSequence[r[m.Ldif.ParseResponse]] = []
                for test_case in test_cases:
                    ldif_content = str(test_case.get("ldif_content", ""))
                    should_succeed = test_case.get("should_succeed")
                    server_type = str(test_case.get("server_type", "rfc"))
                    result = parser_service.parse_string(
                        content=ldif_content,
                        server_type=server_type,
                    )
                    if validate_all and should_succeed is True and result.is_failure:
                        raise AssertionError(
                            f"Expected success but got failure: {result.error}",
                        )
                    if validate_all and should_succeed is False and result.is_success:
                        msg = "Expected failure but got success"
                        raise AssertionError(msg)
                    results.append(result)
                return results

            @staticmethod
            def helper_api_write_and_unwrap(
                api: FlextLdif,
                entries: MutableSequence[m.Ldif.Entry],
                must_contain: t.StrSequence | None = None,
            ) -> str:
                """Write entries to string and unwrap result.

                Args:
                    api: ldif instance
                    entries: List of entries to write
                    must_contain: List of strings that must appear in output

                Returns:
                    LDIF string

                """
                response: m.Ldif.WriteResponse = u.expect_success(
                    api.write(entries),
                    message="write() failed",
                )
                ldif_string = response.content or str(response)
                if must_contain:
                    for substring in must_contain:
                        assert substring in ldif_string, (
                            f"'{substring}' not found in LDIF output"
                        )
                return ldif_string

            @staticmethod
            def api_parse_write_file_and_assert(
                api: ldif,
                entries: MutableSequence[m.Ldif.Entry],
                output_file: str | Path,
                must_contain: t.StrSequence | None = None,
            ) -> None:
                """Write entries to file and assert content.

                Args:
                    api: ldif instance
                    entries: List of entries to write
                    output_file: Path to output file
                    must_contain: List of strings that must appear in output

                """
                assert isinstance(api, ldif)
                assert isinstance(output_file, Path)
                ldif_string = TestsFlextLdifConstants.Ldif.TestDeduplicationHelpers.helper_api_write_and_unwrap(
                    api,
                    entries,
                    must_contain=must_contain,
                )
                output_file.write_text(ldif_string)
                assert output_file.exists(), (
                    f"Output file {output_file} was not created"
                )

            @staticmethod
            def api_parse_write_string_and_assert(
                api: ldif,
                entries: MutableSequence[m.Ldif.Entry],
                must_contain: t.StrSequence | None = None,
            ) -> None:
                """Write entries to string and assert content.

                Args:
                    api: ldif instance
                    entries: List of entries to write
                    must_contain: List of strings that must appear in output

                """
                TestsFlextLdifConstants.Ldif.TestDeduplicationHelpers.helper_api_write_and_unwrap(
                    api,
                    entries,
                    must_contain=must_contain,
                )

            @staticmethod
            def quirk_parse_and_unwrap(
                quirk: (
                    p.Ldif.SchemaQuirk
                    | p.Ldif.AclQuirk
                    | p.Ldif.EntryQuirk
                    | FlextLdifServersBaseSchema
                    | FlextLdifServersBaseSchemaAcl
                ),
                content: str,
                msg: str | None = None,
                parse_method: str | None = None,
                expected_type: type | None = None,
                should_succeed: bool | None = None,
            ) -> BaseModel | None:
                """Parse using quirk and unwrap result.

                Args:
                    quirk: Schema quirk instance with parse method
                    content: Content to parse
                    msg: Optional message for assertion
                    parse_method: Optional specific parse method name (e.g., 'parse_attribute')
                    expected_type: Optional expected type for validation
                    should_succeed: Expected outcome (True=must succeed, False=must fail,
                        None=any outcome acceptable)

                Returns:
                    Parsed result value if successful, None if expected failure

                Raises:
                    AssertionError: If should_succeed specified and result doesn't match,
                        or if type doesn't match

                """
                raw_result: object
                parse_fn: Callable[[str], object] | None
                if parse_method:
                    parse_fn = getattr(quirk, parse_method, None)
                    if parse_fn is None or not callable(parse_fn):
                        raise AssertionError(f"Quirk has no method '{parse_method}'")
                    raw_result = parse_fn(content)
                else:
                    parse_fn = getattr(quirk, "parse", None)
                    if parse_fn is None or not callable(parse_fn):
                        msg = "Quirk has no callable parse method"
                        raise AssertionError(msg)
                    raw_result = parse_fn(content)
                is_success: bool | None = getattr(raw_result, "is_success", None)
                is_failure: bool | None = getattr(raw_result, "is_failure", None)
                if not isinstance(is_success, bool) or not isinstance(is_failure, bool):
                    msg = "Parse method must return r-like t.NormalizedValue"
                    raise AssertionError(msg)
                error_val: object = getattr(raw_result, "error", None)
                error_message = (
                    str(error_val) if error_val is not None else "Unknown parse error"
                )
                if should_succeed is False:
                    if is_success:
                        raise AssertionError(
                            msg or "Expected failure but parse succeeded",
                        )
                    return None
                if should_succeed is True and is_failure:
                    raise AssertionError(
                        msg or f"Expected success but parse failed: {error_message}",
                    )
                if should_succeed is None:
                    assert is_success, msg or f"quirk.parse() failed: {error_message}"
                if is_failure:
                    return None
                value: object = getattr(raw_result, "value", None)
                if expected_type is not None:
                    if hasattr(expected_type, "__protocol_attrs__"):
                        pass
                    elif not isinstance(value, expected_type):
                        raise AssertionError(
                            f"Expected {expected_type.__name__}, got {type(value).__name__}",
                        )
                if not isinstance(value, BaseModel):
                    return None
                return value

            @staticmethod
            def quirk_write_and_unwrap(
                quirk: (
                    p.Ldif.SchemaQuirk
                    | p.Ldif.AclQuirk
                    | FlextLdifServersBaseSchema
                    | FlextLdifServersBaseSchemaAcl
                ),
                data: m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl,
                msg: str | None = None,
                write_method: str | None = None,
                must_contain: t.StrSequence | None = None,
            ) -> str:
                """Write using quirk and unwrap result.

                Args:
                    quirk: Schema quirk instance with write method
                    data: Data to write (Entry, SchemaAttribute, SchemaObjectClass, etc.)
                    msg: Optional message for assertion
                    write_method: Optional specific write method name (e.g., '_write_attribute')
                    must_contain: Optional list of strings that must appear in output

                Returns:
                    Written string result

                Raises:
                    AssertionError: If writing fails or must_contain strings not found

                """
                if write_method:
                    method = getattr(quirk, write_method, None)
                    if method is None:
                        raise AssertionError(f"Quirk has no method '{write_method}'")
                    result = method(data)
                else:
                    method = getattr(quirk, "write", None)
                    if method is None:
                        msg = "Quirk has no write method"
                        raise AssertionError(msg)
                    result = method(data)
                if hasattr(result, "is_success"):
                    assert result.is_success, (
                        msg or f"quirk.write() failed: {result.error}"
                    )
                    output = result.value
                else:
                    output = result
                output = output if isinstance(output, str) else str(output)
                if must_contain:
                    for substring in must_contain:
                        if substring not in output:
                            raise AssertionError(
                                f"'{substring}' not found in output: {output[:200]}...",
                            )
                return output

        class Scenarios:
            """Test scenario enums for parametrized quirk testing."""

            class Apache:
                """Apache Directory Server test scenarios."""

                @unique
                class Attribute(StrEnum):
                    APACHE_OID = "apache_oid"
                    ADS_PREFIX = "ads_prefix"
                    APACHEDS_NAME = "apacheds_name"
                    STANDARD_RFC = "standard_rfc"

                @unique
                class ObjectClass(StrEnum):
                    APACHE_OID = "apache_oid"
                    ADS_NAME = "ads_name"
                    STANDARD_RFC = "standard_rfc"

                @unique
                class Entry(StrEnum):
                    OU_CONFIG = "ou_config"
                    OU_SERVICES = "ou_services"
                    OU_SYSTEM = "ou_system"
                    OU_PARTITIONS = "ou_partitions"
                    ADS_ATTRIBUTE = "ads_attribute"
                    APACHEDS_ATTRIBUTE = "apacheds_attribute"
                    ADS_OBJECTCLASS = "ads_objectclass"
                    STANDARD_RFC = "standard_rfc"

                @unique
                class Acl(StrEnum):
                    ADS_ACI = "ads_aci"
                    ACI_ATTRIBUTE = "aci_attribute"
                    VERSION_PREFIX = "version_prefix"
                    NEGATIVE = "negative"
                    EMPTY_LINE = "empty_line"
                    WRITE_WITH_CONTENT = "write_with_content"
                    WRITE_CLAUSES_ONLY = "write_clauses_only"
                    WRITE_EMPTY = "write_empty"

            class Ds389:
                """389 Directory Server test scenarios."""

                @unique
                class Attribute(StrEnum):
                    DS389_OID = "ds389_oid"
                    DS389_PREFIX = "ds389_prefix"
                    NSSLAPD_PREFIX = "nsslapd_prefix"
                    NSDS_PREFIX = "nsds_prefix"
                    NSUNIQUEID_PREFIX = "nsuniqueid_prefix"
                    NSUNIQUE = "nsunique"
                    STANDARD_RFC = "standard_rfc"
                    FEDORA_PREFIX = "fedora_prefix"

                @unique
                class ObjectClass(StrEnum):
                    DS389_OID = "ds389_oid"
                    DS389_NAME = "ds389_name"
                    NS_NAME = "ns_name"
                    STANDARD_RFC = "standard_rfc"

                @unique
                class Acl(StrEnum):
                    ACI_ATTRIBUTE = "aci_attribute"
                    VERSION_PREFIX = "version_prefix"
                    OPENLDAP_FORMAT = "openldap_format"
                    NEGATIVE = "negative"
                    EMPTY_LINE = "empty_line"

                @unique
                class Entry(StrEnum):
                    CN_CONFIG = "cn_config"
                    CN_MONITOR = "cn_monitor"
                    CN_CHANGELOG = "cn_changelog"
                    OU_CONFIG = "ou_config"
                    OU_REPLICATION = "ou_replication"
                    NSSLAPD_ATTRIBUTE = "nsslapd_attribute"
                    NSDS_ATTRIBUTE = "nsds_attribute"
                    NSUNIQUEID_ATTRIBUTE = "nsuniqueid_attribute"
                    NS_OBJECTCLASS = "ns_objectclass"
                    DS389_OBJECTCLASS = "ds389_objectclass"
                    MEMBEROF_PLUGIN = "memberof_plugin"
                    SCHEMA_ATTRIBUTE = "schema_attribute"
                    STANDARD_RFC = "standard_rfc"

            class Novell:
                """Novell eDirectory test scenarios."""

                @unique
                class Attribute(StrEnum):
                    NOVELL_OID = "novell_oid"
                    NDS_PREFIX = "nds_prefix"
                    NSPM_PREFIX = "nspm_prefix"
                    LOGIN_PREFIX = "login_prefix"
                    DIRXML_PREFIX = "dirxml_prefix"
                    EDIR_PREFIX = "edir_prefix"
                    NOVELL_PREFIX = "novell_prefix"
                    STANDARD_RFC = "standard_rfc"

                @unique
                class ObjectClass(StrEnum):
                    NOVELL_OID = "novell_oid"
                    NDS_NAME = "nds_name"
                    STANDARD_RFC = "standard_rfc"

                @unique
                class Entry(StrEnum):
                    NDS_PARTITION = "nds_partition"
                    TREE_ROOT = "tree_root"
                    OU_SERVICES = "ou_services"
                    OU_APPS = "ou_apps"
                    OU_SYSTEM = "ou_system"
                    NSPM_ATTRIBUTE = "nspm_attribute"
                    LOGIN_ATTRIBUTE = "login_attribute"
                    NDS_OBJECTCLASS = "nds_objectclass"
                    NDS_ATTRIBUTE = "nds_attribute"
                    EDIR_OBJECTCLASS = "edir_objectclass"
                    NOVELL_OBJECTCLASS = "novell_objectclass"
                    STANDARD_RFC = "standard_rfc"

            class Relaxed:
                """Relaxed quirk test scenarios."""

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

                @unique
                class Write(StrEnum):
                    VALID = "valid"
                    PRESERVE_RAW = "preserve_raw"

            class Api:
                """API integration test scenarios."""

                @unique
                class Scenario(StrEnum):
                    SIMPLE_LDIF = "simple_ldif"
                    BUILD_ENTRY = "build_entry"
                    VALIDATE_ENTRIES = "validate_entries"
                    MULTIPLE_INSTANCES = "multiple_instances"
                    API_FACADE_PROPERTIES = "api_facade_properties"
                    END_TO_END_WORKFLOW = "end_to_end_workflow"

            class AclRegistry:
                """ACL registry test scenarios."""

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
                    """Protocol names in FlextLdifProtocols.Ldif namespace."""

                    __test__ = False
                    SCHEMA = "SchemaQuirk"
                    ACL = "AclQuirk"
                    ENTRY = "EntryQuirk"

                @unique
                class ServerTypes(StrEnum):
                    """Server types implementing schema protocol."""

                    __test__ = False
                    OID = "oid"
                    OUD = "oud"
                    OPENLDAP = "openldap"
                    RELAXED = "relaxed"

        class TestCases:
            """Parametrized test case data for quirk server tests."""

            class Apache:
                """Apache quirk test cases."""

                ATTRIBUTE_TEST_CASES = (
                    TestsFlextLdifModels.Ldif.Tests.AttributeTestCase(
                        scenario="apache_oid",
                        attr_definition="( 1.3.6.1.4.1.18060.0.4.1.2.100 NAME 'ads-enabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
                        expected_can_handle=True,
                        expected_name="ads-enabled",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.AttributeTestCase(
                        scenario="ads_prefix",
                        attr_definition="( 2.16.840.1.113730.3.1.1 NAME 'ads-searchBaseDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
                        expected_can_handle=True,
                        expected_name="ads-searchBaseDN",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.AttributeTestCase(
                        scenario="apacheds_name",
                        attr_definition="( 1.2.3.4 NAME 'apachedsSystemId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                        expected_can_handle=True,
                        expected_name="apachedsSystemId",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.AttributeTestCase(
                        scenario="standard_rfc",
                        attr_definition="( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                        expected_can_handle=False,
                        expected_name="cn",
                    ),
                )
                OBJECTCLASS_TEST_CASES = (
                    TestsFlextLdifModels.Ldif.Tests.ObjectClassTestCase(
                        scenario="apache_oid",
                        oc_definition="( 1.3.6.1.4.1.18060.0.4.1.3.100 NAME 'ads-directoryService' SUP top STRUCTURAL )",
                        expected_can_handle=True,
                        expected_name="ads-directoryService",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.ObjectClassTestCase(
                        scenario="ads_name",
                        oc_definition="( 2.5.6.0 NAME 'ads-base' SUP top ABSTRACT )",
                        expected_can_handle=True,
                        expected_name="ads-base",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.ObjectClassTestCase(
                        scenario="standard_rfc",
                        oc_definition="( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )",
                        expected_can_handle=False,
                        expected_name="posixAccount",
                    ),
                )
                ENTRY_TEST_CASES = (
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="ou_config",
                        entry_dn="ou=config,dc=example,dc=com",
                        attributes={"objectClass": ["organizationalUnit"]},
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="ou_services",
                        entry_dn="ou=services,dc=example,dc=com",
                        attributes={"objectClass": ["organizationalUnit"]},
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="ou_system",
                        entry_dn="ou=system,dc=example,dc=com",
                        attributes={"objectClass": ["organizationalUnit"]},
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="ou_partitions",
                        entry_dn="ou=partitions,dc=example,dc=com",
                        attributes={"objectClass": ["organizationalUnit"]},
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="ads_attribute",
                        entry_dn="cn=test,dc=example,dc=com",
                        attributes={"ads-enabled": ["TRUE"], "objectClass": ["top"]},
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="apacheds_attribute",
                        entry_dn="cn=test,dc=example,dc=com",
                        attributes={
                            "apachedsSystemId": ["test"],
                            "objectClass": ["top"],
                        },
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="ads_objectclass",
                        entry_dn="cn=test,dc=example,dc=com",
                        attributes={"objectClass": ["top", "ads-directory"]},
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="standard_rfc",
                        entry_dn="cn=user,dc=example,dc=com",
                        attributes={"objectClass": ["person"], "cn": ["user"]},
                        expected_can_handle=True,
                    ),
                )

            class Ds389:
                """DS389 quirk test cases."""

                ATTRIBUTE_TEST_CASES = (
                    TestsFlextLdifModels.Ldif.Tests.AttributeTestCase(
                        scenario="ds389_oid",
                        attr_definition="( 2.16.840.1.113730.3.1.1 NAME 'nsslapd-suffix' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
                        expected_can_handle=True,
                        expected_oid="2.16.840.1.113730.3.1.1",
                        expected_name="nsslapd-suffix",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.AttributeTestCase(
                        scenario="nsslapd_prefix",
                        attr_definition="( 1.2.3.4 NAME 'nsslapd-port' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
                        expected_can_handle=True,
                        expected_name="nsslapd-port",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.AttributeTestCase(
                        scenario="nsds_prefix",
                        attr_definition="( 1.2.3.4 NAME 'nsds5ReplicaId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
                        expected_can_handle=True,
                        expected_name="nsds5ReplicaId",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.AttributeTestCase(
                        scenario="nsuniqueid_prefix",
                        attr_definition="( 1.2.3.4 NAME 'nsuniqueid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                        expected_can_handle=True,
                        expected_name="nsuniqueid",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.AttributeTestCase(
                        scenario="standard_rfc",
                        attr_definition="( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                        expected_can_handle=False,
                    ),
                )
                OBJECTCLASS_TEST_CASES = (
                    TestsFlextLdifModels.Ldif.Tests.ObjectClassTestCase(
                        scenario="ds389_oid",
                        oc_definition="( 2.16.840.1.113730.3.2.1 NAME 'nscontainer' SUP top STRUCTURAL )",
                        expected_can_handle=True,
                        expected_oid="2.16.840.1.113730.3.2.1",
                        expected_name="nscontainer",
                        expected_kind="STRUCTURAL",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.ObjectClassTestCase(
                        scenario="ns_name",
                        oc_definition="( 2.5.6.0 NAME 'nsperson' SUP top STRUCTURAL )",
                        expected_can_handle=True,
                        expected_name="nsperson",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.ObjectClassTestCase(
                        scenario="standard_rfc",
                        oc_definition="( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )",
                        expected_can_handle=False,
                    ),
                )
                ACL_TEST_CASES = (
                    TestsFlextLdifModels.Ldif.Tests.AclTestCase(
                        scenario="aci_attribute",
                        acl_line='aci: (version 3.0; acl "Admin Access"; allow (all) userdn = "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)',
                        expected_can_handle=True,
                        expected_success=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.AclTestCase(
                        scenario="version_prefix",
                        acl_line='(version 3.0; acl "Admin Access"; allow (all) userdn = "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)',
                        expected_can_handle=True,
                        expected_success=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.AclTestCase(
                        scenario="openldap_format",
                        acl_line="access to * by * read",
                        expected_can_handle=False,
                        expected_success=False,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.AclTestCase(
                        scenario="empty_line",
                        acl_line="",
                        expected_can_handle=False,
                        expected_success=False,
                    ),
                )
                ENTRY_TEST_CASES = (
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="cn_config",
                        entry_dn="cn=config",
                        attributes={
                            FlextLdifConstants.Ldif.DictKeys.OBJECTCLASS: [
                                "nscontainer"
                            ]
                        },
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="cn_monitor",
                        entry_dn="cn=monitor",
                        attributes={
                            FlextLdifConstants.Ldif.DictKeys.OBJECTCLASS: ["top"]
                        },
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="cn_changelog",
                        entry_dn="cn=changelog",
                        attributes={
                            FlextLdifConstants.Ldif.DictKeys.OBJECTCLASS: ["top"]
                        },
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="nsslapd_attribute",
                        entry_dn="cn=test,dc=example,dc=com",
                        attributes={"nsslapd-port": ["389"], "objectclass": ["top"]},
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="nsds_attribute",
                        entry_dn="cn=test,dc=example,dc=com",
                        attributes={"nsds5ReplicaId": ["1"], "objectclass": ["top"]},
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="nsuniqueid_attribute",
                        entry_dn="cn=test,dc=example,dc=com",
                        attributes={"nsuniqueid": ["12345"], "objectclass": ["top"]},
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="ns_objectclass",
                        entry_dn="cn=test,dc=example,dc=com",
                        attributes={
                            FlextLdifConstants.Ldif.DictKeys.OBJECTCLASS: [
                                "top",
                                "nscontainer",
                            ]
                        },
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="standard_rfc",
                        entry_dn="cn=user,dc=example,dc=com",
                        attributes={
                            FlextLdifConstants.Ldif.DictKeys.OBJECTCLASS: ["person"],
                            "cn": ["user"],
                        },
                        expected_can_handle=False,
                    ),
                )

            class Novell:
                """Novell quirk test cases."""

                ATTRIBUTE_TEST_CASES = (
                    TestsFlextLdifModels.Ldif.Tests.AttributeTestCase(
                        scenario="novell_oid",
                        attr_definition="( 2.16.840.1.113719.1.1.4.1.501 NAME 'nspmPasswordPolicyDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
                        expected_can_handle=True,
                        expected_oid="2.16.840.1.113719.1.1.4.1.501",
                        expected_name="nspmPasswordPolicyDN",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.AttributeTestCase(
                        scenario="nspm_prefix",
                        attr_definition="( 1.2.3.4 NAME 'nspmPasswordPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                        expected_can_handle=True,
                        expected_name="nspmPasswordPolicy",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.AttributeTestCase(
                        scenario="login_prefix",
                        attr_definition="( 1.2.3.4 NAME 'loginDisabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
                        expected_can_handle=True,
                        expected_name="loginDisabled",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.AttributeTestCase(
                        scenario="dirxml_prefix",
                        attr_definition="( 1.2.3.4 NAME 'dirxml-associations' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                        expected_can_handle=True,
                        expected_name="dirxml-associations",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.AttributeTestCase(
                        scenario="standard_rfc",
                        attr_definition="( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                        expected_can_handle=False,
                    ),
                )
                OBJECTCLASS_TEST_CASES = (
                    TestsFlextLdifModels.Ldif.Tests.ObjectClassTestCase(
                        scenario="novell_oid",
                        oc_definition="( 2.16.840.1.113719.2.2.6.1 NAME 'ndsPerson' SUP top STRUCTURAL )",
                        expected_can_handle=True,
                        expected_oid="2.16.840.1.113719.2.2.6.1",
                        expected_name="ndsPerson",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.ObjectClassTestCase(
                        scenario="nds_name",
                        oc_definition="( 2.5.6.0 NAME 'ndsserver' SUP top STRUCTURAL )",
                        expected_can_handle=True,
                        expected_name="ndsserver",
                    ),
                    TestsFlextLdifModels.Ldif.Tests.ObjectClassTestCase(
                        scenario="standard_rfc",
                        oc_definition="( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )",
                        expected_can_handle=False,
                    ),
                )
                ENTRY_TEST_CASES = (
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="ou_services",
                        entry_dn="ou=services,o=Example",
                        attributes={"objectClass": ["organizationalUnit"]},
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="ou_apps",
                        entry_dn="ou=apps,o=Example",
                        attributes={"objectClass": ["organizationalUnit"]},
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="ou_system",
                        entry_dn="ou=system,o=Example",
                        attributes={"objectClass": ["organizationalUnit"]},
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="nspm_attribute",
                        entry_dn="cn=user,o=Example",
                        attributes={
                            "nspmpasswordpolicy": ["policy1"],
                            "objectClass": ["top"],
                        },
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="login_attribute",
                        entry_dn="cn=user,o=Example",
                        attributes={"logindisabled": ["TRUE"], "objectClass": ["top"]},
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="nds_objectclass",
                        entry_dn="cn=user,o=Example",
                        attributes={"objectClass": ["top", "ndsperson"]},
                        expected_can_handle=True,
                    ),
                    TestsFlextLdifModels.Ldif.Tests.EntryTestCase(
                        scenario="standard_rfc",
                        entry_dn="cn=user,dc=example,dc=com",
                        attributes={"objectClass": ["person"], "cn": ["user"]},
                        expected_can_handle=False,
                    ),
                )

        class ConftestFactory:
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


c = TestsFlextLdifConstants

__all__ = ["TestsFlextLdifConstants", "c"]
