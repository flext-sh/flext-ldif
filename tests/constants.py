"""Centralized flat test constants for flext-ldif."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Final

from flext_ldap import c as ldap_c
from flext_tests import FlextTestsConstants
from frozenlist import FrozenList

from flext_ldif import c as ldif_c
from tests.models import m


class TestsFlextLdifConstants(FlextTestsConstants, ldap_c, ldif_c):
    """Flat test constants for flext-ldif."""

    class Ldif(ldif_c.Ldif):
        """LDIF test constants namespace."""

        class Tests:
            """Flat test-only constants consumed as c.Ldif.Tests.*."""

            FIXTURES_DIR: Final[Path] = Path(__file__).parent / "fixtures"
            PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[1]

            RFC: Final[str] = ldif_c.Ldif.ServerTypes.RFC.value
            OID: Final[str] = ldif_c.Ldif.ServerTypes.OID.value
            OUD: Final[str] = ldif_c.Ldif.ServerTypes.OUD.value
            OPENLDAP: Final[str] = ldif_c.Ldif.ServerTypes.OPENLDAP.value
            OPENLDAP1: Final[str] = ldif_c.Ldif.ServerTypes.OPENLDAP1.value
            DS389: Final[str] = ldif_c.Ldif.ServerTypes.DS389.value
            APACHE: Final[str] = ldif_c.Ldif.ServerTypes.APACHE.value
            NOVELL: Final[str] = ldif_c.Ldif.ServerTypes.NOVELL.value
            TIVOLI: Final[str] = ldif_c.Ldif.ServerTypes.IBM_TIVOLI.value
            AD: Final[str] = ldif_c.Ldif.ServerTypes.AD.value

            SCHEMA: Final[str] = "schema"
            ACL: Final[str] = "acl"
            ENTRIES: Final[str] = "entries"
            INTEGRATION: Final[str] = "integration"

            DOCKER_CONTAINER_NAME: Final[str] = "flext-openldap-test"
            DOCKER_COMPOSE_FILE_REL: Final[str] = "docker/docker-compose.openldap.yml"
            DOCKER_SERVICE_NAME: Final[str] = "openldap"
            DOCKER_PORT: Final[int] = 3390
            DOCKER_BASE_DN: Final[str] = "dc=flext,dc=local"
            DOCKER_ADMIN_DN: Final[str] = "cn=admin,dc=flext,dc=local"
            DOCKER_ADMIN_PASSWORD: Final[str] = "admin123"
            DOCKER_LEGACY_ADMIN_DN: Final[str] = (
                "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
            )
            DOCKER_LEGACY_ADMIN_PASSWORD: Final[str] = "REDACTED_LDAP_BIND_PASSWORD123"

            SCHEMA_STRUCTURAL: Final[str] = ldif_c.Ldif.SchemaKind.STRUCTURAL.value
            SCHEMA_AUXILIARY: Final[str] = ldif_c.Ldif.SchemaKind.AUXILIARY.value
            SCHEMA_ABSTRACT: Final[str] = ldif_c.Ldif.SchemaKind.ABSTRACT.value

            NAME_CN: Final[str] = "cn"
            NAME_SN: Final[str] = "sn"
            NAME_MAIL: Final[str] = "mail"
            NAME_UID: Final[str] = "uid"
            NAME_OBJECTCLASS: Final[str] = ldif_c.Ldif.DictKeys.OBJECTCLASS.value
            NAME_PERSON: Final[str] = "person"
            NAME_TOP: Final[str] = "top"
            NAME_ORCLUSER: Final[str] = "orcluser"
            NAME_SUBSCHEMA: Final[str] = "subschema"
            NAME_MEMBER: Final[str] = "member"
            NAME_GROUP_OF_NAMES: Final[str] = "groupOfNames"
            NAME_ACI: Final[str] = "aci"
            NAME_ORCLACI: Final[str] = "orclaci"

            DN_TEST: Final[str] = "cn=test,dc=example,dc=com"
            DN_TEST_USER: Final[str] = "cn=testuser,dc=example,dc=com"

            BOOLEAN_TRUE: Final[str] = "TRUE"
            BOOLEAN_FALSE: Final[str] = "FALSE"
            ATTR_ORCL_IS_ENABLED: Final[str] = "orclIsEnabled"
            ATTR_ORCL_ACCOUNT_LOCKED: Final[str] = "orclAccountLocked"
            ACL_READ_VALUE: Final[str] = "access to entry by * (read)"

            RFC_SAMPLE_LDIF_BASIC: Final[str] = (
                "dn: cn=test,dc=example,dc=com\n"
                "objectClass: person\n"
                "cn: test\n"
                "sn: user\n"
            )
            RFC_SAMPLE_LDIF_MULTIPLE: Final[str] = (
                "dn: cn=user1,dc=example,dc=com\n"
                "objectClass: person\n"
                "cn: user1\n\n"
                "dn: cn=user2,dc=example,dc=com\n"
                "objectClass: person\n"
                "cn: user2\n"
            )
            RFC_TEST_DN: Final[str] = DN_TEST

            ATTR_VALUE_TEST: Final[str] = "test"
            ATTR_VALUE_USER: Final[str] = "user"
            VERSION_EXPECTED_EXPORTS: Final[tuple[str, ...]] = (
                "FlextLdifVersion",
                "__author__",
                "__author_email__",
                "__description__",
                "__license__",
                "__title__",
                "__url__",
                "__version__",
                "__version_info__",
            )

            CONFIG_BASIC_ENTRY: Final[str] = (
                "dn: cn=Test,dc=example,dc=com\ncn: Test\nobjectClass: person\n"
            )
            CONFIG_MULTIPLE_ENTRIES: Final[str] = (
                "dn: cn=User1,dc=example,dc=com\n"
                "cn: User1\n"
                "objectClass: person\n\n"
                "dn: cn=User2,dc=example,dc=com\n"
                "cn: User2\n"
                "objectClass: person\n\n"
                "dn: cn=User3,dc=example,dc=com\n"
                "cn: User3\n"
                "objectClass: person\n"
            )
            CONFIG_SERVER_TYPES: Final[tuple[str, ...]] = (
                OID,
                OUD,
                OPENLDAP,
                RFC,
            )
            CONFIG_SERVER_CONTENT: Final[Mapping[str, str]] = MappingProxyType(
                {
                    OID: (
                        "dn: cn=OID Test,dc=example,dc=com\n"
                        "cn: OID Test\n"
                        "objectClass: person\n"
                    ),
                    OUD: (
                        "dn: cn=OUD Test,dc=example,dc=com\n"
                        "cn: OUD Test\n"
                        "objectClass: person\n"
                    ),
                    OPENLDAP: (
                        "dn: cn=OpenLDAP Test,dc=example,dc=com\n"
                        "cn: OpenLDAP Test\n"
                        "objectClass: person\n"
                    ),
                    RFC: (
                        "dn: cn=RFC Test,dc=example,dc=com\n"
                        "cn: RFC Test\n"
                        "objectClass: person\n"
                    ),
                },
            )

            CROSS_QUIRK_OID_ATTRIBUTE_ORCLGUID: Final[str] = (
                "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' DESC 'Oracle GUID' "
                "EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
            )
            CROSS_QUIRK_OID_OBJECTCLASS_ORCLCONTAINER: Final[str] = (
                "( 2.16.840.1.113894.2.1.1 NAME 'orclContainer' DESC 'Oracle Container' "
                "SUP top STRUCTURAL MUST cn MAY description )"
            )
            CROSS_QUIRK_OID_OBJECTCLASS_ORCLCONTEXT: Final[str] = (
                "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
            )
            CROSS_QUIRK_OID_ACL_ANONYMOUS: Final[str] = (
                "orclaci: access to entry by * (browse)"
            )
            CROSS_QUIRK_OUD_ACI_ANONYMOUS: Final[str] = (
                'aci: (targetattr="*")(version 3.0; acl "Test ACL"; allow (read,search) userdn="ldap:///anyone";)'
            )
            CROSS_QUIRK_OUD_ATTRIBUTE_ORCLGUID: Final[str] = (
                "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
            )

            BOOLEAN_RFC_TO_OID: Final[Mapping[str, str]] = MappingProxyType(
                {"TRUE": "1", "FALSE": "0"},
            )
            BOOLEAN_OID_TO_RFC: Final[Mapping[str, str]] = MappingProxyType(
                {"1": "TRUE", "0": "FALSE"},
            )
            MIGRATION_BOOLEAN_ENTRY_TEMPLATE: Final[str] = (
                "dn: {dn}\n"
                "{objectclass}: {top}\n"
                "{objectclass}: {person}\n"
                "{objectclass}: {orcluser}\n"
                "{cn}: {cn_value}\n"
                "{sn}: {sn_value}\n"
                "{attr_enabled}: {val_true}\n"
                "{attr_locked}: {val_false}\n"
            )
            MIGRATION_ACL_ENTRY_TEMPLATE: Final[str] = (
                "dn: {dn}\n"
                "{objectclass}: {top}\n"
                "{objectclass}: {person}\n"
                "{cn}: {cn_value}\n"
                "{sn}: {sn_value}\n"
                "{acl_attribute}: {acl_value}\n"
            )
            MIGRATION_SCHEMA_ENTRY_TEMPLATE: Final[str] = (
                "dn: {dn}\n"
                "{objectclass}: {top}\n"
                "{objectclass}: {subschema}\n"
                "{cn}: subschemasubentry\n"
            )
            MIGRATION_ACI_LINE_REGEX: Final[re.Pattern[str]] = re.compile(
                r"(^|\\n)aci:",
                re.MULTILINE,
            )
            MIGRATION_BOOLEAN_CASES: Final[Mapping[str, tuple[str, str, str, str]]] = (
                MappingProxyType(
                    {
                        "oid_to_rfc": (
                            OID,
                            RFC,
                            BOOLEAN_RFC_TO_OID[BOOLEAN_TRUE],
                            BOOLEAN_RFC_TO_OID[BOOLEAN_FALSE],
                        ),
                        "rfc_to_oid": (
                            RFC,
                            OID,
                            BOOLEAN_TRUE,
                            BOOLEAN_FALSE,
                        ),
                    },
                )
            )
            MIGRATION_ACL_CASES: Final[Mapping[str, tuple[str, str, str, str]]] = (
                MappingProxyType(
                    {
                        "oid_to_rfc": (
                            OID,
                            RFC,
                            NAME_ORCLACI,
                            NAME_ACI,
                        ),
                        "rfc_to_oid": (
                            RFC,
                            OID,
                            NAME_ACI,
                            NAME_ORCLACI,
                        ),
                    },
                )
            )

            WRITER_ENTRY_ALPHA_DN: Final[str] = "cn=writer-alpha,dc=example,dc=com"
            WRITER_ENTRY_BETA_DN: Final[str] = "cn=writer-beta,dc=example,dc=com"
            WRITER_ENTRY_GAMMA_DN: Final[str] = "cn=writer-gamma,dc=example,dc=com"
            WRITER_ENTRY_DNS: Final[frozenset[str]] = frozenset(
                {
                    WRITER_ENTRY_ALPHA_DN,
                    WRITER_ENTRY_BETA_DN,
                    WRITER_ENTRY_GAMMA_DN,
                },
            )
            WRITER_SERVER_CASES: Final[Mapping[str, str]] = MappingProxyType(
                {
                    "writer_rfc": RFC,
                    "writer_oid": OID,
                    "writer_oud": OUD,
                },
            )
            WRITER_UNKNOWN_SERVER_PREFIX: Final[str] = "writer_unknown"
            WRITER_OUTPUT_FILENAME: Final[str] = "writer_output.ldif"
            WRITER_OUTPUT_REGEX: Final[re.Pattern[str]] = re.compile(
                r"(?m)^dn:\s+cn=writer-[a-z]+,dc=example,dc=com$",
            )
            WRITER_INVALID_UTF8_BYTES: Final[bytes] = b"\xff\xfe\xfd"

            RELAXED_PARSE_VALID: Final[str] = "valid"
            RELAXED_PARSE_MALFORMED: Final[str] = "malformed"
            API_SCENARIO_SIMPLE_LDIF: Final[str] = "simple_ldif"
            API_SCENARIO_MULTIPLE_INSTANCES: Final[str] = "multiple_instances"
            EDGE_CASE_UNICODE_LDIF: Final[str] = (
                "dn: cn=José,ou=Users,dc=example,dc=com\n"
                "cn: José\n"
                "sn: García\n"
                "objectClass: person\n\n"
            )
            EDGE_CASE_DEEP_DN_LDIF: Final[str] = (
                "dn: cn=level1,ou=level2,ou=level3,ou=level4,ou=level5,ou=level6,dc=example,dc=com\n"
                "cn: level1\n"
                "objectClass: person\n\n"
            )
            EDGE_CASE_LARGE_MULTIVALUE_LDIF: Final[str] = (
                "dn: cn=test,dc=example,dc=com\n"
                "cn: test\n"
                "member: cn=user1,dc=example,dc=com\n"
                "member: cn=user2,dc=example,dc=com\n"
                "member: cn=user3,dc=example,dc=com\n"
                "member: cn=user4,dc=example,dc=com\n"
                "member: cn=user5,dc=example,dc=com\n"
                "objectClass: groupOfNames\n\n"
            )
            EDGE_CASE_NON_ASCII_REGEX: Final[re.Pattern[str]] = re.compile(
                r"[^\x00-\x7F]",
            )
            EDGE_CASE_LARGE_MULTIVALUE_FIXTURE_RELATIVE: Final[Path] = (
                Path("edge_cases") / "size" / "large_multivalue.ldif"
            )
            EDGE_CASE_MIN_MULTIVALUE_COUNT: Final[int] = 10
            EDGE_CASE_INLINE_PARSE_RULES: Final[
                Mapping[str, tuple[str, int, int, bool]]
            ] = MappingProxyType(
                {
                    "unicode": (EDGE_CASE_UNICODE_LDIF, 1, 0, True),
                    "deep_dn": (EDGE_CASE_DEEP_DN_LDIF, 1, 7, False),
                },
            )
            EDGE_CASE_ROUNDTRIP_CASES: Final[Mapping[str, tuple[str, str]]] = (
                MappingProxyType(
                    {
                        "unicode": (
                            EDGE_CASE_UNICODE_LDIF,
                            "unicode_roundtrip.ldif",
                        ),
                        "deep_dn": (
                            EDGE_CASE_DEEP_DN_LDIF,
                            "deep_dn_roundtrip.ldif",
                        ),
                        "large_multivalue": (
                            EDGE_CASE_LARGE_MULTIVALUE_LDIF,
                            "large_multivalue_roundtrip.ldif",
                        ),
                    },
                )
            )

            ACL_REGISTRY_GET_ACL_ATTRIBUTES_DATA: Final[
                Mapping[str, tuple[str, str | None, tuple[str, ...], tuple[str, ...]]]
            ] = MappingProxyType(
                {
                    "get_acl_attributes_rfc_foundation": (
                        RFC,
                        None,
                        ("aci", "acl", "olcAccess", "aclRights", "aclEntry"),
                        (),
                    ),
                    "get_acl_attributes_oid_quirks": (
                        OID,
                        OID,
                        ("orclaci", "orclentrylevelaci", "aci", "acl"),
                        (),
                    ),
                    "get_acl_attributes_oud_quirks": (
                        OUD,
                        OUD,
                        ("orclaci", "orclentrylevelaci", "aci"),
                        (),
                    ),
                    "get_acl_attributes_ad_quirks": (
                        AD,
                        AD,
                        ("nTSecurityDescriptor", "aci"),
                        (),
                    ),
                    "get_acl_attributes_generic": (
                        "generic",
                        "generic",
                        ("aci", "acl"),
                        ("orclaci", "nTSecurityDescriptor"),
                    ),
                    "get_acl_attributes_unknown": (
                        "unknown_server",
                        "unknown_server",
                        ("aci", "acl"),
                        ("orclaci", "nTSecurityDescriptor"),
                    ),
                    "get_acl_attributes_none": (
                        "none",
                        None,
                        ("aci", "acl"),
                        ("orclaci",),
                    ),
                },
            )
            ACL_REGISTRY_IS_ACL_ATTRIBUTE_DATA: Final[
                Mapping[str, tuple[str, str, str | None, bool]]
            ] = MappingProxyType(
                {
                    "is_acl_attribute_rfc_aci": ("valid_rfc", "aci", None, True),
                    "is_acl_attribute_rfc_acl": ("valid_rfc", "acl", None, True),
                    "is_acl_attribute_rfc_olcAccess": (
                        "valid_rfc",
                        "olcAccess",
                        None,
                        True,
                    ),
                    "is_acl_attribute_oid_orclaci": (
                        "valid_server_specific",
                        "orclaci",
                        OID,
                        True,
                    ),
                    "is_acl_attribute_oud_orclaci": (
                        "valid_server_specific",
                        "orclaci",
                        OUD,
                        True,
                    ),
                    "is_acl_attribute_invalid_cn": ("invalid", "cn", None, False),
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
                        OID,
                        True,
                    ),
                },
            )

            RELAXED_ATTRIBUTE_DEFINITIONS: Final[Mapping[str, tuple[str, bool]]] = (
                MappingProxyType(
                    {
                        RELAXED_PARSE_VALID: (
                            "( 1.2.3.4 NAME 'testAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                            True,
                        ),
                        RELAXED_PARSE_MALFORMED: ("( 2.5.4.3 NAME 'broken'", True),
                        "missing_name": ("( 1.2.3.4 )", True),
                        "no_oid": ("NAME 'onlyName'", False),
                        "empty": ("", False),
                        "whitespace": ("   ", False),
                        "binary_data": (
                            "( 1.2.3.4 NAME 'test' \x00\x01 )".encode("latin1").decode(
                                "latin1"
                            ),
                            True,
                        ),
                        "unicode": ("( 1.2.3.4 NAME 'тест' 😀 )", True),
                        "long_definition": (
                            "( 1.2.3.4 " + "NAME 'test' " * 100 + ")",
                            True,
                        ),
                    },
                )
            )
            RELAXED_OBJECTCLASS_DEFINITIONS: Final[Mapping[str, tuple[str, bool]]] = (
                MappingProxyType(
                    {
                        RELAXED_PARSE_VALID: (
                            "( 1.2.3 NAME 'testOc' STRUCTURAL )",
                            True,
                        ),
                        RELAXED_PARSE_MALFORMED: ("( 2.5.6.0 NAME 'broken'", True),
                        "missing_name": ("( 1.2.3.4 STRUCTURAL )", True),
                        "no_oid": ("BROKEN CLASS", False),
                        "empty": ("", False),
                        "whitespace": ("   ", False),
                        "unicode": ("( 1.2.3.4 NAME 'тест' 😀 )", True),
                    },
                )
            )
            RELAXED_ACL_DEFINITIONS: Final[Mapping[str, tuple[str, bool]]] = (
                MappingProxyType(
                    {
                        RELAXED_PARSE_VALID: (
                            '(targetentry="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")(version 3.0;acl "REDACTED_LDAP_BIND_PASSWORD";allow(all)',
                            True,
                        ),
                        RELAXED_PARSE_MALFORMED: ("(targetentry incomplete", True),
                        "broken": ("(targetentry invalid) broken", True),
                    },
                )
            )

            APACHE_ATTRIBUTE_TEST_CASES = FrozenList(
                [
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
                ],
            )
            APACHE_ATTRIBUTE_TEST_CASES.freeze()
            APACHE_OBJECTCLASS_TEST_CASES = FrozenList(
                [
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
                ],
            )
            APACHE_OBJECTCLASS_TEST_CASES.freeze()
            APACHE_ENTRY_TEST_CASES = FrozenList(
                [
                    m.Ldif.Tests.EntryTestCase(
                        scenario="ou_config",
                        entry_dn="ou=settings,dc=example,dc=com",
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
                        entry_dn=DN_TEST,
                        attributes={"ads-enabled": ["TRUE"], "objectClass": ["top"]},
                        expected_can_handle=True,
                    ),
                    m.Ldif.Tests.EntryTestCase(
                        scenario="apacheds_attribute",
                        entry_dn=DN_TEST,
                        attributes={
                            "apachedsSystemId": ["test"],
                            "objectClass": ["top"],
                        },
                        expected_can_handle=True,
                    ),
                    m.Ldif.Tests.EntryTestCase(
                        scenario="ads_objectclass",
                        entry_dn=DN_TEST,
                        attributes={"objectClass": ["top", "ads-directory"]},
                        expected_can_handle=True,
                    ),
                    m.Ldif.Tests.EntryTestCase(
                        scenario="standard_rfc",
                        entry_dn="cn=user,dc=example,dc=com",
                        attributes={"objectClass": ["person"], "cn": ["user"]},
                        expected_can_handle=True,
                    ),
                ],
            )
            APACHE_ENTRY_TEST_CASES.freeze()

            DS389_ATTRIBUTE_TEST_CASES = FrozenList(
                [
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
                ],
            )
            DS389_ATTRIBUTE_TEST_CASES.freeze()
            DS389_OBJECTCLASS_TEST_CASES = FrozenList(
                [
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
                ],
            )
            DS389_OBJECTCLASS_TEST_CASES.freeze()
            DS389_ENTRY_TEST_CASES = FrozenList(
                [
                    m.Ldif.Tests.EntryTestCase(
                        scenario="cn_config",
                        entry_dn="cn=settings",
                        attributes={
                            ldif_c.Ldif.DictKeys.OBJECTCLASS.value: ["nscontainer"]
                        },
                        expected_can_handle=True,
                    ),
                    m.Ldif.Tests.EntryTestCase(
                        scenario="cn_monitor",
                        entry_dn="cn=monitor",
                        attributes={ldif_c.Ldif.DictKeys.OBJECTCLASS.value: ["top"]},
                        expected_can_handle=True,
                    ),
                    m.Ldif.Tests.EntryTestCase(
                        scenario="cn_changelog",
                        entry_dn="cn=changelog",
                        attributes={ldif_c.Ldif.DictKeys.OBJECTCLASS.value: ["top"]},
                        expected_can_handle=True,
                    ),
                    m.Ldif.Tests.EntryTestCase(
                        scenario="nsslapd_attribute",
                        entry_dn=DN_TEST,
                        attributes={"nsslapd-port": ["389"], "objectclass": ["top"]},
                        expected_can_handle=True,
                    ),
                    m.Ldif.Tests.EntryTestCase(
                        scenario="nsds_attribute",
                        entry_dn=DN_TEST,
                        attributes={"nsds5ReplicaId": ["1"], "objectclass": ["top"]},
                        expected_can_handle=True,
                    ),
                    m.Ldif.Tests.EntryTestCase(
                        scenario="nsuniqueid_attribute",
                        entry_dn=DN_TEST,
                        attributes={"nsuniqueid": ["12345"], "objectclass": ["top"]},
                        expected_can_handle=True,
                    ),
                    m.Ldif.Tests.EntryTestCase(
                        scenario="ns_objectclass",
                        entry_dn=DN_TEST,
                        attributes={
                            ldif_c.Ldif.DictKeys.OBJECTCLASS.value: [
                                "top",
                                "nscontainer",
                            ]
                        },
                        expected_can_handle=True,
                    ),
                    m.Ldif.Tests.EntryTestCase(
                        scenario="standard_rfc",
                        entry_dn="cn=user,dc=example,dc=com",
                        attributes={
                            ldif_c.Ldif.DictKeys.OBJECTCLASS.value: ["person"],
                            "cn": ["user"],
                        },
                        expected_can_handle=False,
                    ),
                ],
            )
            DS389_ENTRY_TEST_CASES.freeze()

            NOVELL_ATTRIBUTE_TEST_CASES = FrozenList(
                [
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
                ],
            )
            NOVELL_ATTRIBUTE_TEST_CASES.freeze()
            NOVELL_OBJECTCLASS_TEST_CASES = FrozenList(
                [
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
                ],
            )
            NOVELL_OBJECTCLASS_TEST_CASES.freeze()
            NOVELL_ENTRY_TEST_CASES = FrozenList(
                [
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
                        attributes={"logindisabled": ["TRUE"], "objectClass": ["top"]},
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
                ],
            )
            NOVELL_ENTRY_TEST_CASES.freeze()


c = TestsFlextLdifConstants

__all__: list[str] = ["TestsFlextLdifConstants", "c"]
