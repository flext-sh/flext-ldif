"""Centralized flat test constants for flext-ldif."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Final, Literal

from flext_ldap import c
from flext_tests import FlextTestsConstants
from frozenlist import FrozenList

from tests import m


class TestsFlextLdifConstants(FlextTestsConstants, c):
    """Flat test constants for flext-ldif."""

    class Tests(FlextTestsConstants.Tests):
        """LDIF test constants namespace."""

        FIXTURES_DIR: Final[Path] = Path(__file__).parent / "fixtures"
        PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[1]

        RFC: Final[str] = c.Ldif.ServerTypes.RFC.value
        OID: Final[str] = c.Ldif.ServerTypes.OID.value
        OUD: Final[str] = c.Ldif.ServerTypes.OUD.value
        OPENLDAP: Final[str] = c.Ldif.ServerTypes.OPENLDAP.value
        OPENLDAP1: Final[str] = c.Ldif.ServerTypes.OPENLDAP1.value
        GENERIC: Final[str] = c.Ldif.ServerTypes.GENERIC.value
        DS389: Final[str] = c.Ldif.ServerTypes.DS389.value
        APACHE: Final[str] = c.Ldif.ServerTypes.APACHE.value
        NOVELL: Final[str] = c.Ldif.ServerTypes.NOVELL.value
        TIVOLI: Final[str] = c.Ldif.ServerTypes.IBM_TIVOLI.value
        AD: Final[str] = c.Ldif.ServerTypes.AD.value

        SCHEMA: Final[str] = "schema"
        ACL: Final[str] = "acl"
        ENTRIES: Final[str] = "entries"
        INTEGRATION: Final[str] = "integration"
        FIXTURE_SERVERS_SCHEMA: Final[tuple[str, ...]] = (
            OID,
            OUD,
            OPENLDAP,
            RFC,
        )
        FIXTURE_SERVERS_COMMON: Final[tuple[str, ...]] = (
            OID,
            OUD,
            OPENLDAP,
        )
        FIXTURE_KIND_SERVERS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
            {
                SCHEMA: FIXTURE_SERVERS_SCHEMA,
                ACL: FIXTURE_SERVERS_COMMON,
                ENTRIES: FIXTURE_SERVERS_COMMON,
                INTEGRATION: FIXTURE_SERVERS_COMMON,
            },
        )
        FIXTURE_KINDS: Final[frozenset[str]] = frozenset(
            FIXTURE_KIND_SERVERS.keys(),
        )
        PARAMETRIZED_REAL_SERVERS: Final[tuple[str, ...]] = (
            OPENLDAP,
            AD,
            OID,
            OUD,
        )

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

        SCHEMA_STRUCTURAL: Final[str] = c.Ldif.SchemaKind.STRUCTURAL.value
        SCHEMA_AUXILIARY: Final[str] = c.Ldif.SchemaKind.AUXILIARY.value
        SCHEMA_ABSTRACT: Final[str] = c.Ldif.SchemaKind.ABSTRACT.value

        NAME_CN: Final[str] = "cn"
        NAME_SN: Final[str] = "sn"
        NAME_MAIL: Final[str] = "mail"
        NAME_DESCRIPTION: Final[str] = "description"
        NAME_UID: Final[str] = "uid"
        NAME_OBJECTCLASS: Final[str] = c.Ldif.DictKeys.OBJECTCLASS.value
        NAME_PERSON: Final[str] = "person"
        NAME_TOP: Final[str] = "top"
        NAME_ORCLUSER: Final[str] = "orcluser"
        NAME_SUBSCHEMA: Final[str] = "subschema"
        NAME_MEMBER: Final[str] = "member"
        NAME_GROUP_OF_NAMES: Final[str] = "groupOfNames"
        NAME_INET_ORG_PERSON: Final[str] = "inetOrgPerson"
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
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: user\n"
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

        WRITER_ENTRY_DNS: Final[frozenset[str]] = frozenset(
            {
                "cn=writer-alpha,dc=example,dc=com",
                "cn=writer-beta,dc=example,dc=com",
                "cn=writer-gamma,dc=example,dc=com",
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
        WRITER_BLOCKING_PARENT_NAME: Final[str] = "blocking_parent"
        WRITER_DIRECTORY_TARGET_NAME: Final[str] = "dir_target"
        WRITER_OUTPUT_REGEX: Final[re.Pattern[str]] = re.compile(
            r"(?m)^dn:\s+cn=writer-[a-z]+,dc=example,dc=com$",
        )
        WRITER_INVALID_UTF8_BYTES: Final[bytes] = b"\xff\xfe\xfd"

        # ── Detector service constants ───────────────────────────────────
        DETECTOR_OID_SNIPPET: Final[str] = (
            "dn: cn=schema\n"
            "objectClass: top\n"
            "objectClass: subschema\n"
            "orclaci: access to entry by * (browse)\n"
            "orclentrylevelaci: access to attr=(*) by * (read,search,compare)\n"
        )
        DETECTOR_OUD_SNIPPET: Final[str] = (
            "dn: cn=schema\n"
            "objectClass: top\n"
            'aci: (targetattr="*")(version 3.0; acl "Test"; allow(read) userdn="ldap:///anyone";)\n'
            "ds-cfg-base-dn: dc=example,dc=com\n"
        )
        DETECTOR_OPENLDAP_SNIPPET: Final[str] = (
            "dn: cn=config\n"
            "objectClass: olcGlobal\n"
            "olcAccess: to * by * read\n"
            "olcLogLevel: stats\n"
        )
        DETECTOR_RFC_SNIPPET: Final[str] = (
            "dn: cn=basic,dc=example,dc=com\nobjectClass: person\ncn: basic\nsn: user\n"
        )
        DETECTOR_SERVER_SNIPPETS: Final[Mapping[str, tuple[str, str]]] = (
            MappingProxyType(
                {
                    "oid": (DETECTOR_OID_SNIPPET, OID),
                    "oud": (DETECTOR_OUD_SNIPPET, OUD),
                },
            )
        )
        DETECTOR_INVALID_UTF8_BYTES: Final[bytes] = b"\x80\x81\x82"
        DETECTOR_MISSING_PATH_NAME: Final[str] = "missing_detector.ldif"
        DETECTOR_BAD_ENCODING_FILENAME: Final[str] = "bad_encoding.ldif"
        DETECTOR_RFC_FILENAME: Final[str] = "rfc.ldif"
        DETECTOR_MAX_LINES_SMALL: Final[int] = 5
        DETECTOR_CONFIDENCE_THRESHOLD: Final[float] = 0.0

        # ── Entries service constants ────────────────────────────────────
        ENTRIES_DN_VALID: Final[str] = "cn=entries-test,dc=example,dc=com"
        ENTRIES_DN_INVALID: Final[str] = "not-a-dn"
        ENTRIES_OBJECTCLASS_PERSON: Final[tuple[str, ...]] = (
            "top",
            "person",
            "organizationalPerson",
        )
        ENTRIES_ATTR_REMOVE_SET: Final[frozenset[str]] = frozenset(
            {"mail", "telephoneNumber", "description"},
        )
        ENTRIES_NORMALIZE_CASES: Final[
            Mapping[
                str,
                tuple[
                    str | list[str] | tuple[str, ...] | set[str] | frozenset[str],
                    bool,
                ],
            ]
        ] = MappingProxyType(
            {
                "string": ("hello", True),
                "list_one": (["world"], True),
                "tuple_one": (("x",), True),
                "frozenset_one": (frozenset({"y"}), True),
                "empty_list": ([], True),
                "empty_string": ("", True),
                "empty_stripped": ("  ", True),
            },
        )
        ENTRIES_DN_DICT_CASES: Final[
            Mapping[str, tuple[dict[str, str | list[str]], bool]]
        ] = MappingProxyType(
            {
                "str_dn": ({"dn": "cn=x,dc=example,dc=com"}, True),
                "list_dn": ({"dn": ["cn=y,dc=example,dc=com"]}, True),
                "empty_list_dn": ({"dn": []}, True),
                "missing_dn": ({}, False),
            },
        )
        ENTRIES_REMOVE_OPERATION: Final[str] = "remove_attributes"
        ENTRIES_OP_CASES: Final[Mapping[str, tuple[str | None, bool]]] = (
            MappingProxyType(
                {
                    "no_op": (None, False),
                    "remove_attrs": (ENTRIES_REMOVE_OPERATION, True),
                    "unknown_op": ("unknown_xyz", False),
                },
            )
        )

        # ── Filters service constants ────────────────────────────────────
        FILTERS_ATTR_OID_VALID: Final[str] = (
            "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        FILTERS_ATTR_OID_ALLOWED: Final[str] = "2.5.4.3"
        FILTERS_OC_OID_VALID: Final[str] = (
            "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL )"
        )
        FILTERS_OC_OID_ALLOWED: Final[str] = "2.5.6.6"
        FILTERS_SCHEMA_ATTR_KEY: Final[str] = "attributeTypes"
        FILTERS_SCHEMA_OC_KEY: Final[str] = "objectClasses"
        FILTERS_ALLOWED_ATTR_KEY: Final[str] = "allowed_attribute_oids"
        FILTERS_ALLOWED_OC_KEY: Final[str] = "allowed_objectclass_oids"
        FILTERS_ALLOWED_MR_KEY: Final[str] = "allowed_matchingrule_oids"
        FILTERS_ALLOWED_MRU_KEY: Final[str] = "allowed_matchingruleuse_oids"
        FILTERS_DN_SCHEMA: Final[str] = "cn=schema"
        FILTERS_DN_USER: Final[str] = "cn=user,dc=example,dc=com"
        FILTERS_DN_BARE: Final[str] = "cn=bare"
        FILTERS_FORBIDDEN_ATTRS_ORDERED: Final[tuple[str, ...]] = (
            NAME_MAIL,
            NAME_DESCRIPTION,
        )
        FILTERS_FORBIDDEN_ATTRS: Final[frozenset[str]] = frozenset(
            FILTERS_FORBIDDEN_ATTRS_ORDERED,
        )
        FILTERS_FORBIDDEN_OCS_ORDERED: Final[tuple[str, ...]] = (NAME_INET_ORG_PERSON,)
        FILTERS_FORBIDDEN_OCS: Final[frozenset[str]] = frozenset(
            FILTERS_FORBIDDEN_OCS_ORDERED,
        )
        FILTERS_USER_MAIL: Final[str] = "user@example.com"
        FILTERS_USER_DESCRIPTION: Final[str] = "a test user"
        FILTERS_UNMATCHED_ATTR_OID: Final[str] = (
            "( 1.9.9.9 NAME 'notAllowed' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        FILTERS_UNWANTED_ATTR_OID: Final[str] = (
            "( 9.9.9.9 NAME 'unwanted' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        PARSER_PATH_FLOW_FILENAME: Final[str] = "path_flow.ldif"
        PARSER_INVALID_UTF8_FILENAME: Final[str] = "invalid_utf8.ldif"
        PARSER_RELATIVE_PREFIX: Final[str] = "tmp_parser_relative"
        PARSER_MISSING_PREFIX: Final[str] = "missing"
        PARSER_UNKNOWN_PREFIX: Final[str] = "unknown"
        FILTERS_ALLOWED_OIDS_FULL: Final[Mapping[str, frozenset[str]]] = (
            MappingProxyType(
                {
                    FILTERS_ALLOWED_ATTR_KEY: frozenset({
                        FILTERS_ATTR_OID_ALLOWED,
                        "2.5.4.4",
                    }),
                    FILTERS_ALLOWED_OC_KEY: frozenset({FILTERS_OC_OID_ALLOWED}),
                    FILTERS_ALLOWED_MR_KEY: frozenset(),
                    FILTERS_ALLOWED_MRU_KEY: frozenset(),
                },
            )
        )
        FILTERS_ALLOWED_OIDS_EMPTY: Final[Mapping[str, frozenset[str]]] = (
            MappingProxyType(
                {
                    FILTERS_ALLOWED_ATTR_KEY: frozenset(),
                    FILTERS_ALLOWED_OC_KEY: frozenset(),
                    FILTERS_ALLOWED_MR_KEY: frozenset(),
                    FILTERS_ALLOWED_MRU_KEY: frozenset(),
                },
            )
        )

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
                m.Tests.AttributeTestCase(
                    scenario="apache_oid",
                    attr_definition="( 1.3.6.1.4.1.18060.0.4.1.2.100 NAME 'ads-enabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
                    expected_can_handle=True,
                    expected_name="ads-enabled",
                ),
                m.Tests.AttributeTestCase(
                    scenario="ads_prefix",
                    attr_definition="( 2.16.840.1.113730.3.1.1 NAME 'ads-searchBaseDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
                    expected_can_handle=True,
                    expected_name="ads-searchBaseDN",
                ),
                m.Tests.AttributeTestCase(
                    scenario="apacheds_name",
                    attr_definition="( 1.2.3.4 NAME 'apachedsSystemId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                    expected_can_handle=True,
                    expected_name="apachedsSystemId",
                ),
                m.Tests.AttributeTestCase(
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
                m.Tests.ObjectClassTestCase(
                    scenario="apache_oid",
                    oc_definition="( 1.3.6.1.4.1.18060.0.4.1.3.100 NAME 'ads-directoryService' SUP top STRUCTURAL )",
                    expected_can_handle=True,
                    expected_name="ads-directoryService",
                ),
                m.Tests.ObjectClassTestCase(
                    scenario="ads_name",
                    oc_definition="( 2.5.6.0 NAME 'ads-base' SUP top ABSTRACT )",
                    expected_can_handle=True,
                    expected_name="ads-base",
                ),
                m.Tests.ObjectClassTestCase(
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
                m.Tests.EntryTestCase(
                    scenario="ou_config",
                    entry_dn="ou=settings,dc=example,dc=com",
                    attributes={"objectClass": ["organizationalUnit"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="ou_services",
                    entry_dn="ou=services,dc=example,dc=com",
                    attributes={"objectClass": ["organizationalUnit"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="ou_system",
                    entry_dn="ou=system,dc=example,dc=com",
                    attributes={"objectClass": ["organizationalUnit"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="ou_partitions",
                    entry_dn="ou=partitions,dc=example,dc=com",
                    attributes={"objectClass": ["organizationalUnit"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="ads_attribute",
                    entry_dn=DN_TEST,
                    attributes={"ads-enabled": ["TRUE"], "objectClass": ["top"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="apacheds_attribute",
                    entry_dn=DN_TEST,
                    attributes={
                        "apachedsSystemId": ["test"],
                        "objectClass": ["top"],
                    },
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="ads_objectclass",
                    entry_dn=DN_TEST,
                    attributes={"objectClass": ["top", "ads-directory"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
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
                m.Tests.AttributeTestCase(
                    scenario="ds389_oid",
                    attr_definition="( 2.16.840.1.113730.3.1.1 NAME 'nsslapd-suffix' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
                    expected_can_handle=True,
                    expected_oid="2.16.840.1.113730.3.1.1",
                    expected_name="nsslapd-suffix",
                ),
                m.Tests.AttributeTestCase(
                    scenario="nsslapd_prefix",
                    attr_definition="( 1.2.3.4 NAME 'nsslapd-port' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
                    expected_can_handle=True,
                    expected_name="nsslapd-port",
                ),
                m.Tests.AttributeTestCase(
                    scenario="nsds_prefix",
                    attr_definition="( 1.2.3.4 NAME 'nsds5ReplicaId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
                    expected_can_handle=True,
                    expected_name="nsds5ReplicaId",
                ),
                m.Tests.AttributeTestCase(
                    scenario="nsuniqueid_prefix",
                    attr_definition="( 1.2.3.4 NAME 'nsuniqueid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                    expected_can_handle=True,
                    expected_name="nsuniqueid",
                ),
                m.Tests.AttributeTestCase(
                    scenario="standard_rfc",
                    attr_definition="( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                    expected_can_handle=False,
                ),
            ],
        )
        DS389_ATTRIBUTE_TEST_CASES.freeze()
        DS389_OBJECTCLASS_TEST_CASES = FrozenList(
            [
                m.Tests.ObjectClassTestCase(
                    scenario="ds389_oid",
                    oc_definition="( 2.16.840.1.113730.3.2.1 NAME 'nscontainer' SUP top STRUCTURAL )",
                    expected_can_handle=True,
                    expected_oid="2.16.840.1.113730.3.2.1",
                    expected_name="nscontainer",
                    expected_kind="STRUCTURAL",
                ),
                m.Tests.ObjectClassTestCase(
                    scenario="ns_name",
                    oc_definition="( 2.5.6.0 NAME 'nsperson' SUP top STRUCTURAL )",
                    expected_can_handle=True,
                    expected_name="nsperson",
                ),
                m.Tests.ObjectClassTestCase(
                    scenario="standard_rfc",
                    oc_definition="( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )",
                    expected_can_handle=False,
                ),
            ],
        )
        DS389_OBJECTCLASS_TEST_CASES.freeze()
        DS389_ENTRY_TEST_CASES = FrozenList(
            [
                m.Tests.EntryTestCase(
                    scenario="cn_config",
                    entry_dn="cn=settings",
                    attributes={c.Ldif.DictKeys.OBJECTCLASS.value: ["nscontainer"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="cn_monitor",
                    entry_dn="cn=monitor",
                    attributes={c.Ldif.DictKeys.OBJECTCLASS.value: ["top"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="cn_changelog",
                    entry_dn="cn=changelog",
                    attributes={c.Ldif.DictKeys.OBJECTCLASS.value: ["top"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="nsslapd_attribute",
                    entry_dn=DN_TEST,
                    attributes={"nsslapd-port": ["389"], "objectclass": ["top"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="nsds_attribute",
                    entry_dn=DN_TEST,
                    attributes={"nsds5ReplicaId": ["1"], "objectclass": ["top"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="nsuniqueid_attribute",
                    entry_dn=DN_TEST,
                    attributes={"nsuniqueid": ["12345"], "objectclass": ["top"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="ns_objectclass",
                    entry_dn=DN_TEST,
                    attributes={
                        c.Ldif.DictKeys.OBJECTCLASS.value: [
                            "top",
                            "nscontainer",
                        ]
                    },
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="standard_rfc",
                    entry_dn="cn=user,dc=example,dc=com",
                    attributes={
                        c.Ldif.DictKeys.OBJECTCLASS.value: ["person"],
                        "cn": ["user"],
                    },
                    expected_can_handle=False,
                ),
            ],
        )
        DS389_ENTRY_TEST_CASES.freeze()

        NOVELL_ATTRIBUTE_TEST_CASES = FrozenList(
            [
                m.Tests.AttributeTestCase(
                    scenario="novell_oid",
                    attr_definition="( 2.16.840.1.113719.1.1.4.1.501 NAME 'nspmPasswordPolicyDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
                    expected_can_handle=True,
                    expected_oid="2.16.840.1.113719.1.1.4.1.501",
                    expected_name="nspmPasswordPolicyDN",
                ),
                m.Tests.AttributeTestCase(
                    scenario="nspm_prefix",
                    attr_definition="( 1.2.3.4 NAME 'nspmPasswordPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                    expected_can_handle=True,
                    expected_name="nspmPasswordPolicy",
                ),
                m.Tests.AttributeTestCase(
                    scenario="login_prefix",
                    attr_definition="( 1.2.3.4 NAME 'loginDisabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
                    expected_can_handle=True,
                    expected_name="loginDisabled",
                ),
                m.Tests.AttributeTestCase(
                    scenario="dirxml_prefix",
                    attr_definition="( 1.2.3.4 NAME 'dirxml-associations' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                    expected_can_handle=True,
                    expected_name="dirxml-associations",
                ),
                m.Tests.AttributeTestCase(
                    scenario="standard_rfc",
                    attr_definition="( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                    expected_can_handle=False,
                ),
            ],
        )
        NOVELL_ATTRIBUTE_TEST_CASES.freeze()
        NOVELL_OBJECTCLASS_TEST_CASES = FrozenList(
            [
                m.Tests.ObjectClassTestCase(
                    scenario="novell_oid",
                    oc_definition="( 2.16.840.1.113719.2.2.6.1 NAME 'ndsPerson' SUP top STRUCTURAL )",
                    expected_can_handle=True,
                    expected_oid="2.16.840.1.113719.2.2.6.1",
                    expected_name="ndsPerson",
                ),
                m.Tests.ObjectClassTestCase(
                    scenario="nds_name",
                    oc_definition="( 2.5.6.0 NAME 'ndsserver' SUP top STRUCTURAL )",
                    expected_can_handle=True,
                    expected_name="ndsserver",
                ),
                m.Tests.ObjectClassTestCase(
                    scenario="standard_rfc",
                    oc_definition="( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )",
                    expected_can_handle=False,
                ),
            ],
        )
        NOVELL_OBJECTCLASS_TEST_CASES.freeze()
        NOVELL_ENTRY_TEST_CASES = FrozenList(
            [
                m.Tests.EntryTestCase(
                    scenario="ou_services",
                    entry_dn="ou=services,o=Example",
                    attributes={"objectClass": ["organizationalUnit"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="ou_apps",
                    entry_dn="ou=apps,o=Example",
                    attributes={"objectClass": ["organizationalUnit"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="ou_system",
                    entry_dn="ou=system,o=Example",
                    attributes={"objectClass": ["organizationalUnit"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="nspm_attribute",
                    entry_dn="cn=user,o=Example",
                    attributes={
                        "nspmpasswordpolicy": ["policy1"],
                        "objectClass": ["top"],
                    },
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="login_attribute",
                    entry_dn="cn=user,o=Example",
                    attributes={"logindisabled": ["TRUE"], "objectClass": ["top"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="nds_objectclass",
                    entry_dn="cn=user,o=Example",
                    attributes={"objectClass": ["top", "ndsperson"]},
                    expected_can_handle=True,
                ),
                m.Tests.EntryTestCase(
                    scenario="standard_rfc",
                    entry_dn="cn=user,dc=example,dc=com",
                    attributes={"objectClass": ["person"], "cn": ["user"]},
                    expected_can_handle=False,
                ),
            ],
        )
        NOVELL_ENTRY_TEST_CASES.freeze()

        # ── ACL service constants ────────────────────────────────────────
        ACL_OUD_STRING: Final[str] = (
            '(targetattr="*")(version 3.0; acl "Test ACL"; allow (read,search) userdn="ldap:///anyone";)'
        )
        ACL_OID_STRING: Final[str] = "access to entry by * (browse)"
        ACL_OPENLDAP_STRING: Final[str] = "to * by * read"
        ACL_RFC_STRING: Final[str] = "access to entry by * (read)"
        ACL_SERVER_CASES: Final[Mapping[str, tuple[str, str]]] = MappingProxyType(
            {
                "oud": (ACL_OUD_STRING, OUD),
                "oid": (ACL_OID_STRING, OID),
                "rfc": (ACL_RFC_STRING, RFC),
            },
        )
        ACL_PERMISSIONS_READ_ONLY: Final[Mapping[str, bool]] = MappingProxyType(
            {
                "read": True,
                "write": False,
                "delete": False,
                "add": False,
                "search": False,
                "compare": False,
            },
        )
        ACL_PERMISSIONS_EMPTY: Final[Mapping[str, bool]] = MappingProxyType(
            {
                "read": False,
                "write": False,
                "delete": False,
                "add": False,
                "search": False,
                "compare": False,
            },
        )
        ACL_ENTRY_DN: Final[str] = "cn=acltest,dc=example,dc=com"
        ACL_ENTRY_ORCLACI_VALUE: Final[str] = "access to entry by * (browse)"
        ACL_ENTRY_ACI_VALUE: Final[str] = (
            '(targetattr="*")(version 3.0; acl "Entry ACL"; allow (read,search) userdn="ldap:///anyone";)'
        )
        ACL_INVALID_SERVER_TYPE: Final[str] = "NOT_A_VALID_SERVER_XYZ"
        ACL_PARSE_FAILURE_CASES: Final[Mapping[str, tuple[str, str]]] = (
            MappingProxyType(
                {
                    "invalid_server": (ACL_OUD_STRING, ACL_INVALID_SERVER_TYPE),
                    "generic_server_without_acl_quirk": (ACL_OUD_STRING, GENERIC),
                    "openldap_invalid_acl_format": (ACL_INVALID_SERVER_TYPE, OPENLDAP),
                },
            )
        )
        ACL_SERVICE_CHECK_EMPTY_ACLS: Final[int] = 0

        # ── Analysis service constants ───────────────────────────────────
        ANALYSIS_DN_VALID: Final[str] = "cn=analysis-user,dc=example,dc=com"
        ANALYSIS_DN_EMPTY_DN: Final[str] = ""
        ANALYSIS_ATTR_CN_VALUE: Final[str] = "analysis-user"
        ANALYSIS_ATTR_INVALID_NAME: Final[str] = "invalid_attr"
        ANALYSIS_OC_PERSON: Final[str] = "person"
        ANALYSIS_OC_INVALID: Final[str] = "invalid_oc"
        ANALYSIS_VALID_ENTRY_ATTRS: Final[Mapping[str, list[str]]] = MappingProxyType(
            {
                "objectClass": [ANALYSIS_OC_PERSON, "top"],
                "cn": [ANALYSIS_ATTR_CN_VALUE],
                "sn": ["user"],
            },
        )
        ANALYSIS_INVALID_ATTR_ENTRY_ATTRS: Final[Mapping[str, list[str]]] = (
            MappingProxyType(
                {
                    "objectClass": [ANALYSIS_OC_PERSON],
                    ANALYSIS_ATTR_INVALID_NAME: ["value"],
                },
            )
        )
        ANALYSIS_INVALID_OC_ENTRY_ATTRS: Final[Mapping[str, list[str]]] = (
            MappingProxyType(
                {
                    "objectClass": [ANALYSIS_OC_INVALID],
                    "cn": ["user"],
                },
            )
        )
        ANALYSIS_PARSE_RESPONSE_LDIF: Final[str] = (
            "dn: cn=user1,dc=example,dc=com\n"
            "objectClass: person\n"
            "cn: user1\n\n"
            "dn: cn=user2,dc=example,dc=com\n"
            "objectClass: person\n"
            "cn: user2\n"
        )
        ANALYSIS_MULTIENTRY_PARSE_LDIF: Final[str] = (
            "dn: cn=valid,dc=example,dc=com\nobjectClass: person\ncn: valid\n"
        )

        # ── Migration pipeline constants ─────────────────────────────────
        MIGRATION_INPUT_FILENAME: Final[str] = "mig_input.ldif"
        MIGRATION_OUTPUT_FILENAME: Final[str] = "mig_output.ldif"
        MIGRATION_EMPTY_LDIF: Final[str] = ""
        MIGRATION_INVALID_LDIF: Final[str] = "not valid ldif content"
        MIGRATION_SINGLE_ENTRY_LDIF: Final[str] = (
            "dn: cn=migrate-me,dc=example,dc=com\n"
            "objectClass: person\n"
            "cn: migrate-me\n"
            "sn: user\n"
        )
        MIGRATION_MULTI_ENTRY_LDIF: Final[str] = (
            "dn: cn=user1,dc=example,dc=com\nobjectClass: person\ncn: user1\n\n"
            "dn: cn=user2,dc=example,dc=com\nobjectClass: person\ncn: user2\n"
        )
        MIGRATION_SERVER_PAIRS: Final[Mapping[str, tuple[str, str]]] = MappingProxyType(
            {
                "oid_to_rfc": (OID, RFC),
                "oud_to_rfc": (OUD, RFC),
                "rfc_to_oid": (RFC, OID),
                "rfc_to_oud": (RFC, OUD),
            },
        )
        MIGRATION_UNKNOWN_SERVER: Final[str] = "TOTALLY_UNKNOWN_SERVER_XYZ"
        MIGRATION_COERCE_CASES: Final[Mapping[str, tuple[str, str]]] = MappingProxyType(
            {
                "rfc_lower": ("rfc", RFC),
                "oid_upper": ("OID", OID),
                "unknown_falls_back": (MIGRATION_UNKNOWN_SERVER, RFC),
            },
        )

        # ── Writer advanced constants ────────────────────────────────────
        WRITER_MULTI_ENTRY_LDIF: Final[str] = (
            "dn: cn=writer-alpha,dc=example,dc=com\n"
            "objectClass: person\n"
            "cn: writer-alpha\n\n"
            "dn: cn=writer-beta,dc=example,dc=com\n"
            "objectClass: person\n"
            "cn: writer-beta\n"
        )
        WRITER_FORMAT_OPTIONS_LINE_LENGTH: Final[int] = 76
        WRITER_PARSE_RESPONSE_LDIF: Final[str] = (
            "dn: cn=wr-user,dc=example,dc=com\nobjectClass: person\ncn: wr-user\n"
        )
        WRITER_EMPTY_ENTRY_LIST_COUNT: Final[int] = 0
        WRITER_KNOWN_SERVER_TYPES: Final[frozenset[str]] = frozenset(
            {RFC, OID, OUD, OPENLDAP},
        )
        WRITER_FILE_WRITE_CASES: Final[Mapping[str, tuple[str, str]]] = (
            MappingProxyType(
                {
                    "rfc_file": (RFC, "out_rfc.ldif"),
                    "oid_file": (OID, "out_oid.ldif"),
                },
            )
        )

        # ── Server service constants ─────────────────────────────────────
        SERVER_VALID_TYPES: Final[frozenset[str]] = frozenset(
            {RFC, OID, OUD, OPENLDAP},
        )
        SERVER_QUIRK_ENTRY_DN: Final[str] = "cn=quirk-entry,dc=example,dc=com"
        SERVER_QUIRK_ATTRS: Final[Mapping[str, list[str]]] = MappingProxyType(
            {"objectClass": ["person"], "cn": ["quirk-entry"]},
        )
        SERVER_INVALID_QUIRK_TYPE: Final[str] = "invalid_server_xyz"
        SERVER_SCHEMA_ENTRY_DN: Final[str] = "cn=schema"
        SERVER_SCHEMA_ATTRS: Final[Mapping[str, list[str]]] = MappingProxyType(
            {"objectClass": ["subschema", "top"]},
        )

        # ── Validation service constants ─────────────────────────────────
        VALIDATION_VALID_ATTR_NAMES: Final[tuple[str, ...]] = (
            "cn",
            "sn",
            "mail",
            "objectClass",
            "description",
            "telephoneNumber",
        )
        VALIDATION_INVALID_ATTR_NAMES: Final[tuple[str, ...]] = (
            "invalid_attr",
            "attr with space",
            "cn_test",
        )
        VALIDATION_VALID_DN_STRINGS: Final[tuple[str, ...]] = (
            "cn=user,dc=example,dc=com",
            "dc=example,dc=com",
            "cn=test",
        )
        VALIDATION_INVALID_DN_STRINGS: Final[tuple[str, ...]] = (
            "not a dn at all",
            "",
        )
        VALIDATION_VALID_OC_NAMES: Final[tuple[str, ...]] = (
            "person",
            "top",
            "organizationalUnit",
            "inetOrgPerson",
        )

        # ── Pipeline constants ───────────────────────────────────────────
        PIPELINE_ENTRY_DN: Final[str] = "cn=pipeline-entry,dc=example,dc=com"
        PIPELINE_ENTRY_ATTRS: Final[Mapping[str, list[str]]] = MappingProxyType(
            {"objectClass": ["person"], "cn": ["pipeline-entry"]},
        )
        PIPELINE_LDIF_CONTENT: Final[str] = (
            "dn: cn=pipeline-entry,dc=example,dc=com\n"
            "objectClass: person\n"
            "cn: pipeline-entry\n"
        )
        PIPELINE_SERVER_PAIRS: Final[Mapping[str, tuple[str, str]]] = MappingProxyType(
            {
                "rfc_to_oid": (RFC, OID),
                "oid_to_rfc": (OID, RFC),
            },
        )

        # ── Processing service constants ───────────────────────────────
        PROCESSING_VALID_DNS: Final[tuple[str, ...]] = (
            "cn=processing-one,dc=example,dc=com",
            "cn=processing-two,dc=example,dc=com",
        )
        PROCESSING_ATTRS: Final[Mapping[str, list[str]]] = MappingProxyType(
            {
                "objectClass": ["person", "top"],
                "cn": ["processing-user"],
                "sn": ["processing"],
            },
        )
        PROCESSING_OPTIONS_CASES: Final[
            Mapping[
                str,
                tuple[Literal["transform", "validate"], bool, int, int],
            ]
        ] = MappingProxyType(
            {
                "batch_transform": ("transform", False, 1, 2),
                "parallel_validate": ("validate", True, 1, 2),
            },
        )

        # ── Statistics service constants ───────────────────────────────
        STATS_SERVER_TYPES: Final[tuple[str, ...]] = (
            RFC,
            OID,
        )
        STATS_EXPECTED_OBJECTCLASS: Final[str] = "person"


c = TestsFlextLdifConstants

__all__: list[str] = ["TestsFlextLdifConstants", "c"]
