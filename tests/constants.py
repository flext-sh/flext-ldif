"""Centralized flat test constants for flext-ldif."""

from __future__ import annotations

import re
from enum import StrEnum, unique
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Final, Literal

from flext_tests import FlextTestsConstants

from flext_ldif import FlextLdifConstants
from tests import m

if TYPE_CHECKING:
    from tests import t


class TestsFlextLdifConstants(FlextTestsConstants, FlextLdifConstants):
    """Flat test constants for flext-ldif."""

    class Ldap:
        """ldap3 wire constants consumed by the real-directory tests.

        flext-ldif is the base library of the LDAP client, so the client cannot
        be a declared dependency here (see ``tests.utilities``). These are the
        ldap3 protocol values the tests pass to the dynamically resolved client,
        not a second implementation of an owned facade.
        """

        @unique
        class Ldap3SearchScope(StrEnum):
            """ldap3-compatible search scope string values."""

            BASE = "BASE"
            LEVEL = "LEVEL"
            SUBTREE = "SUBTREE"

        @unique
        class Ldap3GetInfo(StrEnum):
            """ldap3-compatible get-info option string values."""

            ALL = "ALL"
            DSA = "DSA"
            NO_INFO = "NO_INFO"
            SCHEMA = "SCHEMA"

    class Tests(FlextTestsConstants.Tests):
        """LDIF test constants namespace."""

        FIXTURES_DIR: ClassVar[Path] = Path(__file__).parent / "fixtures"
        PROJECT_ROOT: ClassVar[Path] = Path(__file__).resolve().parents[1]

        RFC: ClassVar[str] = FlextLdifConstants.Ldif.ServerTypes.RFC.value
        OID: ClassVar[str] = FlextLdifConstants.Ldif.ServerTypes.OID.value
        OUD: ClassVar[str] = FlextLdifConstants.Ldif.ServerTypes.OUD.value
        OPENLDAP: ClassVar[str] = FlextLdifConstants.Ldif.ServerTypes.OPENLDAP.value
        OPENLDAP1: ClassVar[str] = FlextLdifConstants.Ldif.ServerTypes.OPENLDAP1.value
        GENERIC: ClassVar[str] = FlextLdifConstants.Ldif.ServerTypes.GENERIC.value
        DS389: ClassVar[str] = FlextLdifConstants.Ldif.ServerTypes.DS389.value
        APACHE: ClassVar[str] = FlextLdifConstants.Ldif.ServerTypes.APACHE.value
        NOVELL: ClassVar[str] = FlextLdifConstants.Ldif.ServerTypes.NOVELL.value
        TIVOLI: ClassVar[str] = FlextLdifConstants.Ldif.ServerTypes.IBM_TIVOLI.value
        AD: ClassVar[str] = FlextLdifConstants.Ldif.ServerTypes.AD.value

        SCHEMA: ClassVar[str] = "schema"
        ACL: ClassVar[str] = "acl"
        ENTRIES: ClassVar[str] = "entries"
        INTEGRATION: ClassVar[str] = "integration"
        FIXTURE_SERVERS_SCHEMA: ClassVar[t.StrSequence] = (OID, OUD, OPENLDAP, RFC)
        FIXTURE_SERVERS_COMMON: ClassVar[t.StrSequence] = (OID, OUD, OPENLDAP)
        FIXTURE_KIND_SERVERS: ClassVar[t.MappingKV[str, t.StrSequence]] = (
            MappingProxyType({
                SCHEMA: FIXTURE_SERVERS_SCHEMA,
                ACL: FIXTURE_SERVERS_COMMON,
                ENTRIES: FIXTURE_SERVERS_COMMON,
                INTEGRATION: FIXTURE_SERVERS_COMMON,
            })
        )
        FIXTURE_KINDS: ClassVar[frozenset[str]] = frozenset(FIXTURE_KIND_SERVERS.keys())
        PARAMETRIZED_REAL_SERVERS: ClassVar[t.StrSequence] = (OPENLDAP, AD, OID, OUD)

        DOCKER_CONTAINER_NAME: ClassVar[str] = "flext-openldap-test"
        DOCKER_PORT: ClassVar[int] = 3390
        DOCKER_BASE_DN: ClassVar[str] = "dc=flext,dc=local"
        DOCKER_ADMIN_DN: ClassVar[str] = "cn=admin,dc=flext,dc=local"
        # SSOT: docker/docker-compose.openldap.yml -> LDAP_ADMIN_PASSWORD of the
        # shared flext-openldap-test container. A value that does not bind makes
        # every real-LDAP test skip after burning the whole probe budget.
        DOCKER_ADMIN_CREDENTIAL: ClassVar[str] = "admin123"
        DOCKER_LEGACY_ADMIN_DN: ClassVar[str] = (
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
        )
        DOCKER_LEGACY_ADMIN_CREDENTIAL: ClassVar[str] = "flext-legacy-admin"

        SCHEMA_STRUCTURAL: ClassVar[str] = (
            FlextLdifConstants.Ldif.SchemaKind.STRUCTURAL.value
        )
        SCHEMA_AUXILIARY: ClassVar[str] = (
            FlextLdifConstants.Ldif.SchemaKind.AUXILIARY.value
        )
        SCHEMA_ABSTRACT: ClassVar[str] = (
            FlextLdifConstants.Ldif.SchemaKind.ABSTRACT.value
        )

        NAME_CN: ClassVar[str] = "cn"
        NAME_SN: ClassVar[str] = "sn"
        NAME_MAIL: ClassVar[str] = "mail"
        NAME_DESCRIPTION: ClassVar[str] = "description"
        NAME_UID: ClassVar[str] = "uid"
        NAME_OBJECTCLASS: ClassVar[str] = (
            FlextLdifConstants.Ldif.DictKeys.OBJECTCLASS.value
        )
        NAME_PERSON: ClassVar[str] = "person"
        NAME_TOP: ClassVar[str] = "top"
        NAME_ORCLUSER: ClassVar[str] = "orcluser"
        NAME_SUBSCHEMA: ClassVar[str] = "subschema"
        NAME_MEMBER: ClassVar[str] = "member"
        NAME_GROUP_OF_NAMES: ClassVar[str] = "groupOfNames"
        NAME_INET_ORG_PERSON: ClassVar[str] = "inetOrgPerson"
        NAME_ACI: ClassVar[str] = "aci"
        NAME_ORCLACI: ClassVar[str] = "orclaci"

        DN_TEST: ClassVar[str] = "cn=test,dc=example,dc=com"
        DN_TEST_USER: ClassVar[str] = "cn=testuser,dc=example,dc=com"

        BOOLEAN_TRUE: ClassVar[str] = "TRUE"
        BOOLEAN_FALSE: ClassVar[str] = "FALSE"
        ATTR_ORCL_IS_ENABLED: ClassVar[str] = "orclIsEnabled"
        ATTR_ORCL_ACCOUNT_LOCKED: ClassVar[str] = "orclAccountLocked"
        ACL_READ_VALUE: ClassVar[str] = "access to entry by * (read)"

        RFC_SAMPLE_LDIF_BASIC: ClassVar[str] = (
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: user\n"
        )
        RFC_SAMPLE_LDIF_MULTIPLE: ClassVar[str] = (
            "dn: cn=user1,dc=example,dc=com\n"
            "objectClass: person\n"
            "cn: user1\n\n"
            "dn: cn=user2,dc=example,dc=com\n"
            "objectClass: person\n"
            "cn: user2\n"
        )
        RFC_TEST_DN: ClassVar[str] = DN_TEST

        ATTR_VALUE_TEST: ClassVar[str] = "test"
        ATTR_VALUE_USER: ClassVar[str] = "user"
        VERSION_EXPECTED_EXPORTS: ClassVar[t.StrSequence] = (
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

        CONFIG_BASIC_ENTRY: ClassVar[str] = (
            "dn: cn=Test,dc=example,dc=com\ncn: Test\nobjectClass: person\n"
        )
        CONFIG_MULTIPLE_ENTRIES: ClassVar[str] = (
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
        CONFIG_SERVER_TYPES: ClassVar[t.StrSequence] = (OID, OUD, OPENLDAP, RFC)
        _CONFIG_SERVER_LABELS: Final[t.MappingKV[str, str]] = MappingProxyType({
            OID: "OID",
            OUD: "OUD",
            OPENLDAP: "OpenLDAP",
            RFC: "RFC",
        })
        CONFIG_SERVER_CONTENT: ClassVar[t.MappingKV[str, str]] = MappingProxyType({
            server: (
                f"dn: cn={label} Test,dc=example,dc=com\n"
                f"cn: {label} Test\n"
                "objectClass: person\n"
            )
            for server, label in _CONFIG_SERVER_LABELS.items()
        })

        CROSS_SERVER_OID_ATTRIBUTE_ORCLGUID: ClassVar[str] = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' DESC 'Oracle GUID' "
            "EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
        )
        CROSS_SERVER_OID_OBJECTCLASS_ORCLCONTAINER: ClassVar[str] = (
            "( 2.16.840.1.113894.2.1.1 NAME 'orclContainer' DESC 'Oracle Container' "
            "SUP top STRUCTURAL MUST cn MAY description )"
        )
        CROSS_SERVER_OID_OBJECTCLASS_ORCLCONTEXT: ClassVar[str] = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
        )
        CROSS_SERVER_OID_ACL_ANONYMOUS: ClassVar[str] = (
            "orclaci: access to entry by * (browse)"
        )
        CROSS_SERVER_OUD_ACI_ANONYMOUS: ClassVar[str] = (
            'aci: (targetattr="*")(version 3.0; acl "Test ACL"; allow (read,search) userdn="ldap:///anyone";)'
        )
        CROSS_SERVER_OUD_ATTRIBUTE_ORCLGUID: ClassVar[str] = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
        )

        BOOLEAN_RFC_TO_OID: ClassVar[t.MappingKV[str, str]] = MappingProxyType({
            "TRUE": "1",
            "FALSE": "0",
        })
        BOOLEAN_OID_TO_RFC: ClassVar[t.MappingKV[str, str]] = MappingProxyType({
            v: k for k, v in BOOLEAN_RFC_TO_OID.items()
        })
        MIGRATION_BOOLEAN_ENTRY_TEMPLATE: ClassVar[str] = (
            "dn: {dn}\n"
            "{objectclass}: {top}\n"
            "{objectclass}: {person}\n"
            "{objectclass}: {orcluser}\n"
            "{cn}: {cn_value}\n"
            "{sn}: {sn_value}\n"
            "{attr_enabled}: {val_true}\n"
            "{attr_locked}: {val_false}\n"
        )
        MIGRATION_ACL_ENTRY_TEMPLATE: ClassVar[str] = (
            "dn: {dn}\n"
            "{objectclass}: {top}\n"
            "{objectclass}: {person}\n"
            "{cn}: {cn_value}\n"
            "{sn}: {sn_value}\n"
            "{acl_attribute}: {acl_value}\n"
        )
        MIGRATION_SCHEMA_ENTRY_TEMPLATE: ClassVar[str] = (
            "dn: {dn}\n"
            "{objectclass}: {top}\n"
            "{objectclass}: {subschema}\n"
            "{cn}: subschemasubentry\n"
        )
        MIGRATION_ACI_LINE_REGEX: ClassVar[t.Ldif.RegexPattern] = re.compile(
            r"(^|\\n)aci:", re.MULTILINE
        )
        MIGRATION_BOOLEAN_CASES: ClassVar[
            t.MappingKV[str, tuple[str, str, str, str]]
        ] = MappingProxyType({
            "oid_to_rfc": (
                OID,
                RFC,
                BOOLEAN_RFC_TO_OID[BOOLEAN_TRUE],
                BOOLEAN_RFC_TO_OID[BOOLEAN_FALSE],
            ),
            "rfc_to_oid": (RFC, OID, BOOLEAN_TRUE, BOOLEAN_FALSE),
        })
        MIGRATION_ACL_CASES: ClassVar[t.MappingKV[str, tuple[str, str, str, str]]] = (
            MappingProxyType({
                "oid_to_rfc": (OID, RFC, NAME_ORCLACI, NAME_ACI),
                "rfc_to_oid": (RFC, OID, NAME_ACI, NAME_ORCLACI),
            })
        )

        WRITER_ENTRY_DNS: ClassVar[frozenset[str]] = frozenset({
            "cn=writer-alpha,dc=example,dc=com",
            "cn=writer-beta,dc=example,dc=com",
            "cn=writer-gamma,dc=example,dc=com",
        })
        WRITER_SERVER_CASES: ClassVar[t.MappingKV[str, str]] = MappingProxyType({
            "writer_rfc": RFC,
            "writer_oid": OID,
            "writer_oud": OUD,
        })
        WRITER_UNKNOWN_SERVER_PREFIX: ClassVar[str] = "writer_unknown"
        WRITER_OUTPUT_FILENAME: ClassVar[str] = "writer_output.ldif"
        WRITER_BLOCKING_PARENT_NAME: ClassVar[str] = "blocking_parent"
        WRITER_DIRECTORY_TARGET_NAME: ClassVar[str] = "dir_target"
        WRITER_OUTPUT_REGEX: ClassVar[t.Ldif.RegexPattern] = re.compile(
            r"^dn:\s+cn=writer-[a-z]+,dc=example,dc=com$", re.MULTILINE
        )
        WRITER_INVALID_UTF8_BYTES: ClassVar[bytes] = b"\xff\xfe\xfd"

        # ── Detector service constants ───────────────────────────────────
        DETECTOR_OID_SNIPPET: ClassVar[str] = (
            "dn: cn=schema\n"
            "objectClass: top\n"
            "objectClass: subschema\n"
            "orclaci: access to entry by * (browse)\n"
            "orclentrylevelaci: access to attr=(*) by * (read,search,compare)\n"
        )
        DETECTOR_OUD_SNIPPET: ClassVar[str] = (
            "dn: cn=schema\n"
            "objectClass: top\n"
            'aci: (targetattr="*")(version 3.0; acl "Test"; allow(read) userdn="ldap:///anyone";)\n'
            "ds-cfg-base-dn: dc=example,dc=com\n"
        )
        DETECTOR_OPENLDAP_SNIPPET: ClassVar[str] = (
            "dn: cn=config\n"
            "objectClass: olcGlobal\n"
            "olcAccess: to * by * read\n"
            "olcLogLevel: stats\n"
        )
        DETECTOR_RFC_SNIPPET: ClassVar[str] = (
            "dn: cn=basic,dc=example,dc=com\nobjectClass: person\ncn: basic\nsn: user\n"
        )
        DETECTOR_SERVER_SNIPPETS: ClassVar[t.MappingKV[str, tuple[str, str]]] = (
            MappingProxyType({
                "oid": (DETECTOR_OID_SNIPPET, OID),
                "oud": (DETECTOR_OUD_SNIPPET, OUD),
            })
        )
        DETECTOR_INVALID_UTF8_BYTES: ClassVar[bytes] = b"\x80\x81\x82"
        DETECTOR_MISSING_PATH_NAME: ClassVar[str] = "missing_detector.ldif"
        DETECTOR_BAD_ENCODING_FILENAME: ClassVar[str] = "bad_encoding.ldif"
        DETECTOR_RFC_FILENAME: ClassVar[str] = "rfc.ldif"
        DETECTOR_MAX_LINES_SMALL: ClassVar[int] = 5
        DETECTOR_CONFIDENCE_THRESHOLD: ClassVar[float] = 0.0

        # ── Entries service constants ────────────────────────────────────
        ENTRIES_DN_VALID: ClassVar[str] = "cn=entries-test,dc=example,dc=com"
        ENTRIES_DN_INVALID: ClassVar[str] = "not-a-dn"
        ENTRIES_OBJECTCLASS_PERSON: ClassVar[t.StrSequence] = (
            "top",
            "person",
            "organizationalPerson",
        )
        ENTRIES_ATTR_REMOVE_SET: ClassVar[frozenset[str]] = frozenset({
            "mail",
            "telephoneNumber",
            "description",
        })
        ENTRIES_NORMALIZE_CASES: ClassVar[
            t.MappingKV[
                str,
                tuple[
                    str | list[str] | t.StrSequence | set[str] | frozenset[str], bool
                ],
            ]
        ] = MappingProxyType({
            "string": ("hello", True),
            "list_one": (["world"], True),
            "tuple_one": (("x",), True),
            "frozenset_one": (frozenset({"y"}), True),
            "empty_list": ([], True),
            "empty_string": ("", True),
            "empty_stripped": ("  ", True),
        })
        ENTRIES_DN_DICT_CASES: ClassVar[
            t.MappingKV[str, tuple[dict[str, str | list[str]], bool]]
        ] = MappingProxyType({
            "str_dn": ({"dn": "cn=x,dc=example,dc=com"}, True),
            "list_dn": ({"dn": ["cn=y,dc=example,dc=com"]}, True),
            "empty_list_dn": ({"dn": []}, True),
            "missing_dn": ({}, False),
        })
        ENTRIES_REMOVE_OPERATION: ClassVar[str] = "remove_attributes"
        ENTRIES_OP_CASES: ClassVar[t.MappingKV[str, tuple[str | None, bool]]] = (
            MappingProxyType({
                "no_op": (None, False),
                "remove_attrs": (ENTRIES_REMOVE_OPERATION, True),
                "unknown_op": ("unknown_xyz", False),
            })
        )

        # ── Filters service constants ────────────────────────────────────
        FILTERS_ATTR_OID_VALID: ClassVar[str] = (
            "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        FILTERS_ATTR_OID_ALLOWED: ClassVar[str] = "2.5.4.3"
        FILTERS_OC_OID_VALID: ClassVar[str] = (
            "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL )"
        )
        FILTERS_OC_OID_ALLOWED: ClassVar[str] = "2.5.6.6"
        FILTERS_SCHEMA_ATTR_KEY: ClassVar[str] = "attributeTypes"
        FILTERS_SCHEMA_OC_KEY: ClassVar[str] = "objectClasses"
        FILTERS_ALLOWED_ATTR_KEY: ClassVar[str] = "allowed_attribute_oids"
        FILTERS_ALLOWED_OC_KEY: ClassVar[str] = "allowed_objectclass_oids"
        FILTERS_ALLOWED_MR_KEY: ClassVar[str] = "allowed_matchingrule_oids"
        FILTERS_ALLOWED_MRU_KEY: ClassVar[str] = "allowed_matchingruleuse_oids"
        FILTERS_DN_SCHEMA: ClassVar[str] = "cn=schema"
        FILTERS_DN_USER: ClassVar[str] = "cn=user,dc=example,dc=com"
        FILTERS_DN_BARE: ClassVar[str] = "cn=bare"
        FILTERS_FORBIDDEN_ATTRS_ORDERED: ClassVar[t.StrSequence] = (
            NAME_MAIL,
            NAME_DESCRIPTION,
        )
        FILTERS_FORBIDDEN_ATTRS: ClassVar[frozenset[str]] = frozenset(
            FILTERS_FORBIDDEN_ATTRS_ORDERED
        )
        FILTERS_FORBIDDEN_OCS_ORDERED: ClassVar[t.StrSequence] = (NAME_INET_ORG_PERSON,)
        FILTERS_USER_MAIL: ClassVar[str] = "user@example.com"
        FILTERS_USER_DESCRIPTION: ClassVar[str] = "a test user"
        FILTERS_UNWANTED_ATTR_OID: ClassVar[str] = (
            "( 9.9.9.9 NAME 'unwanted' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        PARSER_PATH_FLOW_FILENAME: ClassVar[str] = "path_flow.ldif"
        PARSER_INVALID_UTF8_FILENAME: ClassVar[str] = "invalid_utf8.ldif"
        PARSER_RELATIVE_PREFIX: ClassVar[str] = "tmp_parser_relative"
        PARSER_MISSING_PREFIX: ClassVar[str] = "missing"
        PARSER_UNKNOWN_PREFIX: ClassVar[str] = "unknown"
        FILTERS_ALLOWED_OIDS_FULL: ClassVar[t.MappingKV[str, frozenset[str]]] = (
            MappingProxyType({
                FILTERS_ALLOWED_ATTR_KEY: frozenset({
                    FILTERS_ATTR_OID_ALLOWED,
                    "2.5.4.4",
                }),
                FILTERS_ALLOWED_OC_KEY: frozenset({FILTERS_OC_OID_ALLOWED}),
                FILTERS_ALLOWED_MR_KEY: frozenset(),
                FILTERS_ALLOWED_MRU_KEY: frozenset(),
            })
        )
        FILTERS_ALLOWED_OIDS_EMPTY: ClassVar[t.MappingKV[str, frozenset[str]]] = (
            MappingProxyType({
                FILTERS_ALLOWED_ATTR_KEY: frozenset(),
                FILTERS_ALLOWED_OC_KEY: frozenset(),
                FILTERS_ALLOWED_MR_KEY: frozenset(),
                FILTERS_ALLOWED_MRU_KEY: frozenset(),
            })
        )

        RELAXED_PARSE_VALID: ClassVar[str] = "valid"
        RELAXED_PARSE_MALFORMED: ClassVar[str] = "malformed"
        API_SCENARIO_SIMPLE_LDIF: ClassVar[str] = "simple_ldif"
        API_SCENARIO_MULTIPLE_INSTANCES: ClassVar[str] = "multiple_instances"
        EDGE_CASE_UNICODE_LDIF: ClassVar[str] = (
            "dn: cn=José,ou=Users,dc=example,dc=com\n"
            "cn: José\n"
            "sn: García\n"
            "objectClass: person\n\n"
        )
        EDGE_CASE_DEEP_DN_LDIF: ClassVar[str] = (
            "dn: cn=level1,ou=level2,ou=level3,ou=level4,ou=level5,ou=level6,dc=example,dc=com\n"
            "cn: level1\n"
            "objectClass: person\n\n"
        )
        EDGE_CASE_LARGE_MULTIVALUE_LDIF: ClassVar[str] = (
            "dn: cn=test,dc=example,dc=com\n"
            "cn: test\n"
            "member: cn=user1,dc=example,dc=com\n"
            "member: cn=user2,dc=example,dc=com\n"
            "member: cn=user3,dc=example,dc=com\n"
            "member: cn=user4,dc=example,dc=com\n"
            "member: cn=user5,dc=example,dc=com\n"
            "objectClass: groupOfNames\n\n"
        )
        EDGE_CASE_NON_ASCII_REGEX: ClassVar[t.Ldif.RegexPattern] = re.compile(
            r"[^\x00-\x7F]"
        )
        EXACT_OID_1_2_3_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(r"^1\.2\.3$")
        EDGE_CASE_LARGE_MULTIVALUE_FIXTURE_RELATIVE: ClassVar[Path] = (
            Path("edge_cases") / "size" / "large_multivalue.ldif"
        )
        EDGE_CASE_MIN_MULTIVALUE_COUNT: ClassVar[int] = 10
        EDGE_CASE_INLINE_PARSE_RULES: ClassVar[
            t.MappingKV[str, tuple[str, int, int, bool]]
        ] = MappingProxyType({
            "unicode": (EDGE_CASE_UNICODE_LDIF, 1, 0, True),
            "deep_dn": (EDGE_CASE_DEEP_DN_LDIF, 1, 7, False),
        })
        EDGE_CASE_ROUNDTRIP_CASES: ClassVar[t.MappingKV[str, tuple[str, str]]] = (
            MappingProxyType({
                "unicode": (EDGE_CASE_UNICODE_LDIF, "unicode_roundtrip.ldif"),
                "deep_dn": (EDGE_CASE_DEEP_DN_LDIF, "deep_dn_roundtrip.ldif"),
                "large_multivalue": (
                    EDGE_CASE_LARGE_MULTIVALUE_LDIF,
                    "large_multivalue_roundtrip.ldif",
                ),
            })
        )

        ACL_REGISTRY_GET_ACL_ATTRIBUTES_DATA: ClassVar[
            t.MappingKV[str, tuple[str, str | None, t.StrSequence, t.StrSequence]]
        ] = MappingProxyType({
            "get_acl_attributes_rfc_foundation": (
                RFC,
                None,
                ("aci", "acl", "olcAccess", "aclRights", "aclEntry"),
                (),
            ),
            "get_acl_attributes_oid_servers": (
                OID,
                OID,
                ("orclaci", "orclentrylevelaci", "aci", "acl"),
                (),
            ),
            "get_acl_attributes_oud_servers": (
                OUD,
                OUD,
                ("orclaci", "orclentrylevelaci", "aci"),
                (),
            ),
            "get_acl_attributes_ad_servers": (
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
            "get_acl_attributes_none": ("none", None, ("aci", "acl"), ("orclaci",)),
        })
        ACL_REGISTRY_IS_ACL_ATTRIBUTE_DATA: ClassVar[
            t.MappingKV[str, tuple[str, str, str | None, bool]]
        ] = MappingProxyType({
            "is_acl_attribute_rfc_aci": ("valid_rfc", "aci", None, True),
            "is_acl_attribute_rfc_acl": ("valid_rfc", "acl", None, True),
            "is_acl_attribute_rfc_olcAccess": ("valid_rfc", "olcAccess", None, True),
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
            "is_acl_attribute_invalid_uid": ("invalid", "uid", None, False),
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
        })

        RELAXED_ATTRIBUTE_DEFINITIONS: ClassVar[t.MappingKV[str, tuple[str, bool]]] = (
            MappingProxyType({
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
                "long_definition": ("( 1.2.3.4 " + "NAME 'test' " * 100 + ")", True),
            })
        )
        RELAXED_OBJECTCLASS_DEFINITIONS: ClassVar[
            t.MappingKV[str, tuple[str, bool]]
        ] = MappingProxyType({
            RELAXED_PARSE_VALID: ("( 1.2.3 NAME 'testOc' STRUCTURAL )", True),
            RELAXED_PARSE_MALFORMED: ("( 2.5.6.0 NAME 'broken'", True),
            "missing_name": ("( 1.2.3.4 STRUCTURAL )", True),
            "no_oid": ("BROKEN CLASS", False),
            "empty": ("", False),
            "whitespace": ("   ", False),
            "unicode": ("( 1.2.3.4 NAME 'тест' 😀 )", True),
        })
        RELAXED_ACL_DEFINITIONS: ClassVar[t.MappingKV[str, tuple[str, bool]]] = (
            MappingProxyType({
                RELAXED_PARSE_VALID: (
                    '(targetentry="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")(version 3.0;acl "REDACTED_LDAP_BIND_PASSWORD";allow(all)',
                    True,
                ),
                RELAXED_PARSE_MALFORMED: ("(targetentry incomplete", True),
                "broken": ("(targetentry invalid) broken", True),
            })
        )

        APACHE_ATTRIBUTE_TEST_CASES: ClassVar[
            t.SequenceOf[m.Tests.AttributeTestCase]
        ] = (
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
        )

        APACHE_OBJECTCLASS_TEST_CASES: ClassVar[
            t.SequenceOf[m.Tests.ObjectClassTestCase]
        ] = (
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
        )

        APACHE_ENTRY_TEST_CASES: ClassVar[t.SequenceOf[m.Tests.EntryTestCase]] = (
            *(
                m.Tests.EntryTestCase(
                    scenario=(
                        "ou_config" if ou_name == "settings" else f"ou_{ou_name}"
                    ),
                    entry_dn=f"ou={ou_name},dc=example,dc=com",
                    attributes={"objectClass": ["organizationalUnit"]},
                    expected_can_handle=True,
                )
                for ou_name in ("settings", "services", "system", "partitions")
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
                attributes={"apachedsSystemId": ["test"], "objectClass": ["top"]},
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
        )

        DS389_ATTRIBUTE_TEST_CASES: ClassVar[
            t.SequenceOf[m.Tests.AttributeTestCase]
        ] = (
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
        )

        DS389_OBJECTCLASS_TEST_CASES: ClassVar[
            t.SequenceOf[m.Tests.ObjectClassTestCase]
        ] = (
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
        )

        _DS389_CN_KIND_CASES: Final[t.SequenceOf[tuple[str, t.StrSequence]]] = (
            ("settings", ("nscontainer",)),
            ("monitor", ("top",)),
            ("changelog", ("top",)),
        )
        _DS389_ATTR_PROBE_CASES: Final[t.SequenceOf[tuple[str, str, str]]] = (
            ("nsslapd_attribute", "nsslapd-port", "389"),
            ("nsds_attribute", "nsds5ReplicaId", "1"),
            ("nsuniqueid_attribute", "nsuniqueid", "12345"),
        )
        DS389_ENTRY_TEST_CASES: ClassVar[t.SequenceOf[m.Tests.EntryTestCase]] = (
            *(
                m.Tests.EntryTestCase(
                    scenario=f"cn_{cn}",
                    entry_dn=f"cn={cn}",
                    attributes={
                        FlextLdifConstants.Ldif.DictKeys.OBJECTCLASS.value: list(
                            object_classes
                        )
                    },
                    expected_can_handle=True,
                )
                for cn, object_classes in _DS389_CN_KIND_CASES
            ),
            *(
                m.Tests.EntryTestCase(
                    scenario=scenario,
                    entry_dn="cn=test,dc=example,dc=com",
                    attributes={attr: [value], "objectclass": ["top"]},
                    expected_can_handle=True,
                )
                for scenario, attr, value in _DS389_ATTR_PROBE_CASES
            ),
            m.Tests.EntryTestCase(
                scenario="ns_objectclass",
                entry_dn=DN_TEST,
                attributes={
                    FlextLdifConstants.Ldif.DictKeys.OBJECTCLASS.value: [
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
                    FlextLdifConstants.Ldif.DictKeys.OBJECTCLASS.value: ["person"],
                    "cn": ["user"],
                },
                expected_can_handle=False,
            ),
        )

        # NB: cn_config / cn_settings naming preserved → first case key
        # historically was "cn_config" (not "cn_settings"); align to that.

        NOVELL_ATTRIBUTE_TEST_CASES: ClassVar[
            t.SequenceOf[m.Tests.AttributeTestCase]
        ] = (
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
        )

        NOVELL_OBJECTCLASS_TEST_CASES: ClassVar[
            t.SequenceOf[m.Tests.ObjectClassTestCase]
        ] = (
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
        )

        NOVELL_ENTRY_TEST_CASES: ClassVar[t.SequenceOf[m.Tests.EntryTestCase]] = (
            *(
                m.Tests.EntryTestCase(
                    scenario=f"ou_{ou_name}",
                    entry_dn=f"ou={ou_name},o=Example",
                    attributes={"objectClass": ["organizationalUnit"]},
                    expected_can_handle=True,
                )
                for ou_name in ("services", "apps", "system")
            ),
            m.Tests.EntryTestCase(
                scenario="nspm_attribute",
                entry_dn="cn=user,o=Example",
                attributes={"nspmpasswordpolicy": ["policy1"], "objectClass": ["top"]},
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
        )

        # ── ACL service constants ────────────────────────────────────────
        ACL_OUD_STRING: ClassVar[str] = (
            '(targetattr="*")(version 3.0; acl "Test ACL"; allow (read,search) userdn="ldap:///anyone";)'
        )
        ACL_OID_STRING: ClassVar[str] = "access to entry by * (browse)"
        ACL_RFC_STRING: ClassVar[str] = ACL_READ_VALUE
        ACL_SERVER_CASES: ClassVar[t.MappingKV[str, tuple[str, str]]] = (
            MappingProxyType({
                "oud": (ACL_OUD_STRING, OUD),
                "oid": (ACL_OID_STRING, OID),
                "rfc": (ACL_RFC_STRING, RFC),
            })
        )
        _ACL_PERMISSION_KEYS: Final[t.StrSequence] = (
            "read",
            "write",
            "delete",
            "add",
            "search",
            "compare",
        )
        ACL_PERMISSIONS_EMPTY: ClassVar[t.MappingKV[str, bool]] = MappingProxyType(
            dict.fromkeys(_ACL_PERMISSION_KEYS, False)
        )
        ACL_PERMISSIONS_READ_ONLY: ClassVar[t.MappingKV[str, bool]] = MappingProxyType({
            **ACL_PERMISSIONS_EMPTY,
            "read": True,
        })
        ACL_ENTRY_DN: ClassVar[str] = "cn=acltest,dc=example,dc=com"
        ACL_ENTRY_ORCLACI_VALUE: ClassVar[str] = "access to entry by * (browse)"
        ACL_ENTRY_ACI_VALUE: ClassVar[str] = (
            '(targetattr="*")(version 3.0; acl "Entry ACL"; allow (read,search) userdn="ldap:///anyone";)'
        )
        ACL_INVALID_SERVER_TYPE: ClassVar[str] = "NOT_A_VALID_SERVER_XYZ"
        ACL_PARSE_FAILURE_CASES: ClassVar[t.MappingKV[str, tuple[str, str]]] = (
            MappingProxyType({
                "invalid_server": (ACL_OUD_STRING, ACL_INVALID_SERVER_TYPE),
                "generic_server_without_acl_server": (ACL_OUD_STRING, GENERIC),
                "openldap_invalid_acl_format": (ACL_INVALID_SERVER_TYPE, OPENLDAP),
            })
        )
        ACL_SERVICE_CHECK_EMPTY_ACLS: ClassVar[int] = 0

        # ── Analysis service constants ───────────────────────────────────
        ANALYSIS_DN_VALID: ClassVar[str] = "cn=analysis-user,dc=example,dc=com"
        ANALYSIS_ATTR_CN_VALUE: ClassVar[str] = "analysis-user"
        ANALYSIS_ATTR_INVALID_NAME: ClassVar[str] = "invalid_attr"
        ANALYSIS_OC_PERSON: ClassVar[str] = "person"
        ANALYSIS_OC_INVALID: ClassVar[str] = "invalid_oc"
        ANALYSIS_VALID_ENTRY_ATTRS: ClassVar[t.MappingKV[str, list[str]]] = (
            MappingProxyType({
                "objectClass": [ANALYSIS_OC_PERSON, "top"],
                "cn": [ANALYSIS_ATTR_CN_VALUE],
                "sn": ["user"],
            })
        )
        ANALYSIS_INVALID_ATTR_ENTRY_ATTRS: ClassVar[t.MappingKV[str, list[str]]] = (
            MappingProxyType({
                "objectClass": [ANALYSIS_OC_PERSON],
                ANALYSIS_ATTR_INVALID_NAME: ["value"],
            })
        )
        ANALYSIS_PARSE_RESPONSE_LDIF: ClassVar[str] = (
            "dn: cn=user1,dc=example,dc=com\n"
            "objectClass: person\n"
            "cn: user1\n\n"
            "dn: cn=user2,dc=example,dc=com\n"
            "objectClass: person\n"
            "cn: user2\n"
        )

        # ── Migration pipeline constants ─────────────────────────────────
        MIGRATION_INPUT_FILENAME: ClassVar[str] = "mig_input.ldif"
        MIGRATION_SINGLE_ENTRY_LDIF: ClassVar[str] = (
            "dn: cn=migrate-me,dc=example,dc=com\n"
            "objectClass: person\n"
            "cn: migrate-me\n"
            "sn: user\n"
        )
        MIGRATION_UNKNOWN_SERVER: ClassVar[str] = "TOTALLY_UNKNOWN_SERVER_XYZ"
        MIGRATION_COERCE_CASES: ClassVar[t.MappingKV[str, tuple[str, str]]] = (
            MappingProxyType({
                "rfc_lower": ("rfc", RFC),
                "oid_upper": ("OID", OID),
                "unknown_falls_back": (MIGRATION_UNKNOWN_SERVER, RFC),
            })
        )

        # ── Writer advanced constants ────────────────────────────────────

        # ── Server service constants ─────────────────────────────────────
        SERVER_INVALID_SERVER_TYPE: ClassVar[str] = "invalid_server_xyz"

        # ── Validation service constants ─────────────────────────────────
        VALIDATION_VALID_OC_NAMES: ClassVar[t.StrSequence] = (
            "person",
            "top",
            "organizationalUnit",
            "inetOrgPerson",
        )
        VALIDATION_INVALID_DESCRIPTOR: ClassVar[str] = "invalid name"

        # ── Pipeline constants ───────────────────────────────────────────

        # ── Processing service constants ───────────────────────────────
        PROCESSING_VALID_DNS: ClassVar[t.StrSequence] = (
            "cn=processing-one,dc=example,dc=com",
            "cn=processing-two,dc=example,dc=com",
        )
        PROCESSING_ATTRS: ClassVar[t.MappingKV[str, list[str]]] = MappingProxyType({
            "objectClass": ["person", "top"],
            "cn": ["processing-user"],
            "sn": ["processing"],
        })
        PROCESSING_OPTIONS_CASES: ClassVar[
            t.MappingKV[str, tuple[Literal["transform", "validate"], bool, int, int]]
        ] = MappingProxyType({
            "batch_transform": ("transform", False, 1, 2),
            "parallel_validate": ("validate", True, 1, 2),
        })

        # ── Statistics service constants ───────────────────────────────
        STATS_SERVER_TYPES: ClassVar[t.StrSequence] = (RFC, OID)
        STATS_EXPECTED_OBJECTCLASS: ClassVar[str] = "person"


c = TestsFlextLdifConstants

__all__: list[str] = ["TestsFlextLdifConstants", "c"]
