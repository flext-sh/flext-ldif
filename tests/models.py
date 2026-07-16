"""Test model definitions composing src models for centralized test objects."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, ClassVar

from flext_tests import FlextTestsModels

from flext_ldif import m, u
from tests.constants import c
from tests.typings import t


class TestsFlextLdifModels(FlextTestsModels, m):
    """Test models composed from the project and shared test namespaces."""

    class Tests(FlextTestsModels.Tests):
        """Test fixture models namespace."""

        class _Frozen(m.BaseModel):
            """Base for every frozen test model in this namespace."""

            model_config: ClassVar[t.ConfigDict] = m.ConfigDict(frozen=True)

        class _CanHandleCase(_Frozen):
            """Shared fields for can_handle-style detection cases."""

            scenario: Annotated[str, u.Field(description="Scenario identifier")]
            expected_can_handle: Annotated[
                bool,
                u.Field(description="Expected can_handle result"),
            ]

        class _SchemaCase(_CanHandleCase):
            """Shared OID/NAME parsed-value expectations."""

            expected_oid: Annotated[
                str | None,
                u.Field(description="Expected parsed OID"),
            ] = None
            expected_name: Annotated[
                str | None,
                u.Field(description="Expected parsed name"),
            ] = None

        class LdifTestData(m.Value):
            """Test data for LDIF utilities."""

            id: Annotated[
                str,
                u.Field(description="Unique identifier for the test data entry"),
            ]
            server_type: Annotated[
                str,
                u.Field(description="Type of server associated with the entry"),
            ]
            dn: Annotated[
                str,
                u.Field(description="Distinguished name of the LDAP entry"),
            ]
            attributes: Annotated[
                t.StrSequenceMapping,
                u.Field(description="LDAP attributes mapped to their values"),
            ]

        class FixtureMetadata(_Frozen):
            """Metadata about a discovered fixture file."""

            server_type: Annotated[
                t.Tests.FixtureServer,
                u.Field(description="Fixture server identifier"),
            ]
            fixture_type: Annotated[
                t.Tests.FixtureKind,
                u.Field(description="Fixture category identifier"),
            ]
            file_path: Annotated[Path, u.Field(description="Fixture file path")]
            line_count: Annotated[
                int,
                u.Field(description="Number of lines in the fixture file"),
            ]
            entry_count: Annotated[
                int,
                u.Field(description="Number of LDIF entries in the fixture"),
            ]
            size_bytes: Annotated[
                int,
                u.Field(description="Fixture file size in bytes"),
            ]

        class AttributeTestCase(_SchemaCase):
            """Unified test case for attribute detection."""

            attr_definition: Annotated[str, u.Field(description="Attribute definition")]

        class ObjectClassTestCase(_SchemaCase):
            """Unified test case for objectClass detection."""

            oc_definition: Annotated[str, u.Field(description="ObjectClass definition")]
            expected_kind: Annotated[
                str | None,
                u.Field(description="Expected parsed objectClass kind"),
            ] = None

        class EntryTestCase(_CanHandleCase):
            """Unified test case for entry detection."""

            entry_dn: Annotated[str, u.Field(description="Entry DN")]
            attributes: Annotated[
                t.MutableStrSequenceMapping,
                u.Field(description="Entry attributes"),
            ]

        class ProtocolServer(_Frozen):
            """Server implementation for protocol testing."""

            name: Annotated[str, u.Field(description="Implementation name")]
            server_class: Annotated[type, u.Field(description="Server class")]
            schema_class: Annotated[type, u.Field(description="Schema class")]
            fixture_servers: Annotated[
                t.SequenceOf[t.Tests.FixtureServer],
                u.Field(description="Servers covered by the implementation"),
            ] = ()

        class AclTestCase(_Frozen):
            """Unified test case for ACL handling."""

            scenario: Annotated[str, u.Field(description="ACL scenario")]
            acl_line: Annotated[str | None, u.Field(description="ACL line")] = None
            expected_can_handle: Annotated[
                bool,
                u.Field(description="Expected can_handle result"),
            ] = False
            expected_success: Annotated[
                bool,
                u.Field(description="Expected parse success"),
            ] = False

        # mro-0ftd.3.6: modeled cases live with their canonical model owner.
        APACHE_ATTRIBUTE_TEST_CASES: ClassVar[t.SequenceOf[AttributeTestCase]] = (
            AttributeTestCase(
                scenario="apache_oid",
                attr_definition="( 1.3.6.1.4.1.18060.0.4.1.2.100 NAME 'ads-enabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
                expected_can_handle=True,
                expected_name="ads-enabled",
            ),
            AttributeTestCase(
                scenario="ads_prefix",
                attr_definition="( 2.16.840.1.113730.3.1.1 NAME 'ads-searchBaseDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
                expected_can_handle=True,
                expected_name="ads-searchBaseDN",
            ),
            AttributeTestCase(
                scenario="apacheds_name",
                attr_definition="( 1.2.3.4 NAME 'apachedsSystemId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                expected_can_handle=True,
                expected_name="apachedsSystemId",
            ),
            AttributeTestCase(
                scenario="standard_rfc",
                attr_definition="( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                expected_can_handle=False,
                expected_name="cn",
            ),
        )
        APACHE_OBJECTCLASS_TEST_CASES: ClassVar[t.SequenceOf[ObjectClassTestCase]] = (
            ObjectClassTestCase(
                scenario="apache_oid",
                oc_definition="( 1.3.6.1.4.1.18060.0.4.1.3.100 NAME 'ads-directoryService' SUP top STRUCTURAL )",
                expected_can_handle=True,
                expected_name="ads-directoryService",
            ),
            ObjectClassTestCase(
                scenario="ads_name",
                oc_definition="( 2.5.6.0 NAME 'ads-base' SUP top ABSTRACT )",
                expected_can_handle=True,
                expected_name="ads-base",
            ),
            ObjectClassTestCase(
                scenario="standard_rfc",
                oc_definition="( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )",
                expected_can_handle=False,
                expected_name="posixAccount",
            ),
        )
        APACHE_ENTRY_TEST_CASES: ClassVar[t.SequenceOf[EntryTestCase]] = (
            EntryTestCase(
                scenario="ou_config",
                entry_dn="ou=settings,dc=example,dc=com",
                attributes={"objectClass": ["organizationalUnit"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="ou_services",
                entry_dn="ou=services,dc=example,dc=com",
                attributes={"objectClass": ["organizationalUnit"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="ou_system",
                entry_dn="ou=system,dc=example,dc=com",
                attributes={"objectClass": ["organizationalUnit"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="ou_partitions",
                entry_dn="ou=partitions,dc=example,dc=com",
                attributes={"objectClass": ["organizationalUnit"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="ads_attribute",
                entry_dn=c.Tests.DN_TEST,
                attributes={"ads-enabled": ["TRUE"], "objectClass": ["top"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="apacheds_attribute",
                entry_dn=c.Tests.DN_TEST,
                attributes={"apachedsSystemId": ["test"], "objectClass": ["top"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="ads_objectclass",
                entry_dn=c.Tests.DN_TEST,
                attributes={"objectClass": ["top", "ads-directory"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="standard_rfc",
                entry_dn="cn=user,dc=example,dc=com",
                attributes={"objectClass": ["person"], "cn": ["user"]},
                expected_can_handle=True,
            ),
        )
        DS389_ATTRIBUTE_TEST_CASES: ClassVar[t.SequenceOf[AttributeTestCase]] = (
            AttributeTestCase(
                scenario="ds389_oid",
                attr_definition="( 2.16.840.1.113730.3.1.1 NAME 'nsslapd-suffix' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
                expected_can_handle=True,
                expected_oid="2.16.840.1.113730.3.1.1",
                expected_name="nsslapd-suffix",
            ),
            AttributeTestCase(
                scenario="nsslapd_prefix",
                attr_definition="( 1.2.3.4 NAME 'nsslapd-port' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
                expected_can_handle=True,
                expected_name="nsslapd-port",
            ),
            AttributeTestCase(
                scenario="nsds_prefix",
                attr_definition="( 1.2.3.4 NAME 'nsds5ReplicaId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
                expected_can_handle=True,
                expected_name="nsds5ReplicaId",
            ),
            AttributeTestCase(
                scenario="nsuniqueid_prefix",
                attr_definition="( 1.2.3.4 NAME 'nsuniqueid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                expected_can_handle=True,
                expected_name="nsuniqueid",
            ),
            AttributeTestCase(
                scenario="standard_rfc",
                attr_definition="( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                expected_can_handle=False,
            ),
        )
        DS389_OBJECTCLASS_TEST_CASES: ClassVar[t.SequenceOf[ObjectClassTestCase]] = (
            ObjectClassTestCase(
                scenario="ds389_oid",
                oc_definition="( 2.16.840.1.113730.3.2.1 NAME 'nscontainer' SUP top STRUCTURAL )",
                expected_can_handle=True,
                expected_oid="2.16.840.1.113730.3.2.1",
                expected_name="nscontainer",
                expected_kind="STRUCTURAL",
            ),
            ObjectClassTestCase(
                scenario="ns_name",
                oc_definition="( 2.5.6.0 NAME 'nsperson' SUP top STRUCTURAL )",
                expected_can_handle=True,
                expected_name="nsperson",
            ),
            ObjectClassTestCase(
                scenario="standard_rfc",
                oc_definition="( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )",
                expected_can_handle=False,
            ),
        )
        DS389_ENTRY_TEST_CASES: ClassVar[t.SequenceOf[EntryTestCase]] = (
            EntryTestCase(
                scenario="cn_settings",
                entry_dn="cn=settings",
                attributes={c.Ldif.DictKeys.OBJECTCLASS.value: ["nscontainer"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="cn_monitor",
                entry_dn="cn=monitor",
                attributes={c.Ldif.DictKeys.OBJECTCLASS.value: ["top"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="cn_changelog",
                entry_dn="cn=changelog",
                attributes={c.Ldif.DictKeys.OBJECTCLASS.value: ["top"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="nsslapd_attribute",
                entry_dn="cn=test,dc=example,dc=com",
                attributes={"nsslapd-port": ["389"], "objectclass": ["top"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="nsds_attribute",
                entry_dn="cn=test,dc=example,dc=com",
                attributes={"nsds5ReplicaId": ["1"], "objectclass": ["top"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="nsuniqueid_attribute",
                entry_dn="cn=test,dc=example,dc=com",
                attributes={"nsuniqueid": ["12345"], "objectclass": ["top"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="ns_objectclass",
                entry_dn=c.Tests.DN_TEST,
                attributes={
                    c.Ldif.DictKeys.OBJECTCLASS.value: ["top", "nscontainer"],
                },
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="standard_rfc",
                entry_dn="cn=user,dc=example,dc=com",
                attributes={
                    c.Ldif.DictKeys.OBJECTCLASS.value: ["person"],
                    "cn": ["user"],
                },
                expected_can_handle=False,
            ),
        )
        NOVELL_ATTRIBUTE_TEST_CASES: ClassVar[t.SequenceOf[AttributeTestCase]] = (
            AttributeTestCase(
                scenario="novell_oid",
                attr_definition="( 2.16.840.1.113719.1.1.4.1.501 NAME 'nspmPasswordPolicyDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
                expected_can_handle=True,
                expected_oid="2.16.840.1.113719.1.1.4.1.501",
                expected_name="nspmPasswordPolicyDN",
            ),
            AttributeTestCase(
                scenario="nspm_prefix",
                attr_definition="( 1.2.3.4 NAME 'nspmPasswordPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                expected_can_handle=True,
                expected_name="nspmPasswordPolicy",
            ),
            AttributeTestCase(
                scenario="login_prefix",
                attr_definition="( 1.2.3.4 NAME 'loginDisabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
                expected_can_handle=True,
                expected_name="loginDisabled",
            ),
            AttributeTestCase(
                scenario="dirxml_prefix",
                attr_definition="( 1.2.3.4 NAME 'dirxml-associations' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                expected_can_handle=True,
                expected_name="dirxml-associations",
            ),
            AttributeTestCase(
                scenario="standard_rfc",
                attr_definition="( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                expected_can_handle=False,
            ),
        )
        NOVELL_OBJECTCLASS_TEST_CASES: ClassVar[t.SequenceOf[ObjectClassTestCase]] = (
            ObjectClassTestCase(
                scenario="novell_oid",
                oc_definition="( 2.16.840.1.113719.2.2.6.1 NAME 'ndsPerson' SUP top STRUCTURAL )",
                expected_can_handle=True,
                expected_oid="2.16.840.1.113719.2.2.6.1",
                expected_name="ndsPerson",
            ),
            ObjectClassTestCase(
                scenario="nds_name",
                oc_definition="( 2.5.6.0 NAME 'ndsserver' SUP top STRUCTURAL )",
                expected_can_handle=True,
                expected_name="ndsserver",
            ),
            ObjectClassTestCase(
                scenario="standard_rfc",
                oc_definition="( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )",
                expected_can_handle=False,
            ),
        )
        NOVELL_ENTRY_TEST_CASES: ClassVar[t.SequenceOf[EntryTestCase]] = (
            EntryTestCase(
                scenario="ou_services",
                entry_dn="ou=services,o=Example",
                attributes={"objectClass": ["organizationalUnit"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="ou_apps",
                entry_dn="ou=apps,o=Example",
                attributes={"objectClass": ["organizationalUnit"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="ou_system",
                entry_dn="ou=system,o=Example",
                attributes={"objectClass": ["organizationalUnit"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="nspm_attribute",
                entry_dn="cn=user,o=Example",
                attributes={
                    "nspmpasswordpolicy": ["policy1"],
                    "objectClass": ["top"],
                },
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="login_attribute",
                entry_dn="cn=user,o=Example",
                attributes={"logindisabled": ["TRUE"], "objectClass": ["top"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="nds_objectclass",
                entry_dn="cn=user,o=Example",
                attributes={"objectClass": ["top", "ndsperson"]},
                expected_can_handle=True,
            ),
            EntryTestCase(
                scenario="standard_rfc",
                entry_dn="cn=user,dc=example,dc=com",
                attributes={"objectClass": ["person"], "cn": ["user"]},
                expected_can_handle=False,
            ),
        )


m = TestsFlextLdifModels

__all__: list[str] = ["TestsFlextLdifModels", "m"]
