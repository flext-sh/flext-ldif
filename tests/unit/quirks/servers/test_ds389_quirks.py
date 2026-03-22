"""Tests for 389 Directory Server (DS389) LDIF quirks handling.

This module tests the FlextLdifServersDs389 implementation for handling 389
Directory Server-specific attributes, t.NormalizedValue classes, and entries in LDIF format.
"""

from __future__ import annotations

from enum import StrEnum, unique
from typing import ClassVar

import pytest
from flext_tests import tm
from pydantic import BaseModel, ConfigDict, Field
from tests import c, m, s

from flext_ldif import FlextLdifServersDs389

RfcTestHelpers = c.RfcTestHelpers


@unique
class AttributeScenario(StrEnum):
    """DS389 attribute detection scenarios."""

    DS389_OID = "ds389_oid"
    NSSLAPD_PREFIX = "nsslapd_prefix"
    NSDS_PREFIX = "nsds_prefix"
    NSUNIQUEID_PREFIX = "nsuniqueid_prefix"
    STANDARD_RFC = "standard_rfc"


@unique
class ObjectClassScenario(StrEnum):
    """DS389 objectClass detection scenarios."""

    DS389_OID = "ds389_oid"
    NS_NAME = "ns_name"
    STANDARD_RFC = "standard_rfc"


@unique
class AclScenario(StrEnum):
    """DS389 ACL handling scenarios."""

    ACI_ATTRIBUTE = "aci_attribute"
    VERSION_PREFIX = "version_prefix"
    OPENLDAP_FORMAT = "openldap_format"
    EMPTY_LINE = "empty_line"


@unique
class EntryScenario(StrEnum):
    """DS389 entry detection scenarios."""

    CN_CONFIG = "cn_config"
    CN_MONITOR = "cn_monitor"
    CN_CHANGELOG = "cn_changelog"
    NSSLAPD_ATTRIBUTE = "nsslapd_attribute"
    NSDS_ATTRIBUTE = "nsds_attribute"
    NSUNIQUEID_ATTRIBUTE = "nsuniqueid_attribute"
    NS_OBJECTCLASS = "ns_objectclass"
    STANDARD_RFC = "standard_rfc"


class AttributeTestCase(BaseModel):
    """Test case for attribute detection and parsing."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    scenario: AttributeScenario = Field(description="Attribute scenario identifier")
    attr_definition: str = Field(description="Schema attribute definition string")
    expected_can_handle: bool = Field(description="Expected can_handle result")
    expected_oid: str | None = Field(default=None, description="Expected parsed OID")
    expected_name: str | None = Field(
        default=None,
        description="Expected parsed attribute name",
    )


class ObjectClassTestCase(BaseModel):
    """Test case for objectClass detection and parsing."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    scenario: ObjectClassScenario = Field(description="ObjectClass scenario identifier")
    oc_definition: str = Field(description="Schema objectClass definition string")
    expected_can_handle: bool = Field(description="Expected can_handle result")
    expected_oid: str | None = Field(default=None, description="Expected parsed OID")
    expected_name: str | None = Field(
        default=None,
        description="Expected parsed objectClass name",
    )
    expected_kind: str | None = Field(
        default=None,
        description="Expected parsed objectClass kind",
    )


class AclTestCase(BaseModel):
    """Test case for ACL handling."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    scenario: AclScenario = Field(description="ACL scenario identifier")
    acl_line: str = Field(description="ACL line under test")
    expected_can_handle: bool = Field(description="Expected can_handle result")
    expected_success: bool = Field(
        default=False,
        description="Expected parse success state",
    )


class EntryTestCase(BaseModel):
    """Test case for entry detection."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    scenario: EntryScenario = Field(description="Entry detection scenario identifier")
    entry_dn: str = Field(description="Entry distinguished name")
    attributes: dict[str, list[str]] = Field(
        description="Entry attributes mapped by name"
    )
    expected_can_handle: bool = Field(description="Expected can_handle result")


ATTRIBUTE_TEST_CASES = (
    AttributeTestCase(
        scenario=AttributeScenario.DS389_OID,
        attr_definition="( 2.16.840.1.113730.3.1.1 NAME 'nsslapd-suffix' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
        expected_can_handle=True,
        expected_oid="2.16.840.1.113730.3.1.1",
        expected_name="nsslapd-suffix",
    ),
    AttributeTestCase(
        scenario=AttributeScenario.NSSLAPD_PREFIX,
        attr_definition="( 1.2.3.4 NAME 'nsslapd-port' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
        expected_can_handle=True,
        expected_name="nsslapd-port",
    ),
    AttributeTestCase(
        scenario=AttributeScenario.NSDS_PREFIX,
        attr_definition="( 1.2.3.4 NAME 'nsds5ReplicaId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
        expected_can_handle=True,
        expected_name="nsds5ReplicaId",
    ),
    AttributeTestCase(
        scenario=AttributeScenario.NSUNIQUEID_PREFIX,
        attr_definition="( 1.2.3.4 NAME 'nsuniqueid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        expected_can_handle=True,
        expected_name="nsuniqueid",
    ),
    AttributeTestCase(
        scenario=AttributeScenario.STANDARD_RFC,
        attr_definition="( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        expected_can_handle=False,
    ),
)
OBJECTCLASS_TEST_CASES = (
    ObjectClassTestCase(
        scenario=ObjectClassScenario.DS389_OID,
        oc_definition="( 2.16.840.1.113730.3.2.1 NAME 'nscontainer' SUP top STRUCTURAL )",
        expected_can_handle=True,
        expected_oid="2.16.840.1.113730.3.2.1",
        expected_name="nscontainer",
        expected_kind="STRUCTURAL",
    ),
    ObjectClassTestCase(
        scenario=ObjectClassScenario.NS_NAME,
        oc_definition="( 2.5.6.0 NAME 'nsperson' SUP top STRUCTURAL )",
        expected_can_handle=True,
        expected_name="nsperson",
    ),
    ObjectClassTestCase(
        scenario=ObjectClassScenario.STANDARD_RFC,
        oc_definition="( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )",
        expected_can_handle=False,
    ),
)
ACL_TEST_CASES = (
    AclTestCase(
        scenario=AclScenario.ACI_ATTRIBUTE,
        acl_line='aci: (version 3.0; acl "Admin Access"; allow (all) userdn = "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)',
        expected_can_handle=True,
        expected_success=True,
    ),
    AclTestCase(
        scenario=AclScenario.VERSION_PREFIX,
        acl_line='(version 3.0; acl "Admin Access"; allow (all) userdn = "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)',
        expected_can_handle=True,
        expected_success=True,
    ),
    AclTestCase(
        scenario=AclScenario.OPENLDAP_FORMAT,
        acl_line="access to * by * read",
        expected_can_handle=False,
        expected_success=False,
    ),
    AclTestCase(
        scenario=AclScenario.EMPTY_LINE,
        acl_line="",
        expected_can_handle=False,
        expected_success=False,
    ),
)
ENTRY_TEST_CASES = (
    EntryTestCase(
        scenario=EntryScenario.CN_CONFIG,
        entry_dn="cn=config",
        attributes={c.Ldif.DictKeys.OBJECTCLASS: ["nscontainer"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.CN_MONITOR,
        entry_dn="cn=monitor",
        attributes={c.Ldif.DictKeys.OBJECTCLASS: ["top"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.CN_CHANGELOG,
        entry_dn="cn=changelog",
        attributes={c.Ldif.DictKeys.OBJECTCLASS: ["top"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.NSSLAPD_ATTRIBUTE,
        entry_dn="cn=test,dc=example,dc=com",
        attributes={"nsslapd-port": ["389"], "objectclass": ["top"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.NSDS_ATTRIBUTE,
        entry_dn="cn=test,dc=example,dc=com",
        attributes={"nsds5ReplicaId": ["1"], "objectclass": ["top"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.NSUNIQUEID_ATTRIBUTE,
        entry_dn="cn=test,dc=example,dc=com",
        attributes={"nsuniqueid": ["12345"], "objectclass": ["top"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.NS_OBJECTCLASS,
        entry_dn="cn=test,dc=example,dc=com",
        attributes={c.Ldif.DictKeys.OBJECTCLASS: ["top", "nscontainer"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.STANDARD_RFC,
        entry_dn="cn=user,dc=example,dc=com",
        attributes={c.Ldif.DictKeys.OBJECTCLASS: ["person"], "cn": ["user"]},
        expected_can_handle=False,
    ),
)


class TestsTestFlextLdifDs389Quirks(s):
    """Test FlextLdif DS389 server quirks."""

    ATTRIBUTE_DATA: ClassVar[tuple[AttributeTestCase, ...]] = ATTRIBUTE_TEST_CASES
    OBJECTCLASS_DATA: ClassVar[tuple[ObjectClassTestCase, ...]] = OBJECTCLASS_TEST_CASES
    ACL_DATA: ClassVar[tuple[AclTestCase, ...]] = ACL_TEST_CASES
    ENTRY_DATA: ClassVar[tuple[EntryTestCase, ...]] = ENTRY_TEST_CASES

    def test_server_initialization(self) -> None:
        """Test DS389 server initialization."""
        server = FlextLdifServersDs389()
        tm.that(server.server_type == "ds389", eq=True)
        tm.that(server.priority == 30, eq=True)

    def test_schema_quirk_initialization(self) -> None:
        """Test schema quirk is initialized."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(schema_quirk is not None, eq=True)

    def test_acl_quirk_initialization(self) -> None:
        """Test ACL quirk is initialized."""
        server = FlextLdifServersDs389()
        acl_quirk = server.acl_quirk
        tm.that(acl_quirk is not None, eq=True)

    def test_entry_quirk_initialization(self) -> None:
        """Test entry quirk is initialized."""
        server = FlextLdifServersDs389()
        entry_quirk = server.entry_quirk
        tm.that(entry_quirk is not None, eq=True)

    @pytest.mark.parametrize("test_case", ATTRIBUTE_TEST_CASES)
    def test_schema_attribute_can_handle(self, test_case: AttributeTestCase) -> None:
        """Test attribute detection for various scenarios."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(isinstance(schema_quirk, FlextLdifServersDs389.Schema), eq=True)
        tm.that(hasattr(schema_quirk, "can_handle_attribute"), eq=True)
        result = schema_quirk.can_handle_attribute(test_case.attr_definition)
        tm.that(result is test_case.expected_can_handle, eq=True)

    def test_parse_attribute_success(self) -> None:
        """Test parsing DS389 attribute definition."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(isinstance(schema_quirk, FlextLdifServersDs389.Schema), eq=True)
        attr_def = "( 2.16.840.1.113730.3.1.1 NAME 'nsslapd-suffix' DESC 'Directory suffix' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )"
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            schema_quirk,
            attr_def,
            expected_oid="2.16.840.1.113730.3.1.1",
            expected_name="nsslapd-suffix",
            expected_desc="Directory suffix",
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.12",
            expected_single_value=True,
        )

    def test_parse_attribute_with_syntax_length(self) -> None:
        """Test parsing attribute with syntax length specification."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(isinstance(schema_quirk, FlextLdifServersDs389.Schema), eq=True)
        attr_def = "( 2.16.840.1.113730.3.1.2 NAME 'nsslapd-database' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            schema_quirk,
            attr_def,
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.15",
            expected_length=256,
        )

    def test_parse_attribute_missing_oid(self) -> None:
        """Test parsing attribute without OID fails."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(isinstance(schema_quirk, FlextLdifServersDs389.Schema), eq=True)
        attr_def = "NAME 'nsslapd-port' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
        result = schema_quirk.parse(attr_def)
        tm.that(result.is_failure, eq=True)
        tm.that(result.error is not None, eq=True)
        if result.error is not None:
            tm.that("missing an OID" in result.error, eq=True)

    @pytest.mark.parametrize("test_case", OBJECTCLASS_TEST_CASES)
    def test_schema_objectclass_can_handle(
        self, test_case: ObjectClassTestCase
    ) -> None:
        """Test objectClass detection for various scenarios."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(isinstance(schema_quirk, FlextLdifServersDs389.Schema), eq=True)
        tm.that(hasattr(schema_quirk, "can_handle_objectclass"), eq=True)
        result = schema_quirk.can_handle_objectclass(test_case.oc_definition)
        tm.that(result is test_case.expected_can_handle, eq=True)

    def test_parse_objectclass_structural(self) -> None:
        """Test parsing STRUCTURAL objectClass."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(isinstance(schema_quirk, FlextLdifServersDs389.Schema), eq=True)
        oc_def = "( 2.16.840.1.113730.3.2.1 NAME 'nscontainer' DESC 'Container class' SUP top STRUCTURAL MUST ( cn ) MAY ( nsslapd-port ) )"
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            schema_quirk,
            oc_def,
            expected_oid="2.16.840.1.113730.3.2.1",
            expected_name="nscontainer",
            expected_kind="STRUCTURAL",
            expected_sup="top",
            expected_must=["cn"],
            expected_may=["nsslapd-port"],
        )

    def test_parse_objectclass_auxiliary(self) -> None:
        """Test parsing AUXILIARY objectClass."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(isinstance(schema_quirk, FlextLdifServersDs389.Schema), eq=True)
        oc_def = "( 2.16.840.1.113730.3.2.2 NAME 'nsds5replica' AUXILIARY MAY ( nsds5ReplicaId $ nsds5ReplicaRoot ) )"
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            schema_quirk, oc_def, expected_kind="AUXILIARY"
        )

    def test_parse_objectclass_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(isinstance(schema_quirk, FlextLdifServersDs389.Schema), eq=True)
        oc_def = "( 2.16.840.1.113730.3.2.3 NAME 'nsds5base' ABSTRACT )"
        result = schema_quirk.parse(oc_def)
        tm.that(result.is_success, eq=True)
        oc_data = result.value
        assert isinstance(oc_data, m.Ldif.SchemaObjectClass)
        tm.that(oc_data.kind == "ABSTRACT", eq=True)

    def test_parse_objectclass_missing_oid(self) -> None:
        """Test parsing objectClass without OID fails."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(isinstance(schema_quirk, FlextLdifServersDs389.Schema), eq=True)
        oc_def = "NAME 'nscontainer' SUP top STRUCTURAL"
        result = schema_quirk.parse(oc_def)
        tm.that(result.is_failure, eq=True)
        tm.that(result.error is not None, eq=True)
        if result.error is not None:
            tm.that("missing an OID" in result.error, eq=True)

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(isinstance(schema_quirk, FlextLdifServersDs389.Schema), eq=True)
        oc_data = m.Ldif.SchemaObjectClass(
            oid="2.16.840.1.113730.3.2.1",
            name="nscontainer",
            kind="STRUCTURAL",
            sup="top",
            must=["cn"],
            may=["nsslapd-port"],
        )
        result = schema_quirk.write(oc_data)
        tm.that(result.is_success, eq=True)
        oc_str = result.value
        tm.that("2.16.840.1.113730.3.2.1" in oc_str, eq=True)
        tm.that("nscontainer" in oc_str, eq=True)
        tm.that("STRUCTURAL" in oc_str, eq=True)

    @pytest.mark.parametrize("test_case", ENTRY_TEST_CASES)
    def test_entry_can_handle(self, test_case: EntryTestCase) -> None:
        """Test entry detection for various scenarios."""
        server = FlextLdifServersDs389()
        entry_quirk = server.entry_quirk
        tm.that(isinstance(entry_quirk, FlextLdifServersDs389.Entry), eq=True)
        result = entry_quirk.can_handle(test_case.entry_dn, test_case.attributes)
        tm.that(result is test_case.expected_can_handle, eq=True)
