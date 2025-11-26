"""Tests for 389 Directory Server quirks implementation.

Test coverage for DS389 server-specific quirks:
- Schema attribute and objectClass handling
- ACL (Access Control) parsing and writing
- Entry detection and validation
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from typing import cast

import pytest

from flext_ldif import FlextLdifConstants, FlextLdifModels
from flext_ldif.servers.ds389 import FlextLdifServersDs389
from tests.helpers.test_rfc_helpers import RfcTestHelpers


class AttributeScenario(StrEnum):
    """DS389 attribute detection scenarios."""

    DS389_OID = "ds389_oid"
    NSSLAPD_PREFIX = "nsslapd_prefix"
    NSDS_PREFIX = "nsds_prefix"
    NSUNIQUEID_PREFIX = "nsuniqueid_prefix"
    STANDARD_RFC = "standard_rfc"


class ObjectClassScenario(StrEnum):
    """DS389 objectClass detection scenarios."""

    DS389_OID = "ds389_oid"
    NS_NAME = "ns_name"
    STANDARD_RFC = "standard_rfc"


class AclScenario(StrEnum):
    """DS389 ACL handling scenarios."""

    ACI_ATTRIBUTE = "aci_attribute"
    VERSION_PREFIX = "version_prefix"
    OPENLDAP_FORMAT = "openldap_format"
    EMPTY_LINE = "empty_line"


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


@dataclasses.dataclass(frozen=True)
class AttributeTestCase:
    """Test case for attribute detection and parsing."""

    scenario: AttributeScenario
    attr_definition: str
    expected_can_handle: bool
    expected_oid: str | None = None
    expected_name: str | None = None


@dataclasses.dataclass(frozen=True)
class ObjectClassTestCase:
    """Test case for objectClass detection and parsing."""

    scenario: ObjectClassScenario
    oc_definition: str
    expected_can_handle: bool
    expected_oid: str | None = None
    expected_name: str | None = None
    expected_kind: str | None = None


@dataclasses.dataclass(frozen=True)
class AclTestCase:
    """Test case for ACL handling."""

    scenario: AclScenario
    acl_line: str
    expected_can_handle: bool
    expected_success: bool = False


@dataclasses.dataclass(frozen=True)
class EntryTestCase:
    """Test case for entry detection."""

    scenario: EntryScenario
    entry_dn: str
    attributes: dict[str, object]
    expected_can_handle: bool


# Attribute test data
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

# ObjectClass test data
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

# ACL test data
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

# Entry test data
ENTRY_TEST_CASES = (
    EntryTestCase(
        scenario=EntryScenario.CN_CONFIG,
        entry_dn="cn=config",
        attributes={FlextLdifConstants.DictKeys.OBJECTCLASS: ["nscontainer"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.CN_MONITOR,
        entry_dn="cn=monitor",
        attributes={FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.CN_CHANGELOG,
        entry_dn="cn=changelog",
        attributes={FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"]},
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
        attributes={FlextLdifConstants.DictKeys.OBJECTCLASS: ["top", "nscontainer"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.STANDARD_RFC,
        entry_dn="cn=user,dc=example,dc=com",
        attributes={
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["person"],
            "cn": ["user"],
        },
        expected_can_handle=False,
    ),
)


@pytest.fixture
def ds389_server() -> FlextLdifServersDs389:
    """Create DS389 server instance."""
    return FlextLdifServersDs389()


@pytest.fixture
def schema_quirk(
    ds389_server: FlextLdifServersDs389,
) -> object:
    """Get schema quirk from DS389 server."""
    return ds389_server.schema_quirk


@pytest.fixture
def acl_quirk(
    ds389_server: FlextLdifServersDs389,
) -> object:
    """Get ACL quirk from DS389 server."""
    return ds389_server.acl_quirk


@pytest.fixture
def entry_quirk(
    ds389_server: FlextLdifServersDs389,
) -> object:
    """Get entry quirk from DS389 server."""
    return ds389_server.entry_quirk


class TestDs389Initialization:
    """Test initialization of DS389 quirks."""

    def test_server_initialization(self) -> None:
        """Test DS389 server initialization."""
        server = FlextLdifServersDs389()
        assert server.server_type == "389ds"
        assert server.priority == 30

    def test_schema_quirk_initialization(
        self,
        schema_quirk: object,
    ) -> None:
        """Test schema quirk is initialized."""
        assert schema_quirk is not None

    def test_acl_quirk_initialization(
        self,
        acl_quirk: object,
    ) -> None:
        """Test ACL quirk is initialized."""
        assert acl_quirk is not None

    def test_entry_quirk_initialization(
        self,
        entry_quirk: object,
    ) -> None:
        """Test entry quirk is initialized."""
        assert entry_quirk is not None


class TestDs389SchemaAttributeDetection:
    """Test schema attribute detection."""

    @pytest.mark.parametrize("test_case", ATTRIBUTE_TEST_CASES)
    def test_can_handle_attribute(
        self,
        test_case: AttributeTestCase,
        schema_quirk: object,
    ) -> None:
        """Test attribute detection for various scenarios."""
        schema = cast("object", schema_quirk)
        assert hasattr(schema, "can_handle_attribute")
        result = schema.can_handle_attribute(test_case.attr_definition)
        assert result is test_case.expected_can_handle


class TestDs389SchemaAttributeParsing:
    """Test schema attribute parsing."""

    def test_parse_attribute_success(
        self,
        schema_quirk: object,
    ) -> None:
        """Test parsing DS389 attribute definition."""
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

    def test_parse_attribute_with_syntax_length(
        self,
        schema_quirk: object,
    ) -> None:
        """Test parsing attribute with syntax length specification."""
        attr_def = "( 2.16.840.1.113730.3.1.2 NAME 'nsslapd-database' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            schema_quirk,
            attr_def,
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.15",
            expected_length=256,
        )

    def test_parse_attribute_missing_oid(
        self,
        schema_quirk: object,
    ) -> None:
        """Test parsing attribute without OID fails."""
        attr_def = "NAME 'nsslapd-port' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
        result = schema_quirk.parse(attr_def)

        assert result.is_failure
        assert result.error is not None
        assert "missing an OID" in result.error


class TestDs389SchemaObjectClassDetection:
    """Test schema objectClass detection."""

    @pytest.mark.parametrize("test_case", OBJECTCLASS_TEST_CASES)
    def test_can_handle_objectclass(
        self,
        test_case: ObjectClassTestCase,
        schema_quirk: object,
    ) -> None:
        """Test objectClass detection for various scenarios."""
        schema = cast("object", schema_quirk)
        assert hasattr(schema, "can_handle_objectclass")
        result = schema.can_handle_objectclass(test_case.oc_definition)
        assert result is test_case.expected_can_handle


class TestDs389SchemaObjectClassParsing:
    """Test schema objectClass parsing."""

    def test_parse_objectclass_structural(
        self,
        schema_quirk: object,
    ) -> None:
        """Test parsing STRUCTURAL objectClass."""
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

    def test_parse_objectclass_auxiliary(
        self,
        schema_quirk: object,
    ) -> None:
        """Test parsing AUXILIARY objectClass."""
        oc_def = "( 2.16.840.1.113730.3.2.2 NAME 'nsds5replica' AUXILIARY MAY ( nsds5ReplicaId $ nsds5ReplicaRoot ) )"
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            schema_quirk,
            oc_def,
            expected_kind="AUXILIARY",
        )

    def test_parse_objectclass_abstract(
        self,
        schema_quirk: object,
    ) -> None:
        """Test parsing ABSTRACT objectClass."""
        oc_def = "( 2.16.840.1.113730.3.2.3 NAME 'nsds5base' ABSTRACT )"
        result = schema_quirk.parse(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "ABSTRACT"

    def test_parse_objectclass_missing_oid(
        self,
        schema_quirk: object,
    ) -> None:
        """Test parsing objectClass without OID fails."""
        oc_def = "NAME 'nscontainer' SUP top STRUCTURAL"
        result = schema_quirk.parse(oc_def)

        assert result.is_failure
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_write_objectclass_to_rfc(
        self,
        schema_quirk: object,
    ) -> None:
        """Test writing objectClass to RFC string format."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113730.3.2.1",
            name="nscontainer",
            kind="STRUCTURAL",
            sup="top",
            must=["cn"],
            may=["nsslapd-port"],
        )
        result = schema_quirk.write(oc_data)

        assert result.is_success
        oc_str = result.unwrap()
        assert "2.16.840.1.113730.3.2.1" in oc_str
        assert "nscontainer" in oc_str
        assert "STRUCTURAL" in oc_str


class TestDs389EntryDetection:
    """Test entry detection and validation."""

    @pytest.mark.parametrize("test_case", ENTRY_TEST_CASES)
    def test_can_handle_entry(
        self,
        test_case: EntryTestCase,
        entry_quirk: object,
    ) -> None:
        """Test entry detection for various scenarios."""
        entry = cast("object", entry_quirk)
        assert hasattr(entry, "can_handle")
        result = entry.can_handle(test_case.entry_dn, test_case.attributes)
        assert result is test_case.expected_can_handle


__all__ = [
    "ACL_TEST_CASES",
    "ATTRIBUTE_TEST_CASES",
    "ENTRY_TEST_CASES",
    "OBJECTCLASS_TEST_CASES",
    "AclScenario",
    "AclTestCase",
    "AttributeScenario",
    "AttributeTestCase",
    "EntryScenario",
    "EntryTestCase",
    "ObjectClassScenario",
    "ObjectClassTestCase",
    "TestDs389EntryDetection",
    "TestDs389Initialization",
    "TestDs389SchemaAttributeDetection",
    "TestDs389SchemaAttributeParsing",
    "TestDs389SchemaObjectClassDetection",
    "TestDs389SchemaObjectClassParsing",
]
