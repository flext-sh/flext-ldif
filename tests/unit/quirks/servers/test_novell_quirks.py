"""Tests for Novell eDirectory (NDS) server-specific LDIF quirks handling.

This module tests the FlextLdifServersNovell implementation for handling Novell
eDirectory-specific attributes, object classes, and entries in LDIF format.
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum

import pytest
from tests import RfcTestHelpers, TestDeduplicationHelpers, s

from flext_ldif.models import m
from flext_ldif.servers.novell import FlextLdifServersNovell


class AttributeScenario(StrEnum):
    """Novell attribute detection scenarios."""

    NOVELL_OID = "novell_oid"
    NSPM_PREFIX = "nspm_prefix"
    LOGIN_PREFIX = "login_prefix"
    DIRXML_PREFIX = "dirxml_prefix"
    STANDARD_RFC = "standard_rfc"


class ObjectClassScenario(StrEnum):
    """Novell objectClass detection scenarios."""

    NOVELL_OID = "novell_oid"
    NDS_NAME = "nds_name"
    STANDARD_RFC = "standard_rfc"


class EntryScenario(StrEnum):
    """Novell entry detection scenarios."""

    OU_SERVICES = "ou_services"
    OU_APPS = "ou_apps"
    OU_SYSTEM = "ou_system"
    NSPM_ATTRIBUTE = "nspm_attribute"
    LOGIN_ATTRIBUTE = "login_attribute"
    NDS_OBJECTCLASS = "nds_objectclass"
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
class EntryTestCase:
    """Test case for entry detection."""

    scenario: EntryScenario
    entry_dn: str
    attributes: dict[str, list[str]]
    expected_can_handle: bool


# Attribute test data
ATTRIBUTE_TEST_CASES = (
    AttributeTestCase(
        scenario=AttributeScenario.NOVELL_OID,
        attr_definition="( 2.16.840.1.113719.1.1.4.1.501 NAME 'nspmPasswordPolicyDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
        expected_can_handle=True,
        expected_oid="2.16.840.1.113719.1.1.4.1.501",
        expected_name="nspmPasswordPolicyDN",
    ),
    AttributeTestCase(
        scenario=AttributeScenario.NSPM_PREFIX,
        attr_definition="( 1.2.3.4 NAME 'nspmPasswordPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        expected_can_handle=True,
        expected_name="nspmPasswordPolicy",
    ),
    AttributeTestCase(
        scenario=AttributeScenario.LOGIN_PREFIX,
        attr_definition="( 1.2.3.4 NAME 'loginDisabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
        expected_can_handle=True,
        expected_name="loginDisabled",
    ),
    AttributeTestCase(
        scenario=AttributeScenario.DIRXML_PREFIX,
        attr_definition="( 1.2.3.4 NAME 'dirxml-associations' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        expected_can_handle=True,
        expected_name="dirxml-associations",
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
        scenario=ObjectClassScenario.NOVELL_OID,
        oc_definition="( 2.16.840.1.113719.2.2.6.1 NAME 'ndsPerson' SUP top STRUCTURAL )",
        expected_can_handle=True,
        expected_oid="2.16.840.1.113719.2.2.6.1",
        expected_name="ndsPerson",
    ),
    ObjectClassTestCase(
        scenario=ObjectClassScenario.NDS_NAME,
        oc_definition="( 2.5.6.0 NAME 'ndsserver' SUP top STRUCTURAL )",
        expected_can_handle=True,
        expected_name="ndsserver",
    ),
    ObjectClassTestCase(
        scenario=ObjectClassScenario.STANDARD_RFC,
        oc_definition="( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )",
        expected_can_handle=False,
    ),
)

# Entry test data
ENTRY_TEST_CASES = (
    EntryTestCase(
        scenario=EntryScenario.OU_SERVICES,
        entry_dn="ou=services,o=Example",
        attributes={"objectClass": ["organizationalUnit"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.OU_APPS,
        entry_dn="ou=apps,o=Example",
        attributes={"objectClass": ["organizationalUnit"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.OU_SYSTEM,
        entry_dn="ou=system,o=Example",
        attributes={"objectClass": ["organizationalUnit"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.NSPM_ATTRIBUTE,
        entry_dn="cn=user,o=Example",
        attributes={
            "nspmpasswordpolicy": ["policy1"],
            "objectClass": ["top"],
        },
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.LOGIN_ATTRIBUTE,
        entry_dn="cn=user,o=Example",
        attributes={
            "logindisabled": ["TRUE"],
            "objectClass": ["top"],
        },
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.NDS_OBJECTCLASS,
        entry_dn="cn=user,o=Example",
        attributes={"objectClass": ["top", "ndsperson"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.STANDARD_RFC,
        entry_dn="cn=user,dc=example,dc=com",
        attributes={
            "objectClass": ["person"],
            "cn": ["user"],
        },
        expected_can_handle=False,
    ),
)


@pytest.fixture
def novell_server() -> FlextLdifServersNovell:
    """Create Novell server instance."""
    return FlextLdifServersNovell()


@pytest.fixture
def schema_quirk(
    novell_server: FlextLdifServersNovell,
) -> FlextLdifServersNovell.Schema:
    """Get schema quirk from Novell server."""
    quirk = novell_server.schema_quirk

    assert isinstance(quirk, FlextLdifServersNovell.Schema)

    return quirk


@pytest.fixture
def entry_quirk(novell_server: FlextLdifServersNovell) -> FlextLdifServersNovell.Entry:
    """Get entry quirk from Novell server."""
    quirk = novell_server.entry_quirk

    assert isinstance(quirk, FlextLdifServersNovell.Entry)

    return quirk


class TestsFlextLdifNovellInitialization(s):
    """Test initialization of Novell quirks."""

    def test_server_initialization(self) -> None:
        """Test Novell eDirectory server initialization."""
        server = FlextLdifServersNovell()
        assert server.server_type == "novell"
        assert server.priority == 20

    def test_schema_quirk_initialization(
        self,
        schema_quirk: object,
    ) -> None:
        """Test schema quirk is initialized."""
        assert schema_quirk is not None


class TestNovellSchemaAttributeDetection:
    """Test schema attribute detection."""

    @pytest.mark.parametrize("test_case", ATTRIBUTE_TEST_CASES)
    def test_can_handle_attribute(
        self,
        test_case: AttributeTestCase,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test attribute detection for various scenarios."""
        result = schema_quirk.can_handle_attribute(test_case.attr_definition)
        assert result is test_case.expected_can_handle


class TestNovellSchemaAttributeParsing:
    """Test schema attribute parsing."""

    def test_parse_attribute_success(
        self,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test parsing Novell eDirectory attribute definition."""
        attr_def = "( 2.16.840.1.113719.1.1.4.1.501 NAME 'nspmPasswordPolicyDN' DESC 'Password Policy DN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )"
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            schema_quirk,
            attr_def,
            expected_oid="2.16.840.1.113719.1.1.4.1.501",
            expected_name="nspmPasswordPolicyDN",
            expected_desc="Password Policy DN",
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.12",
            expected_single_value=True,
        )

    def test_parse_attribute_with_syntax_length(
        self,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test parsing attribute with syntax length specification."""
        attr_def = "( 2.16.840.1.113719.1.1.4.1.1 NAME 'nspmAdminGroup' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            schema_quirk,
            attr_def,
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.15",
            expected_length=256,
        )

    def test_parse_attribute_missing_oid(
        self,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test parsing attribute without OID fails."""
        attr_def = "NAME 'nspmPasswordPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15"
        result = schema_quirk.parse_attribute(attr_def)

        assert result.is_failure
        assert result.error is not None
        assert "missing an OID" in result.error


class TestNovellSchemaObjectClassDetection:
    """Test schema objectClass detection."""

    @pytest.mark.parametrize("test_case", OBJECTCLASS_TEST_CASES)
    def test_can_handle_objectclass(
        self,
        test_case: ObjectClassTestCase,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test objectClass detection for various scenarios."""
        result = schema_quirk.can_handle_objectclass(test_case.oc_definition)
        assert result is test_case.expected_can_handle


class TestNovellSchemaObjectClassParsing:
    """Test schema objectClass parsing."""

    def test_parse_objectclass_structural(
        self,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test parsing STRUCTURAL objectClass."""
        oc_def = "( 2.16.840.1.113719.2.2.6.1 NAME 'ndsPerson' DESC 'NDS Person' SUP top STRUCTURAL MUST ( cn ) MAY ( loginDisabled ) )"
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            schema_quirk,
            oc_def,
            expected_oid="2.16.840.1.113719.2.2.6.1",
            expected_name="ndsPerson",
            expected_kind="STRUCTURAL",
            expected_sup="top",
            expected_must=["cn"],
            expected_may=["loginDisabled"],
        )

    def test_parse_objectclass_auxiliary(
        self,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test parsing AUXILIARY objectClass."""
        oc_def = "( 2.16.840.1.113719.2.2.6.2 NAME 'nspmPasswordPolicy' AUXILIARY MAY ( nspmPasswordPolicyDN ) )"
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            schema_quirk,
            oc_def,
            expected_kind="AUXILIARY",
        )

    def test_parse_objectclass_abstract(
        self,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test parsing ABSTRACT objectClass."""
        oc_def = "( 2.16.840.1.113719.2.2.6.3 NAME 'ndsbase' ABSTRACT )"
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            schema_quirk,
            oc_def,
            expected_kind="ABSTRACT",
        )

    def test_parse_objectclass_missing_oid(
        self,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test parsing objectClass without OID fails."""
        oc_def = "NAME 'ndsPerson' SUP top STRUCTURAL"
        quirk_schema = schema_quirk
        result = quirk_schema.parse_objectclass(oc_def)

        assert result.is_failure
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_write_attribute_to_rfc(
        self,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test writing attribute to RFC string format."""
        attr_data = m.Ldif.SchemaAttribute(
            oid="2.16.840.1.113719.1.1.4.1.501",
            name="nspmPasswordPolicyDN",
            desc="Password Policy DN",
            syntax="1.3.6.1.4.1.1466.115.121.1.12",
            single_value=True,
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            schema_quirk,
            attr_data,
            write_method="_write_attribute",
            must_contain=[
                "2.16.840.1.113719.1.1.4.1.501",
                "nspmPasswordPolicyDN",
                "SINGLE-VALUE",
            ],
        )

    def test_write_objectclass_to_rfc(
        self,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test writing objectClass to RFC string format."""
        oc_data = m.Ldif.SchemaObjectClass(
            oid="2.16.840.1.113719.2.2.6.1",
            name="ndsPerson",
            kind="STRUCTURAL",
            sup="top",
            must=["cn"],
            may=["loginDisabled"],
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            schema_quirk,
            oc_data,
            write_method="_write_objectclass",
            must_contain=["2.16.840.1.113719.2.2.6.1", "ndsPerson", "STRUCTURAL"],
        )


class TestNovellAcls:
    """Tests for Novell eDirectory ACL quirk handling."""

    def test_acl_initialization(
        self,
        novell_server: FlextLdifServersNovell,
    ) -> None:
        """Test ACL quirk initialization."""
        novell_server.Acl()


class TestNovellEntryDetection:
    """Test entry detection."""

    def test_entry_initialization(
        self,
        entry_quirk: object,
    ) -> None:
        """Test entry quirk is initialized."""
        assert entry_quirk is not None

    @pytest.mark.parametrize("test_case", ENTRY_TEST_CASES)
    def test_can_handle_entry(
        self,
        test_case: EntryTestCase,
        entry_quirk: FlextLdifServersNovell.Entry,
    ) -> None:
        """Test entry detection for various scenarios."""
        quirk_entry = entry_quirk
        result = quirk_entry.can_handle(test_case.entry_dn, test_case.attributes)
        assert result is test_case.expected_can_handle
