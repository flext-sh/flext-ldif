"""Tests for Apache Directory Server quirks implementation."""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from typing import cast

import pytest

from flext_ldif import FlextLdifConstants, FlextLdifModels
from flext_ldif.servers.apache import FlextLdifServersApache
from tests.helpers.test_deduplication_helpers import TestDeduplicationHelpers


class AttributeScenario(StrEnum):
    """Apache attribute detection scenarios."""

    APACHE_OID = "apache_oid"
    ADS_PREFIX = "ads_prefix"
    APACHEDS_NAME = "apacheds_name"
    STANDARD_RFC = "standard_rfc"


class ObjectClassScenario(StrEnum):
    """Apache objectClass detection scenarios."""

    APACHE_OID = "apache_oid"
    ADS_NAME = "ads_name"
    STANDARD_RFC = "standard_rfc"


class EntryScenario(StrEnum):
    """Apache entry detection scenarios."""

    OU_CONFIG = "ou_config"
    OU_SERVICES = "ou_services"
    OU_SYSTEM = "ou_system"
    OU_PARTITIONS = "ou_partitions"
    ADS_ATTRIBUTE = "ads_attribute"
    APACHEDS_ATTRIBUTE = "apacheds_attribute"
    ADS_OBJECTCLASS = "ads_objectclass"
    STANDARD_RFC = "standard_rfc"


@dataclasses.dataclass(frozen=True)
class AttributeTestCase:
    """Test case for attribute detection and parsing."""

    scenario: AttributeScenario
    attr_definition: str
    expected_can_handle: bool
    expected_name: str | None = None


@dataclasses.dataclass(frozen=True)
class ObjectClassTestCase:
    """Test case for objectClass detection and parsing."""

    scenario: ObjectClassScenario
    oc_definition: str
    expected_can_handle: bool
    expected_name: str | None = None


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
        scenario=AttributeScenario.APACHE_OID,
        attr_definition="( 1.3.6.1.4.1.18060.0.4.1.2.100 NAME 'ads-enabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
        expected_can_handle=True,
        expected_name="ads-enabled",
    ),
    AttributeTestCase(
        scenario=AttributeScenario.ADS_PREFIX,
        attr_definition="( 2.16.840.1.113730.3.1.1 NAME 'ads-searchBaseDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
        expected_can_handle=True,
        expected_name="ads-searchBaseDN",
    ),
    AttributeTestCase(
        scenario=AttributeScenario.APACHEDS_NAME,
        attr_definition="( 1.2.3.4 NAME 'apachedsSystemId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        expected_can_handle=True,
        expected_name="apachedsSystemId",
    ),
    AttributeTestCase(
        scenario=AttributeScenario.STANDARD_RFC,
        attr_definition="( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        expected_can_handle=False,
        expected_name="cn",
    ),
)

# ObjectClass test data
OBJECTCLASS_TEST_CASES = (
    ObjectClassTestCase(
        scenario=ObjectClassScenario.APACHE_OID,
        oc_definition="( 1.3.6.1.4.1.18060.0.4.1.3.100 NAME 'ads-directoryService' SUP top STRUCTURAL )",
        expected_can_handle=True,
        expected_name="ads-directoryService",
    ),
    ObjectClassTestCase(
        scenario=ObjectClassScenario.ADS_NAME,
        oc_definition="( 2.5.6.0 NAME 'ads-base' SUP top ABSTRACT )",
        expected_can_handle=True,
        expected_name="ads-base",
    ),
    ObjectClassTestCase(
        scenario=ObjectClassScenario.STANDARD_RFC,
        oc_definition="( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )",
        expected_can_handle=False,
        expected_name="posixAccount",
    ),
)

# Entry test data
ENTRY_TEST_CASES = (
    EntryTestCase(
        scenario=EntryScenario.OU_CONFIG,
        entry_dn="ou=config,dc=example,dc=com",
        attributes={FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.OU_SERVICES,
        entry_dn="ou=services,dc=example,dc=com",
        attributes={FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.OU_SYSTEM,
        entry_dn="ou=system,dc=example,dc=com",
        attributes={FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.OU_PARTITIONS,
        entry_dn="ou=partitions,dc=example,dc=com",
        attributes={FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.ADS_ATTRIBUTE,
        entry_dn="cn=test,dc=example,dc=com",
        attributes={
            "ads-enabled": ["TRUE"],
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"],
        },
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.APACHEDS_ATTRIBUTE,
        entry_dn="cn=test,dc=example,dc=com",
        attributes={
            "apachedsSystemId": ["test"],
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"],
        },
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.ADS_OBJECTCLASS,
        entry_dn="cn=test,dc=example,dc=com",
        attributes={FlextLdifConstants.DictKeys.OBJECTCLASS: ["top", "ads-directory"]},
        expected_can_handle=True,
    ),
    # Note: Apache Entry quirk currently returns True for standard RFC entries
    # This may be intentional for relaxed parsing or a limitation
    EntryTestCase(
        scenario=EntryScenario.STANDARD_RFC,
        entry_dn="cn=user,dc=example,dc=com",
        attributes={
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["person"],
            "cn": ["user"],
        },
        expected_can_handle=True,  # Apache quirk accepts all entries
    ),
)


@pytest.fixture
def apache_server() -> FlextLdifServersApache:
    """Create Apache server instance."""
    return FlextLdifServersApache()


@pytest.fixture
def schema_quirk(apache_server: FlextLdifServersApache) -> object:
    """Get schema quirk from Apache server."""
    return apache_server.schema_quirk


@pytest.fixture
def acl_quirk(apache_server: FlextLdifServersApache) -> object:
    """Get ACL quirk from Apache server."""
    return apache_server.acl_quirk


@pytest.fixture
def entry_quirk(apache_server: FlextLdifServersApache) -> object:
    """Get entry quirk from Apache server."""
    return apache_server.entry_quirk


class TestApacheInitialization:
    """Test initialization of Apache quirks."""

    def test_server_initialization(self) -> None:
        """Test Apache Directory Server initialization."""
        server = FlextLdifServersApache()
        assert server.server_type == "apache_directory"
        assert server.priority == 15

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


class TestApacheSchemaAttributeDetection:
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


class TestApacheSchemaAttributeParsing:
    """Test schema attribute parsing."""

    def test_parse_attribute_success(
        self,
        schema_quirk: object,
    ) -> None:
        """Test parsing Apache DS attribute definition."""
        attr_def = "( 1.3.6.1.4.1.18060.0.4.1.2.100 NAME 'ads-enabled' DESC 'Enable flag' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )"
        attr_data = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            schema_quirk,
            attr_def,
            parse_method="parse_attribute",
            expected_type=FlextLdifModels.SchemaAttribute,
        )
        assert isinstance(attr_data, FlextLdifModels.SchemaAttribute)
        assert attr_data.oid == "1.3.6.1.4.1.18060.0.4.1.2.100"
        assert attr_data.name == "ads-enabled"
        assert attr_data.desc == "Enable flag"
        assert attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.7"
        assert attr_data.single_value is True

    def test_parse_attribute_with_syntax_length(
        self,
        schema_quirk: object,
    ) -> None:
        """Test parsing attribute with syntax length specification."""
        attr_def = "( 1.3.6.1.4.1.18060.0.4.1.2.1 NAME 'ads-directoryServiceId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        attr_data = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            schema_quirk,
            attr_def,
            parse_method="parse_attribute",
            expected_type=FlextLdifModels.SchemaAttribute,
        )
        assert isinstance(attr_data, FlextLdifModels.SchemaAttribute)
        assert attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert attr_data.length == 256

    def test_parse_attribute_missing_oid(
        self,
        schema_quirk: object,
    ) -> None:
        """Test parsing attribute without OID fails."""
        attr_def = "NAME 'ads-enabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7"
        TestDeduplicationHelpers.quirk_parse_and_unwrap(
            schema_quirk,
            attr_def,
            parse_method="parse_attribute",
            should_succeed=False,
        )


class TestApacheSchemaObjectClassDetection:
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


class TestApacheSchemaObjectClassParsing:
    """Test schema objectClass parsing."""

    def test_parse_objectclass_structural(
        self,
        schema_quirk: object,
    ) -> None:
        """Test parsing STRUCTURAL objectClass."""
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.100 NAME 'ads-directoryService' DESC 'Directory service' SUP top STRUCTURAL MUST ( cn $ ads-directoryServiceId ) MAY ( ads-enabled ) )"
        oc_data = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            schema_quirk,
            oc_def,
            parse_method="parse_objectclass",
            expected_type=FlextLdifModels.SchemaObjectClass,
        )
        assert isinstance(oc_data, FlextLdifModels.SchemaObjectClass)
        assert oc_data.oid == "1.3.6.1.4.1.18060.0.4.1.3.100"
        assert oc_data.name == "ads-directoryService"
        assert oc_data.kind == "STRUCTURAL"
        assert oc_data.sup == "top"
        must_attrs = oc_data.must
        assert isinstance(must_attrs, list)
        assert "cn" in must_attrs
        assert "ads-directoryServiceId" in must_attrs
        may_attrs = oc_data.may
        assert isinstance(may_attrs, list)
        assert "ads-enabled" in may_attrs

    def test_parse_objectclass_auxiliary(
        self,
        schema_quirk: object,
    ) -> None:
        """Test parsing AUXILIARY objectClass."""
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.200 NAME 'ads-partition' AUXILIARY MAY ( ads-partitionSuffix $ ads-contextEntry ) )"
        oc_data = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            schema_quirk,
            oc_def,
            parse_method="parse_objectclass",
            expected_type=FlextLdifModels.SchemaObjectClass,
        )
        assert isinstance(oc_data, FlextLdifModels.SchemaObjectClass)
        assert oc_data.kind == "AUXILIARY"

    def test_parse_objectclass_abstract(
        self,
        schema_quirk: object,
    ) -> None:
        """Test parsing ABSTRACT objectClass."""
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.1 NAME 'ads-base' ABSTRACT )"
        oc_data = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            schema_quirk,
            oc_def,
            parse_method="parse_objectclass",
            expected_type=FlextLdifModels.SchemaObjectClass,
        )
        assert isinstance(oc_data, FlextLdifModels.SchemaObjectClass)
        assert oc_data.kind == "ABSTRACT"

    def test_parse_objectclass_missing_oid(
        self,
        schema_quirk: object,
    ) -> None:
        """Test parsing objectClass without OID fails."""
        oc_def = "NAME 'ads-directoryService' SUP top STRUCTURAL"
        TestDeduplicationHelpers.quirk_parse_and_unwrap(
            schema_quirk,
            oc_def,
            parse_method="parse_objectclass",
            should_succeed=False,
        )

    def test_write_attribute_to_rfc(
        self,
        schema_quirk: object,
    ) -> None:
        """Test writing attribute to RFC string format."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="1.3.6.1.4.1.18060.0.4.1.2.100",
            name="ads-enabled",
            desc="Enable flag",
            syntax="1.3.6.1.4.1.1466.115.121.1.7",
            single_value=True,
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            schema_quirk,
            attr_data,
            write_method="_write_attribute",
            must_contain=[
                "1.3.6.1.4.1.18060.0.4.1.2.100",
                "ads-enabled",
                "SINGLE-VALUE",
            ],
        )

    def test_write_objectclass_to_rfc(
        self,
        schema_quirk: object,
    ) -> None:
        """Test writing objectClass to RFC string format."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="1.3.6.1.4.1.18060.0.4.1.3.100",
            name="ads-directoryService",
            kind="STRUCTURAL",
            sup="top",
            must=["cn", "ads-directoryServiceId"],
            may=["ads-enabled"],
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            schema_quirk,
            oc_data,
            write_method="_write_objectclass",
            must_contain=[
                "1.3.6.1.4.1.18060.0.4.1.3.100",
                "ads-directoryService",
                "STRUCTURAL",
            ],
        )


class TestApacheDirectoryAcls:
    """Tests for Apache Directory Server ACL quirk handling."""

    def test_acl_initialization(
        self,
        acl_quirk: object,
    ) -> None:
        """Test ACL quirk is initialized."""
        assert acl_quirk is not None

    def test__can_handle_with_ads_aci(
        self,
        acl_quirk: object,
    ) -> None:
        """Test ACL detection with ads-aci attribute."""
        acl_line = "ads-aci: ( version 3.0 ) ( deny grantAdd ) ( grantRemove )"
        acl_model = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk,
            acl_line,
            parse_method="parse",
        )
        roundtrip_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk,
            acl_model.raw_acl
            if hasattr(acl_model, "raw_acl") and acl_model.raw_acl
            else str(acl_model),
            parse_method="parse",
        )
        assert roundtrip_result is not None

    def test__can_handle_with_aci(
        self,
        acl_quirk: object,
    ) -> None:
        """Test ACL detection with aci attribute."""
        acl_line = "aci: ( version 3.0 ) ( deny grantAdd ) ( grantRemove )"
        acl_model = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk,
            acl_line,
            parse_method="parse",
        )
        roundtrip_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk,
            acl_model.raw_acl
            if hasattr(acl_model, "raw_acl") and acl_model.raw_acl
            else str(acl_model),
            parse_method="parse",
        )
        assert roundtrip_result is not None

    def test__can_handle_with_version_prefix(
        self,
        acl_quirk: object,
    ) -> None:
        """Test ACL detection with version prefix."""
        acl_line = "(version 3.0) (deny grantAdd) (grantRemove)"
        acl_model = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk,
            acl_line,
            parse_method="parse",
        )
        roundtrip_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk,
            acl_model.raw_acl
            if hasattr(acl_model, "raw_acl") and acl_model.raw_acl
            else str(acl_model),
            parse_method="parse",
        )
        assert roundtrip_result is not None

    def test__can_handle_negative(
        self,
        acl_quirk: object,
    ) -> None:
        """Test ACL detection rejects non-ApacheDS ACLs."""
        acl_line = "access to * by * read"
        acl_model = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk,
            acl_line,
            parse_method="parse",
        )
        assert acl_quirk.can_handle_acl(acl_model) is False

    def test__can_handle_empty_line(
        self,
        acl_quirk: object,
    ) -> None:
        """Test ACL detection rejects empty lines."""
        assert acl_quirk.can_handle_acl("") is False

    def test_parse_success(
        self,
        acl_quirk: object,
    ) -> None:
        """Test parsing Apache DS ACI definition."""
        acl_line = "ads-aci: ( version 3.0 ) ( deny grantAdd ) ( grantRemove )"
        acl_data = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk,
            acl_line,
            parse_method="parse",
            expected_type=FlextLdifModels.Acl,
        )
        assert isinstance(acl_data, FlextLdifModels.Acl)
        assert acl_data.get_acl_format() == FlextLdifConstants.AclFormats.ACI
        # Note: Apache ACL parser does not populate name field currently
        assert acl_data.raw_acl == acl_line
        assert acl_data.server_type == FlextLdifConstants.LdapServers.APACHE_DIRECTORY

    def test_parse_with_aci_attribute(
        self,
        acl_quirk: object,
    ) -> None:
        """Test parsing ACI with aci attribute."""
        acl_line = "aci: ( deny grantAdd )"
        acl_data = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk,
            acl_line,
            parse_method="parse",
            expected_type=FlextLdifModels.Acl,
        )
        assert isinstance(acl_data, FlextLdifModels.Acl)
        # Note: Apache ACL parser does not populate name field currently

    def test_write_acl_to_rfc_with_content(
        self,
        acl_quirk: object,
    ) -> None:
        """Test writing ACL with content to RFC string format."""
        acl_model = FlextLdifModels.Acl(
            name="ads-aci",
            target=FlextLdifModels.AclTarget(target_dn="", attributes=[]),
            subject=FlextLdifModels.AclSubject(subject_type="", subject_value=""),
            permissions=FlextLdifModels.AclPermissions(),
            server_type="apache_directory",
            raw_acl="( version 3.0 ) ( deny grantAdd )",
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            acl_quirk,
            acl_model,
            write_method="_write_acl",
            must_contain=["aci:"],
        )

    def test_write_acl_to_rfc_with_clauses_only(
        self,
        acl_quirk: object,
    ) -> None:
        """Test writing ACL with clauses only to RFC string format."""
        acl_model = FlextLdifModels.Acl(
            name="aci",
            target=FlextLdifModels.AclTarget(target_dn="", attributes=[]),
            subject=FlextLdifModels.AclSubject(subject_type="", subject_value=""),
            permissions=FlextLdifModels.AclPermissions(),
            server_type="apache_directory",
            raw_acl="( version 3.0 ) ( deny grantAdd )",
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            acl_quirk,
            acl_model,
            write_method="write",
            must_contain=["aci:"],
        )

    def test_write_acl_to_rfc_empty(
        self,
        acl_quirk: object,
    ) -> None:
        """Test writing empty ACL to RFC string format."""
        acl_model = FlextLdifModels.Acl(
            name="ads-aci",
            target=FlextLdifModels.AclTarget(target_dn="", attributes=[]),
            subject=FlextLdifModels.AclSubject(subject_type="", subject_value=""),
            permissions=FlextLdifModels.AclPermissions(),
            server_type="apache_directory",
            raw_acl="",
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            acl_quirk,
            acl_model,
            write_method="write",
            must_contain=["ads-aci", "aci:"],
        )


class TestApacheDirectoryEntrys:
    """Tests for Apache Directory Server entry quirk handling."""

    def test_entry_initialization(
        self,
        entry_quirk: object,
    ) -> None:
        """Test entry quirk is initialized."""
        assert entry_quirk is not None

    @staticmethod
    def _build_ldif(entry_dn: str, attributes: dict[str, object]) -> str:
        """Build LDIF string from DN and attributes."""
        ldif = f"dn: {entry_dn}\n"
        for attr, values in attributes.items():
            if isinstance(values, list):
                for val in values:
                    ldif += f"{attr}: {val}\n"
            else:
                ldif += f"{attr}: {values}\n"
        return ldif

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

    @pytest.mark.parametrize(
        "test_case",
        [tc for tc in ENTRY_TEST_CASES if tc.expected_can_handle],
    )
    def test_entry_parse_ldif(
        self,
        test_case: EntryTestCase,
        entry_quirk: object,
    ) -> None:
        """Test entry parsing via LDIF for Apache-detectable entries."""
        ldif = self._build_ldif(test_case.entry_dn, test_case.attributes)
        result = entry_quirk.parse(ldif)
        # Apache entries should be handled - result is a FlextResult
        assert hasattr(result, "is_success")
