"""Tests for Apache Directory Server (ApacheDS) LDIF quirks handling.

This module tests the FlextLdifServersApache implementation for handling Apache
Directory Server-specific attributes, object classes, entries, and ACLs in LDIF format.
"""

from __future__ import annotations

from enum import StrEnum, unique
from typing import ClassVar

import pytest
from flext_tests import tm
from pydantic import BaseModel, ConfigDict, Field
from tests import c, m, s

from flext_ldif.servers.apache import FlextLdifServersApache

TestDeduplicationHelpers = c.TestDeduplicationHelpers


@unique
class AttributeScenario(StrEnum):
    """Apache attribute detection scenarios."""

    APACHE_OID = "apache_oid"
    ADS_PREFIX = "ads_prefix"
    APACHEDS_NAME = "apacheds_name"
    STANDARD_RFC = "standard_rfc"


@unique
class ObjectClassScenario(StrEnum):
    """Apache objectClass detection scenarios."""

    APACHE_OID = "apache_oid"
    ADS_NAME = "ads_name"
    STANDARD_RFC = "standard_rfc"


@unique
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


@unique
class AclScenario(StrEnum):
    """Apache ACL handling scenarios."""

    ADS_ACI = "ads_aci"
    ACI_ATTRIBUTE = "aci_attribute"
    VERSION_PREFIX = "version_prefix"
    NEGATIVE = "negative"
    EMPTY_LINE = "empty_line"
    WRITE_WITH_CONTENT = "write_with_content"
    WRITE_CLAUSES_ONLY = "write_clauses_only"
    WRITE_EMPTY = "write_empty"


class AttributeTestCase(BaseModel):
    """Test case for attribute detection and parsing."""

    model_config = ConfigDict(frozen=True)

    scenario: AttributeScenario = Field(description="Attribute scenario identifier")
    attr_definition: str = Field(description="Schema attribute definition string")
    expected_can_handle: bool = Field(description="Expected can_handle result")
    expected_name: str | None = Field(
        default=None,
        description="Expected parsed attribute name",
    )


class ObjectClassTestCase(BaseModel):
    """Test case for objectClass detection and parsing."""

    model_config = ConfigDict(frozen=True)

    scenario: ObjectClassScenario = Field(description="ObjectClass scenario identifier")
    oc_definition: str = Field(description="Schema objectClass definition string")
    expected_can_handle: bool = Field(description="Expected can_handle result")
    expected_name: str | None = Field(
        default=None,
        description="Expected parsed objectClass name",
    )


class EntryTestCase(BaseModel):
    """Test case for entry detection."""

    model_config = ConfigDict(frozen=True)

    scenario: EntryScenario = Field(description="Entry detection scenario identifier")
    entry_dn: str = Field(description="Entry distinguished name")
    attributes: dict[str, list[str]] = Field(
        description="Entry attributes mapped by name"
    )
    expected_can_handle: bool = Field(description="Expected can_handle result")


class AclTestCase(BaseModel):
    """Test case for ACL handling."""

    model_config = ConfigDict(frozen=True)

    scenario: AclScenario = Field(description="ACL scenario identifier")
    acl_line: str | None = Field(
        default=None,
        description="ACL line under test",
    )
    expected_can_handle: bool = Field(
        default=False,
        description="Expected can_handle result",
    )
    expected_success: bool = Field(
        default=False,
        description="Expected parse success state",
    )


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
ENTRY_TEST_CASES = (
    EntryTestCase(
        scenario=EntryScenario.OU_CONFIG,
        entry_dn="ou=config,dc=example,dc=com",
        attributes={"objectClass": ["organizationalUnit"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.OU_SERVICES,
        entry_dn="ou=services,dc=example,dc=com",
        attributes={"objectClass": ["organizationalUnit"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.OU_SYSTEM,
        entry_dn="ou=system,dc=example,dc=com",
        attributes={"objectClass": ["organizationalUnit"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.OU_PARTITIONS,
        entry_dn="ou=partitions,dc=example,dc=com",
        attributes={"objectClass": ["organizationalUnit"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.ADS_ATTRIBUTE,
        entry_dn="cn=test,dc=example,dc=com",
        attributes={"ads-enabled": ["TRUE"], "objectClass": ["top"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.APACHEDS_ATTRIBUTE,
        entry_dn="cn=test,dc=example,dc=com",
        attributes={"apachedsSystemId": ["test"], "objectClass": ["top"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.ADS_OBJECTCLASS,
        entry_dn="cn=test,dc=example,dc=com",
        attributes={"objectClass": ["top", "ads-directory"]},
        expected_can_handle=True,
    ),
    EntryTestCase(
        scenario=EntryScenario.STANDARD_RFC,
        entry_dn="cn=user,dc=example,dc=com",
        attributes={"objectClass": ["person"], "cn": ["user"]},
        expected_can_handle=True,
    ),
)


class TestsTestFlextLdifApacheQuirks(s):
    """Test Apache Directory Server quirks implementation."""

    ATTRIBUTE_DATA: ClassVar = ATTRIBUTE_TEST_CASES
    OBJECTCLASS_DATA: ClassVar = OBJECTCLASS_TEST_CASES
    ENTRY_DATA: ClassVar = ENTRY_TEST_CASES

    def test_server_initialization(self) -> None:
        """Test Apache Directory Server initialization."""
        server = FlextLdifServersApache()
        tm.that(server.server_type == "apache", eq=True)
        tm.that(server.priority == 15, eq=True)

    def test_schema_quirk_initialization(self) -> None:
        """Test schema quirk is initialized."""
        server = FlextLdifServersApache()
        tm.that(server.schema_quirk is not None, eq=True)

    def test_acl_quirk_initialization(self) -> None:
        """Test ACL quirk is initialized."""
        server = FlextLdifServersApache()
        tm.that(server.acl_quirk is not None, eq=True)

    def test_entry_quirk_initialization(self) -> None:
        """Test entry quirk is initialized."""
        server = FlextLdifServersApache()
        tm.that(server.entry_quirk is not None, eq=True)

    @pytest.mark.parametrize("test_case", ATTRIBUTE_TEST_CASES)
    def test_schema_attribute_can_handle(self, test_case: AttributeTestCase) -> None:
        """Test attribute detection for various scenarios."""
        server = FlextLdifServersApache()
        schema_quirk = server.schema_quirk
        tm.that(isinstance(schema_quirk, FlextLdifServersApache.Schema), eq=True)
        result = schema_quirk.can_handle_attribute(test_case.attr_definition)
        tm.that(result is test_case.expected_can_handle, eq=True)

    def test_schema_attribute_parse_success(self) -> None:
        """Test parsing Apache DS attribute definition."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        attr_def = "( 1.3.6.1.4.1.18060.0.4.1.2.100 NAME 'ads-enabled' DESC 'Enable flag' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )"
        attr_data = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            schema,
            attr_def,
            parse_method="parse_attribute",
            expected_type=m.Ldif.SchemaAttribute,
        )
        tm.that(isinstance(attr_data, m.Ldif.SchemaAttribute), eq=True)
        if isinstance(attr_data, m.Ldif.SchemaAttribute):
            tm.that(attr_data.oid == "1.3.6.1.4.1.18060.0.4.1.2.100", eq=True)
            tm.that(attr_data.name == "ads-enabled", eq=True)
            tm.that(attr_data.desc == "Enable flag", eq=True)
            tm.that(attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.7", eq=True)
            tm.that(attr_data.single_value is True, eq=True)

    def test_schema_attribute_parse_with_syntax_length(self) -> None:
        """Test parsing attribute with syntax length specification."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        attr_def = "( 1.3.6.1.4.1.18060.0.4.1.2.1 NAME 'ads-directoryServiceId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        attr_data = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            schema,
            attr_def,
            parse_method="parse_attribute",
            expected_type=m.Ldif.SchemaAttribute,
        )
        tm.that(isinstance(attr_data, m.Ldif.SchemaAttribute), eq=True)
        if isinstance(attr_data, m.Ldif.SchemaAttribute):
            tm.that(attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.15", eq=True)
            tm.that(attr_data.length == 256, eq=True)

    def test_schema_attribute_parse_missing_oid(self) -> None:
        """Test parsing attribute without OID fails."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        attr_def = "NAME 'ads-enabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7"
        TestDeduplicationHelpers.quirk_parse_and_unwrap(
            schema, attr_def, parse_method="parse_attribute", should_succeed=False
        )

    @pytest.mark.parametrize("test_case", OBJECTCLASS_TEST_CASES)
    def test_schema_objectclass_can_handle(
        self, test_case: ObjectClassTestCase
    ) -> None:
        """Test objectClass detection for various scenarios."""
        server = FlextLdifServersApache()
        schema_quirk = server.schema_quirk
        tm.that(isinstance(schema_quirk, FlextLdifServersApache.Schema), eq=True)
        result = schema_quirk.can_handle_objectclass(test_case.oc_definition)
        tm.that(result is test_case.expected_can_handle, eq=True)

    def test_schema_objectclass_parse_structural(self) -> None:
        """Test parsing STRUCTURAL objectClass."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.100 NAME 'ads-directoryService' DESC 'Directory service' SUP top STRUCTURAL MUST ( cn $ ads-directoryServiceId ) MAY ( ads-enabled ) )"
        oc_data = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            schema,
            oc_def,
            parse_method="parse_objectclass",
            expected_type=m.Ldif.SchemaObjectClass,
        )
        tm.that(isinstance(oc_data, m.Ldif.SchemaObjectClass), eq=True)
        tm.that(oc_data.oid == "1.3.6.1.4.1.18060.0.4.1.3.100", eq=True)
        tm.that(oc_data.name == "ads-directoryService", eq=True)
        tm.that(oc_data.kind == "STRUCTURAL", eq=True)
        tm.that(oc_data.sup == "top", eq=True)
        must_attrs = oc_data.must
        tm.that(isinstance(must_attrs, list), eq=True)
        tm.that("cn" in must_attrs, eq=True)
        tm.that("ads-directoryServiceId" in must_attrs, eq=True)
        may_attrs = oc_data.may
        tm.that(isinstance(may_attrs, list), eq=True)
        tm.that("ads-enabled" in may_attrs, eq=True)

    def test_schema_objectclass_parse_auxiliary(self) -> None:
        """Test parsing AUXILIARY objectClass."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.200 NAME 'ads-partition' AUXILIARY MAY ( ads-partitionSuffix $ ads-contextEntry ) )"
        oc_data = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            schema,
            oc_def,
            parse_method="parse_objectclass",
            expected_type=m.Ldif.SchemaObjectClass,
        )
        tm.that(isinstance(oc_data, m.Ldif.SchemaObjectClass), eq=True)
        tm.that(oc_data.kind == "AUXILIARY", eq=True)

    def test_schema_objectclass_parse_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.1 NAME 'ads-base' ABSTRACT )"
        oc_data = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            schema,
            oc_def,
            parse_method="parse_objectclass",
            expected_type=m.Ldif.SchemaObjectClass,
        )
        tm.that(isinstance(oc_data, m.Ldif.SchemaObjectClass), eq=True)
        tm.that(oc_data.kind == "ABSTRACT", eq=True)

    def test_schema_objectclass_parse_missing_oid(self) -> None:
        """Test parsing objectClass without OID fails."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        oc_def = "NAME 'ads-directoryService' SUP top STRUCTURAL"
        TestDeduplicationHelpers.quirk_parse_and_unwrap(
            schema, oc_def, parse_method="parse_objectclass", should_succeed=False
        )

    def test_schema_write_attribute_to_rfc(self) -> None:
        """Test writing attribute to RFC string format."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        attr_data = m.Ldif.SchemaAttribute(
            oid="1.3.6.1.4.1.18060.0.4.1.2.100",
            name="ads-enabled",
            desc="Enable flag",
            syntax="1.3.6.1.4.1.1466.115.121.1.7",
            single_value=True,
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            schema,
            attr_data,
            write_method="_write_attribute",
            must_contain=[
                "1.3.6.1.4.1.18060.0.4.1.2.100",
                "ads-enabled",
                "SINGLE-VALUE",
            ],
        )

    def test_schema_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        oc_data = m.Ldif.SchemaObjectClass(
            oid="1.3.6.1.4.1.18060.0.4.1.3.100",
            name="ads-directoryService",
            kind="STRUCTURAL",
            sup="top",
            must=["cn", "ads-directoryServiceId"],
            may=["ads-enabled"],
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            schema,
            oc_data,
            write_method="_write_objectclass",
            must_contain=[
                "1.3.6.1.4.1.18060.0.4.1.3.100",
                "ads-directoryService",
                "STRUCTURAL",
            ],
        )

    def test_acl_can_handle_with_ads_aci(self) -> None:
        """Test ACL detection with ads-aci attribute."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        acl_line = "ads-aci: ( version 3.0 ) ( deny grantAdd ) ( grantRemove )"
        acl_model = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk, acl_line, parse_method="parse", expected_type=m.Ldif.Tests.Acl
        )
        tm.that(isinstance(acl_model, m.Ldif.Tests.Acl), eq=True)
        roundtrip_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk, acl_model.raw_acl or str(acl_model), parse_method="parse"
        )
        tm.that(roundtrip_result is not None, eq=True)

    def test_acl_can_handle_with_aci(self) -> None:
        """Test ACL detection with aci attribute."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        acl_line = "aci: ( version 3.0 ) ( deny grantAdd ) ( grantRemove )"
        acl_model = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk, acl_line, parse_method="parse", expected_type=m.Ldif.Tests.Acl
        )
        tm.that(isinstance(acl_model, m.Ldif.Tests.Acl), eq=True)
        roundtrip_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk, acl_model.raw_acl or str(acl_model), parse_method="parse"
        )
        tm.that(roundtrip_result is not None, eq=True)

    def test_acl_can_handle_with_version_prefix(self) -> None:
        """Test ACL detection with version prefix."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        acl_line = "(version 3.0) (deny grantAdd) (grantRemove)"
        acl_model = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk, acl_line, parse_method="parse", expected_type=m.Ldif.Tests.Acl
        )
        tm.that(isinstance(acl_model, m.Ldif.Tests.Acl), eq=True)
        roundtrip_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk, acl_model.raw_acl or str(acl_model), parse_method="parse"
        )
        tm.that(roundtrip_result is not None, eq=True)

    def test_acl_can_handle_negative(self) -> None:
        """Test ACL detection rejects non-ApacheDS ACLs."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        tm.that(isinstance(acl_quirk, FlextLdifServersApache.Acl), eq=True)
        acl_line = "access to * by * read"
        tm.that(acl_quirk.can_handle_acl(acl_line) is False, eq=True)

    def test_acl_can_handle_empty_line(self) -> None:
        """Test ACL detection rejects empty lines."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        tm.that(isinstance(acl_quirk, FlextLdifServersApache.Acl), eq=True)
        tm.that(acl_quirk.can_handle_acl("") is False, eq=True)

    def test_acl_parse_success(self) -> None:
        """Test parsing Apache DS ACI definition."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        acl_line = "ads-aci: ( version 3.0 ) ( deny grantAdd ) ( grantRemove )"
        acl_data = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk, acl_line, parse_method="parse", expected_type=m.Ldif.Tests.Acl
        )
        tm.that(isinstance(acl_data, m.Ldif.Tests.Acl), eq=True)
        tm.that(acl_data.get_acl_format() == c.Ldif.AclFormats.ACI, eq=True)
        tm.that(acl_data.server_type == c.Ldif.LdapServers.APACHE_DIRECTORY, eq=True)

    def test_acl_parse_with_aci_attribute(self) -> None:
        """Test parsing ACI with aci attribute."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        acl_line = "aci: ( deny grantAdd )"
        acl_data = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            acl_quirk, acl_line, parse_method="parse", expected_type=m.Ldif.Tests.Acl
        )
        tm.that(isinstance(acl_data, m.Ldif.Tests.Acl), eq=True)

    def test_acl_write_with_content(self) -> None:
        """Test writing ACL with content to RFC string format."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        acl_model = m.Ldif.Tests.Acl(
            name="ads-aci",
            target=m.Ldif.Tests.AclTarget(target_dn="", attributes=[]),
            subject=m.Ldif.Tests.AclSubject(subject_type="all", subject_value=""),
            permissions=m.Ldif.Tests.AclPermissions(),
            server_type="apache",
            raw_acl="( version 3.0 ) ( deny grantAdd )",
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            acl_quirk, acl_model, write_method="_write_acl", must_contain=["aci:"]
        )

    def test_acl_write_with_clauses_only(self) -> None:
        """Test writing ACL with clauses only to RFC string format."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        acl_model = m.Ldif.Tests.Acl(
            name="aci",
            target=m.Ldif.Tests.AclTarget(target_dn="", attributes=[]),
            subject=m.Ldif.Tests.AclSubject(subject_type="all", subject_value=""),
            permissions=m.Ldif.Tests.AclPermissions(),
            server_type="apache",
            raw_acl="( version 3.0 ) ( deny grantAdd )",
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            acl_quirk, acl_model, write_method="write", must_contain=["aci:"]
        )

    def test_acl_write_empty(self) -> None:
        """Test writing empty ACL to RFC string format."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        acl_model = m.Ldif.Tests.Acl(
            name="ads-aci",
            target=m.Ldif.Tests.AclTarget(target_dn="", attributes=[]),
            subject=m.Ldif.Tests.AclSubject(subject_type="all", subject_value=""),
            permissions=m.Ldif.Tests.AclPermissions(),
            server_type="apache",
            raw_acl="",
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            acl_quirk, acl_model, write_method="write", must_contain=["ads-aci", "aci:"]
        )

    @pytest.mark.parametrize("test_case", ENTRY_TEST_CASES)
    def test_entry_can_handle(self, test_case: EntryTestCase) -> None:
        """Test entry detection for various scenarios."""
        server = FlextLdifServersApache()
        entry_quirk = server.entry_quirk
        tm.that(isinstance(entry_quirk, FlextLdifServersApache.Entry), eq=True)
        result = entry_quirk.can_handle(test_case.entry_dn, test_case.attributes)
        tm.that(result is test_case.expected_can_handle, eq=True)

    @staticmethod
    def _build_ldif(entry_dn: str, attributes: dict[str, list[str]]) -> str:
        """Build LDIF string from DN and attributes."""
        ldif = f"dn: {entry_dn}\n"
        for attr, values in attributes.items():
            if isinstance(values, list):
                for val in values:
                    ldif += f"{attr}: {val}\n"
            else:
                ldif += f"{attr}: {values}\n"
        return ldif

    @pytest.mark.parametrize(
        "test_case", [c for c in ENTRY_TEST_CASES if c.expected_can_handle]
    )
    def test_entry_parse_ldif(self, test_case: EntryTestCase) -> None:
        """Test entry parsing via LDIF for Apache-detectable entries."""
        server = FlextLdifServersApache()
        entry_quirk = server.entry_quirk
        ldif = self._build_ldif(test_case.entry_dn, test_case.attributes)
        result = entry_quirk.parse(ldif)
        tm.that(hasattr(result, "is_success"), eq=True)
