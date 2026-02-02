"""Tests for OpenLDAP server LDIF quirks handling.

This module tests the OpenLDAP implementation for handling OpenLDAP-specific
attributes, object classes, and entries in LDIF format.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import ClassVar

import pytest
from tests import RfcTestHelpers, c, s
from tests.unit.quirks.servers.test_utils import FlextLdifTestUtils

from flext_ldif import FlextLdif
from flext_ldif.models import m
from flext_ldif.servers.openldap import FlextLdifServersOpenldap


# TypedDicts (GenericFieldsDict, GenericTestCaseDict, etc.) are available from conftest.py
class FixtureType(StrEnum):
    """Fixture types for OpenLDAP tests."""

    SCHEMA = "schema"
    ENTRIES = "entries"
    ACL = "acl"
    INTEGRATION = "integration"


class AttributeTestType(StrEnum):
    """Attribute test types."""

    OLC_PREFIX = "olc_prefix"
    STANDARD = "standard"
    WITH_SYNTAX = "with_syntax"
    SINGLE_VALUE = "single_value"
    MISSING_OID = "missing_oid"


class ObjectClassTestType(StrEnum):
    """ObjectClass test types."""

    OLC_PREFIX = "olc_prefix"
    STANDARD = "standard"
    STRUCTURAL = "structural"
    AUXILIARY = "auxiliary"
    ABSTRACT = "abstract"
    MISSING_OID = "missing_oid"


class AclTestType(StrEnum):
    """ACL test types."""

    TO_BY = "to_by"
    INDEXED = "indexed"
    OLC_ACCESS = "olc_access"
    NON_ACL = "non_acl"


class EntryTestType(StrEnum):
    """Entry test types."""

    CONFIG = "config"
    OLC_ATTRIBUTE = "olc_attribute"
    OLC_OBJECTCLASS = "olc_objectclass"
    STANDARD = "standard"


@pytest.mark.unit
class TestsFlextLdifOpenldapQuirks(s):
    """Consolidated test class for OpenLDAP 2.x quirks."""

    # Pytest fixtures with ClassVar annotations
    ldif_api: ClassVar[FlextLdif]  # pytest fixture
    server: ClassVar[FlextLdifServersOpenldap]  # pytest fixture
    schema_quirk: ClassVar[FlextLdifServersOpenldap.Schema]  # pytest fixture
    acl_quirk: ClassVar[FlextLdifServersOpenldap.Acl]  # pytest fixture
    entry_quirk: ClassVar[FlextLdifServersOpenldap.Entry]  # pytest fixture

    # =========================================================================
    # FIXTURE SCENARIOS
    # =========================================================================
    FIXTURE_SCENARIOS: ClassVar[dict[FixtureType, tuple[str, str, bool]]] = {
        FixtureType.SCHEMA: ("openldap", "openldap_schema_fixtures.ldif", True),
        FixtureType.INTEGRATION: (
            "openldap",
            "openldap_integration_fixtures.ldif",
            True,
        ),
    }

    # =========================================================================
    # ATTRIBUTE TEST SCENARIOS
    # =========================================================================
    ATTRIBUTE_SCENARIOS: ClassVar[
        dict[AttributeTestType, tuple[str, bool, str | None]]
    ] = {
        AttributeTestType.OLC_PREFIX: (
            "olcAttributeTypes: ( 1.2.3.4 NAME 'test' DESC 'Test attribute' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
            True,
            "1.2.3.4",
        ),
        AttributeTestType.STANDARD: (
            "( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC2256: common name(s)' SUP name )",
            True,
            "2.5.4.3",
        ),
        AttributeTestType.WITH_SYNTAX: (
            "( 2.5.4.2 NAME 'knowledgeInformation' DESC 'RFC2256' "
            "EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
            True,
            "2.5.4.2",
        ),
        AttributeTestType.SINGLE_VALUE: (
            "( 2.5.4.6 NAME 'c' DESC 'RFC2256: country name' SUP name SINGLE-VALUE )",
            True,
            "2.5.4.6",
        ),
        AttributeTestType.MISSING_OID: (
            "( NAME 'invalid' DESC 'No OID' )",
            False,
            None,
        ),
    }

    # =========================================================================
    # OBJECTCLASS TEST SCENARIOS
    # =========================================================================
    OBJECTCLASS_SCENARIOS: ClassVar[
        dict[ObjectClassTestType, tuple[str, bool, str | None, str | None]]
    ] = {
        ObjectClassTestType.OLC_PREFIX: (
            "olcObjectClasses: ( 1.2.3.4 NAME 'testClass' DESC 'Test class' "
            "SUP top STRUCTURAL MUST cn MAY description )",
            True,
            "1.2.3.4",
            "STRUCTURAL",
        ),
        ObjectClassTestType.STANDARD: (
            "( 2.5.6.6 NAME 'person' DESC 'RFC2256: person' "
            "MUST ( sn $ cn ) MAY ( userPassword ) )",
            True,
            "2.5.6.6",
            None,
        ),
        ObjectClassTestType.STRUCTURAL: (
            "( 1.3.6.1.4.1.4203.1.4.1 NAME 'olcDatabaseConfig' STRUCTURAL SUP olcConfig )",
            True,
            "1.3.6.1.4.1.4203.1.4.1",
            "STRUCTURAL",
        ),
        ObjectClassTestType.AUXILIARY: (
            "( 1.3.6.1.4.1.4203.1.4.2 NAME 'olcModuleList' AUXILIARY SUP top )",
            True,
            "1.3.6.1.4.1.4203.1.4.2",
            "AUXILIARY",
        ),
        ObjectClassTestType.ABSTRACT: (
            "( 2.5.6.0 NAME 'top' ABSTRACT )",
            True,
            "2.5.6.0",
            "ABSTRACT",
        ),
        ObjectClassTestType.MISSING_OID: (
            "( NAME 'testClass' )",
            False,
            None,
            None,
        ),
    }

    # =========================================================================
    # ACL TEST SCENARIOS
    # =========================================================================
    ACL_SCENARIOS: ClassVar[dict[AclTestType, tuple[str, bool]]] = {
        AclTestType.TO_BY: (
            "to attrs=userPassword by self write by anonymous auth by * none",
            True,
        ),
        AclTestType.INDEXED: ("{0}to * by * read", True),
        AclTestType.OLC_ACCESS: ("olcAccess: to * by * read", True),
        AclTestType.NON_ACL: (
            "random text",
            True,
        ),  # Parser accepts any non-empty string
    }

    # =========================================================================
    # ENTRY TEST SCENARIOS
    # =========================================================================
    ENTRY_SCENARIOS: ClassVar[
        dict[EntryTestType, tuple[str, dict[str, list[str]], bool]]
    ] = {
        EntryTestType.CONFIG: (
            "cn=config",
            {"cn": ["config"]},
            True,
        ),
        EntryTestType.OLC_ATTRIBUTE: (
            "olcDatabase={1}mdb,cn=config",
            {"olcDatabase": ["{1}mdb"], "olcSuffix": ["dc=example,dc=com"]},
            True,
        ),
        EntryTestType.OLC_OBJECTCLASS: (
            "cn=schema,cn=config",
            {"objectclass": ["olcSchemaConfig"]},
            True,
        ),
        EntryTestType.STANDARD: (
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectclass": ["person"]},
            False,
        ),
    }

    # =========================================================================
    # FIXTURES
    # =========================================================================
    @pytest.fixture(scope="class")
    def ldif_api(self) -> FlextLdif:
        """Provides FlextLdif API instance."""
        return FlextLdif()

    @pytest.fixture(scope="class")
    def server(self) -> FlextLdifServersOpenldap:
        """Provides OpenLDAP server instance."""
        return FlextLdifServersOpenldap()

    @pytest.fixture
    def schema_quirk(
        self,
        server: FlextLdifServersOpenldap,
    ) -> FlextLdifServersOpenldap.Schema:
        """Provides OpenLDAP schema quirk instance."""
        quirk = server.schema_quirk
        assert isinstance(quirk, FlextLdifServersOpenldap.Schema)
        return quirk

    @pytest.fixture
    def acl_quirk(
        self,
        server: FlextLdifServersOpenldap,
    ) -> FlextLdifServersOpenldap.Acl:
        """Provides OpenLDAP ACL quirk instance."""
        quirk = server.acl_quirk
        assert isinstance(quirk, FlextLdifServersOpenldap.Acl)
        return quirk

    @pytest.fixture
    def entry_quirk(
        self,
        server: FlextLdifServersOpenldap,
    ) -> FlextLdifServersOpenldap.Entry:
        """Provides OpenLDAP entry quirk instance."""
        quirk = server.entry_quirk
        assert isinstance(quirk, FlextLdifServersOpenldap.Entry)
        return quirk

    # =========================================================================
    # SERVER INITIALIZATION TESTS
    # =========================================================================
    def test_server_initialization(self, server: FlextLdifServersOpenldap) -> None:
        """Test OpenLDAP server initialization."""
        assert server.server_type == "openldap2"
        assert server.priority == 20

    def test_server_has_all_quirks(self, server: FlextLdifServersOpenldap) -> None:
        """Test server has schema, ACL, and entry quirks."""
        assert server.schema_quirk is not None
        assert server.acl_quirk is not None
        assert server.entry_quirk is not None

    # =========================================================================
    # FIXTURE PARSING TESTS (parametrized)
    # =========================================================================
    @pytest.mark.parametrize(
        ("fixture_type", "config"),
        [
            (FixtureType.SCHEMA, FIXTURE_SCENARIOS[FixtureType.SCHEMA]),
            (FixtureType.INTEGRATION, FIXTURE_SCENARIOS[FixtureType.INTEGRATION]),
        ],
        ids=["schema", "integration"],
    )
    def test_parse_fixture(
        self,
        ldif_api: FlextLdif,
        fixture_type: FixtureType,
        config: tuple[str, str, bool],
    ) -> None:
        """Test parsing OpenLDAP fixtures."""
        server_dir, filename, should_have_entries = config
        # server_dir is "openldap" from FIXTURE_SCENARIOS dict
        assert server_dir == "openldap"
        server_type = server_dir
        fixture_path = FlextLdifTestUtils.get_fixture_path(server_type, filename)
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")
        entries = FlextLdifTestUtils.load_fixture(ldif_api, server_type, filename)
        if should_have_entries:
            assert entries is not None
            assert len(entries) > 0

    def test_roundtrip_integration(
        self,
        ldif_api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Test roundtrip of OpenLDAP integration fixture."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api,
            "openldap",
            "openldap_integration_fixtures.ldif",
            tmp_path,
        )

    # =========================================================================
    # ATTRIBUTE TESTS (parametrized)
    # =========================================================================
    @pytest.mark.parametrize(
        ("test_type", "config"),
        [
            (
                AttributeTestType.OLC_PREFIX,
                ATTRIBUTE_SCENARIOS[AttributeTestType.OLC_PREFIX],
            ),
            (
                AttributeTestType.STANDARD,
                ATTRIBUTE_SCENARIOS[AttributeTestType.STANDARD],
            ),
            (
                AttributeTestType.WITH_SYNTAX,
                ATTRIBUTE_SCENARIOS[AttributeTestType.WITH_SYNTAX],
            ),
            (
                AttributeTestType.SINGLE_VALUE,
                ATTRIBUTE_SCENARIOS[AttributeTestType.SINGLE_VALUE],
            ),
        ],
        ids=["olc_prefix", "standard", "with_syntax", "single_value"],
    )
    def test_can_handle_attribute(
        self,
        schema_quirk: FlextLdifServersOpenldap.Schema,
        test_type: AttributeTestType,
        config: tuple[str, bool, str | None],
    ) -> None:
        """Test attribute detection."""
        attr_def, should_handle, _ = config
        result = schema_quirk.can_handle_attribute(attr_def)
        assert result is should_handle

    @pytest.mark.parametrize(
        ("test_type", "config"),
        [
            (
                AttributeTestType.OLC_PREFIX,
                ATTRIBUTE_SCENARIOS[AttributeTestType.OLC_PREFIX],
            ),
            (
                AttributeTestType.STANDARD,
                ATTRIBUTE_SCENARIOS[AttributeTestType.STANDARD],
            ),
            (
                AttributeTestType.WITH_SYNTAX,
                ATTRIBUTE_SCENARIOS[AttributeTestType.WITH_SYNTAX],
            ),
            (
                AttributeTestType.SINGLE_VALUE,
                ATTRIBUTE_SCENARIOS[AttributeTestType.SINGLE_VALUE],
            ),
        ],
        ids=["olc_prefix", "standard", "with_syntax", "single_value"],
    )
    def test_parse_attribute_success(
        self,
        schema_quirk: FlextLdifServersOpenldap.Schema,
        test_type: AttributeTestType,
        config: tuple[str, bool, str | None],
    ) -> None:
        """Test successful attribute parsing."""
        attr_def, _, expected_oid = config
        # Remove olc prefix if present for parsing
        clean_def = attr_def
        if attr_def.startswith("olcAttributeTypes:"):
            clean_def = attr_def.split(": ", 1)[1].strip()
        result = schema_quirk.parse_attribute(clean_def)
        assert result.is_success
        if expected_oid:
            attr = result.value
            assert attr.oid == expected_oid

    def test_parse_attribute_missing_oid(
        self,
        schema_quirk: FlextLdifServersOpenldap.Schema,
    ) -> None:
        """Test attribute parsing fails without OID."""
        attr_def, should_succeed, _ = self.ATTRIBUTE_SCENARIOS[
            AttributeTestType.MISSING_OID
        ]
        result = schema_quirk.parse_attribute(attr_def)
        assert result.is_failure == (not should_succeed)

    def test_can_handle_empty_attribute(
        self,
        schema_quirk: FlextLdifServersOpenldap.Schema,
    ) -> None:
        """Test handling of empty attribute definition."""
        assert schema_quirk.can_handle_attribute("") is False

    # =========================================================================
    # OBJECTCLASS TESTS (parametrized)
    # =========================================================================
    @pytest.mark.parametrize(
        ("test_type", "config"),
        [
            (
                ObjectClassTestType.OLC_PREFIX,
                OBJECTCLASS_SCENARIOS[ObjectClassTestType.OLC_PREFIX],
            ),
            (
                ObjectClassTestType.STANDARD,
                OBJECTCLASS_SCENARIOS[ObjectClassTestType.STANDARD],
            ),
            (
                ObjectClassTestType.STRUCTURAL,
                OBJECTCLASS_SCENARIOS[ObjectClassTestType.STRUCTURAL],
            ),
            (
                ObjectClassTestType.AUXILIARY,
                OBJECTCLASS_SCENARIOS[ObjectClassTestType.AUXILIARY],
            ),
            (
                ObjectClassTestType.ABSTRACT,
                OBJECTCLASS_SCENARIOS[ObjectClassTestType.ABSTRACT],
            ),
        ],
        ids=["olc_prefix", "standard", "structural", "auxiliary", "abstract"],
    )
    def test_can_handle_objectclass(
        self,
        schema_quirk: FlextLdifServersOpenldap.Schema,
        test_type: ObjectClassTestType,
        config: tuple[str, bool, str | None, str | None],
    ) -> None:
        """Test objectClass detection."""
        oc_def, should_handle, _, _ = config
        result = schema_quirk.can_handle_objectclass(oc_def)
        assert result is should_handle

    @pytest.mark.parametrize(
        ("test_type", "config"),
        [
            (
                ObjectClassTestType.OLC_PREFIX,
                OBJECTCLASS_SCENARIOS[ObjectClassTestType.OLC_PREFIX],
            ),
            (
                ObjectClassTestType.STANDARD,
                OBJECTCLASS_SCENARIOS[ObjectClassTestType.STANDARD],
            ),
            (
                ObjectClassTestType.STRUCTURAL,
                OBJECTCLASS_SCENARIOS[ObjectClassTestType.STRUCTURAL],
            ),
            (
                ObjectClassTestType.AUXILIARY,
                OBJECTCLASS_SCENARIOS[ObjectClassTestType.AUXILIARY],
            ),
            (
                ObjectClassTestType.ABSTRACT,
                OBJECTCLASS_SCENARIOS[ObjectClassTestType.ABSTRACT],
            ),
        ],
        ids=["olc_prefix", "standard", "structural", "auxiliary", "abstract"],
    )
    def test_parse_objectclass_success(
        self,
        schema_quirk: FlextLdifServersOpenldap.Schema,
        test_type: ObjectClassTestType,
        config: tuple[str, bool, str | None, str | None],
    ) -> None:
        """Test successful objectClass parsing."""
        oc_def, _, expected_oid, expected_kind = config
        # Remove olc prefix if present for parsing
        clean_def = oc_def
        if oc_def.startswith("olcObjectClasses:"):
            clean_def = oc_def.split(": ", 1)[1].strip()
        result = schema_quirk.parse_objectclass(clean_def)
        assert result.is_success
        if expected_oid:
            oc = result.value
            assert oc.oid == expected_oid
            if expected_kind:
                assert oc.kind == expected_kind

    def test_parse_objectclass_missing_oid(
        self,
        schema_quirk: FlextLdifServersOpenldap.Schema,
    ) -> None:
        """Test objectClass parsing fails without OID."""
        oc_def, should_succeed, _, _ = self.OBJECTCLASS_SCENARIOS[
            ObjectClassTestType.MISSING_OID
        ]
        result = schema_quirk._parse_objectclass(oc_def)
        assert result.is_failure == (not should_succeed)

    # =========================================================================
    # ACL TESTS (parametrized)
    # =========================================================================
    @pytest.mark.parametrize(
        ("test_type", "config"),
        [
            (AclTestType.TO_BY, ACL_SCENARIOS[AclTestType.TO_BY]),
            (AclTestType.INDEXED, ACL_SCENARIOS[AclTestType.INDEXED]),
            (AclTestType.OLC_ACCESS, ACL_SCENARIOS[AclTestType.OLC_ACCESS]),
        ],
        ids=["to_by", "indexed", "olc_access"],
    )
    def test_parse_acl_success(
        self,
        acl_quirk: FlextLdifServersOpenldap.Acl,
        test_type: AclTestType,
        config: tuple[str, bool],
    ) -> None:
        """Test successful ACL parsing."""
        acl_line, should_parse = config
        result = acl_quirk.parse(acl_line)
        assert result.is_success == should_parse
        if should_parse:
            acl = result.value
            assert acl is not None

    def test_acl_can_handle_to_clause(
        self,
        acl_quirk: FlextLdifServersOpenldap.Acl,
    ) -> None:
        """Test ACL detection with 'to' clause."""
        acl_line, _ = self.ACL_SCENARIOS[AclTestType.TO_BY]
        # Parse first to verify valid format
        result = acl_quirk.parse(acl_line)
        assert result.is_success
        assert acl_quirk.can_handle(acl_line) is True

    def test_acl_non_acl_format(
        self,
        acl_quirk: FlextLdifServersOpenldap.Acl,
    ) -> None:
        """Test ACL detection returns false for non-OpenLDAP ACL."""
        acl_line, _ = self.ACL_SCENARIOS[AclTestType.NON_ACL]
        result = acl_quirk.parse(acl_line)
        if result.is_success:
            # Parser accepts any string but can_handle should return False
            assert acl_quirk.can_handle(acl_line) is False

    def test_acl_write_to_rfc(
        self,
        acl_quirk: FlextLdifServersOpenldap.Acl,
    ) -> None:
        """Test writing ACL in RFC format."""
        acl_data = m.Ldif.Acl(
            name="test-acl",
            target=m.Ldif.AclTarget(
                target_dn="*",
                attributes=["userPassword"],
            ),
            subject=m.Ldif.AclSubject(
                subject_type="user",
                subject_value="self",
            ),
            permissions=m.Ldif.AclPermissions(write=True),
            metadata=m.Ldif.QuirkMetadata.create_for("openldap"),
        )
        result = acl_quirk.write(acl_data)
        assert result.is_success
        acl_str = result.value
        assert isinstance(acl_str, str)

    # =========================================================================
    # ENTRY TESTS (parametrized)
    # =========================================================================
    @pytest.mark.parametrize(
        ("test_type", "config"),
        [
            (EntryTestType.CONFIG, ENTRY_SCENARIOS[EntryTestType.CONFIG]),
            (EntryTestType.OLC_ATTRIBUTE, ENTRY_SCENARIOS[EntryTestType.OLC_ATTRIBUTE]),
            (
                EntryTestType.OLC_OBJECTCLASS,
                ENTRY_SCENARIOS[EntryTestType.OLC_OBJECTCLASS],
            ),
            (EntryTestType.STANDARD, ENTRY_SCENARIOS[EntryTestType.STANDARD]),
        ],
        ids=["config", "olc_attribute", "olc_objectclass", "standard"],
    )
    def test_entry_can_handle(
        self,
        entry_quirk: FlextLdifServersOpenldap.Entry,
        test_type: EntryTestType,
        config: tuple[str, dict[str, list[str]], bool],
    ) -> None:
        """Test entry detection."""
        dn, attributes, should_handle = config
        result = entry_quirk.can_handle(dn, attributes)
        assert result is should_handle

    # =========================================================================
    # WRITE TESTS
    # =========================================================================
    def test_write_attribute_to_rfc(
        self,
        schema_quirk: FlextLdifServersOpenldap.Schema,
    ) -> None:
        """Test writing attribute to RFC string format."""
        attr_dict: dict[str, str | bool] = {
            "oid": c.Rfc.ATTR_OID_CN,
            "name": c.Rfc.ATTR_NAME_CN,
            "desc": "common name",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            "single_value": False,
        }
        attr_model = RfcTestHelpers.test_create_schema_attribute_from_dict(
            attr_dict,
        )
        result = schema_quirk.write(attr_model)
        assert result.is_success
        attr_str = result.value
        assert c.Rfc.ATTR_OID_CN in attr_str
        assert c.Rfc.ATTR_NAME_CN in attr_str

    def test_write_objectclass_to_rfc(
        self,
        schema_quirk: FlextLdifServersOpenldap.Schema,
    ) -> None:
        """Test writing objectClass to RFC string format."""
        oc_dict: dict[str, str | list[str]] = {
            "oid": c.Rfc.OC_OID_PERSON,
            "name": c.Rfc.OC_NAME_PERSON,
            "desc": "RFC2256: person",
            "kind": "STRUCTURAL",
            "must": ["sn", "cn"],
            "may": ["userPassword"],
        }
        oc_model = RfcTestHelpers.test_create_schema_objectclass_from_dict(
            oc_dict,
        )
        result = schema_quirk._write_objectclass(oc_model)
        assert result.is_success
        oc_str = result.value
        assert c.Rfc.OC_OID_PERSON in oc_str
        assert c.Rfc.OC_NAME_PERSON in oc_str
        assert "STRUCTURAL" in oc_str
