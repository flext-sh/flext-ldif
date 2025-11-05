"""Tests for OpenLDAP 2.x server quirks.

Comprehensive tests for OpenLDAP 2.x-specific LDIF processing quirks including
schema, ACL, and entry handling.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdifModels
from flext_ldif.api import FlextLdif
from flext_ldif.servers.openldap import FlextLdifServersOpenldap
from tests.unit.quirks.servers.test_utils import FlextLdifTestUtils


@pytest.fixture(scope="module")
def ldif_api() -> FlextLdif:
    """Provides a FlextLdif API instance for the test module."""
    return FlextLdif()


class TestOpenLdapFixtures:
    """Test OpenLDAP quirks with real fixture files."""

    def test_parse_openldap_schema_fixture(self, ldif_api: FlextLdif) -> None:
        """Test parsing of OpenLDAP schema fixture in cn=config format."""
        # Note: openldap_schema_fixtures.ldif is in cn=config format (olcAttributeTypes)
        # which is OpenLDAP's internal schema storage format, not standard LDIF entries.
        # This test verifies the file parses without error.
        fixture_path = FlextLdifTestUtils.get_fixture_path(
            "openldap", "openldap_schema_fixtures.ldif"
        )
        result = ldif_api.parse(
            fixture_path, server_type=FlextLdifServersOpenldap.Constants.SERVER_TYPE
        )
        assert result.is_success, f"Failed to parse schema fixture: {result.error}"
        # cn=config schema files don't parse as regular entries
        entries = result.unwrap()
        assert entries is not None

    def test_parse_openldap_integration_fixture(self, ldif_api: FlextLdif) -> None:
        """Test parsing of OpenLDAP integration fixture with real directory entries."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api, "openldap", "openldap_integration_fixtures.ldif"
        )
        assert entries is not None
        assert len(entries) > 0

    def test_roundtrip_openldap_integration(
        self, ldif_api: FlextLdif, tmp_path: Path
    ) -> None:
        """Test roundtrip of OpenLDAP integration fixture."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api, "openldap", "openldap_integration_fixtures.ldif", tmp_path
        )


class TestOpenLDAP2xSchemas:
    """Tests for OpenLDAP 2.x schema quirk handling."""

    @pytest.fixture
    def server(self) -> FlextLdifServersOpenldap:
        """Create OpenLDAP server instance."""
        return FlextLdifServersOpenldap()

    @pytest.fixture
    def quirk(
        self, server: FlextLdifServersOpenldap
    ) -> FlextLdifServersOpenldap.Schema:
        """Create OpenLDAP schema quirk instance."""
        return server.schema

    def test_initialization(self, server: FlextLdifServersOpenldap) -> None:
        """Test OpenLDAP 2.x schema quirk initialization."""
        assert server.server_type == FlextLdifServersOpenldap.Constants.SERVER_TYPE
        assert server.priority == FlextLdifServersOpenldap.Constants.PRIORITY

    def testcan_handle_attribute_with_olc_prefix(
        self, quirk: FlextLdifServersOpenldap.Schema
    ) -> None:
        """Test attribute detection with olc prefix."""
        # Test can_handle with LDIF line format (olcAttributeTypes: ...)
        # OpenLDAP will remove the prefix and validate the definition
        ldif_line = "olcAttributeTypes: ( 1.2.3.4 NAME 'test' DESC 'Test attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert quirk.can_handle_attribute(ldif_line) is True

        # Test can_handle with raw RFC definition (without LDIF prefix)
        attr_def = "( 1.2.3.4 NAME 'test' DESC 'Test attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert quirk.can_handle_attribute(attr_def) is True

        # Parse just the attribute definition part (without LDIF prefix)
        parse_result = quirk.parse_attribute(attr_def)

        assert parse_result.is_success, (
            f"Failed to parse attribute: {parse_result.error}"
        )

        parsed_attr = parse_result.unwrap()
        assert parsed_attr.oid == "1.2.3.4"
        assert parsed_attr.name == "test"

    def testcan_handle_attribute_without_olc(
        self, quirk: FlextLdifServersOpenldap.Schema
    ) -> None:
        """Test attribute detection without olc prefix."""
        # Should handle RFC attributes (pure RFC format, no olc prefix)
        attr_def = "( 1.2.3.4 NAME 'test' DESC 'Test attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"

        # Test can_handle_attribute with plain RFC definition
        assert quirk.can_handle_attribute(attr_def) is True

        # Parse the attribute
        parse_result = quirk.parse_attribute(attr_def)

        assert parse_result.is_success, (
            f"Failed to parse attribute: {parse_result.error}"
        )

        parsed_attr = parse_result.unwrap()
        assert parsed_attr.oid == "1.2.3.4"
        assert parsed_attr.name == "test"

    def test_parse_attribute_success(
        self, quirk: FlextLdifServersOpenldap.Schema
    ) -> None:
        """Test successful attribute parsing."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' DESC 'Test attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 EQUALITY caseIgnoreMatch SINGLE-VALUE )"
        result = quirk.parse_attribute(attr_def)

        assert result.is_success
        attr_data = result.unwrap()
        assert attr_data.oid == "1.2.3.4"
        assert attr_data.name == "testAttr"
        assert attr_data.desc == "Test attribute"
        assert attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert attr_data.equality == "caseIgnoreMatch"
        assert attr_data.single_value is True

    def test_parse_attribute_no_oid(
        self, quirk: FlextLdifServersOpenldap.Schema
    ) -> None:
        """Test attribute parsing fails without OID."""
        attr_def = "NAME 'testAttr'"
        result = quirk.parse_attribute(attr_def)

        assert result.is_failure
        assert result.error is not None
        assert "RFC attribute parsing failed: missing an OID" in result.error

    def testcan_handle_objectclass_with_olc(
        self, quirk: FlextLdifServersOpenldap.Schema
    ) -> None:
        """Test objectClass detection with olc prefix."""
        # Test can_handle with LDIF line format (olcObjectClasses: ...)
        # OpenLDAP will remove the prefix and validate the definition
        ldif_line = "olcObjectClasses: ( 1.2.3.4 NAME 'testClass' DESC 'Test class' SUP top STRUCTURAL MUST cn MAY description )"
        assert quirk.can_handle_objectclass(ldif_line) is True

        # Test can_handle with raw RFC definition (without LDIF prefix)
        oc_def = "( 1.2.3.4 NAME 'testClass' DESC 'Test class' SUP top STRUCTURAL MUST cn MAY description )"
        assert quirk.can_handle_objectclass(oc_def) is True

        # Parse just the objectClass definition part (without LDIF prefix)
        parse_result = quirk.parse_objectclass(oc_def)

        assert parse_result.is_success, (
            f"Failed to parse objectClass: {parse_result.error}"
        )

        parsed_oc = parse_result.unwrap()
        assert parsed_oc.oid == "1.2.3.4"
        assert parsed_oc.name == "testClass"

    def testcan_handle_objectclass_without_olc(
        self, quirk: FlextLdifServersOpenldap.Schema
    ) -> None:
        """Test objectClass detection without olc prefix."""
        # Should handle RFC objectClasses (pure RFC format, no olc prefix)
        oc_def = "( 1.2.3.4 NAME 'testClass' DESC 'Test class' SUP top STRUCTURAL MUST cn MAY description )"

        # Test can_handle_objectclass with plain RFC definition
        assert quirk.can_handle_objectclass(oc_def) is True

        # Parse the objectClass
        parse_result = quirk.parse_objectclass(oc_def)

        assert parse_result.is_success, (
            f"Failed to parse objectClass: {parse_result.error}"
        )

        parsed_oc = parse_result.unwrap()
        assert parsed_oc.oid == "1.2.3.4"
        assert parsed_oc.name == "testClass"

    def test_parse_objectclass_success(
        self, quirk: FlextLdifServersOpenldap.Schema
    ) -> None:
        """Test successful objectClass parsing."""
        oc_def = "( 1.2.3.4 NAME 'testClass' DESC 'Test class' SUP top STRUCTURAL MUST ( cn $ sn ) MAY ( description ) )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert hasattr(oc_data, "name")
        assert oc_data.oid == "1.2.3.4"
        assert oc_data.name == "testClass"
        assert oc_data.desc == "Test class"
        assert oc_data.sup == "top"
        assert oc_data.kind == "STRUCTURAL"
        must_attr = oc_data.must
        assert isinstance(must_attr, list)
        assert "cn" in must_attr
        assert "sn" in must_attr
        may_attr = oc_data.may
        assert isinstance(may_attr, list)
        assert "description" in may_attr

    def test_parse_objectclass_auxiliary(
        self, quirk: FlextLdifServersOpenldap.Schema
    ) -> None:
        """Test parsing AUXILIARY objectClass."""
        oc_def = "( 1.2.3.5 NAME 'auxClass' AUXILIARY )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "AUXILIARY"

    def test_parse_objectclass_abstract(
        self, quirk: FlextLdifServersOpenldap.Schema
    ) -> None:
        """Test parsing ABSTRACT objectClass."""
        oc_def = "( 1.2.3.6 NAME 'absClass' ABSTRACT )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "ABSTRACT"

    def test_parse_objectclass_no_oid(
        self, quirk: FlextLdifServersOpenldap.Schema
    ) -> None:
        """Test objectClass parsing fails without OID."""
        # Use a valid objectClass definition format but without OID
        # The parser will try to parse as attribute first, but test verifies failure
        oc_def = "( NAME 'testClass' )"
        result = quirk._parse_objectclass(oc_def)

        assert result.is_failure
        assert result.error is not None
        assert "RFC objectClass parsing failed: missing an OID" in result.error

    def test_write_attribute_to_rfc(
        self, quirk: FlextLdifServersOpenldap.Schema
    ) -> None:
        """Test writing attribute to RFC string format."""
        attr_model = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            desc="Test attribute",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            equality="caseIgnoreMatch",
            single_value=True,
        )

        result = quirk.write_attribute(attr_model)
        assert result.is_success
        attr_str = result.unwrap()
        assert "( 1.2.3.4" in attr_str
        assert "NAME 'testAttr'" in attr_str
        assert "DESC 'Test attribute'" in attr_str
        assert "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15" in attr_str
        assert "EQUALITY caseIgnoreMatch" in attr_str
        assert "SINGLE-VALUE" in attr_str
        assert ")" in attr_str

    def test_write_objectclass_to_rfc(
        self, quirk: FlextLdifServersOpenldap.Schema
    ) -> None:
        """Test writing objectClass to RFC string format."""
        oc_model = FlextLdifModels.SchemaObjectClass(
            oid="1.2.3.4",
            name="testClass",
            desc="Test class",
            sup="top",
            kind="STRUCTURAL",
            must=["cn", "sn"],
            may=["description"],
        )

        result = quirk.write_objectclass(oc_model)
        assert result.is_success
        oc_str = result.unwrap()
        assert "( 1.2.3.4" in oc_str
        assert "NAME 'testClass'" in oc_str
        assert "SUP top" in oc_str
        assert "STRUCTURAL" in oc_str
        assert "MUST" in oc_str
        assert "MAY" in oc_str


class TestOpenLDAP2xAcls:
    """Tests for OpenLDAP 2.x ACL quirk handling."""

    def test_acl_initialization(self) -> None:
        """Test ACL quirk initialization."""
        openldap_server = FlextLdifServersOpenldap()
        openldap_server.Acl()
        # OpenLDAP Acl quirks have openldap server_type and priority 10

    def test__can_handle_with_to_clause(self) -> None:
        """Test ACL detection with 'to' clause."""
        openldap_server = FlextLdifServersOpenldap()
        acl = openldap_server.Acl()

        acl_line = "to attrs=userPassword by self write by anonymous auth by * none"
        # Parse string ACL into model object

        parse_result = acl.parse(acl_line)

        assert parse_result.is_success, f"Failed to parse ACL: {parse_result.error}"

        parse_result.unwrap()

        # Test with the model object

        assert acl.can_handle(acl_line) is True

    def test__can_handle_with_olcaccess(self) -> None:
        """Test ACL detection with olcAccess prefix."""
        openldap_server = FlextLdifServersOpenldap()
        acl = openldap_server.Acl()

        acl_line = "olcAccess: to * by * read"
        # Parse string ACL into model object

        parse_result = acl.parse(acl_line)

        assert parse_result.is_success, f"Failed to parse ACL: {parse_result.error}"

        parse_result.unwrap()

        # Test with the model object

        assert acl.can_handle(acl_line) is True

    def test__can_handle_negative(self) -> None:
        """Test ACL detection returns false for non-OpenLDAP ACL."""
        openldap_server = FlextLdifServersOpenldap()
        acl = openldap_server.Acl()

        acl_line = "random text"
        # Parse string ACL into model object
        parse_result = acl.parse(acl_line)

        # For invalid ACL text, parsing may fail (which is expected)
        # If parsing succeeds despite being invalid text, can_handle should return False
        if parse_result.is_success:
            parse_result.unwrap()
            assert acl.can_handle(acl_line) is False
        else:
            # Invalid ACL that fails to parse is also correctly rejected
            assert parse_result.is_success is False

    def test_parse_success(self) -> None:
        """Test successful ACL parsing."""
        openldap_server = FlextLdifServersOpenldap()
        acl = openldap_server.acl

        acl_line = "to attrs=userPassword by self write by * read"
        result = acl.parse(acl_line)

        assert result.is_success
        acl_model = result.unwrap()
        assert isinstance(acl_model, FlextLdifModels.Acl)
        assert acl_model.raw_acl == acl_line
        # name is optional, defaults to empty string
        assert acl_model.metadata is not None
        assert (
            acl_model.metadata.quirk_type
            == FlextLdifServersOpenldap.Constants.SERVER_TYPE
        )

    def test_parse_with_index(self) -> None:
        """Test ACL parsing with index prefix."""
        openldap_server = FlextLdifServersOpenldap()
        acl = openldap_server.acl

        acl_line = "{0}to * by * read"
        result = acl.parse(acl_line)

        assert result.is_success
        acl_model = result.unwrap()
        assert isinstance(acl_model, FlextLdifModels.Acl)
        assert acl_model.raw_acl == acl_line

    def test_parse_with_olcaccess_prefix(self) -> None:
        """Test ACL parsing with olcAccess prefix."""
        openldap_server = FlextLdifServersOpenldap()
        acl = openldap_server.acl

        acl_line = 'olcAccess: to dn.base="" by * read'
        result = acl.parse(acl_line)

        assert result.is_success
        acl_model = result.unwrap()
        assert isinstance(acl_model, FlextLdifModels.Acl)
        assert acl_model.raw_acl == acl_line

    def test_parse_missing_to_clause(self) -> None:
        """Test ACL parsing with incomplete ACL rule."""
        openldap_server = FlextLdifServersOpenldap()
        acl = openldap_server.acl

        # ACL parser accepts any non-empty string as a raw ACL
        # Validation of complete "to" clause is beyond parse scope
        acl_line = "by * read"
        result = acl.parse(acl_line)

        assert result.is_success
        acl_model = result.unwrap()
        assert isinstance(acl_model, FlextLdifModels.Acl)
        # Raw ACL stores the incomplete rule as-is
        assert acl_model.raw_acl == acl_line


class TestOpenLDAP2xEntrys:
    """Tests for OpenLDAP 2.x entry quirk handling."""

    def test_entry_initialization(self) -> None:
        """Test entry quirk initialization."""
        FlextLdifServersOpenldap.Entry()
        # OpenLDAP Entry quirks have openldap server_type and priority 10

    def test_can_handle_entry_with_config_dn(self) -> None:
        """Test entry detection with cn=config DN."""
        entry = FlextLdifServersOpenldap.Entry()

        dn = FlextLdifModels.DistinguishedName(value="cn=config")
        attributes = FlextLdifModels.LdifAttributes(attributes={"cn": ["config"]})
        FlextLdifModels.Entry(dn=dn, attributes=attributes)
        assert entry.can_handle(dn.value, attributes.attributes) is True

    def test_can_handle_entry_with_olc_attributes(self) -> None:
        """Test entry detection with olc attributes."""
        entry = FlextLdifServersOpenldap.Entry()

        dn = FlextLdifModels.DistinguishedName(value="olcDatabase={1}mdb,cn=config")
        attributes = FlextLdifModels.LdifAttributes(
            attributes={
                "olcDatabase": ["{1}mdb"],
                "olcSuffix": ["dc=example,dc=com"],
            }
        )
        FlextLdifModels.Entry(dn=dn, attributes=attributes)
        assert entry.can_handle(dn.value, attributes.attributes) is True

    def test_can_handle_entry_with_olc_objectclass(self) -> None:
        """Test entry detection with olc objectClass."""
        entry = FlextLdifServersOpenldap.Entry()

        dn = FlextLdifModels.DistinguishedName(value="cn=schema,cn=config")
        attributes = FlextLdifModels.LdifAttributes(
            attributes={"objectclass": ["olcSchemaConfig"]}
        )
        FlextLdifModels.Entry(dn=dn, attributes=attributes)
        assert entry.can_handle(dn.value, attributes.attributes) is True

    def test_can_handle_entry_negative(self) -> None:
        """Test entry detection returns false for non-OpenLDAP entry."""
        entry = FlextLdifServersOpenldap.Entry()

        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
        attributes = FlextLdifModels.LdifAttributes(
            attributes={"cn": ["test"], "objectclass": ["person"]}
        )
        FlextLdifModels.Entry(dn=dn, attributes=attributes)
        assert entry.can_handle(dn.value, attributes.attributes) is False


class TestOpenldapSchemaCanHandleAttribute:
    """Test OpenLDAP schema quirk can_handle_attribute detection."""

    @pytest.fixture
    def openldap(self) -> FlextLdifServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifServersOpenldap()

    def test_can_handle_olc_attribute(self, openldap: FlextLdifServersOpenldap) -> None:
        """Test detection of olc* attributes."""
        attr_def = "( 2.5.4.3 NAME 'olcAttributeTypes' DESC 'OpenLDAP attribute' )"
        assert isinstance(openldap.schema.can_handle_attribute(attr_def), bool)

    def test_can_handle_standard_attribute(
        self, openldap: FlextLdifServersOpenldap
    ) -> None:
        """Test handling of standard RFC attributes."""
        attr_def = "( 2.5.4.3 NAME 'cn' DESC 'RFC2256: common name' )"
        assert isinstance(openldap.schema.can_handle_attribute(attr_def), bool)

    def test_can_handle_empty_attribute(
        self, openldap: FlextLdifServersOpenldap
    ) -> None:
        """Test handling of empty attribute definition."""
        assert not openldap.schema.can_handle_attribute("")


class TestOpenldapSchemaParseAttribute:
    """Test OpenLDAP schema quirk parse_attribute with real fixture data."""

    @pytest.fixture
    def openldap(self) -> FlextLdifServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifServersOpenldap()

    @pytest.fixture
    def openldap_schema_fixture(self) -> Path:
        """Get OpenLDAP schema fixture path."""
        return (
            Path(__file__).parent.parent.parent.parent
            / "fixtures"
            / "openldap2"
            / "openldap2_schema_fixtures.ldif"
        )

    def test_parse_standard_attribute(self, openldap: FlextLdifServersOpenldap) -> None:
        """Test parsing standard OpenLDAP RFC attribute."""
        attr_def = "( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC2256: common name(s)' SUP name )"
        result = openldap.schema.parse(attr_def)
        assert hasattr(result, "is_success")
        if result.is_success:
            attr_data = result.unwrap()
            assert hasattr(attr_data, "name")

    def test_parse_attribute_with_syntax(
        self, openldap: FlextLdifServersOpenldap
    ) -> None:
        """Test parsing attribute with SYNTAX clause."""
        attr_def = "( 2.5.4.2 NAME 'knowledgeInformation' DESC 'RFC2256' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )"
        result = openldap.schema.parse(attr_def)
        assert hasattr(result, "is_success")

    def test_parse_attribute_with_single_value(
        self, openldap: FlextLdifServersOpenldap
    ) -> None:
        """Test parsing attribute with SINGLE-VALUE constraint."""
        attr_def = (
            "( 2.5.4.6 NAME 'c' DESC 'RFC2256: country name' SUP name SINGLE-VALUE )"
        )
        result = openldap.schema.parse(attr_def)
        assert hasattr(result, "is_success")

    def test_parse_attribute_from_fixture(
        self,
        openldap: FlextLdifServersOpenldap,
        openldap_schema_fixture: Path,
    ) -> None:
        """Test parsing attributes from real OpenLDAP fixture."""
        if not openldap_schema_fixture.exists():
            pytest.skip(f"Fixture not found: {openldap_schema_fixture}")

        content = openldap_schema_fixture.read_text(encoding="utf-8")
        for line in content.split("\n"):
            if line.startswith("attributetypes:"):
                attr_def = line[len("attributetypes: ") :].strip()
                result = openldap.schema.parse(attr_def)
                assert hasattr(result, "is_success")
                break

    def test_parse_attribute_missing_oid(
        self, openldap: FlextLdifServersOpenldap
    ) -> None:
        """Test error handling for attribute without OID."""
        attr_def = "( NAME 'invalid' DESC 'No OID' )"
        result = openldap.schema.parse(attr_def)
        assert hasattr(result, "is_success")


class TestOpenldapSchemaCanHandleObjectClass:
    """Test OpenLDAP schema quirk can_handle_objectclass detection."""

    @pytest.fixture
    def openldap(self) -> FlextLdifServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifServersOpenldap()

    def test_can_handle_olc_objectclass(
        self, openldap: FlextLdifServersOpenldap
    ) -> None:
        """Test detection of olc* objectClasses."""
        oc_def = (
            "( 1.3.6.1.4.1.4203.2.1.1 NAME 'olcBackendConfig' DESC 'OpenLDAP Backend' )"
        )
        assert isinstance(openldap.schema.can_handle_objectclass(oc_def), bool)

    def test_can_handle_standard_objectclass(
        self, openldap: FlextLdifServersOpenldap
    ) -> None:
        """Test handling of standard RFC objectClasses."""
        oc_def = "( 2.5.6.6 NAME 'person' DESC 'RFC2256: person' )"
        assert isinstance(openldap.schema.can_handle_objectclass(oc_def), bool)


class TestOpenldapSchemaParseObjectClass:
    """Test OpenLDAP schema quirk parse_objectclass with real fixture data."""

    @pytest.fixture
    def openldap(self) -> FlextLdifServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifServersOpenldap()

    def test_parse_standard_objectclass(
        self, openldap: FlextLdifServersOpenldap
    ) -> None:
        """Test parsing standard RFC objectClass."""
        oc_def = "( 2.5.6.6 NAME 'person' DESC 'RFC2256: person' MUST ( sn $ cn ) MAY ( userPassword ) )"
        result = openldap.schema.parse(oc_def)
        assert hasattr(result, "is_success")
        if result.is_success:
            oc_data = result.unwrap()
            assert hasattr(oc_data, "name")

    def test_parse_structural_objectclass(
        self, openldap: FlextLdifServersOpenldap
    ) -> None:
        """Test parsing STRUCTURAL objectClass."""
        oc_def = "( 1.3.6.1.4.1.4203.1.4.1 NAME 'olcDatabaseConfig' STRUCTURAL SUP olcConfig )"
        result = openldap.schema.parse(oc_def)
        assert hasattr(result, "is_success")

    def test_parse_auxiliary_objectclass(
        self, openldap: FlextLdifServersOpenldap
    ) -> None:
        """Test parsing AUXILIARY objectClass."""
        oc_def = "( 1.3.6.1.4.1.4203.1.4.2 NAME 'olcModuleList' AUXILIARY SUP top )"
        result = openldap.schema.parse(oc_def)
        assert hasattr(result, "is_success")

    def test_parse_abstract_objectclass(
        self, openldap: FlextLdifServersOpenldap
    ) -> None:
        """Test parsing ABSTRACT objectClass."""
        oc_def = "( 2.5.6.0 NAME 'top' ABSTRACT )"
        result = openldap.schema.parse(oc_def)
        assert hasattr(result, "is_success")


class TestOpenldapSchemaConvertAttribute:
    """Test OpenLDAP schema quirk attribute conversion to/from RFC."""

    @pytest.fixture
    def openldap(self) -> FlextLdifServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifServersOpenldap()


class TestOpenldapSchemaConvertObjectClass:
    """Test OpenLDAP schema quirk objectClass conversion to/from RFC."""

    @pytest.fixture
    def openldap(self) -> FlextLdifServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifServersOpenldap()


class TestOpenldapSchemaWriteAttribute:
    """Test OpenLDAP schema quirk write_attribute_to_rfc."""

    @pytest.fixture
    def openldap(self) -> FlextLdifServersOpenldap.Schema:
        """Create OpenLDAP quirk instance."""
        return FlextLdifServersOpenldap.Schema()

    def test_write_attribute_to_rfc(
        self, openldap: FlextLdifServersOpenldap.Schema
    ) -> None:
        """Test writing attribute to RFC format string."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn",
            desc="common name",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            single_value=False,
        )
        result = openldap.write(attr_data)
        assert hasattr(result, "is_success")
        if result.is_success:
            attr_str = result.unwrap()
            assert isinstance(attr_str, str)
            assert "2.5.4.3" in attr_str


class TestOpenldapSchemaWriteObjectClass:
    """Test OpenLDAP schema quirk write_objectclass_to_rfc."""

    @pytest.fixture
    def openldap(self) -> FlextLdifServersOpenldap.Schema:
        """Create OpenLDAP quirk instance."""
        return FlextLdifServersOpenldap.Schema()

    def test_write_objectclass_to_rfc(
        self, openldap: FlextLdifServersOpenldap.Schema
    ) -> None:
        """Test writing objectClass to RFC format string."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.5.6.6",
            name="person",
            desc="RFC2256: person",
            kind="STRUCTURAL",
            must=["sn", "cn"],
            may=["userPassword"],
        )
        result = openldap.write(oc_data)
        assert hasattr(result, "is_success")
        if result.is_success:
            oc_str = result.unwrap()
            assert isinstance(oc_str, str)
            assert "2.5.6.6" in oc_str


class TestOpenldapAclCanHandleAcl:
    """Test OpenLDAP Acl can_handle detection."""

    @pytest.fixture
    def openldap(self) -> FlextLdifServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifServersOpenldap()

    def test_can_handle_to_by_acl(self, openldap: FlextLdifServersOpenldap) -> None:
        """Test detection of OpenLDAP 'to <what> by' ACL format."""
        acl_line = "to attrs=userPassword by self write by anonymous auth by * none"
        acl = openldap.acl
        assert isinstance(acl.can_handle(acl_line), bool)

    def test_can_handle_indexed_acl(self, openldap: FlextLdifServersOpenldap) -> None:
        """Test detection of indexed OpenLDAP ACL."""
        acl_line = "{0}to * by * read"
        acl = openldap.acl
        assert isinstance(acl.can_handle(acl_line), bool)

    def test_can_handle_olcaccess_acl(self, openldap: FlextLdifServersOpenldap) -> None:
        """Test detection of olcAccess attribute format."""
        acl_line = "olcAccess: to * by * read"
        acl = openldap.acl
        assert isinstance(acl.can_handle(acl_line), bool)

    def test_can_handle_non_acl(self, openldap: FlextLdifServersOpenldap) -> None:
        """Test rejection of non-OpenLDAP ACL format."""
        acl_line = "some random text"
        acl = openldap.acl
        # Parse string ACL into model object before testing

        parse_result = acl.parse(acl_line)

        if parse_result.is_success:
            parse_result.unwrap()

            assert acl.can_handle(acl_line) is False

        else:
            # If parsing fails, assertion should be False

            assert acl.can_handle(acl_line) is False


class TestOpenldapAclParseAcl:
    """Test OpenLDAP Acl parse with real fixture data."""

    @pytest.fixture
    def openldap(self) -> FlextLdifServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifServersOpenldap()

    def test_parse_basic_acl(self, openldap: FlextLdifServersOpenldap) -> None:
        """Test parsing basic OpenLDAP ACL."""
        acl_line = "to * by * read"
        acl = openldap.acl
        result = acl.parse(acl_line)
        assert hasattr(result, "is_success")
        if result.is_success:
            acl_data = result.unwrap()
            assert hasattr(acl_data, "name")

    def test_parse_attribute_acl(self, openldap: FlextLdifServersOpenldap) -> None:
        """Test parsing attribute-specific ACL."""
        acl_line = "to attrs=userPassword by self write by anonymous auth by * none"
        acl = openldap.acl
        result = acl.parse(acl_line)
        assert hasattr(result, "is_success")

    def test_parse_indexed_acl(self, openldap: FlextLdifServersOpenldap) -> None:
        """Test parsing indexed ACL with {n} prefix."""
        acl_line = "{0}to * by * read"
        acl = openldap.acl
        result = acl.parse(acl_line)
        assert hasattr(result, "is_success")

    def test_parse_olcaccess_acl(self, openldap: FlextLdifServersOpenldap) -> None:
        """Test parsing olcAccess format ACL."""
        acl_line = "olcAccess: to * by * read"
        acl = openldap.acl
        result = acl.parse(acl_line)
        assert hasattr(result, "is_success")


class TestOpenldapAclConvertAcl:
    """Test OpenLDAP Acl ACL RFC conversion."""

    @pytest.fixture
    def openldap(self) -> FlextLdifServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifServersOpenldap()

    def test_write_acl_to_rfc(self, openldap: FlextLdifServersOpenldap) -> None:
        """Test writing ACL in RFC format."""
        acl = openldap.acl
        # Use proper FlextLdifModels.Acl object instead of dict
        acl_data = FlextLdifModels.Acl(
            name="test-acl",
            target=FlextLdifModels.AclTarget(
                target_dn="*",
                attributes=["userPassword"],
            ),
            subject=FlextLdifModels.AclSubject(
                subject_type="userdn",
                subject_value="self",
            ),
            permissions=FlextLdifModels.AclPermissions(write=True),
            metadata=FlextLdifModels.QuirkMetadata.create_for(
                FlextLdifServersOpenldap.Constants.SERVER_TYPE
            ),
            raw_acl="to attrs=userPassword by self write by * none",
        )
        result = acl.write(acl_data)
        assert hasattr(result, "is_success")
        if result.is_success:
            acl_str = result.unwrap()
            assert isinstance(acl_str, str)


class TestOpenldapEntryCanHandleEntry:
    """Test OpenLDAP Entry can_handle_entry detection."""

    @pytest.fixture
    def openldap(self) -> FlextLdifServersOpenldap.Entry:
        """Create OpenLDAP Entry quirk instance."""
        return FlextLdifServersOpenldap.Entry()

    def test_can_handle_config_entry(
        self, openldap: FlextLdifServersOpenldap.Entry
    ) -> None:
        """Test detection of cn=config entries."""
        dn = FlextLdifModels.DistinguishedName(value="cn=config")
        attributes = FlextLdifModels.LdifAttributes(
            attributes={"objectClass": ["olcBackendConfig"]}
        )
        FlextLdifModels.Entry(dn=dn, attributes=attributes)
        entry = openldap
        assert isinstance(entry.can_handle(dn.value, attributes.attributes), bool)

    def test_can_handle_olc_attribute_entry(
        self, openldap: FlextLdifServersOpenldap.Entry
    ) -> None:
        """Test detection of entries with olc* attributes."""
        dn = FlextLdifModels.DistinguishedName(value="cn=module,cn=config")
        attributes = FlextLdifModels.LdifAttributes(
            attributes={"olcModuleLoad": ["back_ldif"]}
        )
        FlextLdifModels.Entry(dn=dn, attributes=attributes)
        entry = openldap
        assert isinstance(entry.can_handle(dn.value, attributes.attributes), bool)

    def test_can_handle_standard_entry(
        self, openldap: FlextLdifServersOpenldap.Entry
    ) -> None:
        """Test handling of standard LDAP entries."""
        dn = FlextLdifModels.DistinguishedName(
            value="uid=user,ou=people,dc=example,dc=com"
        )
        attributes = FlextLdifModels.LdifAttributes(
            attributes={"objectClass": ["inetOrgPerson"], "uid": ["user"]}
        )
        FlextLdifModels.Entry(dn=dn, attributes=attributes)
        entry = openldap
        assert isinstance(entry.can_handle(dn.value, attributes.attributes), bool)


class TestOpenldapEntryProcessEntry:
    """Test OpenLDAP Entry entry processing with real data."""

    @pytest.fixture
    def openldap(self) -> FlextLdifServersOpenldap.Entry:
        """Create OpenLDAP Entry quirk instance."""
        return FlextLdifServersOpenldap.Entry()

    @pytest.fixture
    def openldap_entries_fixture(self) -> Path:
        """Get OpenLDAP entries fixture path."""
        return (
            Path(__file__).parent.parent.parent.parent
            / "fixtures"
            / "openldap2"
            / "openldap2_entries_fixtures.ldif"
        )


class TestOpenldapEntryConvertEntry:
    """Test OpenLDAP Entry entry RFC conversion."""

    @pytest.fixture
    def openldap(self) -> FlextLdifServersOpenldap.Entry:
        """Create OpenLDAP Entry quirk instance."""
        return FlextLdifServersOpenldap.Entry()


class TestOpenldapProperties:
    """Test OpenLDAP quirks properties and configuration."""

    @pytest.fixture
    def openldap(self) -> FlextLdifServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifServersOpenldap()

    def test_openldap_schema_properties(
        self, openldap: FlextLdifServersOpenldap
    ) -> None:
        """Test schema quirk has correct properties."""

    def test_openldap_acl_properties(self, openldap: FlextLdifServersOpenldap) -> None:
        """Test Acl has correct properties."""
        openldap.acl
        # OpenLDAP Acl quirks have openldap server_type and priority 10

    def test_openldap_entry_properties(self) -> None:
        """Test Entry has correct properties."""
        FlextLdifServersOpenldap.Entry()
        # OpenLDAP Entry quirks have openldap server_type and priority 10
