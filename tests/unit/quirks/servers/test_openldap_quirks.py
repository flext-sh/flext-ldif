"""Tests for OpenLDAP 2.x server quirks.

Comprehensive tests for OpenLDAP 2.x-specific LDIF processing quirks including
schema, ACL, and entry handling.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.quirks.servers.openldap_quirks import FlextLdifQuirksServersOpenldap


class TestOpenLDAP2xSchemaQuirks:
    """Tests for OpenLDAP 2.x schema quirk handling."""

    def test_initialization(self) -> None:
        """Test OpenLDAP 2.x schema quirk initialization."""
        quirk = FlextLdifQuirksServersOpenldap()
        assert quirk.server_type == "openldap2"
        assert quirk.priority == 10

    def test_can_handle_attribute_with_olc_prefix(self) -> None:
        """Test attribute detection with olc prefix."""
        quirk = FlextLdifQuirksServersOpenldap()

        # Should handle olcAttributeTypes
        attr_def = "olcAttributeTypes: ( 1.2.3.4 NAME 'test' )"
        assert quirk.can_handle_attribute(attr_def) is True

        # Should handle olcAccess
        acl_def = "olcAccess: to * by * read"
        assert quirk.can_handle_attribute(acl_def) is True

    def test_can_handle_attribute_without_olc(self) -> None:
        """Test attribute detection without olc prefix."""
        quirk = FlextLdifQuirksServersOpenldap()

        # Should not handle non-olc attributes
        attr_def = "( 1.2.3.4 NAME 'test' )"
        assert quirk.can_handle_attribute(attr_def) is False

    def test_parse_attribute_success(self) -> None:
        """Test successful attribute parsing."""
        quirk = FlextLdifQuirksServersOpenldap()

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

    def test_parse_attribute_no_oid(self) -> None:
        """Test attribute parsing fails without OID."""
        quirk = FlextLdifQuirksServersOpenldap()

        attr_def = "NAME 'testAttr'"
        result = quirk.parse_attribute(attr_def)

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "No OID found" in result.error

    def test_can_handle_objectclass_with_olc(self) -> None:
        """Test objectClass detection with olc prefix."""
        quirk = FlextLdifQuirksServersOpenldap()

        oc_def = "olcObjectClasses: ( 1.2.3.4 NAME 'testClass' )"
        assert quirk.can_handle_objectclass(oc_def) is True

    def test_can_handle_objectclass_without_olc(self) -> None:
        """Test objectClass detection without olc prefix."""
        quirk = FlextLdifQuirksServersOpenldap()

        oc_def = "( 1.2.3.4 NAME 'testClass' )"
        assert quirk.can_handle_objectclass(oc_def) is False

    def test_parse_objectclass_success(self) -> None:
        """Test successful objectClass parsing."""
        quirk = FlextLdifQuirksServersOpenldap()

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

    def test_parse_objectclass_auxiliary(self) -> None:
        """Test parsing AUXILIARY objectClass."""
        quirk = FlextLdifQuirksServersOpenldap()

        oc_def = "( 1.2.3.5 NAME 'auxClass' AUXILIARY )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "AUXILIARY"

    def test_parse_objectclass_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        quirk = FlextLdifQuirksServersOpenldap()

        oc_def = "( 1.2.3.6 NAME 'absClass' ABSTRACT )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "ABSTRACT"

    def test_parse_objectclass_no_oid(self) -> None:
        """Test objectClass parsing fails without OID."""
        quirk = FlextLdifQuirksServersOpenldap()

        oc_def = "NAME 'testClass'"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "No OID found" in result.error

    def test_convert_attribute_to_rfc(self) -> None:
        """Test attribute conversion to RFC format."""
        quirk = FlextLdifQuirksServersOpenldap()

        attr_data: dict[str, object] = {
            "oid": "1.2.3.4",
            "name": "testAttr",
            "desc": "Test",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            "equality": "caseIgnoreMatch",
            "single_value": True,
        }

        result = quirk.convert_attribute_to_rfc(attr_data)
        assert result.is_success
        rfc_data = result.unwrap()
        assert rfc_data["oid"] == "1.2.3.4"
        assert rfc_data["name"] == "testAttr"

    def test_convert_objectclass_to_rfc(self) -> None:
        """Test objectClass conversion to RFC format."""
        quirk = FlextLdifQuirksServersOpenldap()

        oc_data: dict[str, object] = {
            "oid": "1.2.3.4",
            "name": "testClass",
            "desc": "Test",
            "sup": "top",
            "kind": "STRUCTURAL",
            "must": ["cn"],
            "may": ["description"],
        }

        result = quirk.convert_objectclass_to_rfc(oc_data)
        assert result.is_success
        rfc_data = result.unwrap()
        assert rfc_data["oid"] == "1.2.3.4"
        assert rfc_data["kind"] == "STRUCTURAL"

    def test_convert_attribute_from_rfc(self) -> None:
        """Test attribute conversion from RFC format."""
        quirk = FlextLdifQuirksServersOpenldap()

        rfc_data: dict[str, object] = {
            "oid": "1.2.3.4",
            "name": "testAttr",
            "desc": "Test",
        }

        result = quirk.convert_attribute_from_rfc(rfc_data)
        assert result.is_success
        openldap_data = result.unwrap()
        assert openldap_data["server_type"] == "openldap2"
        assert openldap_data.oid == "1.2.3.4"

    def test_convert_objectclass_from_rfc(self) -> None:
        """Test objectClass conversion from RFC format."""
        quirk = FlextLdifQuirksServersOpenldap()

        rfc_data: dict[str, object] = {
            "oid": "1.2.3.4",
            "name": "testClass",
        }

        result = quirk.convert_objectclass_from_rfc(rfc_data)
        assert result.is_success
        openldap_data = result.unwrap()
        assert openldap_data["server_type"] == "openldap2"

    def test_write_attribute_to_rfc(self) -> None:
        """Test writing attribute to RFC string format."""
        quirk = FlextLdifQuirksServersOpenldap()

        attr_data: dict[str, object] = {
            "oid": "1.2.3.4",
            "name": "testAttr",
            "desc": "Test attribute",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            "equality": "caseIgnoreMatch",
            "single_value": True,
        }

        result = quirk.write_attribute_to_rfc(attr_data)
        assert result.is_success
        attr_str = result.unwrap()
        assert "( 1.2.3.4" in attr_str
        assert "NAME 'testAttr'" in attr_str
        assert "DESC 'Test attribute'" in attr_str
        assert "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15" in attr_str
        assert "EQUALITY caseIgnoreMatch" in attr_str
        assert "SINGLE-VALUE" in attr_str
        assert ")" in attr_str

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        quirk = FlextLdifQuirksServersOpenldap()

        oc_data: dict[str, object] = {
            "oid": "1.2.3.4",
            "name": "testClass",
            "desc": "Test class",
            "sup": "top",
            "kind": "STRUCTURAL",
            "must": ["cn", "sn"],
            "may": ["description"],
        }

        result = quirk.write_objectclass_to_rfc(oc_data)
        assert result.is_success
        oc_str = result.unwrap()
        assert "( 1.2.3.4" in oc_str
        assert "NAME 'testClass'" in oc_str
        assert "SUP top" in oc_str
        assert "STRUCTURAL" in oc_str
        assert "MUST" in oc_str
        assert "MAY" in oc_str


class TestOpenLDAP2xAclQuirks:
    """Tests for OpenLDAP 2.x ACL quirk handling."""

    def test_acl_quirk_initialization(self) -> None:
        """Test ACL quirk initialization."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        acl_quirk = main_quirk.AclQuirk()
        assert acl_quirk.server_type == "generic"
        assert acl_quirk.priority == 10

    def test_can_handle_acl_with_to_clause(self) -> None:
        """Test ACL detection with 'to' clause."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        acl_quirk = main_quirk.AclQuirk()

        acl_line = "to attrs=userPassword by self write by anonymous auth by * none"
        assert acl_quirk.can_handle_acl(acl_line) is True

    def test_can_handle_acl_with_olcaccess(self) -> None:
        """Test ACL detection with olcAccess prefix."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        acl_quirk = main_quirk.AclQuirk()

        acl_line = "olcAccess: to * by * read"
        assert acl_quirk.can_handle_acl(acl_line) is True

    def test_can_handle_acl_negative(self) -> None:
        """Test ACL detection returns false for non-OpenLDAP ACL."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        acl_quirk = main_quirk.AclQuirk()

        acl_line = "random text"
        assert acl_quirk.can_handle_acl(acl_line) is False

    def test_parse_acl_success(self) -> None:
        """Test successful ACL parsing."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        acl_quirk = main_quirk.AclQuirk()

        acl_line = "to attrs=userPassword by self write by * read"
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_success
        acl_data = result.unwrap()
        assert hasattr(acl_data, "name")
        assert acl_data["type"] == "openldap2_acl"
        assert acl_data["what"] == "attrs=userPassword"
        by_clauses = acl_data["by_clauses"]
        assert isinstance(by_clauses, list)
        assert len(by_clauses) == 2
        first_clause = by_clauses[0]
        assert hasattr(first_clause, "name")
        assert first_clause["who"] == "self"
        assert first_clause["access"] == "write"

    def test_parse_acl_with_index(self) -> None:
        """Test ACL parsing with index prefix."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        acl_quirk = main_quirk.AclQuirk()

        acl_line = "{0}to * by * read"
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_success
        acl_data = result.unwrap()
        assert acl_data["index"] == 0
        assert acl_data["what"] == "*"

    def test_parse_acl_with_olcaccess_prefix(self) -> None:
        """Test ACL parsing with olcAccess prefix."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        acl_quirk = main_quirk.AclQuirk()

        acl_line = 'olcAccess: to dn.base="" by * read'
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_success
        acl_data = result.unwrap()
        assert acl_data["format"] == "olcAccess"

    def test_parse_acl_missing_to_clause(self) -> None:
        """Test ACL parsing fails without 'to' clause."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        acl_quirk = main_quirk.AclQuirk()

        acl_line = "by * read"
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_failure
        assert result.error is not None
        assert "missing 'to' clause" in result.error.lower()

    def test_convert_acl_to_rfc(self) -> None:
        """Test ACL conversion to RFC format."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        acl_quirk = main_quirk.AclQuirk()

        acl_data: dict[str, object] = {
            "type": "openldap2_acl",
            "what": "*",
            "by_clauses": [{"who": "*", "access": "read"}],
        }

        result = acl_quirk.convert_acl_to_rfc(acl_data)
        assert result.is_success
        rfc_data = result.unwrap()
        assert rfc_data["type"] == "acl"
        assert rfc_data["format"] == "rfc_generic"

    def test_convert_acl_from_rfc(self) -> None:
        """Test ACL conversion from RFC format."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        acl_quirk = main_quirk.AclQuirk()

        acl_data: dict[str, object] = {"type": "acl", "format": "rfc_generic"}
        result = acl_quirk.convert_acl_from_rfc(acl_data)

        assert result.is_success
        openldap_data = result.unwrap()
        assert openldap_data["format"] == "openldap2"


class TestOpenLDAP2xEntryQuirks:
    """Tests for OpenLDAP 2.x entry quirk handling."""

    def test_entry_quirk_initialization(self) -> None:
        """Test entry quirk initialization."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        entry_quirk = main_quirk.EntryQuirk()
        assert entry_quirk.server_type == "generic"
        assert entry_quirk.priority == 10

    def test_can_handle_entry_with_config_dn(self) -> None:
        """Test entry detection with cn=config DN."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        entry_quirk = main_quirk.EntryQuirk()

        dn = "cn=config"
        attributes: dict[str, object] = {"cn": ["config"]}
        assert entry_quirk.can_handle_entry(dn, attributes) is True

    def test_can_handle_entry_with_olc_attributes(self) -> None:
        """Test entry detection with olc attributes."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        entry_quirk = main_quirk.EntryQuirk()

        dn = "olcDatabase={1}mdb,cn=config"
        attributes: dict[str, object] = {
            "olcDatabase": ["{1}mdb"],
            "olcSuffix": ["dc=example,dc=com"],
        }
        assert entry_quirk.can_handle_entry(dn, attributes) is True

    def test_can_handle_entry_with_olc_objectclass(self) -> None:
        """Test entry detection with olc objectClass."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        entry_quirk = main_quirk.EntryQuirk()

        dn = "cn=schema,cn=config"
        attributes: dict[str, object] = {"objectclass": ["olcSchemaConfig"]}
        assert entry_quirk.can_handle_entry(dn, attributes) is True

    def test_can_handle_entry_negative(self) -> None:
        """Test entry detection returns false for non-OpenLDAP entry."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        entry_quirk = main_quirk.EntryQuirk()

        dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {"cn": ["test"], "objectclass": ["person"]}
        assert entry_quirk.can_handle_entry(dn, attributes) is False

    def test_process_entry_success(self) -> None:
        """Test successful entry processing."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        entry_quirk = main_quirk.EntryQuirk()

        dn = "cn=config"
        attributes: dict[str, object] = {"cn": ["config"], "objectclass": ["olcGlobal"]}
        result = entry_quirk.process_entry(dn, attributes)

        assert result.is_success
        entry_data = result.unwrap()
        assert entry_data["dn"] == dn
        assert entry_data["server_type"] == "openldap2"
        assert entry_data["is_config_entry"] is True
        assert entry_data["cn"] == ["config"]

    def test_process_entry_non_config(self) -> None:
        """Test processing non-config entry."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        entry_quirk = main_quirk.EntryQuirk()

        dn = "cn=user,dc=example,dc=com"
        attributes: dict[str, object] = {"cn": ["user"], "objectclass": ["person"]}
        result = entry_quirk.process_entry(dn, attributes)

        assert result.is_success
        entry_data = result.unwrap()
        assert entry_data["is_config_entry"] is False

    def test_convert_entry_to_rfc(self) -> None:
        """Test entry conversion to RFC format."""
        main_quirk = FlextLdifQuirksServersOpenldap()
        entry_quirk = main_quirk.EntryQuirk()

        entry_data: dict[str, object] = {
            "dn": "cn=config",
            "cn": ["config"],
            "objectclass": ["olcGlobal"],
        }

        result = entry_quirk.convert_entry_to_rfc(entry_data)
        assert result.is_success
        # OpenLDAP entries are RFC-compliant, so should return unchanged
        rfc_data = result.unwrap()
        assert rfc_data["dn"] == "cn=config"


# NOTE: OpenLDAP quirks do not implement extract_schemas_from_ldif() method.
# That method only exists in OID and OUD quirks. OpenLDAP comprehensive tests
# would require implementing that method first, which is beyond the scope of
# the current Phase 5 refactoring (which focused on OID/OUD schema extraction).


# ===== Merged from test_openldap_quirks_phase6d.py =====


class TestOpenldapSchemaQuirkCanHandleAttribute:
    """Test OpenLDAP schema quirk can_handle_attribute detection."""

    @pytest.fixture
    def openldap_quirk(self) -> FlextLdifQuirksServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifQuirksServersOpenldap()

    def test_can_handle_olc_attribute(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test detection of olc* attributes."""
        attr_def = "( 2.5.4.3 NAME 'olcAttributeTypes' DESC 'OpenLDAP attribute' )"
        assert isinstance(openldap_quirk.can_handle_attribute(attr_def), bool)

    def test_can_handle_standard_attribute(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test handling of standard RFC attributes."""
        attr_def = "( 2.5.4.3 NAME 'cn' DESC 'RFC2256: common name' )"
        assert isinstance(openldap_quirk.can_handle_attribute(attr_def), bool)

    def test_can_handle_empty_attribute(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test handling of empty attribute definition."""
        assert not openldap_quirk.can_handle_attribute("")


class TestOpenldapSchemaQuirkParseAttribute:
    """Test OpenLDAP schema quirk parse_attribute with real fixture data."""

    @pytest.fixture
    def openldap_quirk(self) -> FlextLdifQuirksServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifQuirksServersOpenldap()

    @pytest.fixture
    def openldap_schema_fixture(self) -> Path:
        """Get OpenLDAP schema fixture path."""
        return (
            Path(__file__).parent.parent.parent.parent
            / "fixtures"
            / "openldap2"
            / "openldap2_schema_fixtures.ldif"
        )

    def test_parse_standard_attribute(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test parsing standard OpenLDAP RFC attribute."""
        attr_def = "( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC2256: common name(s)' SUP name )"
        result = openldap_quirk.parse_attribute(attr_def)
        assert hasattr(result, "is_success")
        if result.is_success:
            attr_data = result.unwrap()
            assert hasattr(attr_data, "name")

    def test_parse_attribute_with_syntax(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test parsing attribute with SYNTAX clause."""
        attr_def = "( 2.5.4.2 NAME 'knowledgeInformation' DESC 'RFC2256' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )"
        result = openldap_quirk.parse_attribute(attr_def)
        assert hasattr(result, "is_success")

    def test_parse_attribute_with_single_value(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test parsing attribute with SINGLE-VALUE constraint."""
        attr_def = (
            "( 2.5.4.6 NAME 'c' DESC 'RFC2256: country name' SUP name SINGLE-VALUE )"
        )
        result = openldap_quirk.parse_attribute(attr_def)
        assert hasattr(result, "is_success")

    def test_parse_attribute_from_fixture(
        self,
        openldap_quirk: FlextLdifQuirksServersOpenldap,
        openldap_schema_fixture: Path,
    ) -> None:
        """Test parsing attributes from real OpenLDAP fixture."""
        if not openldap_schema_fixture.exists():
            pytest.skip(f"Fixture not found: {openldap_schema_fixture}")

        content = openldap_schema_fixture.read_text(encoding="utf-8")
        for line in content.split("\n"):
            if line.startswith("attributetypes:"):
                attr_def = line[len("attributetypes: ") :].strip()
                result = openldap_quirk.parse_attribute(attr_def)
                assert hasattr(result, "is_success")
                break

    def test_parse_attribute_missing_oid(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test error handling for attribute without OID."""
        attr_def = "( NAME 'invalid' DESC 'No OID' )"
        result = openldap_quirk.parse_attribute(attr_def)
        assert hasattr(result, "is_success")


class TestOpenldapSchemaQuirkCanHandleObjectClass:
    """Test OpenLDAP schema quirk can_handle_objectclass detection."""

    @pytest.fixture
    def openldap_quirk(self) -> FlextLdifQuirksServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifQuirksServersOpenldap()

    def test_can_handle_olc_objectclass(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test detection of olc* objectClasses."""
        oc_def = (
            "( 1.3.6.1.4.1.4203.2.1.1 NAME 'olcBackendConfig' DESC 'OpenLDAP Backend' )"
        )
        assert isinstance(openldap_quirk.can_handle_objectclass(oc_def), bool)

    def test_can_handle_standard_objectclass(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test handling of standard RFC objectClasses."""
        oc_def = "( 2.5.6.6 NAME 'person' DESC 'RFC2256: person' )"
        assert isinstance(openldap_quirk.can_handle_objectclass(oc_def), bool)


class TestOpenldapSchemaQuirkParseObjectClass:
    """Test OpenLDAP schema quirk parse_objectclass with real fixture data."""

    @pytest.fixture
    def openldap_quirk(self) -> FlextLdifQuirksServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifQuirksServersOpenldap()

    def test_parse_standard_objectclass(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test parsing standard RFC objectClass."""
        oc_def = "( 2.5.6.6 NAME 'person' DESC 'RFC2256: person' MUST ( sn $ cn ) MAY ( userPassword ) )"
        result = openldap_quirk.parse_objectclass(oc_def)
        assert hasattr(result, "is_success")
        if result.is_success:
            oc_data = result.unwrap()
            assert hasattr(oc_data, "name")

    def test_parse_structural_objectclass(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test parsing STRUCTURAL objectClass."""
        oc_def = "( 1.3.6.1.4.1.4203.1.4.1 NAME 'olcDatabaseConfig' STRUCTURAL SUP olcConfig )"
        result = openldap_quirk.parse_objectclass(oc_def)
        assert hasattr(result, "is_success")

    def test_parse_auxiliary_objectclass(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test parsing AUXILIARY objectClass."""
        oc_def = "( 1.3.6.1.4.1.4203.1.4.2 NAME 'olcModuleList' AUXILIARY SUP top )"
        result = openldap_quirk.parse_objectclass(oc_def)
        assert hasattr(result, "is_success")

    def test_parse_abstract_objectclass(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test parsing ABSTRACT objectClass."""
        oc_def = "( 2.5.6.0 NAME 'top' ABSTRACT )"
        result = openldap_quirk.parse_objectclass(oc_def)
        assert hasattr(result, "is_success")


class TestOpenldapSchemaQuirkConvertAttribute:
    """Test OpenLDAP schema quirk attribute conversion to/from RFC."""

    @pytest.fixture
    def openldap_quirk(self) -> FlextLdifQuirksServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifQuirksServersOpenldap()

    def test_convert_attribute_to_rfc(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test converting OpenLDAP attribute to RFC format."""
        attr_data = {
            "oid": "2.5.4.3",
            "name": "cn",
            "desc": "common name",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            "single_value": False,
        }
        result = openldap_quirk.convert_attribute_to_rfc(attr_data)
        assert hasattr(result, "is_success")

    def test_convert_attribute_from_rfc(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test converting RFC attribute to OpenLDAP format."""
        rfc_data = {
            "oid": "2.5.4.3",
            "name": "cn",
            "desc": "common name",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
        }
        result = openldap_quirk.convert_attribute_from_rfc(rfc_data)
        assert hasattr(result, "is_success")


class TestOpenldapSchemaQuirkConvertObjectClass:
    """Test OpenLDAP schema quirk objectClass conversion to/from RFC."""

    @pytest.fixture
    def openldap_quirk(self) -> FlextLdifQuirksServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifQuirksServersOpenldap()

    def test_convert_objectclass_to_rfc(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test converting OpenLDAP objectClass to RFC format."""
        oc_data = {
            "oid": "2.5.6.6",
            "name": "person",
            "desc": "RFC2256: person",
            "kind": "STRUCTURAL",
            "must": ["sn", "cn"],
            "may": ["userPassword"],
        }
        result = openldap_quirk.convert_objectclass_to_rfc(oc_data)
        assert hasattr(result, "is_success")

    def test_convert_objectclass_from_rfc(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test converting RFC objectClass to OpenLDAP format."""
        rfc_data = {
            "oid": "2.5.6.6",
            "name": "person",
            "desc": "RFC2256: person",
            "kind": "STRUCTURAL",
            "must": ["sn", "cn"],
            "may": [],
        }
        result = openldap_quirk.convert_objectclass_from_rfc(rfc_data)
        assert hasattr(result, "is_success")


class TestOpenldapSchemaQuirkWriteAttribute:
    """Test OpenLDAP schema quirk write_attribute_to_rfc."""

    @pytest.fixture
    def openldap_quirk(self) -> FlextLdifQuirksServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifQuirksServersOpenldap()

    def test_write_attribute_to_rfc(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test writing attribute to RFC format string."""
        attr_data = {
            "oid": "2.5.4.3",
            "name": "cn",
            "desc": "common name",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            "single_value": False,
        }
        result = openldap_quirk.write_attribute_to_rfc(attr_data)
        assert hasattr(result, "is_success")
        if result.is_success:
            attr_str = result.unwrap()
            assert isinstance(attr_str, str)
            assert "2.5.4.3" in attr_str


class TestOpenldapSchemaQuirkWriteObjectClass:
    """Test OpenLDAP schema quirk write_objectclass_to_rfc."""

    @pytest.fixture
    def openldap_quirk(self) -> FlextLdifQuirksServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifQuirksServersOpenldap()

    def test_write_objectclass_to_rfc(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test writing objectClass to RFC format string."""
        oc_data = {
            "oid": "2.5.6.6",
            "name": "person",
            "desc": "RFC2256: person",
            "kind": "STRUCTURAL",
            "must": ["sn", "cn"],
            "may": ["userPassword"],
        }
        result = openldap_quirk.write_objectclass_to_rfc(oc_data)
        assert hasattr(result, "is_success")
        if result.is_success:
            oc_str = result.unwrap()
            assert isinstance(oc_str, str)
            assert "2.5.6.6" in oc_str


class TestOpenldapAclQuirkCanHandleAcl:
    """Test OpenLDAP AclQuirk can_handle_acl detection."""

    @pytest.fixture
    def openldap_quirk(self) -> FlextLdifQuirksServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifQuirksServersOpenldap()

    def test_can_handle_to_by_acl(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test detection of OpenLDAP 'to <what> by' ACL format."""
        acl_line = "to attrs=userPassword by self write by anonymous auth by * none"
        acl_quirk = openldap_quirk.AclQuirk()
        assert isinstance(acl_quirk.can_handle_acl(acl_line), bool)

    def test_can_handle_indexed_acl(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test detection of indexed OpenLDAP ACL."""
        acl_line = "{0}to * by * read"
        acl_quirk = openldap_quirk.AclQuirk()
        assert isinstance(acl_quirk.can_handle_acl(acl_line), bool)

    def test_can_handle_olcaccess_acl(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test detection of olcAccess attribute format."""
        acl_line = "olcAccess: to * by * read"
        acl_quirk = openldap_quirk.AclQuirk()
        assert isinstance(acl_quirk.can_handle_acl(acl_line), bool)

    def test_can_handle_non_acl(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test rejection of non-OpenLDAP ACL format."""
        acl_line = "some random text"
        acl_quirk = openldap_quirk.AclQuirk()
        assert not acl_quirk.can_handle_acl(acl_line)


class TestOpenldapAclQuirkParseAcl:
    """Test OpenLDAP AclQuirk parse_acl with real fixture data."""

    @pytest.fixture
    def openldap_quirk(self) -> FlextLdifQuirksServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifQuirksServersOpenldap()

    def test_parse_basic_acl(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test parsing basic OpenLDAP ACL."""
        acl_line = "to * by * read"
        acl_quirk = openldap_quirk.AclQuirk()
        result = acl_quirk.parse_acl(acl_line)
        assert hasattr(result, "is_success")
        if result.is_success:
            acl_data = result.unwrap()
            assert hasattr(acl_data, "name")

    def test_parse_attribute_acl(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test parsing attribute-specific ACL."""
        acl_line = "to attrs=userPassword by self write by anonymous auth by * none"
        acl_quirk = openldap_quirk.AclQuirk()
        result = acl_quirk.parse_acl(acl_line)
        assert hasattr(result, "is_success")

    def test_parse_indexed_acl(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test parsing indexed ACL with {n} prefix."""
        acl_line = "{0}to * by * read"
        acl_quirk = openldap_quirk.AclQuirk()
        result = acl_quirk.parse_acl(acl_line)
        assert hasattr(result, "is_success")

    def test_parse_olcaccess_acl(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test parsing olcAccess format ACL."""
        acl_line = "olcAccess: to * by * read"
        acl_quirk = openldap_quirk.AclQuirk()
        result = acl_quirk.parse_acl(acl_line)
        assert hasattr(result, "is_success")


class TestOpenldapAclQuirkConvertAcl:
    """Test OpenLDAP AclQuirk ACL RFC conversion."""

    @pytest.fixture
    def openldap_quirk(self) -> FlextLdifQuirksServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifQuirksServersOpenldap()

    def test_convert_acl_to_rfc(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test converting OpenLDAP ACL to RFC format."""
        acl_quirk = openldap_quirk.AclQuirk()
        acl_data = {
            "type": "openldap2_acl",
            "format": "olcAccess",
            "what": "attrs=userPassword",
            "by_clauses": [{"who": "self", "access": "write"}],
        }
        result = acl_quirk.convert_acl_to_rfc(acl_data)
        assert hasattr(result, "is_success")

    def test_convert_acl_from_rfc(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test converting RFC ACL to OpenLDAP format."""
        acl_quirk = openldap_quirk.AclQuirk()
        rfc_data = {
            "type": "acl",
            "format": "generic_rfc",
            "permissions": [{"action": "allow", "operations": ["read"]}],
        }
        result = acl_quirk.convert_acl_from_rfc(rfc_data)
        assert hasattr(result, "is_success")

    def test_write_acl_to_rfc(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test writing ACL in RFC format."""
        acl_quirk = openldap_quirk.AclQuirk()
        acl_data = {
            "what": "attrs=userPassword",
            "by_clauses": [
                {"who": "self", "access": "write"},
                {"who": "*", "access": "none"},
            ],
        }
        result = acl_quirk.write_acl_to_rfc(acl_data)
        assert hasattr(result, "is_success")
        if result.is_success:
            acl_str = result.unwrap()
            assert isinstance(acl_str, str)


class TestOpenldapEntryQuirkCanHandleEntry:
    """Test OpenLDAP EntryQuirk can_handle_entry detection."""

    @pytest.fixture
    def openldap_quirk(self) -> FlextLdifQuirksServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifQuirksServersOpenldap()

    def test_can_handle_config_entry(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test detection of cn=config entries."""
        dn = "cn=config"
        attributes = {"objectClass": ["olcBackendConfig"]}
        entry_quirk = openldap_quirk.EntryQuirk()
        assert isinstance(entry_quirk.can_handle_entry(dn, attributes), bool)

    def test_can_handle_olc_attribute_entry(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test detection of entries with olc* attributes."""
        dn = "cn=module,cn=config"
        attributes = {"olcModuleLoad": "back_ldif"}
        entry_quirk = openldap_quirk.EntryQuirk()
        assert isinstance(entry_quirk.can_handle_entry(dn, attributes), bool)

    def test_can_handle_standard_entry(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test handling of standard LDAP entries."""
        dn = "uid=user,ou=people,dc=example,dc=com"
        attributes = {"objectClass": ["inetOrgPerson"], "uid": ["user"]}
        entry_quirk = openldap_quirk.EntryQuirk()
        assert isinstance(entry_quirk.can_handle_entry(dn, attributes), bool)


class TestOpenldapEntryQuirkProcessEntry:
    """Test OpenLDAP EntryQuirk entry processing with real data."""

    @pytest.fixture
    def openldap_quirk(self) -> FlextLdifQuirksServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifQuirksServersOpenldap()

    @pytest.fixture
    def openldap_entries_fixture(self) -> Path:
        """Get OpenLDAP entries fixture path."""
        return (
            Path(__file__).parent.parent.parent.parent
            / "fixtures"
            / "openldap2"
            / "openldap2_entries_fixtures.ldif"
        )

    def test_process_config_entry(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test processing cn=config entry."""
        entry_quirk = openldap_quirk.EntryQuirk()
        dn = "cn=config"
        attributes = {
            "objectClass": ["olcGlobal"],
            "cn": ["config"],
        }
        result = entry_quirk.process_entry(dn, attributes)
        assert hasattr(result, "is_success")

    def test_process_standard_entry(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test processing standard directory entry."""
        entry_quirk = openldap_quirk.EntryQuirk()
        dn = "uid=ldapuser,ou=people,dc=example,dc=com"
        attributes = {
            "objectClass": ["inetOrgPerson", "uidObject"],
            "uid": ["ldapuser"],
            "cn": ["LDAP Test User"],
            "sn": ["User"],
            "mail": ["ldapuser@example.com"],
        }
        result = entry_quirk.process_entry(dn, attributes)
        assert hasattr(result, "is_success")

    def test_process_entry_from_fixture(
        self,
        openldap_quirk: FlextLdifQuirksServersOpenldap,
        openldap_entries_fixture: Path,
    ) -> None:
        """Test processing entries from real OpenLDAP fixture."""
        if not openldap_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {openldap_entries_fixture}")

        entry_quirk = openldap_quirk.EntryQuirk()
        # Use a realistic entry
        dn = "ou=people,dc=example,dc=com"
        attributes = {"objectClass": ["organizationalUnit"], "ou": ["people"]}
        result = entry_quirk.process_entry(dn, attributes)
        assert hasattr(result, "is_success")


class TestOpenldapEntryQuirkConvertEntry:
    """Test OpenLDAP EntryQuirk entry RFC conversion."""

    @pytest.fixture
    def openldap_quirk(self) -> FlextLdifQuirksServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifQuirksServersOpenldap()

    def test_convert_entry_to_rfc(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test converting OpenLDAP entry to RFC format."""
        entry_quirk = openldap_quirk.EntryQuirk()
        entry_dict = {
            "dn": "uid=user,ou=people,dc=example,dc=com",
            "objectClass": ["inetOrgPerson"],
            "uid": ["user"],
            "cn": ["Test User"],
        }
        result = entry_quirk.convert_entry_to_rfc(entry_dict)
        assert hasattr(result, "is_success")

    def test_convert_config_entry_to_rfc(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test converting cn=config entry to RFC format."""
        entry_quirk = openldap_quirk.EntryQuirk()
        entry_dict = {
            "dn": "cn=module,cn=config",
            "objectClass": ["olcModuleList"],
            "olcModuleLoad": ["back_ldif"],
        }
        result = entry_quirk.convert_entry_to_rfc(entry_dict)
        assert hasattr(result, "is_success")


class TestOpenldapProperties:
    """Test OpenLDAP quirks properties and configuration."""

    @pytest.fixture
    def openldap_quirk(self) -> FlextLdifQuirksServersOpenldap:
        """Create OpenLDAP quirk instance."""
        return FlextLdifQuirksServersOpenldap()

    def test_openldap_schema_quirk_properties(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test schema quirk has correct properties."""
        assert openldap_quirk.server_type == "openldap2"
        assert openldap_quirk.priority == 10

    def test_openldap_acl_quirk_properties(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test AclQuirk has correct properties."""
        acl_quirk = openldap_quirk.AclQuirk()
        assert acl_quirk.server_type == "openldap2"
        assert acl_quirk.priority == 10

    def test_openldap_entry_quirk_properties(
        self, openldap_quirk: FlextLdifQuirksServersOpenldap
    ) -> None:
        """Test EntryQuirk has correct properties."""
        entry_quirk = openldap_quirk.EntryQuirk()
        assert entry_quirk.server_type == "generic"
        assert entry_quirk.priority == 10
