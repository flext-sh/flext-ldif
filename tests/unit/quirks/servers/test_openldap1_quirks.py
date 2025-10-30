"""Tests for OpenLDAP 1.x server quirks.

Comprehensive tests for OpenLDAP 1.x-specific LDIF processing quirks including
schema, ACL, and entry handling for legacy slapd.conf-based configurations.
"""

from __future__ import annotations

from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.openldap1 import FlextLdifServersOpenldap1


class TestOpenLDAP1xSchemas:
    """Tests for OpenLDAP 1.x schema quirk handling."""

    def test_initialization(self) -> None:
        """Test OpenLDAP 1.x schema quirk initialization."""
        quirk = FlextLdifServersOpenldap1.Schema()
        assert quirk.server_type == "openldap1"
        assert quirk.priority == 20  # Lower priority than OpenLDAP 2.x

    def test_can_handle_attribute_with_attributetype_prefix(self) -> None:
        """Test attribute detection with attributetype prefix."""
        quirk = FlextLdifServersOpenldap1.Schema()

        # Should handle attributetype (without olc)
        attr_def = "attributetype ( 1.2.3.4 NAME 'test' )"
        assert quirk.can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_olc_rejected(self) -> None:
        """Test attribute detection rejects olc prefix (OpenLDAP 2.x)."""
        quirk = FlextLdifServersOpenldap1.Schema()

        # Should NOT handle olc* (that's OpenLDAP 2.x)
        attr_def = "attributetype ( 1.2.3.4 NAME 'olcTest' )"
        assert quirk.can_handle_attribute(attr_def) is False

    def test_parse_attribute_success(self) -> None:
        """Test successful attribute parsing."""
        quirk = FlextLdifServersOpenldap1.Schema()

        attr_def = "attributetype ( 1.2.3.4 NAME 'testAttr' DESC 'Test attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 EQUALITY caseIgnoreMatch SINGLE-VALUE )"
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
        quirk = FlextLdifServersOpenldap1.Schema()

        attr_def = "attributetype NAME 'testAttr'"
        result = quirk.parse_attribute(attr_def)

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "RFC attribute parsing failed: missing an OID" in result.error

    def test_can_handle_objectclass_with_objectclass_prefix(self) -> None:
        """Test objectClass detection with objectclass prefix."""
        quirk = FlextLdifServersOpenldap1.Schema()

        oc_def = "objectclass ( 1.2.3.4 NAME 'testClass' )"
        assert quirk.can_handle_objectclass(oc_def) is True

    def test_can_handle_objectclass_with_olc_rejected(self) -> None:
        """Test objectClass detection rejects olc (OpenLDAP 2.x)."""
        quirk = FlextLdifServersOpenldap1.Schema()

        oc_def = "objectclass ( 1.2.3.4 NAME 'olcTestClass' )"
        assert quirk.can_handle_objectclass(oc_def) is False

    def test_parse_objectclass_success(self) -> None:
        """Test successful objectClass parsing."""
        quirk = FlextLdifServersOpenldap1.Schema()

        oc_def = "objectclass ( 1.2.3.4 NAME 'testClass' DESC 'Test class' SUP top STRUCTURAL MUST ( cn $ sn ) MAY ( description ) )"
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
        quirk = FlextLdifServersOpenldap1.Schema()

        oc_def = "objectclass ( 1.2.3.5 NAME 'auxClass' AUXILIARY )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "AUXILIARY"

    def test_parse_objectclass_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        quirk = FlextLdifServersOpenldap1.Schema()

        oc_def = "objectclass ( 1.2.3.6 NAME 'absClass' ABSTRACT )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "ABSTRACT"

    def test_parse_objectclass_no_oid(self) -> None:
        """Test objectClass parsing fails without OID."""
        quirk = FlextLdifServersOpenldap1.Schema()

        oc_def = "objectclass NAME 'testClass'"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "RFC objectClass parsing failed: missing an OID" in result.error

    def test_convert_attribute_to_rfc(self) -> None:
        """Test attribute conversion to RFC format."""
        quirk = FlextLdifServersOpenldap1.Schema()

        attr_data = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            desc="Test",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            equality="caseIgnoreMatch",
            single_value=True,
        )

        result = quirk.convert_attribute_to_rfc(attr_data)
        assert result.is_success
        rfc_data = result.unwrap()
        # Result is a SchemaAttribute model object, verify its attributes
        assert rfc_data.oid == "1.2.3.4"
        assert rfc_data.name == "testAttr"

    def test_convert_objectclass_to_rfc(self) -> None:
        """Test objectClass conversion to RFC format."""
        quirk = FlextLdifServersOpenldap1.Schema()

        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="1.2.3.4",
            name="testClass",
            desc="Test",
            sup="top",
            kind="STRUCTURAL",
            must=["cn"],
            may=["description"],
        )

        result = quirk.convert_objectclass_to_rfc(oc_data)
        assert result.is_success
        rfc_data = result.unwrap()
        # Result is a SchemaObjectClass model object, verify its attributes
        assert rfc_data.oid == "1.2.3.4"
        assert rfc_data.kind == "STRUCTURAL"

    def test_convert_attribute_from_rfc(self) -> None:
        """Test attribute conversion from RFC format."""
        quirk = FlextLdifServersOpenldap1.Schema()

        rfc_data = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            desc="Test",
        )

        result = quirk.convert_attribute_from_rfc(rfc_data)
        assert result.is_success
        openldap_data = result.unwrap()
        # Result is a SchemaAttribute model object, verify its attributes
        assert openldap_data.oid == "1.2.3.4"
        assert openldap_data.name == "testAttr"

    def test_convert_objectclass_from_rfc(self) -> None:
        """Test objectClass conversion from RFC format."""
        quirk = FlextLdifServersOpenldap1.Schema()

        rfc_data = FlextLdifModels.SchemaObjectClass(
            oid="1.2.3.4",
            name="testClass",
        )

        result = quirk.convert_objectclass_from_rfc(rfc_data)
        assert result.is_success
        openldap_data = result.unwrap()
        # Result is a SchemaObjectClass model object, verify its attributes
        assert openldap_data.oid == "1.2.3.4"
        assert openldap_data.name == "testClass"

    def test_write_attribute_to_rfc(self) -> None:
        """Test writing attribute to RFC string format with attributetype prefix."""
        quirk = FlextLdifServersOpenldap1.Schema()

        attr_data = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            desc="Test attribute",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            equality="caseIgnoreMatch",
            single_value=True,
        )

        result = quirk.write_attribute_to_rfc(attr_data)
        assert result.is_success
        attr_str = result.unwrap()
        assert "attributetype ( 1.2.3.4" in attr_str  # OpenLDAP 1.x prefix
        assert "NAME 'testAttr'" in attr_str
        assert "DESC 'Test attribute'" in attr_str
        assert "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15" in attr_str
        assert "EQUALITY caseIgnoreMatch" in attr_str
        assert "SINGLE-VALUE" in attr_str
        assert ")" in attr_str

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format with objectclass prefix."""
        quirk = FlextLdifServersOpenldap1.Schema()

        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="1.2.3.4",
            name="testClass",
            desc="Test class",
            sup="top",
            kind="STRUCTURAL",
            must=["cn", "sn"],
            may=["description"],
        )

        result = quirk.write_objectclass_to_rfc(oc_data)
        assert result.is_success
        oc_str = result.unwrap()
        assert "objectclass ( 1.2.3.4" in oc_str  # OpenLDAP 1.x prefix
        assert "NAME 'testClass'" in oc_str
        assert "SUP top" in oc_str
        assert "STRUCTURAL" in oc_str
        assert "MUST" in oc_str
        assert "MAY" in oc_str


class TestOpenLDAP1xAcls:
    """Tests for OpenLDAP 1.x ACL quirk handling."""

    def test_acl_quirk_initialization(self) -> None:
        """Test ACL quirk initialization."""
        main_quirk = FlextLdifServersOpenldap1.Schema()
        acl_quirk = main_quirk.Acl()
        assert acl_quirk.server_type == "openldap1"
        assert acl_quirk.priority == 20  # OpenLDAP 1.x ACL priority

    def test_can_handle_acl_with_access_to(self) -> None:
        """Test ACL detection with 'access to' prefix."""
        main_quirk = FlextLdifServersOpenldap1.Schema()
        acl_quirk = main_quirk.Acl()

        acl_line = "access to attrs=userPassword by self write by * auth"
        assert acl_quirk.can_handle_acl(acl_line) is True

    def test_can_handle_acl_negative(self) -> None:
        """Test ACL detection returns false for non-OpenLDAP 1.x ACL."""
        main_quirk = FlextLdifServersOpenldap1.Schema()
        acl_quirk = main_quirk.Acl()

        acl_line = "random text"
        assert acl_quirk.can_handle_acl(acl_line) is False

    def test_parse_acl_success(self) -> None:
        """Test successful ACL parsing."""
        main_quirk = FlextLdifServersOpenldap1.Schema()
        acl_quirk = main_quirk.Acl()

        acl_line = "access to attrs=userPassword by self write by * read"
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_success
        acl_data = result.unwrap()
        assert isinstance(acl_data, FlextLdifModels.Acl)
        assert acl_data.target.attributes == ["userPassword"]
        assert acl_data.subject.subject_value == "self"
        assert acl_data.permissions.write is True

    def test_parse_acl_missing_to_clause(self) -> None:
        """Test ACL parsing fails without 'to' clause."""
        main_quirk = FlextLdifServersOpenldap1.Schema()
        acl_quirk = main_quirk.Acl()

        acl_line = "access by * read"
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_failure
        assert result.error is not None
        assert "missing 'to' clause" in result.error.lower()

    def test_convert_acl_to_rfc(self) -> None:
        """Test ACL conversion to RFC format."""
        main_quirk = FlextLdifServersOpenldap1.Schema()
        acl_quirk = main_quirk.Acl()

        acl_data = FlextLdifModels.Acl(
            name="access",
            target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
            subject=FlextLdifModels.AclSubject(
                subject_type="userdn", subject_value="*"
            ),
            permissions=FlextLdifModels.AclPermissions(read=True),
            server_type="openldap1",
            raw_acl="access to * by * read",
        )

        result = acl_quirk.convert_acl_to_rfc(acl_data)
        assert result.is_success
        rfc_data = result.unwrap()
        assert rfc_data.server_type == "generic"

    def test_convert_acl_from_rfc(self) -> None:
        """Test ACL conversion from RFC format."""
        main_quirk = FlextLdifServersOpenldap1.Schema()
        acl_quirk = main_quirk.Acl()

        acl_data = FlextLdifModels.Acl(
            name="access",
            target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
            subject=FlextLdifModels.AclSubject(
                subject_type="userdn", subject_value="*"
            ),
            permissions=FlextLdifModels.AclPermissions(read=True),
            server_type="generic",
            raw_acl="acl: to * by * read",
        )

        result = acl_quirk.convert_acl_from_rfc(acl_data)
        assert result.is_success
        openldap_data = result.unwrap()
        assert openldap_data.server_type == "generic"


class TestOpenLDAP1xEntrys:
    """Tests for OpenLDAP 1.x entry quirk handling."""

    def test_entry_quirk_initialization(self) -> None:
        """Test entry quirk initialization."""
        main_quirk = FlextLdifServersOpenldap1.Schema()
        entry_quirk = main_quirk.Entry()
        assert entry_quirk.server_type == "openldap1"
        assert entry_quirk.priority == 20  # OpenLDAP 1.x Entry priority

    def test_can_handle_entry_traditional_dit(self) -> None:
        """Test entry detection for traditional DIT (no cn=config)."""
        main_quirk = FlextLdifServersOpenldap1.Schema()
        entry_quirk = main_quirk.Entry()

        dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {"cn": ["test"], "objectclass": ["person"]}
        assert entry_quirk.can_handle_entry(dn, attributes) is True

    def test_can_handle_entry_rejects_config_dn(self) -> None:
        """Test entry detection rejects cn=config DNs (OpenLDAP 2.x)."""
        main_quirk = FlextLdifServersOpenldap1.Schema()
        entry_quirk = main_quirk.Entry()

        dn = "cn=config"
        attributes: dict[str, object] = {"cn": ["config"]}
        assert entry_quirk.can_handle_entry(dn, attributes) is False

    def test_can_handle_entry_rejects_olc_attributes(self) -> None:
        """Test entry detection rejects olc* attributes (OpenLDAP 2.x)."""
        main_quirk = FlextLdifServersOpenldap1.Schema()
        entry_quirk = main_quirk.Entry()

        dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {"olcDatabase": ["{1}mdb"]}
        assert entry_quirk.can_handle_entry(dn, attributes) is False

    def test_process_entry_success(self) -> None:
        """Test successful entry processing."""
        main_quirk = FlextLdifServersOpenldap1.Schema()
        entry_quirk = main_quirk.Entry()

        dn = "cn=user,ou=people,dc=example,dc=com"
        attributes: dict[str, object] = {
            "cn": ["user"],
            "objectclass": ["person", "inetOrgPerson"],
        }
        result = entry_quirk.process_entry(dn, attributes)

        assert result.is_success
        entry_data = result.unwrap()
        assert entry_data["dn"] == dn
        assert entry_data["server_type"] == "generic"
        assert entry_data["is_traditional_dit"] is True
        assert entry_data["cn"] == ["user"]

    def test_convert_entry_to_rfc(self) -> None:
        """Test entry conversion to RFC format."""
        main_quirk = FlextLdifServersOpenldap1.Schema()
        entry_quirk = main_quirk.Entry()

        entry_data: dict[str, object] = {
            "dn": "cn=test,dc=example,dc=com",
            "cn": ["test"],
            "objectclass": ["person"],
        }

        result = entry_quirk.convert_entry_to_rfc(entry_data)
        assert result.is_success
        # OpenLDAP 1.x entries are RFC-compliant, so should return unchanged
        rfc_data = result.unwrap()
        assert rfc_data["dn"] == "cn=test,dc=example,dc=com"
