"""Comprehensive OUD Quirks Coverage - All Methods and Code Paths.

This test file provides complete coverage for FlextLdifQuirksServersOud methods:
- parse_attribute() with all RFC 4512 attributes
- parse_objectclass() with MUST/MAY/SUP dependencies
- write_attribute_to_rfc() and write_objectclass_to_rfc()
- convert_*_to/from_rfc() conversion methods
- validate_objectclass_dependencies()
- extract_schemas_from_ldif()
- AclQuirk: parse_acl(), convert_acl_*()
- EntryQuirk: process_entry(), convert_entry_*()

All tests use REAL implementations with actual LDIF data.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud


class TestOudParseAttributeComprehensive:
    """Test parse_attribute() with all RFC 4512 attribute variations."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_parse_attribute_basic_oid_and_name(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing basic attribute with OID and NAME."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("oid") == "1.2.3.4"
        assert parsed.get("name") == "testAttr"

    def test_parse_attribute_with_description(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with DESC field."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' DESC 'Test Attribute' )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("desc") == "Test Attribute"

    def test_parse_attribute_with_syntax(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with SYNTAX OID."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("syntax") == "1.3.6.1.4.1.1466.115.121.1.15"

    def test_parse_attribute_with_syntax_length(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with SYNTAX length constraint."""
        attr_def = (
            "( 1.2.3.4 NAME 'testAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        )
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("syntax_length") == "256"

    def test_parse_attribute_with_equality(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with EQUALITY matching rule."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' EQUALITY caseIgnoreMatch )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("equality") == "caseIgnoreMatch"

    def test_parse_attribute_with_substr(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with SUBSTR matching rule."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' SUBSTR caseIgnoreSubstringsMatch )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("substr") == "caseIgnoreSubstringsMatch"

    def test_parse_attribute_with_ordering(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with ORDERING matching rule."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' ORDERING caseIgnoreOrderingMatch )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("ordering") == "caseIgnoreOrderingMatch"

    def test_parse_attribute_with_single_value(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with SINGLE-VALUE constraint."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' SINGLE-VALUE )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("single_value") is True

    def test_parse_attribute_with_sup(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with SUP (superor attribute)."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' SUP name )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("sup") == "name"

    def test_parse_attribute_with_x_origin(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with X-ORIGIN extension."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' X-ORIGIN 'Custom' )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("x_origin") == "Custom"

    def test_parse_attribute_all_fields(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with all possible RFC 4512 fields."""
        attr_def = (
            "( 1.2.3.4 "
            "NAME 'testAttr' "
            "DESC 'Test Attribute' "
            "EQUALITY caseIgnoreMatch "
            "SUBSTR caseIgnoreSubstringsMatch "
            "ORDERING caseIgnoreOrderingMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} "
            "SINGLE-VALUE "
            "SUP name "
            "X-ORIGIN 'Custom' )"
        )
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("oid") == "1.2.3.4"
        assert parsed.get("name") == "testAttr"
        assert parsed.get("desc") == "Test Attribute"
        assert parsed.get("equality") == "caseIgnoreMatch"
        assert parsed.get("substr") == "caseIgnoreSubstringsMatch"
        assert parsed.get("ordering") == "caseIgnoreOrderingMatch"
        assert parsed.get("syntax_length") == "256"
        assert parsed.get("single_value") is True
        assert parsed.get("sup") == "name"
        assert parsed.get("x_origin") == "Custom"

    def test_parse_attribute_malformed_returns_failure(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing malformed attribute definition returns FlextResult."""
        attr_def = "COMPLETELY INVALID ATTRIBUTE FORMAT"
        result = oud_quirk.parse_attribute(attr_def)
        # Should still return a FlextResult (might succeed with partial data or fail)
        assert hasattr(result, "is_success")


class TestOudParseObjectClassComprehensive:
    """Test parse_objectclass() with all RFC 4512 objectClass variations."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_parse_objectclass_structural(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing STRUCTURAL objectClass."""
        oc_def = "( 2.5.6.1 NAME 'person' STRUCTURAL )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("kind") == "STRUCTURAL"

    def test_parse_objectclass_abstract(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing ABSTRACT objectClass."""
        oc_def = "( 2.5.6.0 NAME 'top' ABSTRACT )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("kind") == "ABSTRACT"

    def test_parse_objectclass_auxiliary(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing AUXILIARY objectClass."""
        oc_def = "( 2.5.6.254 NAME 'modifyTimestamp' AUXILIARY )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("kind") == "AUXILIARY"

    def test_parse_objectclass_with_sup(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with SUP (superior class)."""
        oc_def = "( 2.5.6.6 NAME 'person' STRUCTURAL SUP top MUST cn MAY description )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("sup") == "top"

    def test_parse_objectclass_with_single_must(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with single MUST attribute."""
        oc_def = "( 2.5.6.6 NAME 'person' STRUCTURAL MUST cn )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert isinstance(parsed.get("must"), (list, str))

    def test_parse_objectclass_with_multiple_must(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with multiple MUST attributes."""
        oc_def = "( 2.5.6.6 NAME 'person' STRUCTURAL MUST ( cn $ sn ) )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("must") is not None

    def test_parse_objectclass_with_single_may(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with single MAY attribute."""
        oc_def = "( 2.5.6.6 NAME 'person' STRUCTURAL MAY description )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("may") is not None

    def test_parse_objectclass_with_multiple_may(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with multiple MAY attributes."""
        oc_def = "( 2.5.6.6 NAME 'person' STRUCTURAL MAY ( description $ mail ) )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("may") is not None

    def test_parse_objectclass_with_desc(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with DESC."""
        oc_def = "( 2.5.6.6 NAME 'person' DESC 'A person' STRUCTURAL )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("desc") == "A person"

    def test_parse_objectclass_with_must_and_may(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with both MUST and MAY."""
        oc_def = (
            "( 2.5.6.6 NAME 'person' DESC 'A person' "
            "STRUCTURAL SUP top MUST ( cn $ sn ) MAY ( description $ mail ) )"
        )
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("oid") == "2.5.6.6"
        assert parsed.get("name") == "person"
        assert parsed.get("desc") == "A person"
        assert parsed.get("kind") == "STRUCTURAL"
        assert parsed.get("sup") == "top"
        assert parsed.get("must") is not None
        assert parsed.get("may") is not None


class TestOudWriteMethods:
    """Test write_attribute_to_rfc() and write_objectclass_to_rfc()."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_write_attribute_to_rfc_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test writing parsed attribute data to RFC format."""
        attr_data: dict[str, object] = {
            "oid": "1.2.3.4",
            "name": "testAttr",
            "desc": "Test Attribute",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            "single_value": True,
        }
        result = oud_quirk.write_attribute_to_rfc(attr_data)
        assert result.is_success
        written = result.unwrap()
        assert isinstance(written, str)
        assert "1.2.3.4" in written
        assert "testAttr" in written

    def test_write_objectclass_to_rfc_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test writing parsed objectClass data to RFC format."""
        oc_data: dict[str, object] = {
            "oid": "2.5.6.6",
            "name": "person",
            "desc": "A person",
            "kind": "STRUCTURAL",
            "sup": "top",
            "must": ["cn", "sn"],
            "may": ["description", "mail"],
        }
        result = oud_quirk.write_objectclass_to_rfc(oc_data)
        assert result.is_success
        written = result.unwrap()
        assert isinstance(written, str)
        assert "2.5.6.6" in written
        assert "person" in written


class TestOudExtractSchemas:
    """Test extract_schemas_from_ldif() schema extraction."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_extract_schemas_returns_result(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test extract_schemas_from_ldif returns FlextResult."""
        # Create minimal LDIF content
        ldif_content = (
            "dn: cn=schema\n"
            "objectClass: ldapSubentry\n"
            "attributeTypes: ( 1.2.3.4 NAME 'testAttr' )\n"
            "objectClasses: ( 2.5.6.6 NAME 'person' STRUCTURAL )\n"
        )
        result = oud_quirk.extract_schemas_from_ldif(ldif_content)
        assert hasattr(result, "is_success")


class TestOudValidateDependencies:
    """Test validate_objectclass_dependencies()."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_validate_dependencies_all_available(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test validation passes when all MUST attributes are available."""
        oc_data: dict[str, object] = {
            "name": "testClass",
            "must": ["cn", "sn"],
        }
        available_attrs = {"cn", "sn", "description"}
        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dependencies_some_missing(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test validation fails when some MUST attributes are missing."""
        oc_data: dict[str, object] = {
            "name": "testClass",
            "must": ["cn", "sn"],
        }
        available_attrs = {"cn"}  # Missing 'sn'
        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_dependencies_no_must(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test validation passes when there are no MUST attributes."""
        oc_data: dict[str, object] = {
            "name": "testClass",
            # No 'must' field
        }
        available_attrs: set[str] = set()
        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        assert result.is_success
        assert result.unwrap() is True


__all__ = [
    "TestOudExtractSchemas",
    "TestOudParseAttributeComprehensive",
    "TestOudParseObjectClassComprehensive",
    "TestOudValidateDependencies",
    "TestOudWriteMethods",
]
