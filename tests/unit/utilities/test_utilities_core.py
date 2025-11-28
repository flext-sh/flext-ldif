"""Comprehensive tests for FlextLdifUtilities core classes.

Consolidates tests for:
- FlextLdifUtilities.DN: RFC 4514 DN operations
- FlextLdifUtilities.DN: Advanced DN manipulation
- FlextLdifUtilities.Schema: Attribute normalization (was AttributeFixer)
- FlextLdifUtilities.Parser: LDIF parsing utilities (was LdifParser)
- FlextLdifUtilities.ACL: ACL parsing utilities
- FlextLdifConstants.ServerTypes: Server type normalization (moved from utilities)

All tests use pure functions (returning primitives, not FlextResult).
Tests validate RFC 4514 compliance with real LDIF fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdifConstants, FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


@pytest.mark.unit
class TestDnOperationsPure:
    """Test DN operations as pure functions returning primitives."""

    def test_norm_component_basic(self) -> None:
        """Test basic DN component normalization."""
        result = FlextLdifUtilities.DN.norm_component("cn = John Doe")
        assert result == "cn=John Doe"

    def test_norm_component_no_spaces(self) -> None:
        """Test component without spaces."""
        result = FlextLdifUtilities.DN.norm_component("cn=Jane Smith")
        assert result == "cn=Jane Smith"

    def test_norm_string_full_dn(self) -> None:
        """Test full DN normalization."""
        dn = "cn = John Doe , ou = Users , dc = example , dc = com"
        result = FlextLdifUtilities.DN.norm_string(dn)
        assert result == "cn=John Doe,ou=Users,dc=example,dc=com"

    def test_norm_string_empty(self) -> None:
        """Test empty DN."""
        result = FlextLdifUtilities.DN.norm_string("")
        assert not result

    def test_split_dn_components(self) -> None:
        """Test splitting DN into components."""
        dn = "cn=John,ou=Users,dc=example,dc=com"
        result = FlextLdifUtilities.DN.split(dn)
        assert result == ["cn=John", "ou=Users", "dc=example", "dc=com"]

    def test_split_dn_with_escaped_commas(self) -> None:
        """Test splitting DN with escaped commas."""
        dn = r"cn=Test\, User,ou=Users,dc=example,dc=com"
        result = FlextLdifUtilities.DN.split(dn)
        assert result == [r"cn=Test\, User", "ou=Users", "dc=example", "dc=com"]

    def test_split_dn_edge_cases(self) -> None:
        """Test splitting DN edge cases."""
        # Empty DN
        assert FlextLdifUtilities.DN.split("") == []

        # Single component
        assert FlextLdifUtilities.DN.split("cn=test") == ["cn=test"]

        # Multiple escaped characters
        dn = r"cn=Test\, User\\More,ou=Users\, Group,dc=example"
        result = FlextLdifUtilities.DN.split(dn)
        assert result == [r"cn=Test\, User\\More", r"ou=Users\, Group", "dc=example"]

    def test_validate_dn_format_valid(self) -> None:
        """Test valid DN validation."""
        valid_dns = [
            "cn=John,dc=example,dc=com",
            "ou=Users,dc=example,dc=com",
            "cn=admin,o=example",
            r"cn=Test\, User,dc=example,dc=com",  # Escaped comma
            r"cn=Test\5CUser,dc=example,dc=com",  # Escaped backslash
            r"cn=Test#User,dc=example,dc=com",  # Hash character
            r"cn=Test\2BUser,dc=example,dc=com",  # Valid hex escape (+)
            r"cn=Test\3DUser,dc=example,dc=com",  # Valid hex escape (=)
        ]
        for dn in valid_dns:
            assert FlextLdifUtilities.DN.validate(dn), f"DN should be valid: {dn}"

    def test_validate_dn_format_invalid(self) -> None:
        """Test invalid DN validation."""
        invalid_dns = [
            "",  # Empty string
            "no_equals_sign",  # No equals sign
            "cn=",  # Empty value
            "=value",  # Empty attribute
            "cn=test,",  # Trailing comma
            ",cn=test",  # Leading comma
            "cn=test,,ou=users",  # Double comma
            "cn=test\\",  # Trailing backslash
            "cn=test\\Z",  # Invalid hex escape
            "cn=test\\XY",  # Invalid hex escape (non-hex chars)
        ]
        for dn in invalid_dns:
            assert not FlextLdifUtilities.DN.validate(dn), f"DN should be invalid: {dn}"

    def test_parse_components(self) -> None:
        """Test DN component parsing."""
        dn = "cn=John,ou=Users,dc=example"
        result = FlextLdifUtilities.DN.parse(dn)
        assert result.is_success
        parsed = result.unwrap()
        assert len(parsed) >= 2

    def test_compare_dns(self) -> None:
        """Test DN comparison."""
        dn1 = "cn=John,dc=example,dc=com"
        dn2 = "cn=jane,dc=example,dc=com"
        result = FlextLdifUtilities.DN.compare_dns(dn1, dn2)

        # compare_dns returns FlextResult[int], not int directly
        assert result.is_success
        comparison = result.unwrap()
        assert isinstance(comparison, int)

    def test_escape_dn_value(self) -> None:
        """Test escaping special DN value characters."""
        value = "Test, Value"
        result = FlextLdifUtilities.DN.esc(value)
        assert isinstance(result, str)

    def test_unescape_dn_value(self) -> None:
        """Test unescaping DN value characters."""
        value = "Test\\,Value"
        result = FlextLdifUtilities.DN.unesc(value)
        assert isinstance(result, str)

    def test_clean_dn(self) -> None:
        """Test DN cleaning."""
        dn = "  cn = John  ,  ou = Users  ,  dc = example  "
        result = FlextLdifUtilities.DN.clean_dn(dn)
        assert isinstance(result, str)
        assert "  " not in result or result == dn


@pytest.mark.unit
class TestDnObjectClassMethods:
    """Test ObjectClass-related DN operations."""

    def test_fix_missing_sup(self) -> None:
        """Test fixing missing SUP in AUXILIARY classes."""
        # Create real SchemaObjectClass with missing SUP
        obj = FlextLdifModels.SchemaObjectClass(
            oid="1.2.3.4",
            name="orcldasattrcategory",
            kind="AUXILIARY",
            sup=None,
        )

        FlextLdifUtilities.ObjectClass.fix_missing_sup(obj)
        assert obj.sup == "top"

    def test_fix_kind_mismatch(self) -> None:
        """Test fixing kind mismatches."""
        # Create real SchemaObjectClass with kind mismatch
        obj = FlextLdifModels.SchemaObjectClass(
            oid="1.2.3.4",
            name="testOC",
            sup="orclpwdverifierprofile",
            kind="AUXILIARY",
        )

        FlextLdifUtilities.ObjectClass.fix_kind_mismatch(obj)
        assert obj.kind == "STRUCTURAL"

    def test_ensure_sup_for_auxiliary(self) -> None:
        """Test ensuring AUXILIARY classes have SUP."""
        # Create real SchemaObjectClass with missing SUP
        obj = FlextLdifModels.SchemaObjectClass(
            oid="1.2.3.4",
            name="testOC",
            kind="AUXILIARY",
            sup=None,
        )

        FlextLdifUtilities.ObjectClass.ensure_sup_for_auxiliary(obj)
        assert obj.sup == "top"


@pytest.mark.unit
class TestAttributeFixer:
    """Test attribute definition normalization."""

    def test_normalize_name_basic(self) -> None:
        """Test basic attribute name normalization."""
        result = FlextLdifUtilities.Schema.normalize_name("testAttr_name;binary")
        assert result == "testAttr-name"

    def test_normalize_name_with_custom_replacements(self) -> None:
        """Test name normalization with custom replacements."""
        result = FlextLdifUtilities.Schema.normalize_name(
            "test_attr_name",
            char_replacements={"_": "-"},
        )
        assert result == "test-attr-name"

    def test_normalize_name_none(self) -> None:
        """Test normalizing None."""
        result = FlextLdifUtilities.Schema.normalize_name(None)
        assert result is None

    def test_normalize_matching_rules_empty(self) -> None:
        """Test normalizing empty matching rules."""
        result = FlextLdifUtilities.Schema.normalize_matching_rules(None)
        assert result == (None, None)

    def test_normalize_matching_rules_equality_only(self) -> None:
        """Test normalizing matching rules with equality rule only."""
        result = FlextLdifUtilities.Schema.normalize_matching_rules("caseIgnoreMatch")
        assert result == ("caseIgnoreMatch", None)

    def test_normalize_matching_rules_both(self) -> None:
        """Test normalizing matching rules with both equality and substr."""
        result = FlextLdifUtilities.Schema.normalize_matching_rules(
            "caseIgnoreMatch",
            "caseIgnoreSubstringsMatch",
        )
        assert result == ("caseIgnoreMatch", "caseIgnoreSubstringsMatch")


@pytest.mark.unit
class TestLdifParser:
    """Test LDIF parsing utilities - simple helper functions."""

    def test_extract_extensions_empty(self) -> None:
        """Test extracting extensions from empty schema definition."""
        definition = ""
        result = FlextLdifUtilities.Parser.extract_extensions(definition)
        assert result == {}

    def test_extract_extensions_with_x_extension(self) -> None:
        """Test extracting X- extensions from schema definition."""
        definition = "( 1.2.3 NAME 'test' X-CUSTOM 'value' X-OTHER 'data' )"
        result = FlextLdifUtilities.Parser.extract_extensions(definition)
        assert result.get("X-CUSTOM") == "value"
        assert result.get("X-OTHER") == "data"

    def test_extract_extensions_with_desc(self) -> None:
        """Test extracting DESC from schema definition."""
        definition = "( 1.2.3 NAME 'test' DESC 'Test attribute' )"
        result = FlextLdifUtilities.Parser.extract_extensions(definition)
        assert result.get("DESC") == "Test attribute"

    def test_parse_ldif_lines_empty(self) -> None:
        """Test parsing empty LDIF content."""
        content = ""
        result = FlextLdifUtilities.Parser.parse_ldif_lines(content)
        assert result == []

    def test_parse_ldif_lines_single_entry(self) -> None:
        """Test parsing single LDIF entry."""
        content = "dn: cn=test,dc=example,dc=com\ncn: test\nobjectClass: person\n"
        result = FlextLdifUtilities.Parser.parse_ldif_lines(content)
        assert len(result) == 1
        dn, attrs = result[0]
        assert dn == "cn=test,dc=example,dc=com"
        assert attrs.get("cn") == ["test"]
        assert attrs.get("objectClass") == ["person"]

    def test_parse_ldif_lines_multiple_entries(self) -> None:
        """Test parsing multiple LDIF entries separated by empty line."""
        # LDIF entries MUST be separated by empty lines
        content = (
            "dn: cn=test1,dc=example,dc=com\n"
            "cn: test1\n"
            "objectClass: person\n"
            "\n"
            "dn: cn=test2,dc=example,dc=com\n"
            "cn: test2\n"
            "objectClass: person\n"
        )
        result = FlextLdifUtilities.Parser.parse_ldif_lines(content)
        assert len(result) == 2, f"Expected 2 entries but got {len(result)}: {result}"

        # First entry
        dn1, attrs1 = result[0]
        assert dn1 == "cn=test1,dc=example,dc=com"
        assert attrs1.get("cn") == ["test1"]
        assert attrs1.get("objectClass") == ["person"]

        # Second entry
        dn2, attrs2 = result[1]
        assert dn2 == "cn=test2,dc=example,dc=com"
        assert attrs2.get("cn") == ["test2"]
        assert attrs2.get("objectClass") == ["person"]

    def test_unfold_lines_basic(self) -> None:
        """Test unfolding RFC 2849 folded lines."""
        content = "dn: cn=verylongname\n withfoldedcontinuation,dc=example,dc=com\n"
        result = FlextLdifUtilities.Parser.unfold_lines(content)
        assert any("withfoldedcontinuation" in line for line in result)


@pytest.mark.unit
class TestAclParser:
    """Test ACL parsing utilities."""

    def test_parse_oid_format(self) -> None:
        """Test parsing OID ACL format."""
        acl_line = 'orclaci: ( VERSION 3.0; ACETYPE ALLOW; (USERDN="ldap:///cn=*,ou=users,o=test");(ACITYPE ALLOW))'
        result = FlextLdifUtilities.ACL.parser(acl_line)
        assert result is not None
        assert result.get("format") == "oid"

    def test_parse_oud_format(self) -> None:
        """Test parsing OUD ACL format."""
        acl_line = "aci: targetattr=*"
        result = FlextLdifUtilities.ACL.parser(acl_line)
        assert result is not None
        assert result.get("format") == "oud"

    def test_parse_empty_acl(self) -> None:
        """Test parsing empty ACL."""
        result = FlextLdifUtilities.ACL.parser("")
        assert result is None


@pytest.mark.unit
class TestServerTypes:
    """Test server type operations (now in FlextLdifConstants.ServerTypes)."""

    def test_normalize_server_type(self) -> None:
        """Test server type normalization."""
        # Test aliases
        assert FlextLdifConstants.ServerTypes.normalize("oracle_oid") == "oid"
        assert FlextLdifConstants.ServerTypes.normalize("rfc") == "rfc"

    def test_matches_server_type(self) -> None:
        """Test server type matching."""
        assert FlextLdifConstants.ServerTypes.matches("oid", "oid", "oud")
        assert not FlextLdifConstants.ServerTypes.matches("ad", "oid", "oud")


@pytest.mark.unit
class TestObjectClassUtilities:
    """Test ObjectClass validation and correction utilities."""

    def test_fix_missing_sup_auxiliary_without_sup(self) -> None:
        """Test fixing missing SUP for known AUXILIARY classes."""
        # Create AUXILIARY class without SUP
        oc = FlextLdifModels.SchemaObjectClass(
            name="orcldAsAttrCategory",
            oid="1.2.3.4.5",
            kind=FlextLdifConstants.Schema.AUXILIARY,
            sup=None,
        )
        assert oc.sup is None

        # Fix should add SUP
        FlextLdifUtilities.ObjectClass.fix_missing_sup(oc, _server_type="oid")
        assert oc.sup == "top"

    def test_fix_missing_sup_auxiliary_with_sup(self) -> None:
        """Test that AUXILIARY with SUP is not modified."""
        oc = FlextLdifModels.SchemaObjectClass(
            name="testAuxiliary",
            oid="1.2.3.4.5",
            kind=FlextLdifConstants.Schema.AUXILIARY,
            sup="top",
        )
        original_sup = oc.sup

        FlextLdifUtilities.ObjectClass.fix_missing_sup(oc)
        assert oc.sup == original_sup

    def test_fix_missing_sup_structural_ignored(self) -> None:
        """Test that STRUCTURAL classes are ignored."""
        oc = FlextLdifModels.SchemaObjectClass(
            name="testStructural",
            oid="1.2.3.4.6",
            kind=FlextLdifConstants.Schema.STRUCTURAL,
            sup=None,
        )
        original_sup = oc.sup

        FlextLdifUtilities.ObjectClass.fix_missing_sup(oc)
        assert oc.sup == original_sup

    def test_ensure_sup_for_auxiliary_adds_sup(self) -> None:
        """Test ensure_sup_for_auxiliary adds SUP when missing."""
        oc = FlextLdifModels.SchemaObjectClass(
            name="testAuxiliary",
            oid="1.2.3.4.7",
            kind=FlextLdifConstants.Schema.AUXILIARY,
            sup=None,
        )
        FlextLdifUtilities.ObjectClass.ensure_sup_for_auxiliary(oc)
        assert oc.sup == "top"

    def test_ensure_sup_for_auxiliary_custom_default(self) -> None:
        """Test ensure_sup_for_auxiliary with custom default SUP."""
        oc = FlextLdifModels.SchemaObjectClass(
            name="testAuxiliary",
            oid="1.2.3.4.8",
            kind=FlextLdifConstants.Schema.AUXILIARY,
            sup=None,
        )
        FlextLdifUtilities.ObjectClass.ensure_sup_for_auxiliary(
            oc,
            default_sup="custom",
        )
        assert oc.sup == "custom"

    def test_fix_kind_mismatch_structural_superior(self) -> None:
        """Test fixing kind mismatch with STRUCTURAL superior."""
        oc = FlextLdifModels.SchemaObjectClass(
            name="testClass",
            oid="1.2.3.4.9",
            kind=FlextLdifConstants.Schema.AUXILIARY,
            sup="orclpwdverifierprofile",
        )
        FlextLdifUtilities.ObjectClass.fix_kind_mismatch(oc)
        assert oc.kind == FlextLdifConstants.Schema.STRUCTURAL

    def test_fix_kind_mismatch_auxiliary_superior(self) -> None:
        """Test fixing kind mismatch with AUXILIARY superior."""
        oc = FlextLdifModels.SchemaObjectClass(
            name="testClass",
            oid="1.2.3.4.10",
            kind=FlextLdifConstants.Schema.STRUCTURAL,
            sup="javanamingref",
        )
        FlextLdifUtilities.ObjectClass.fix_kind_mismatch(oc)
        assert oc.kind == FlextLdifConstants.Schema.AUXILIARY

    def test_align_kind_with_superior_structural(self) -> None:
        """Test aligning kind with STRUCTURAL superior."""
        oc = FlextLdifModels.SchemaObjectClass(
            name="testClass",
            oid="1.2.3.4.11",
            kind=FlextLdifConstants.Schema.AUXILIARY,
            sup="someSuperior",
        )
        FlextLdifUtilities.ObjectClass.align_kind_with_superior(
            oc,
            FlextLdifConstants.Schema.STRUCTURAL,
        )
        assert oc.kind == FlextLdifConstants.Schema.STRUCTURAL

    def test_align_kind_with_superior_auxiliary(self) -> None:
        """Test aligning kind with AUXILIARY superior."""
        oc = FlextLdifModels.SchemaObjectClass(
            name="testClass",
            oid="1.2.3.4.12",
            kind=FlextLdifConstants.Schema.STRUCTURAL,
            sup="someSuperior",
        )
        FlextLdifUtilities.ObjectClass.align_kind_with_superior(
            oc,
            FlextLdifConstants.Schema.AUXILIARY,
        )
        assert oc.kind == FlextLdifConstants.Schema.AUXILIARY

    def test_align_kind_with_superior_no_conflict(self) -> None:
        """Test that matching kinds are not changed."""
        oc = FlextLdifModels.SchemaObjectClass(
            name="testClass",
            oid="1.2.3.4.13",
            kind=FlextLdifConstants.Schema.STRUCTURAL,
            sup="someSuperior",
        )
        original_kind = oc.kind
        FlextLdifUtilities.ObjectClass.align_kind_with_superior(
            oc,
            FlextLdifConstants.Schema.STRUCTURAL,
        )
        assert oc.kind == original_kind
