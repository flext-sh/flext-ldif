"""Tests for LDIF DN operations as pure functions.

This module tests DN (Distinguished Name) utility functions as pure functions returning
primitives, including DN component normalization, full DN normalization, DN parsing,
splitting, component extraction, and handling of special characters and escaped values.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests import c, m, u


@pytest.mark.unit
class TestsFlextLdifDnOperationsPure:
    """Test DN operations as pure functions returning primitives."""

    def test_norm_component_basic(self) -> None:
        """Test basic DN component normalization."""
        result = u.Ldif.norm_component("cn = John Doe")
        tm.that(result == "cn=John Doe", eq=True)

    def test_norm_component_no_spaces(self) -> None:
        """Test component without spaces."""
        result = u.Ldif.norm_component("cn=Jane Smith")
        tm.that(result == "cn=Jane Smith", eq=True)

    def test_norm_string_full_dn(self) -> None:
        """Test full DN normalization."""
        dn = "cn = John Doe , ou = Users , dc = example , dc = com"
        result = u.Ldif.norm_string(dn)
        tm.that(result == "cn=John Doe,ou=Users,dc=example,dc=com", eq=True)

    def test_norm_string_empty(self) -> None:
        """Test empty DN."""
        result = u.Ldif.norm_string("")
        tm.that(not result, eq=True)

    def test_split_dn_components(self) -> None:
        """Test splitting DN into components."""
        dn = "cn=John,ou=Users,dc=example,dc=com"
        result = u.Ldif.split(dn)
        tm.that(result == ["cn=John", "ou=Users", "dc=example", "dc=com"], eq=True)

    def test_split_dn_with_escaped_commas(self) -> None:
        """Test splitting DN with escaped commas."""
        dn = "cn=Test\\, User,ou=Users,dc=example,dc=com"
        result = u.Ldif.split(dn)
        tm.that(
            result == ["cn=Test\\, User", "ou=Users", "dc=example", "dc=com"], eq=True
        )

    def test_split_dn_edge_cases(self) -> None:
        """Test splitting DN edge cases."""
        tm.that(u.Ldif.split("") == [], eq=True)
        tm.that(u.Ldif.split("cn=test") == ["cn=test"], eq=True)
        dn = "cn=Test\\, User\\\\More,ou=Users\\, Group,dc=example"
        result = u.Ldif.split(dn)
        tm.that(
            result == ["cn=Test\\, User\\\\More", "ou=Users\\, Group", "dc=example"],
            eq=True,
        )

    def test_validate_dn_format_valid(self) -> None:
        """Test valid DN validation."""
        valid_dns = [
            "cn=John,dc=example,dc=com",
            "ou=Users,dc=example,dc=com",
            "cn=REDACTED_LDAP_BIND_PASSWORD,o=example",
            "cn=Test\\, User,dc=example,dc=com",
            "cn=Test\\5CUser,dc=example,dc=com",
            "cn=Test#User,dc=example,dc=com",
            "cn=Test\\2BUser,dc=example,dc=com",
            "cn=Test\\3DUser,dc=example,dc=com",
        ]
        for dn in valid_dns:
            (
                tm.that(u.Ldif.validate(dn), eq=True),
                f"DN should be valid: {dn}",
            )

    def test_validate_dn_format_invalid(self) -> None:
        """Test invalid DN validation."""
        invalid_dns = [
            "",
            "no_equals_sign",
            "cn=",
            "=value",
            "cn=test,",
            ",cn=test",
            "cn=test,,ou=users",
            "cn=test\\",
            "cn=test\\Z",
            "cn=test\\XY",
        ]
        for dn in invalid_dns:
            (
                tm.that(not u.Ldif.validate(dn), eq=True),
                f"DN should be invalid: {dn}",
            )

    def test_parse_components(self) -> None:
        """Test DN component parsing."""
        dn = "cn=John,ou=Users,dc=example"
        result = u.Ldif.parse(dn)
        tm.that(result.is_success, eq=True)
        parsed = result.value
        tm.that(len(parsed) >= 2, eq=True)

    def test_compare_dns(self) -> None:
        """Test DN comparison."""
        dn1 = "cn=John,dc=example,dc=com"
        dn2 = "cn=jane,dc=example,dc=com"
        result = u.Ldif.compare_dns(dn1, dn2)
        tm.that(result.is_success, eq=True)
        comparison = result.value
        tm.that(isinstance(comparison, int), eq=True)

    def test_escape_dn_value(self) -> None:
        """Test escaping special DN value characters."""
        value = "Test, Value"
        result = u.Ldif.esc(value)
        tm.that(isinstance(result, str), eq=True)

    def test_unescape_dn_value(self) -> None:
        """Test unescaping DN value characters."""
        value = "Test\\,Value"
        result = u.Ldif.unesc(value)
        tm.that(isinstance(result, str), eq=True)

    def test_clean_dn(self) -> None:
        """Test DN cleaning."""
        dn = "  cn = John  ,  ou = Users  ,  dc = example  "
        result = u.Ldif.clean_dn(dn)
        tm.that(isinstance(result, str), eq=True)
        tm.that("  " not in result or result == dn, eq=True)


@pytest.mark.unit
class TestDnObjectClassMethods:
    """Test ObjectClass-related DN operations."""

    def test_fix_missing_sup(self) -> None:
        """Test fixing missing SUP in AUXILIARY classes."""
        obj = m.Ldif.SchemaObjectClass(
            oid="1.2.3.4", name="orcldasattrcategory", kind="AUXILIARY", sup=None
        )
        u.Ldif.fix_missing_sup(obj)
        tm.that(obj.sup == "top", eq=True)

    def test_fix_kind_mismatch(self) -> None:
        """Test fixing kind mismatches."""
        obj = m.Ldif.SchemaObjectClass(
            oid="1.2.3.4", name="testOC", sup="orclpwdverifierprofile", kind="AUXILIARY"
        )
        u.Ldif.fix_kind_mismatch(obj)
        tm.that(obj.kind == "STRUCTURAL", eq=True)

    def test_ensure_sup_for_auxiliary(self) -> None:
        """Test ensuring AUXILIARY classes have SUP."""
        obj = m.Ldif.SchemaObjectClass(
            oid="1.2.3.4", name="testOC", kind="AUXILIARY", sup=None
        )
        u.Ldif.ensure_sup_for_auxiliary(obj)
        tm.that(obj.sup == "top", eq=True)


@pytest.mark.unit
class TestAttributeFixer:
    """Test attribute definition normalization."""

    def test_normalize_name_basic(self) -> None:
        """Test basic attribute name normalization."""
        result = u.Ldif.normalize_name("testAttr_name;binary")
        tm.that(result == "testAttr-name", eq=True)

    def test_normalize_name_with_custom_replacements(self) -> None:
        """Test name normalization with custom replacements."""
        result = u.Ldif.normalize_name("test_attr_name", char_replacements={"_": "-"})
        tm.that(result == "test-attr-name", eq=True)

    def test_normalize_name_none(self) -> None:
        """Test normalizing None."""
        result = u.Ldif.normalize_name(None)
        tm.that(result is None, eq=True)

    def test_normalize_matching_rules_empty(self) -> None:
        """Test normalizing empty matching rules."""
        result = u.Ldif.normalize_matching_rules(None)
        tm.that(result == (None, None), eq=True)

    def test_normalize_matching_rules_equality_only(self) -> None:
        """Test normalizing matching rules with equality rule only."""
        result = u.Ldif.normalize_matching_rules("caseIgnoreMatch")
        tm.that(result == ("caseIgnoreMatch", None), eq=True)

    def test_normalize_matching_rules_both(self) -> None:
        """Test normalizing matching rules with both equality and substr."""
        result = u.Ldif.normalize_matching_rules(
            "caseIgnoreMatch", "caseIgnoreSubstringsMatch"
        )
        tm.that(result == ("caseIgnoreMatch", "caseIgnoreSubstringsMatch"), eq=True)


@pytest.mark.unit
class TestLdifParser:
    """Test LDIF parsing utilities - simple helper functions."""

    def test_extract_extensions_empty(self) -> None:
        """Test extracting extensions from empty schema definition."""
        definition = ""
        result = u.Ldif.extract_extensions(definition)
        tm.that(result == {}, eq=True)

    def test_extract_extensions_with_x_extension(self) -> None:
        """Test extracting X- extensions from schema definition."""
        definition = "( 1.2.3 NAME 'test' X-CUSTOM 'value' X-OTHER 'data' )"
        result = u.Ldif.extract_extensions(definition)
        tm.that(result.get("X-CUSTOM") == ["value"], eq=True)
        tm.that(result.get("X-OTHER") == ["data"], eq=True)

    def test_extract_extensions_with_desc(self) -> None:
        """Test extracting DESC from schema definition."""
        definition = "( 1.2.3 NAME 'test' DESC 'Test attribute' )"
        result = u.Ldif.extract_extensions(definition)
        tm.that(result.get("DESC") == ["Test attribute"], eq=True)

    def test_parse_ldif_lines_empty(self) -> None:
        """Test parsing empty LDIF content."""
        content = ""
        result = u.Ldif.parse_ldif_lines(content)
        tm.that(result == [], eq=True)

    def test_parse_ldif_lines_single_entry(self) -> None:
        """Test parsing single LDIF entry."""
        content = "dn: cn=test,dc=example,dc=com\ncn: test\nobjectClass: person\n"
        result = u.Ldif.parse_ldif_lines(content)
        tm.that(len(result) == 1, eq=True)
        dn, attrs = result[0]
        tm.that(dn == "cn=test,dc=example,dc=com", eq=True)
        tm.that(attrs.get("cn") == ["test"], eq=True)
        tm.that(attrs.get("objectClass") == ["person"], eq=True)

    def test_parse_ldif_lines_multiple_entries(self) -> None:
        """Test parsing multiple LDIF entries separated by empty line."""
        content = "dn: cn=test1,dc=example,dc=com\ncn: test1\nobjectClass: person\n\ndn: cn=test2,dc=example,dc=com\ncn: test2\nobjectClass: person\n"
        result = u.Ldif.parse_ldif_lines(content)
        (
            tm.that(len(result) == 2, eq=True),
            f"Expected 2 entries but got {len(result)}: {result}",
        )
        dn1, attrs1 = result[0]
        tm.that(dn1 == "cn=test1,dc=example,dc=com", eq=True)
        tm.that(attrs1.get("cn") == ["test1"], eq=True)
        tm.that(attrs1.get("objectClass") == ["person"], eq=True)
        dn2, attrs2 = result[1]
        tm.that(dn2 == "cn=test2,dc=example,dc=com", eq=True)
        tm.that(attrs2.get("cn") == ["test2"], eq=True)
        tm.that(attrs2.get("objectClass") == ["person"], eq=True)

    def test_unfold_lines_basic(self) -> None:
        """Test unfolding RFC 2849 folded lines."""
        content = "dn: cn=verylongname\n withfoldedcontinuation,dc=example,dc=com\n"
        result = u.Ldif.unfold_lines(content)
        tm.that(any("withfoldedcontinuation" in line for line in result), eq=True)


@pytest.mark.unit
class TestAclParser:
    """Test ACL parsing utilities."""

    def test_parse_oid_format(self) -> None:
        """Test parsing OID ACL format."""
        acl_line = 'orclaci: ( VERSION 3.0; ACETYPE ALLOW; (USERDN="ldap:///cn=*,ou=users,o=test");(ACITYPE ALLOW))'
        result = u.Ldif.parser(acl_line)
        tm.that(result is not None, eq=True)
        if result is not None:
            tm.that(result.get("format") == "oid", eq=True)

    def test_parse_oud_format(self) -> None:
        """Test parsing OUD ACL format."""
        acl_line = "aci: targetattr=*"
        result = u.Ldif.parser(acl_line)
        tm.that(result is not None, eq=True)
        if result is not None:
            tm.that(result.get("format") == "oud", eq=True)

    def test_parse_empty_acl(self) -> None:
        """Test parsing empty ACL."""
        result = u.Ldif.parser("")
        tm.that(result is None, eq=True)


@pytest.mark.unit
class TestServerTypes:
    """Test server type operations (via u.Ldif MRO)."""

    def test_normalize_server_type(self) -> None:
        """Test server type normalization."""
        tm.that(u.Ldif.normalize_server_type("oracle_oid") == "oid", eq=True)
        tm.that(u.Ldif.normalize_server_type("rfc") == "rfc", eq=True)

    def test_matches_server_type(self) -> None:
        """Test server type matching."""
        tm.that(u.Ldif.matches("oid", "oid", "oud"), eq=True)
        tm.that(not u.Ldif.matches("ad", "oid", "oud"), eq=True)


@pytest.mark.unit
class TestObjectClassUtilities:
    """Test ObjectClass validation and correction utilities."""

    def test_fix_missing_sup_auxiliary_without_sup(self) -> None:
        """Test fixing missing SUP for known AUXILIARY classes."""
        oc = m.Ldif.SchemaObjectClass(
            name="orcldAsAttrCategory",
            oid="1.2.3.4.5",
            kind=c.Ldif.SchemaKind.AUXILIARY,
            sup=None,
        )
        tm.that(oc.sup is None, eq=True)
        u.Ldif.fix_missing_sup(oc)
        tm.that(oc.sup == "top", eq=True)

    def test_fix_missing_sup_auxiliary_with_sup(self) -> None:
        """Test that AUXILIARY with SUP is not modified."""
        oc = m.Ldif.SchemaObjectClass(
            name="testAuxiliary",
            oid="1.2.3.4.5",
            kind=c.Ldif.SchemaKind.AUXILIARY,
            sup="top",
        )
        original_sup = oc.sup
        u.Ldif.fix_missing_sup(oc)
        tm.that(oc.sup == original_sup, eq=True)

    def test_fix_missing_sup_structural_ignored(self) -> None:
        """Test that STRUCTURAL classes are ignored."""
        oc = m.Ldif.SchemaObjectClass(
            name="testStructural",
            oid="1.2.3.4.6",
            kind=c.Ldif.SchemaKind.STRUCTURAL,
            sup=None,
        )
        original_sup = oc.sup
        u.Ldif.fix_missing_sup(oc)
        tm.that(oc.sup == original_sup, eq=True)

    def test_ensure_sup_for_auxiliary_adds_sup(self) -> None:
        """Test ensure_sup_for_auxiliary adds SUP when missing."""
        oc = m.Ldif.SchemaObjectClass(
            name="testAuxiliary",
            oid="1.2.3.4.7",
            kind=c.Ldif.SchemaKind.AUXILIARY,
            sup=None,
        )
        u.Ldif.ensure_sup_for_auxiliary(oc)
        tm.that(oc.sup == "top", eq=True)

    def test_ensure_sup_for_auxiliary_custom_default(self) -> None:
        """Test ensure_sup_for_auxiliary with custom default SUP."""
        oc = m.Ldif.SchemaObjectClass(
            name="testAuxiliary",
            oid="1.2.3.4.8",
            kind=c.Ldif.SchemaKind.AUXILIARY,
            sup=None,
        )
        u.Ldif.ensure_sup_for_auxiliary(oc, default_sup="custom")
        tm.that(oc.sup == "custom", eq=True)

    def test_fix_kind_mismatch_structural_superior(self) -> None:
        """Test fixing kind mismatch with STRUCTURAL superior."""
        oc = m.Ldif.SchemaObjectClass(
            name="testClass",
            oid="1.2.3.4.9",
            kind=c.Ldif.SchemaKind.AUXILIARY,
            sup="orclpwdverifierprofile",
        )
        u.Ldif.fix_kind_mismatch(oc)
        tm.that(oc.kind == c.Ldif.SchemaKind.STRUCTURAL, eq=True)

    def test_fix_kind_mismatch_auxiliary_superior(self) -> None:
        """Test fixing kind mismatch with AUXILIARY superior."""
        oc = m.Ldif.SchemaObjectClass(
            name="testClass",
            oid="1.2.3.4.10",
            kind=c.Ldif.SchemaKind.STRUCTURAL,
            sup="javanamingref",
        )
        u.Ldif.fix_kind_mismatch(oc)
        tm.that(oc.kind == c.Ldif.SchemaKind.AUXILIARY, eq=True)

    def test_align_kind_with_superior_structural(self) -> None:
        """Test aligning kind with STRUCTURAL superior."""
        oc = m.Ldif.SchemaObjectClass(
            name="testClass",
            oid="1.2.3.4.11",
            kind=c.Ldif.SchemaKind.AUXILIARY,
            sup="someSuperior",
        )
        u.Ldif.align_kind_with_superior(oc, c.Ldif.SchemaKind.STRUCTURAL)
        tm.that(oc.kind == c.Ldif.SchemaKind.STRUCTURAL, eq=True)

    def test_align_kind_with_superior_auxiliary(self) -> None:
        """Test aligning kind with AUXILIARY superior."""
        oc = m.Ldif.SchemaObjectClass(
            name="testClass",
            oid="1.2.3.4.12",
            kind=c.Ldif.SchemaKind.STRUCTURAL,
            sup="someSuperior",
        )
        u.Ldif.align_kind_with_superior(oc, c.Ldif.SchemaKind.AUXILIARY)
        tm.that(oc.kind == c.Ldif.SchemaKind.AUXILIARY, eq=True)

    def test_align_kind_with_superior_no_conflict(self) -> None:
        """Test that matching kinds are not changed."""
        oc = m.Ldif.SchemaObjectClass(
            name="testClass",
            oid="1.2.3.4.13",
            kind=c.Ldif.SchemaKind.STRUCTURAL,
            sup="someSuperior",
        )
        original_kind = oc.kind
        u.Ldif.align_kind_with_superior(oc, c.Ldif.SchemaKind.STRUCTURAL)
        tm.that(oc.kind == original_kind, eq=True)
