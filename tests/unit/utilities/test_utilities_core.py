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

    def test_split_dn_components(self) -> None:
        """Test splitting DN into components."""
        dn = "cn=John,ou=Users,dc=example,dc=com"
        result = u.Ldif.split(dn)
        tm.that(result, eq=["cn=John", "ou=Users", "dc=example", "dc=com"])

    def test_split_dn_with_escaped_commas(self) -> None:
        """Test splitting DN with escaped commas."""
        dn = "cn=Test\\, User,ou=Users,dc=example,dc=com"
        result = u.Ldif.split(dn)
        tm.that(result, eq=["cn=Test\\, User", "ou=Users", "dc=example", "dc=com"])

    def test_split_dn_edge_cases(self) -> None:
        """Test splitting DN edge cases."""
        tm.that(u.Ldif.split(""), eq=[])
        tm.that(u.Ldif.split("cn=test"), eq=["cn=test"])
        dn = "cn=Test\\, User\\\\More,ou=Users\\, Group,dc=example"
        result = u.Ldif.split(dn)
        tm.that(
            result,
            eq=["cn=Test\\, User\\\\More", "ou=Users\\, Group", "dc=example"],
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
            _ = tm.that(u.Ldif.validate(dn), eq=True)

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
            _ = tm.that(not u.Ldif.validate(dn), eq=True)

    def test_parse_components(self) -> None:
        """Test DN component parsing."""
        dn = "cn=John,ou=Users,dc=example"
        result = u.Ldif.parse(dn)
        tm.that(result.is_success, eq=True)
        parsed = result.value
        tm.that(len(parsed), gte=2)

    def test_compare_dns(self) -> None:
        """Test DN comparison."""
        dn1 = "cn=John,dc=example,dc=com"
        dn2 = "cn=jane,dc=example,dc=com"
        result = u.Ldif.compare_dns(dn1, dn2)
        tm.that(result.is_success, eq=True)
        comparison = result.value
        tm.that(comparison, is_=int)

    def test_escape_dn_value(self) -> None:
        """Test escaping special DN value characters."""
        value = "Test, Value"
        result = u.Ldif.esc(value)
        tm.that(result, is_=str)

    def test_unescape_dn_value(self) -> None:
        """Test unescaping DN value characters."""
        value = "Test\\,Value"
        result = u.Ldif.unesc(value)
        tm.that(result, is_=str)

    def test_clean_dn(self) -> None:
        """Test DN cleaning."""
        dn = "  cn = John  ,  ou = Users  ,  dc = example  "
        result = u.Ldif.clean_dn(dn)
        tm.that(result, is_=str)
        tm.that("  " not in result or result == dn, eq=True)


@pytest.mark.unit
class TestDnObjectClassMethods:
    """Test ObjectClass-related DN operations."""

    def test_fix_missing_sup(self) -> None:
        """Test fixing missing SUP in AUXILIARY classes."""
        obj = m.Ldif.SchemaObjectClass(
            oid="1.2.3.4",
            name="orcldasattrcategory",
            kind="AUXILIARY",
            sup=None,
        )
        u.Ldif.fix_missing_sup(obj)
        tm.that(obj.sup, eq="top")

    def test_fix_kind_mismatch(self) -> None:
        """Test fixing kind mismatches."""
        obj = m.Ldif.SchemaObjectClass(
            oid="1.2.3.4",
            name="testOC",
            sup="orclpwdverifierprofile",
            kind="AUXILIARY",
        )
        u.Ldif.fix_kind_mismatch(obj)
        tm.that(obj.kind, eq="STRUCTURAL")


@pytest.mark.unit
class TestAttributeFixer:
    """Test attribute definition normalization."""

    def test_normalize_name_basic(self) -> None:
        """Test basic attribute name normalization."""
        result = u.Ldif.normalize_name("testAttr_name;binary")
        tm.that(result, eq="testAttr-name")

    def test_normalize_name_with_custom_replacements(self) -> None:
        """Test name normalization with custom replacements."""
        result = u.Ldif.normalize_name("test_attr_name", char_replacements={"_": "-"})
        tm.that(result, eq="test-attr-name")

    def test_normalize_name_none(self) -> None:
        """Test normalizing None."""
        result = u.Ldif.normalize_name(None)
        tm.that(result, none=True)

    def test_normalize_matching_rules_empty(self) -> None:
        """Test normalizing empty matching rules."""
        result = u.Ldif.normalize_matching_rules(None)
        tm.that(result, eq=(None, None))

    def test_normalize_matching_rules_equality_only(self) -> None:
        """Test normalizing matching rules with equality rule only."""
        result = u.Ldif.normalize_matching_rules("caseIgnoreMatch")
        tm.that(result, eq=("caseIgnoreMatch", None))

    def test_normalize_matching_rules_both(self) -> None:
        """Test normalizing matching rules with both equality and substr."""
        result = u.Ldif.normalize_matching_rules(
            "caseIgnoreMatch",
            "caseIgnoreSubstringsMatch",
        )
        tm.that(result, eq=("caseIgnoreMatch", "caseIgnoreSubstringsMatch"))


@pytest.mark.unit
class TestLdifParser:
    """Test LDIF parsing utilities - simple helper functions."""

    def test_extract_extensions_empty(self) -> None:
        """Test extracting extensions from empty schema definition."""
        definition = ""
        result = u.Ldif.extract_extensions(definition)
        tm.that(result, eq={})

    def test_extract_extensions_with_x_extension(self) -> None:
        """Test extracting X- extensions from schema definition."""
        definition = "( 1.2.3 NAME 'test' X-CUSTOM 'value' X-OTHER 'data' )"
        result = u.Ldif.extract_extensions(definition)
        tm.that(result.get("X-CUSTOM"), eq=["value"])
        tm.that(result.get("X-OTHER"), eq=["data"])

    def test_extract_extensions_with_desc(self) -> None:
        """Test extracting DESC from schema definition."""
        definition = "( 1.2.3 NAME 'test' DESC 'Test attribute' )"
        result = u.Ldif.extract_extensions(definition)
        tm.that(result.get("DESC"), eq=["Test attribute"])

    def test_parse_ldif_lines_empty(self) -> None:
        """Test parsing empty LDIF content."""
        content = ""
        result = u.Ldif.parse_ldif_lines(content)
        tm.that(result, eq=[])

    def test_parse_ldif_lines_single_entry(self) -> None:
        """Test parsing single LDIF entry."""
        content = "dn: cn=test,dc=example,dc=com\ncn: test\nobjectClass: person\n"
        result = u.Ldif.parse_ldif_lines(content)
        tm.that(len(result), eq=1)
        dn, attrs = result[0]
        tm.that(dn, eq="cn=test,dc=example,dc=com")
        tm.that(attrs.get("cn"), eq=["test"])
        tm.that(attrs.get("objectClass"), eq=["person"])

    def test_parse_ldif_lines_multiple_entries(self) -> None:
        """Test parsing multiple LDIF entries separated by empty line."""
        content = "dn: cn=test1,dc=example,dc=com\ncn: test1\nobjectClass: person\n\ndn: cn=test2,dc=example,dc=com\ncn: test2\nobjectClass: person\n"
        result = u.Ldif.parse_ldif_lines(content)
        _ = tm.that(len(result), eq=2)
        dn1, attrs1 = result[0]
        tm.that(dn1, eq="cn=test1,dc=example,dc=com")
        tm.that(attrs1.get("cn"), eq=["test1"])
        tm.that(attrs1.get("objectClass"), eq=["person"])
        dn2, attrs2 = result[1]
        tm.that(dn2, eq="cn=test2,dc=example,dc=com")
        tm.that(attrs2.get("cn"), eq=["test2"])
        tm.that(attrs2.get("objectClass"), eq=["person"])

    def test_unfold_lines_basic(self) -> None:
        """Test unfolding RFC 2849 folded lines."""
        content = "dn: cn=verylongname\n withfoldedcontinuation,dc=example,dc=com\n"
        result = u.Ldif.unfold_lines(content)
        tm.that(any("withfoldedcontinuation" in line for line in result), eq=True)


@pytest.mark.unit
class TestServerTypes:
    """Test server type operations (via u.Ldif MRO)."""

    def test_normalize_server_type(self) -> None:
        """Test server type normalization."""
        tm.that(u.Ldif.normalize_server_type("oracle_oid"), eq="oid")
        tm.that(u.Ldif.normalize_server_type("rfc"), eq="rfc")

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
        tm.that(oc.sup, none=True)
        u.Ldif.fix_missing_sup(oc)
        tm.that(oc.sup, eq="top")

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
        tm.that(oc.sup, eq=original_sup)

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
        tm.that(oc.sup, eq=original_sup)

    def test_fix_kind_mismatch_structural_superior(self) -> None:
        """Test fixing kind mismatch with STRUCTURAL superior."""
        oc = m.Ldif.SchemaObjectClass(
            name="testClass",
            oid="1.2.3.4.9",
            kind=c.Ldif.SchemaKind.AUXILIARY,
            sup="orclpwdverifierprofile",
        )
        u.Ldif.fix_kind_mismatch(oc)
        tm.that(oc.kind, eq=c.Ldif.SchemaKind.STRUCTURAL)

    def test_fix_kind_mismatch_auxiliary_superior(self) -> None:
        """Test fixing kind mismatch with AUXILIARY superior."""
        oc = m.Ldif.SchemaObjectClass(
            name="testClass",
            oid="1.2.3.4.10",
            kind=c.Ldif.SchemaKind.STRUCTURAL,
            sup="javanamingref",
        )
        u.Ldif.fix_kind_mismatch(oc)
        tm.that(oc.kind, eq=c.Ldif.SchemaKind.AUXILIARY)
