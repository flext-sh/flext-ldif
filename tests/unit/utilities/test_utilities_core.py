"""Tests for LDIF DN operations as pure functions.

This module tests DN (Distinguished Name) utility functions as pure functions returning
primitives, including DN component normalization, full DN normalization, DN parsing,
splitting, component extraction, and handling of special characters and escaped values.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests.constants import c
from tests.models import m
from tests.utilities import u


@pytest.mark.unit
class TestsFlextLdifUtilitiesCore:
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

    def test_dn_model_accepts_escaped_commas(self) -> None:
        """Test DN model validation with escaped commas."""
        dn = m.Ldif.DN(value="cn=Test\\, User,ou=Users,dc=example,dc=com")
        tm.that(dn.value, eq="cn=Test\\, User,ou=Users,dc=example,dc=com")

    def test_split_dn_edge_cases(self) -> None:
        """Test splitting DN edge cases."""
        tm.that(u.Ldif.split(""), empty=True)
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
        parsed = tm.ok(u.Ldif.parse("cn=John,ou=Users,dc=example"))
        tm.that(len(parsed), gte=2)

    def test_compare_dns(self) -> None:
        """Test DN comparison."""
        comparison = tm.ok(
            u.Ldif.compare_dns(
                "cn=John,dc=example,dc=com", "cn=jane,dc=example,dc=com"
            ),
        )
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

    """Test LDIF parsing utilities - simple helper functions."""

    def test_extract_extensions_empty(self) -> None:
        """Test extracting extensions from empty schema definition."""
        definition = ""
        result = u.Ldif.extract_extensions(definition)
        tm.that(result, empty=True)

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

    def test_unfold_lines_basic(self) -> None:
        """Test unfolding RFC 2849 folded lines."""
        content = "dn: cn=verylongname\n withfoldedcontinuation,dc=example,dc=com\n"
        result = u.Ldif.unfold_lines(content)
        tm.that(any("withfoldedcontinuation" in line for line in result), eq=True)

    """Test server type operations (via u.Ldif MRO)."""

    def test_normalize_server_type(self) -> None:
        """Test server type normalization."""
        tm.that(u.Ldif.normalize_server_type("oracle_oid"), eq="oid")
        tm.that(u.Ldif.normalize_server_type("rfc"), eq="rfc")

    def test_validation_rule_flags_resolve_from_canonical_server_capabilities(
        self,
    ) -> None:
        """Validation flags should be derived from canonical server-type capabilities."""
        openldap_flags = u.Ldif.validation_rule_flags("openldap")
        novell_flags = u.Ldif.validation_rule_flags("novell_edirectory")
        ds389_flags = u.Ldif.validation_rule_flags(c.Ldif.ServerTypes.DS389)

        tm.that(openldap_flags["requires_binary_option"], eq=True)
        tm.that(openldap_flags["requires_objectclass"], eq=False)
        tm.that(novell_flags["requires_objectclass"], eq=True)
        tm.that(novell_flags["requires_naming_attr"], eq=False)
        tm.that(ds389_flags["requires_objectclass"], eq=True)
        tm.that(ds389_flags["requires_binary_option"], eq=False)

    def test_matches_server_type(self) -> None:
        """Test server type matching."""
        tm.that(u.Ldif.matches("oid", "oid", "oud"), eq=True)
        tm.that(not u.Ldif.matches("ad", "oid", "oud"), eq=True)

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
