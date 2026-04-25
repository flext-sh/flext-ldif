"""Tests for schema transformation utilities across LDAP servers.

This module tests the schema transformation and attribute name normalization
utilities that enhance RFC schema parsing with server-specific transformations.
"""

from __future__ import annotations

from flext_tests import tm

from tests import u


class TestsFlextLdifSchemaTransformer:
    """Test normalize_attribute_name transformation."""

    def test_normalize_removes_binary_suffix(self) -> None:
        """Test that ;binary suffix is removed from attribute names."""
        result = u.Ldif.normalize_name(
            "userCertificate;binary",
            suffixes_to_remove=[";binary"],
        )
        tm.that(result, eq="userCertificate")

    def test_normalize_replaces_underscores(self) -> None:
        """Test that underscores are replaced with hyphens."""
        result = u.Ldif.normalize_name(
            "oracle_oid_attribute",
            char_replacements={"_": "-"},
        )
        tm.that(result, eq="oracle-oid-attribute")

    def test_normalize_removes_binary_and_underscores(self) -> None:
        """Test that both ;binary and underscores are normalized."""
        result = u.Ldif.normalize_name(
            "oracle_certificate;binary",
            suffixes_to_remove=[";binary"],
            char_replacements={"_": "-"},
        )
        tm.that(result, eq="oracle-certificate")

    def test_normalize_rfc_compliant_name_unchanged(self) -> None:
        """Test that RFC-compliant names are unchanged."""
        result = u.Ldif.normalize_name("cn")
        tm.that(result, eq="cn")

    def test_normalize_handles_empty_string(self) -> None:
        """Test that empty string is handled gracefully."""
        result = u.Ldif.normalize_name("")
        tm.that(not result, eq=True)

    def test_normalize_handles_none(self) -> None:
        """Test that None is handled gracefully."""
        result = u.Ldif.normalize_name(None)
        tm.that(result, none=True)

    """Test normalize_matching_rule transformation."""

    def test_fix_substr_rule_in_equality_field(self) -> None:
        """Test that SUBSTR rules incorrectly in EQUALITY are fixed."""
        equality, substr = u.Ldif.normalize_matching_rules(
            "caseIgnoreSubstringsMatch",
            None,
            substr_rules_in_equality={"caseIgnoreSubstringsMatch": "caseIgnoreMatch"},
        )
        tm.that(equality, eq="caseIgnoreMatch")
        tm.that(substr, eq="caseIgnoreSubstringsMatch")

    def test_fix_substr_rule_capital_s(self) -> None:
        """Test that caseIgnoreSubStringsMatch (capital S) is handled."""
        equality, substr = u.Ldif.normalize_matching_rules(
            "caseIgnoreSubStringsMatch",
            None,
            normalized_substr_values={
                "caseIgnoreSubStringsMatch": "caseIgnoreSubstringsMatch",
            },
            substr_rules_in_equality={"caseIgnoreSubStringsMatch": "caseIgnoreMatch"},
        )
        tm.that(equality, eq="caseIgnoreMatch")
        tm.that(substr, eq="caseIgnoreSubstringsMatch")

    def test_apply_matching_rule_replacements(self) -> None:
        """Test that server-specific matching rule replacements are applied."""
        replacements = {"accessDirectiveMatch": "caseIgnoreMatch"}
        equality, substr = u.Ldif.normalize_matching_rules(
            "accessDirectiveMatch",
            None,
            replacements=replacements,
        )
        tm.that(equality, eq="caseIgnoreMatch")
        tm.that(substr, none=True)

    def test_rfc_compliant_rule_unchanged(self) -> None:
        """Test that RFC-compliant rules are unchanged."""
        equality, substr = u.Ldif.normalize_matching_rules("caseIgnoreMatch", None)
        tm.that(equality, eq="caseIgnoreMatch")
        tm.that(substr, none=True)

    def test_preserve_existing_substr(self) -> None:
        """Test that existing SUBSTR rules are preserved."""
        equality, substr = u.Ldif.normalize_matching_rules(
            "caseIgnoreMatch",
            "caseIgnoreSubstringsMatch",
        )
        tm.that(equality, eq="caseIgnoreMatch")
        tm.that(substr, eq="caseIgnoreSubstringsMatch")

    """Test normalize_syntax_oid transformation."""

    def test_remove_quotes_from_syntax(self) -> None:
        """Test that quotes are removed from syntax OIDs."""
        result = u.Ldif.normalize_syntax_oid("'1.3.6.1.4.1.1466.115.121.1.15'")
        tm.that(result, eq="1.3.6.1.4.1.1466.115.121.1.15")

    def test_apply_syntax_replacements(self) -> None:
        """Test that server-specific syntax replacements are applied."""
        replacements = {"1.3.6.1.4.1.1466.115.121.1.1": "1.3.6.1.4.1.1466.115.121.1.15"}
        result = u.Ldif.normalize_syntax_oid(
            "1.3.6.1.4.1.1466.115.121.1.1",
            replacements=replacements,
        )
        tm.that(result, eq="1.3.6.1.4.1.1466.115.121.1.15")

    def test_rfc_compliant_syntax_unchanged(self) -> None:
        """Test that RFC-compliant syntax OIDs are unchanged."""
        result = u.Ldif.normalize_syntax_oid("1.3.6.1.4.1.1466.115.121.1.15")
        tm.that(result, eq="1.3.6.1.4.1.1466.115.121.1.15")
