"""Tests for schema transformation utilities across LDAP servers.

This module tests the schema transformation and attribute name normalization
utilities that enhance RFC schema parsing with server-specific transformations.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from flext_core import r
from flext_tests import tm
from tests import m, s, t, u


class TestsFlextLdifSchemaTransformerNormalizeAttributeName(s):
    """Test normalize_attribute_name transformation."""

    def test_normalize_removes_binary_suffix(self) -> None:
        """Test that ;binary suffix is removed from attribute names."""
        result = u.Ldif.normalize_name(
            "userCertificate;binary", suffixes_to_remove=[";binary"]
        )
        tm.that(result == "userCertificate", eq=True)

    def test_normalize_replaces_underscores(self) -> None:
        """Test that underscores are replaced with hyphens."""
        result = u.Ldif.normalize_name(
            "oracle_oid_attribute", char_replacements={"_": "-"}
        )
        tm.that(result == "oracle-oid-attribute", eq=True)

    def test_normalize_removes_binary_and_underscores(self) -> None:
        """Test that both ;binary and underscores are normalized."""
        result = u.Ldif.normalize_name(
            "oracle_certificate;binary",
            suffixes_to_remove=[";binary"],
            char_replacements={"_": "-"},
        )
        tm.that(result == "oracle-certificate", eq=True)

    def test_normalize_rfc_compliant_name_unchanged(self) -> None:
        """Test that RFC-compliant names are unchanged."""
        result = u.Ldif.normalize_name("cn")
        tm.that(result == "cn", eq=True)

    def test_normalize_handles_empty_string(self) -> None:
        """Test that empty string is handled gracefully."""
        result = u.Ldif.normalize_name("")
        tm.that(not result, eq=True)

    def test_normalize_handles_none(self) -> None:
        """Test that None is handled gracefully."""
        result = u.Ldif.normalize_name(None)
        tm.that(result is None, eq=True)


class TestSchemaTransformerNormalizeMatchingRule:
    """Test normalize_matching_rule transformation."""

    def test_fix_substr_rule_in_equality_field(self) -> None:
        """Test that SUBSTR rules incorrectly in EQUALITY are fixed."""
        equality, substr = u.Ldif.normalize_matching_rules(
            "caseIgnoreSubstringsMatch",
            None,
            substr_rules_in_equality={"caseIgnoreSubstringsMatch": "caseIgnoreMatch"},
        )
        tm.that(equality == "caseIgnoreMatch", eq=True)
        tm.that(substr == "caseIgnoreSubstringsMatch", eq=True)

    def test_fix_substr_rule_capital_s(self) -> None:
        """Test that caseIgnoreSubStringsMatch (capital S) is handled."""
        equality, substr = u.Ldif.normalize_matching_rules(
            "caseIgnoreSubStringsMatch",
            None,
            normalized_substr_values={
                "caseIgnoreSubStringsMatch": "caseIgnoreSubstringsMatch"
            },
            substr_rules_in_equality={"caseIgnoreSubStringsMatch": "caseIgnoreMatch"},
        )
        tm.that(equality == "caseIgnoreMatch", eq=True)
        tm.that(substr == "caseIgnoreSubstringsMatch", eq=True)

    def test_apply_matching_rule_replacements(self) -> None:
        """Test that server-specific matching rule replacements are applied."""
        replacements = {"accessDirectiveMatch": "caseIgnoreMatch"}
        equality, substr = u.Ldif.normalize_matching_rules(
            "accessDirectiveMatch", None, replacements=replacements
        )
        tm.that(equality == "caseIgnoreMatch", eq=True)
        tm.that(substr is None, eq=True)

    def test_rfc_compliant_rule_unchanged(self) -> None:
        """Test that RFC-compliant rules are unchanged."""
        equality, substr = u.Ldif.normalize_matching_rules("caseIgnoreMatch", None)
        tm.that(equality == "caseIgnoreMatch", eq=True)
        tm.that(substr is None, eq=True)

    def test_preserve_existing_substr(self) -> None:
        """Test that existing SUBSTR rules are preserved."""
        equality, substr = u.Ldif.normalize_matching_rules(
            "caseIgnoreMatch", "caseIgnoreSubstringsMatch"
        )
        tm.that(equality == "caseIgnoreMatch", eq=True)
        tm.that(substr == "caseIgnoreSubstringsMatch", eq=True)


class TestSchemaTransformerNormalizeSyntaxOid:
    """Test normalize_syntax_oid transformation."""

    def test_remove_quotes_from_syntax(self) -> None:
        """Test that quotes are removed from syntax OIDs."""
        result = u.Ldif.normalize_syntax_oid("'1.3.6.1.4.1.1466.115.121.1.15'")
        tm.that(result == "1.3.6.1.4.1.1466.115.121.1.15", eq=True)

    def test_apply_syntax_replacements(self) -> None:
        """Test that server-specific syntax replacements are applied."""
        replacements = {"1.3.6.1.4.1.1466.115.121.1.1": "1.3.6.1.4.1.1466.115.121.1.15"}
        result = u.Ldif.normalize_syntax_oid(
            "1.3.6.1.4.1.1466.115.121.1.1", replacements=replacements
        )
        tm.that(result == "1.3.6.1.4.1.1466.115.121.1.15", eq=True)

    def test_rfc_compliant_syntax_unchanged(self) -> None:
        """Test that RFC-compliant syntax OIDs are unchanged."""
        result = u.Ldif.normalize_syntax_oid("1.3.6.1.4.1.1466.115.121.1.15")
        tm.that(result == "1.3.6.1.4.1.1466.115.121.1.15", eq=True)


class TestSchemaTransformerApplyAttributeTransformations:
    """Test apply_attribute_transformations pipeline."""

    def test_apply_all_transformations(self) -> None:
        """Test applying all three transformations to an attribute."""
        attr = m.Ldif.SchemaAttribute(
            oid="2.5.4.3",
            name="cn;binary",
            equality="caseIgnoreSubstringsMatch",
            syntax="'1.3.6.1.4.1.1466.115.121.1.1'",
        )

        def transform_name(n: str | None) -> str | None:
            n_str: str | None = (
                str(n) if isinstance(n, str) else n if n is None else str(n)
            )
            return u.Ldif.normalize_name(
                n_str, suffixes_to_remove=[";binary"], char_replacements={"_": "-"}
            )

        def transform_equality(eq: str | None) -> str | None:
            eq_str: str | None = (
                str(eq) if isinstance(eq, str) else eq if eq is None else str(eq)
            )
            return u.Ldif.normalize_matching_rules(
                eq_str,
                None,
                substr_rules_in_equality={
                    "caseIgnoreSubstringsMatch": "caseIgnoreMatch"
                },
            )[0]

        def transform_substr(sub: str | None) -> str | None:
            sub_str: str | None = (
                str(sub) if isinstance(sub, str) else sub if sub is None else str(sub)
            )
            return u.Ldif.normalize_matching_rules(
                attr.equality,
                sub_str,
                substr_rules_in_equality={
                    "caseIgnoreSubstringsMatch": "caseIgnoreMatch"
                },
            )[1]

        def transform_syntax(syn: str | None) -> str | None:
            syn_str: str | None = (
                str(syn) if isinstance(syn, str) else syn if syn is None else str(syn)
            )
            return u.Ldif.normalize_syntax_oid(
                syn_str,
                replacements={
                    "1.3.6.1.4.1.1466.115.121.1.1": "1.3.6.1.4.1.1466.115.121.1.15"
                },
            )

        field_transforms: Mapping[
            str,
            Callable[..., t.Container | r[t.Container] | None]
            | str
            | Sequence[str]
            | None,
        ] = {
            "name": transform_name,
            "equality": transform_equality,
            "substr": transform_substr,
            "syntax": transform_syntax,
        }
        result = u.Ldif.apply_transformations(attr, field_transforms=field_transforms)
        tm.that(result.is_success, eq=True)
        transformed = result.value
        tm.that(isinstance(transformed, m.Ldif.SchemaAttribute), eq=True)
        if isinstance(transformed, m.Ldif.SchemaAttribute):
            tm.that(transformed.name == "cn", eq=True)
            tm.that(transformed.equality == "caseIgnoreMatch", eq=True)
            tm.that(transformed.substr == "caseIgnoreSubstringsMatch", eq=True)
            tm.that(transformed.syntax == "1.3.6.1.4.1.1466.115.121.1.15", eq=True)

    def test_partial_transformations(self) -> None:
        """Test applying only some transformations."""
        attr = m.Ldif.SchemaAttribute(
            oid="2.5.4.3", name="cn;binary", equality="caseIgnoreMatch"
        )

        def transform_name(n: str | None) -> str | None:
            n_str: str | None = (
                str(n) if isinstance(n, str) else n if n is None else str(n)
            )
            return u.Ldif.normalize_name(
                n_str, suffixes_to_remove=[";binary"], char_replacements={"_": "-"}
            )

        field_transforms: Mapping[
            str,
            Callable[..., t.Container | r[t.Container] | None]
            | str
            | Sequence[str]
            | None,
        ] = {"name": transform_name}
        result = u.Ldif.apply_transformations(attr, field_transforms=field_transforms)
        tm.that(result.is_success, eq=True)
        transformed = result.value
        tm.that(isinstance(transformed, m.Ldif.SchemaAttribute), eq=True)
        if isinstance(transformed, m.Ldif.SchemaAttribute):
            tm.that(transformed.name == "cn", eq=True)
            tm.that(transformed.equality == "caseIgnoreMatch", eq=True)


class TestSchemaTransformerApplyObjectClassTransformations:
    """Test apply_objectclass_transformations pipeline."""

    def test_apply_objectclass_transformations(self) -> None:
        """Test transforming an objectClass."""
        oc = m.Ldif.SchemaObjectClass(oid="2.5.6.0", name="top")
        result = u.Ldif.apply_transformations(oc, field_transforms=None)
        tm.that(result.is_success, eq=True)
        transformed = result.value
        tm.that(transformed.name == "top", eq=True)
        tm.that(transformed.oid == "2.5.6.0", eq=True)
