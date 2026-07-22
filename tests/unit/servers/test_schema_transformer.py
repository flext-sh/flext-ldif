"""Behavioral tests for LDIF schema normalization helpers.

Exercises the public normalization contract exposed through ``u.Ldif``:
``normalize_name``, ``normalize_matching_rules`` and ``normalize_syntax_oid``.
Every assertion targets an observable return value of a pure function -- no
private state, no collaborator spying, no patching of the unit under test.
"""

from __future__ import annotations

import pytest

from flext_tests import tm
from tests import u


class TestsFlextLdifSchemaTransformer:
    """Contract of the schema normalization helpers via public API."""

    # ------------------------------------------------------------------
    # normalize_name
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        ("name_value", "suffixes", "replacements", "expected"),
        [
            ("userCertificate;binary", [";binary"], None, "userCertificate"),
            ("oracle_oid_attribute", None, {"_": "-"}, "oracle-oid-attribute"),
            (
                "oracle_certificate;binary",
                [";binary"],
                {"_": "-"},
                "oracle-certificate",
            ),
            ("cn", [";binary"], {"_": "-"}, "cn"),
            ("a_b_c", None, {"_": "."}, "a.b.c"),
            ("keep;binary;binary", [";binary"], None, "keep"),
        ],
    )
    def test_normalize_name_applies_suffix_and_char_rules(
        self,
        name_value: str,
        suffixes: list[str] | None,
        replacements: dict[str, str] | None,
        expected: str,
    ) -> None:
        """Configured suffixes and char replacements produce the RFC name."""
        result = u.Ldif.normalize_name(
            name_value, suffixes_to_remove=suffixes, char_replacements=replacements
        )
        tm.that(result, eq=expected)

    @pytest.mark.parametrize(
        ("name_value", "expected"),
        [
            ("userCertificate;binary", "userCertificate"),
            ("oracle_oid", "oracle-oid"),
            ("oracle_cert;binary", "oracle-cert"),
            ("cn", "cn"),
        ],
    )
    def test_normalize_name_defaults_strip_binary_and_underscore(
        self, name_value: str, expected: str
    ) -> None:
        """With no config, defaults strip ``;binary`` and map ``_`` to ``-``."""
        result = u.Ldif.normalize_name(name_value)
        tm.that(result, eq=expected)

    @pytest.mark.parametrize("empty", ["", None])
    def test_normalize_name_returns_falsy_input_unchanged(
        self, empty: str | None
    ) -> None:
        """Empty string and None are returned as-is (no transformation)."""
        result = u.Ldif.normalize_name(empty)
        tm.that(result, eq=empty)

    def test_normalize_name_is_idempotent(self) -> None:
        """Re-normalizing an already-normalized name is a fixed point."""
        once = u.Ldif.normalize_name("oracle_cert;binary")
        twice = u.Ldif.normalize_name(once)
        tm.that(once, eq="oracle-cert")
        tm.that(twice, eq="oracle-cert")

    def test_normalize_name_without_matches_preserves_identity(self) -> None:
        """A name with no suffix/char hits comes back byte-identical."""
        result = u.Ldif.normalize_name(
            "plainName", suffixes_to_remove=[";binary"], char_replacements={"_": "-"}
        )
        tm.that(result, eq="plainName")

    # ------------------------------------------------------------------
    # normalize_matching_rules
    # ------------------------------------------------------------------

    def test_matching_rules_moves_substr_rule_out_of_equality(self) -> None:
        """A SUBSTR rule mistakenly in EQUALITY is relocated to SUBSTR."""
        equality, substr = u.Ldif.normalize_matching_rules(
            "caseIgnoreSubstringsMatch",
            None,
            substr_rules_in_equality={"caseIgnoreSubstringsMatch": "caseIgnoreMatch"},
        )
        tm.that(equality, eq="caseIgnoreMatch")
        tm.that(substr, eq="caseIgnoreSubstringsMatch")

    def test_matching_rules_normalizes_relocated_substr_value(self) -> None:
        """Relocated SUBSTR value is canonicalized via normalized_substr_values."""
        equality, substr = u.Ldif.normalize_matching_rules(
            "caseIgnoreSubStringsMatch",
            None,
            normalized_substr_values={
                "caseIgnoreSubStringsMatch": "caseIgnoreSubstringsMatch"
            },
            substr_rules_in_equality={"caseIgnoreSubStringsMatch": "caseIgnoreMatch"},
        )
        tm.that(equality, eq="caseIgnoreMatch")
        tm.that(substr, eq="caseIgnoreSubstringsMatch")

    def test_matching_rules_applies_equality_replacement(self) -> None:
        """Server-specific EQUALITY replacements map to the RFC rule."""
        equality, substr = u.Ldif.normalize_matching_rules(
            "accessDirectiveMatch",
            None,
            replacements={"accessDirectiveMatch": "caseIgnoreMatch"},
        )
        tm.that(equality, eq="caseIgnoreMatch")
        tm.that(substr, none=True)

    @pytest.mark.parametrize(
        ("equality", "substr", "exp_equality", "exp_substr"),
        [
            ("caseIgnoreMatch", None, "caseIgnoreMatch", None),
            (
                "caseIgnoreMatch",
                "caseIgnoreSubstringsMatch",
                "caseIgnoreMatch",
                "caseIgnoreSubstringsMatch",
            ),
            (None, None, None, None),
        ],
    )
    def test_matching_rules_passthrough_without_config(
        self,
        equality: str | None,
        substr: str | None,
        exp_equality: str | None,
        exp_substr: str | None,
    ) -> None:
        """Without config maps, EQUALITY/SUBSTR pass through untouched."""
        result_equality, result_substr = u.Ldif.normalize_matching_rules(
            equality, substr
        )
        tm.that(result_equality, eq=exp_equality)
        tm.that(result_substr, eq=exp_substr)

    def test_matching_rules_replacement_ignores_unlisted_rule(self) -> None:
        """A replacement map that lacks the rule leaves EQUALITY unchanged."""
        equality, substr = u.Ldif.normalize_matching_rules(
            "distinguishedNameMatch",
            None,
            replacements={"accessDirectiveMatch": "caseIgnoreMatch"},
        )
        tm.that(equality, eq="distinguishedNameMatch")
        tm.that(substr, none=True)

    def test_matching_rules_preserves_existing_substr(self) -> None:
        """An already-present SUBSTR rule is never dropped."""
        equality, substr = u.Ldif.normalize_matching_rules(
            "caseIgnoreMatch", "caseIgnoreSubstringsMatch"
        )
        tm.that(equality, eq="caseIgnoreMatch")
        tm.that(substr, eq="caseIgnoreSubstringsMatch")

    # ------------------------------------------------------------------
    # normalize_syntax_oid
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        ("syntax", "replacements", "expected"),
        [
            ("'1.3.6.1.4.1.1466.115.121.1.15'", None, "1.3.6.1.4.1.1466.115.121.1.15"),
            (
                "1.3.6.1.4.1.1466.115.121.1.1",
                {"1.3.6.1.4.1.1466.115.121.1.1": "1.3.6.1.4.1.1466.115.121.1.15"},
                "1.3.6.1.4.1.1466.115.121.1.15",
            ),
            ("1.3.6.1.4.1.1466.115.121.1.15", None, "1.3.6.1.4.1.1466.115.121.1.15"),
            (
                "'1.3.6.1.4.1.1466.115.121.1.1'",
                {"1.3.6.1.4.1.1466.115.121.1.1": "1.3.6.1.4.1.1466.115.121.1.15"},
                "1.3.6.1.4.1.1466.115.121.1.15",
            ),
        ],
    )
    def test_syntax_oid_strips_quotes_then_applies_replacements(
        self, syntax: str, replacements: dict[str, str] | None, expected: str
    ) -> None:
        """Surrounding quotes are removed, then replacement mapping is applied."""
        result = u.Ldif.normalize_syntax_oid(syntax, replacements=replacements)
        tm.that(result, eq=expected)

    @pytest.mark.parametrize("empty", ["", None])
    def test_syntax_oid_returns_falsy_input_unchanged(self, empty: str | None) -> None:
        """Empty string and None are returned unchanged."""
        result = u.Ldif.normalize_syntax_oid(empty)
        tm.that(result, eq=empty)

    def test_syntax_oid_leaves_one_sided_quote_intact(self) -> None:
        """Only a fully quote-wrapped OID is unquoted; a lone quote stays."""
        result = u.Ldif.normalize_syntax_oid("'1.3.6.1.4.1.1466.115.121.1.15")
        tm.that(result, eq="'1.3.6.1.4.1.1466.115.121.1.15")

    def test_syntax_oid_is_idempotent(self) -> None:
        """Normalizing an already-clean OID is a fixed point."""
        once = u.Ldif.normalize_syntax_oid("'1.3.6.1.4.1.1466.115.121.1.15'")
        twice = u.Ldif.normalize_syntax_oid(once)
        tm.that(once, eq="1.3.6.1.4.1.1466.115.121.1.15")
        tm.that(twice, eq="1.3.6.1.4.1.1466.115.121.1.15")
