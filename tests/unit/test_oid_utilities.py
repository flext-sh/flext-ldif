from __future__ import annotations

import pytest

from flext_tests import tm
from tests import c, t, u


class TestsFlextLdifOidUtilities:
    """Behavioral contract for the OID schema-definition utilities."""

    @pytest.mark.parametrize(
        ("definition", "expected_oid"),
        [
            ("( 1.2.840.113556.1.4.221 NAME 'x' )", "1.2.840.113556.1.4.221"),
            ("(  2.5.4.3 NAME 'cn' )", "2.5.4.3"),
            ("(1.2.3 NAME 'nospace')", "1.2.3"),
            (
                "attributetypes: ( 0.9.2342.19200300.100.1.1 NAME 'uid' )",
                "0.9.2342.19200300.100.1.1",
            ),
        ],
    )
    def test_extract_from_definition_returns_leading_oid(
        self, definition: str, expected_oid: str
    ) -> None:
        result = u.Ldif.extract_from_definition(definition)

        value = u.Tests.assert_success(result)
        tm.that(value, eq=expected_oid)

    @pytest.mark.parametrize(
        "definition",
        [
            "( NAME 'cn' DESC 'no oid' )",
            "NAME 'cn'",
            "",
            "( NAME 'has 1.2.3 but no leading paren-oid' )",
        ],
    )
    def test_extract_from_definition_fails_without_leading_oid(
        self, definition: str
    ) -> None:
        result = u.Ldif.extract_from_definition(definition)

        u.Tests.assert_failure(result)
        tm.that(result.error, contains=repr(definition))

    def test_extract_from_definition_result_is_chainable_on_success(self) -> None:
        result = u.Ldif.extract_from_definition("( 1.2.3 NAME 'x' )")

        mapped = result.map(lambda oid: oid.split("."))
        value = u.Tests.assert_success(mapped)

        tm.that(value, eq=["1", "2", "3"])

    def test_extract_from_definition_is_idempotent(self) -> None:
        definition = "( 1.2.840.113556.1.4.221 NAME 'x' )"

        first = u.Ldif.extract_from_definition(definition)
        second = u.Ldif.extract_from_definition(definition)

        tm.that(u.Tests.assert_success(first), eq=u.Tests.assert_success(second))

    @pytest.mark.parametrize(
        ("definition", "pattern", "expected"),
        [
            ("( 1.2.3 NAME 'x' )", "^1\\.2\\.3$", True),
            ("( 9.9.9 NAME 'x' )", "^1\\.2\\.3$", False),
            ("( 1.2.3.4 NAME 'x' )", "^1\\.2\\.3$", False),
            ("( NAME 'no oid' )", "^1\\.2\\.3$", False),
            ("( 2.5.4.3 NAME 'cn' )", "^2\\.5\\.", True),
        ],
    )
    def test_matches_pattern_reflects_extracted_oid(
        self, definition: str, pattern: str, expected: bool
    ) -> None:
        compiled: t.Ldif.RegexPattern = c.Ldif.compile_pattern(pattern)

        result = u.Ldif.matches_pattern(definition, compiled)

        tm.that(result, eq=expected)

    def test_matches_pattern_false_when_definition_has_no_oid(self) -> None:
        result = u.Ldif.matches_pattern(
            "( NAME 'cn' DESC 'no oid' )", c.Tests.EXACT_OID_1_2_3_RE
        )

        tm.that(result, eq=False)

    def test_matches_pattern_true_against_exact_oid_constant(self) -> None:
        result = u.Ldif.matches_pattern(
            "( 1.2.3 NAME 'cn' )", c.Tests.EXACT_OID_1_2_3_RE
        )

        tm.that(result, eq=True)
