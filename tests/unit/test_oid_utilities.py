from __future__ import annotations

from flext_tests import tm

from tests.constants import c
from tests.utilities import u


class TestsFlextLdifOidUtilities:
    def test_extract_from_definition_failure_no_match(self) -> None:
        result = u.Ldif.extract_from_definition("( NAME 'cn' DESC 'no oid' )")

        u.Tests.assert_failure(result)

    def test_extract_from_definition_success(self) -> None:
        result = u.Ldif.extract_from_definition("( 1.2.840.113556.1.4.221 NAME 'x' )")
        value = u.Tests.assert_success(result)

        tm.that(value, eq="1.2.840.113556.1.4.221")

    def test_matches_pattern_returns_false_for_missing_oid(self) -> None:
        result = u.Ldif.matches_pattern(
            "( NAME 'cn' DESC 'no oid' )",
            c.Tests.EXACT_OID_1_2_3_RE,
        )

        tm.that(result, eq=False)
