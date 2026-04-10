from __future__ import annotations

import re

from flext_tests import tm
from tests import s, u


class TestFlextLdifUtilitiesOID:
    def test_extract_from_definition_failure_no_match(self) -> None:
        result = u.Ldif.extract_from_definition("( NAME 'cn' DESC 'no oid' )")

        s.assert_failure(result)

    def test_extract_from_definition_success(self) -> None:
        result = u.Ldif.extract_from_definition("( 1.2.840.113556.1.4.221 NAME 'x' )")
        value = s.assert_success(result)

        tm.that(value, eq="1.2.840.113556.1.4.221")

    def test_matches_pattern_returns_false_for_missing_oid(self) -> None:
        result = u.Ldif.matches_pattern(
            "( NAME 'cn' DESC 'no oid' )",
            re.compile(r"^1\.2\.3$"),
        )

        tm.that(result, eq=False)
