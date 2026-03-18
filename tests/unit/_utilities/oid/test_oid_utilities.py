from __future__ import annotations

import re
from unittest.mock import patch

from flext_tests import tm
from tests import s

from flext_ldif.utilities import FlextLdifUtilities as u


class TestFlextLdifUtilitiesOID(s):
    def test_extract_from_definition_failure_no_match(self) -> None:
        result = u.Ldif.extract_from_definition("( NAME 'cn' DESC 'no oid' )")

        self.assert_failure(result)

    def test_extract_from_definition_failure_invalid_regex(self) -> None:
        with patch("flext_ldif._utilities.oid.re.search", side_effect=re.error("boom")):
            result = u.Ldif.extract_from_definition("( 1.2.3 NAME 'cn' )")

        self.assert_failure(result)

    def test_extract_from_definition_success(self) -> None:
        result = u.Ldif.extract_from_definition("( 1.2.840.113556.1.4.221 NAME 'x' )")
        value = self.assert_success(result)

        tm.that(value == "1.2.840.113556.1.4.221", eq=True)

    def test_get_server_type_from_oid_failure_unknown(self) -> None:
        result = u.Ldif.get_server_type_from_oid("1.2.3.4.5")

        self.assert_failure(result)

    def test_get_server_type_from_oid_failure_empty(self) -> None:
        result = u.Ldif.get_server_type_from_oid("")

        self.assert_failure(result)

    def test_get_server_type_from_oid_success_oracle(self) -> None:
        result = u.Ldif.get_server_type_from_oid(
            "2\\.16\\.840\\.1\\.113894\\.1\\.1\\.1"
        )
        value = self.assert_success(result)

        tm.that(value == "oid", eq=True)

    def test_parse_to_tuple_failure_not_integers(self) -> None:
        result = u.Ldif.parse_to_tuple("1.2.invalid")

        self.assert_failure(result)

    def test_parse_to_tuple_success(self) -> None:
        result = u.Ldif.parse_to_tuple("1.2.840")
        value = self.assert_success(result)

        tm.that(value == (1, 2, 840), eq=True)
