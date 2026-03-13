from __future__ import annotations

import re
from unittest.mock import patch

from flext_tests import s

from flext_ldif.utilities import FlextLdifUtilities as u


class TestFlextLdifUtilitiesOID(s):
    def test_extract_from_definition_failure_no_match(self) -> None:
        result = u.Ldif.OID.extract_from_definition("( NAME 'cn' DESC 'no oid' )")

        self.assert_failure(result)

    def test_extract_from_definition_failure_invalid_regex(self) -> None:
        with patch("flext_ldif._utilities.oid.re.search", side_effect=re.error("boom")):
            result = u.Ldif.OID.extract_from_definition("( 1.2.3 NAME 'cn' )")

        self.assert_failure(result)

    def test_extract_from_definition_success(self) -> None:
        result = u.Ldif.OID.extract_from_definition(
            "( 1.2.840.113556.1.4.221 NAME 'x' )"
        )
        value = self.assert_success(result)

        assert value == "1.2.840.113556.1.4.221"

    def test_get_server_type_from_oid_failure_unknown(self) -> None:
        result = u.Ldif.OID.get_server_type_from_oid("1.2.3.4.5")

        self.assert_failure(result)

    def test_get_server_type_from_oid_failure_empty(self) -> None:
        result = u.Ldif.OID.get_server_type_from_oid("")

        self.assert_failure(result)

    def test_get_server_type_from_oid_success_oracle(self) -> None:
        result = u.Ldif.OID.get_server_type_from_oid(
            "2\\.16\\.840\\.1\\.113894\\.1\\.1\\.1"
        )
        value = self.assert_success(result)

        assert value == "oid"

    def test_parse_to_tuple_failure_not_integers(self) -> None:
        result = u.Ldif.OID.parse_to_tuple("1.2.invalid")

        self.assert_failure(result)

    def test_parse_to_tuple_success(self) -> None:
        result = u.Ldif.OID.parse_to_tuple("1.2.840")
        value = self.assert_success(result)

        assert value == (1, 2, 840)
