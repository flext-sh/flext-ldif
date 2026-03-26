from __future__ import annotations

import re
from unittest.mock import patch

from flext_tests import tm
from tests.base import FlextLdifTestsServiceBase as s

from flext_ldif import u


class TestFlextLdifUtilitiesOID:
    def test_extract_from_definition_failure_no_match(self) -> None:
        result = u.Ldif.extract_from_definition("( NAME 'cn' DESC 'no oid' )")

        s.assert_failure(result)

    def test_extract_from_definition_failure_invalid_regex(self) -> None:
        with patch("flext_ldif._utilities.oid.re.search", side_effect=re.error("boom")):
            result = u.Ldif.extract_from_definition("( 1.2.3 NAME 'cn' )")

        s.assert_failure(result)

    def test_extract_from_definition_success(self) -> None:
        result = u.Ldif.extract_from_definition("( 1.2.840.113556.1.4.221 NAME 'x' )")
        value = s.assert_success(result)

        tm.that(value, eq="1.2.840.113556.1.4.221")
