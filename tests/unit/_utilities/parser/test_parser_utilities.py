from __future__ import annotations

from tests import s

from flext_ldif.utilities import FlextLdifUtilities as u


class TestFlextLdifUtilitiesParser(s):
    def test_extract_oid_failure_empty_string(self) -> None:
        result = u.Ldif.LdifParser.extract_oid("")

        self.assert_failure(result)

    def test_extract_oid_failure_no_oid_present(self) -> None:
        result = u.Ldif.LdifParser.extract_oid("( NAME 'cn' DESC 'no oid' )")

        self.assert_failure(result)

    def test_extract_oid_success(self) -> None:
        result = u.Ldif.LdifParser.extract_oid("( 1.2.840.113556.1.4.221 NAME 'x' )")
        value = self.assert_success(result)

        assert value == "1.2.840.113556.1.4.221"

    def test_parse_attribute_line_failure_no_colon(self) -> None:
        result = u.Ldif.LdifParser.parse_attribute_line("cn value")

        self.assert_failure(result)

    def test_parse_attribute_line_success_simple(self) -> None:
        result = u.Ldif.LdifParser.parse_attribute_line("cn: test")
        value = self.assert_success(result)

        assert value == ("cn", "test", False)

    def test_parse_attribute_line_success_base64(self) -> None:
        result = u.Ldif.LdifParser.parse_attribute_line("cn:: dGVzdA==")
        value = self.assert_success(result)

        assert value == ("cn", "dGVzdA==", True)
