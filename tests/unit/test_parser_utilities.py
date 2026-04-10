from __future__ import annotations

from flext_tests import tm

from tests import u


class TestFlextLdifUtilitiesParser:
    def test_extract_oid_failure_empty_string(self) -> None:
        result = u.Ldif.extract_oid("")

        u.Tests.assert_failure(result)

    def test_extract_oid_failure_no_oid_present(self) -> None:
        result = u.Ldif.extract_oid("( NAME 'cn' DESC 'no oid' )")

        u.Tests.assert_failure(result)

    def test_extract_oid_success(self) -> None:
        result = u.Ldif.extract_oid("( 1.2.840.113556.1.4.221 NAME 'x' )")
        value = u.Tests.assert_success(result)

        tm.that(value, eq="1.2.840.113556.1.4.221")

    def test_parse_attribute_line_failure_no_colon(self) -> None:
        result = u.Ldif.parse_attribute_line("cn value")

        u.Tests.assert_failure(result)

    def test_parse_attribute_line_success_simple(self) -> None:
        result = u.Ldif.parse_attribute_line("cn: test")
        value = u.Tests.assert_success(result)

        tm.that(value, eq=("cn", "test", False))

    def test_parse_attribute_line_success_base64(self) -> None:
        result = u.Ldif.parse_attribute_line("cn:: dGVzdA==")
        value = u.Tests.assert_success(result)

        tm.that(value, eq=("cn", "dGVzdA==", True))
