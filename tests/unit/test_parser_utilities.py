"""Behavioral tests for the public LDIF parser utility contract.

Every test exercises ``FlextLdifUtilities.Ldif`` public methods through their
observable return values: ``r[T]`` outcomes, plain return values, and public
model fields. No private attribute access, no internal-collaborator spying.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests.constants import c
from tests.utilities import u


class TestsFlextLdifParserUtilities:
    """Public-contract behavior of the LDIF parser utilities."""

    # ------------------------------------------------------------------
    # extract_oid
    # ------------------------------------------------------------------
    @pytest.mark.parametrize(
        "definition",
        [
            "",
            "( NAME 'cn' DESC 'no oid' )",
            "not-an-oid NAME 'x'",
        ],
    )
    def test_extract_oid_fails_without_leading_oid(self, definition: str) -> None:
        result = u.Ldif.extract_oid(definition)

        u.Tests.assert_failure(result)

    @pytest.mark.parametrize(
        ("definition", "expected_oid"),
        [
            ("( 1.2.840.113556.1.4.221 NAME 'x' )", "1.2.840.113556.1.4.221"),
            ("  ( 2.5.4.3 NAME 'cn' )  ", "2.5.4.3"),
            (
                "( 2.5.6.6 NAME 'person' STRUCTURAL MUST cn )",
                "2.5.6.6",
            ),
        ],
    )
    def test_extract_oid_returns_leading_oid(
        self,
        definition: str,
        expected_oid: str,
    ) -> None:
        result = u.Ldif.extract_oid(definition)

        value = u.Tests.assert_success(result)
        tm.that(value, eq=expected_oid)

    # ------------------------------------------------------------------
    # parse_attribute_line
    # ------------------------------------------------------------------
    def test_parse_attribute_line_fails_without_colon(self) -> None:
        result = u.Ldif.parse_attribute_line("cn value")

        u.Tests.assert_failure(result)

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("cn: test", ("cn", "test", False)),
            ("cn:test", ("cn", "test", False)),
            ("cn:   spaced value  ", ("cn", "spaced value", False)),
            ("cn:: dGVzdA==", ("cn", "dGVzdA==", True)),
            ("cn:", ("cn", "", False)),
        ],
    )
    def test_parse_attribute_line_splits_name_value_and_base64_flag(
        self,
        line: str,
        expected: tuple[str, str, bool],
    ) -> None:
        result = u.Ldif.parse_attribute_line(line)

        value = u.Tests.assert_success(result)
        tm.that(value, eq=expected)

    # ------------------------------------------------------------------
    # decode_value
    # ------------------------------------------------------------------
    @pytest.mark.parametrize(
        ("remainder", "expected_value", "expected_origin", "expected_raw"),
        [
            (" plain text", "plain text", c.Ldif.ValueOrigin.PLAIN, "plain text"),
            (": aGVsbG8=", "hello", c.Ldif.ValueOrigin.BASE64, "aGVsbG8="),
            (
                "< http://host/x",
                "http://host/x",
                c.Ldif.ValueOrigin.URL,
                "http://host/x",
            ),
            (
                "< file:///tmp/data",
                "file:///tmp/data",
                c.Ldif.ValueOrigin.FILE,
                "file:///tmp/data",
            ),
        ],
    )
    def test_decode_value_classifies_origin_and_decodes(
        self,
        remainder: str,
        expected_value: str,
        expected_origin: c.Ldif.ValueOrigin,
        expected_raw: str,
    ) -> None:
        decoded, origin, raw = u.Ldif.decode_value(remainder)

        tm.that(decoded, eq=expected_value)
        assert origin == expected_origin
        tm.that(raw, eq=expected_raw)

    # ------------------------------------------------------------------
    # build_control
    # ------------------------------------------------------------------
    @pytest.mark.parametrize(
        ("payload", "expected_type", "expected_criticality", "expected_value"),
        [
            ("1.2.3.4 true payload", "1.2.3.4", True, "payload"),
            ("1.2.3.4 false", "1.2.3.4", False, None),
            ("1.2.3.4", "1.2.3.4", None, None),
        ],
    )
    def test_build_control_parses_control_fields(
        self,
        payload: str,
        expected_type: str,
        expected_criticality: bool | None,
        expected_value: str | None,
    ) -> None:
        control = u.Ldif.build_control(payload)

        tm.that(control.control_type, eq=expected_type)
        assert control.criticality == expected_criticality
        assert control.value == expected_value

    # ------------------------------------------------------------------
    # extract_boolean_flag / extract_optional_field
    # ------------------------------------------------------------------
    @pytest.mark.parametrize(
        ("definition", "expected"),
        [
            ("( 1.1 NAME 'x' SINGLE-VALUE )", True),
            ("( 1.1 NAME 'x' )", False),
            ("", False),
        ],
    )
    def test_extract_boolean_flag_detects_token(
        self,
        definition: str,
        expected: bool,
    ) -> None:
        assert u.Ldif.extract_boolean_flag(definition, "SINGLE-VALUE") is expected

    def test_extract_optional_field_returns_match_when_present(self) -> None:
        value = u.Ldif.extract_optional_field(
            "( 1.1 NAME 'x' DESC 'hello world' )",
            c.Ldif.SCHEMA_DESC_FLEX_RE,
        )

        tm.that(value, eq="hello world")

    def test_extract_optional_field_returns_default_on_empty(self) -> None:
        value = u.Ldif.extract_optional_field(
            "",
            c.Ldif.SCHEMA_DESC_FLEX_RE,
            default="fallback",
        )

        tm.that(value, eq="fallback")

    # ------------------------------------------------------------------
    # extract_extensions
    # ------------------------------------------------------------------
    def test_extract_extensions_captures_x_tokens_and_desc(self) -> None:
        extensions = u.Ldif.extract_extensions(
            "( 1.1 NAME 'x' DESC 'hi there' X-ORIGIN 'user' )",
        )

        assert extensions["X-ORIGIN"] == ["user"]
        assert extensions["DESC"] == ["hi there"]

    def test_extract_extensions_empty_definition_returns_empty_mapping(self) -> None:
        assert u.Ldif.extract_extensions("") == {}

    # ------------------------------------------------------------------
    # unfold_lines
    # ------------------------------------------------------------------
    def test_unfold_lines_merges_continuation_lines(self) -> None:
        unfolded = u.Ldif.unfold_lines("cn: hello\n world\nsn: last")

        # RFC 2849 folding: the single leading space is stripped and the
        # remainder is concatenated verbatim onto the previous line.
        assert unfolded == ["cn: helloworld", "sn: last"]

    def test_unfold_lines_preserves_record_separating_blank(self) -> None:
        unfolded = u.Ldif.unfold_lines("dn: cn=a\n\ndn: cn=b")

        assert unfolded == ["dn: cn=a", "", "dn: cn=b"]

    # ------------------------------------------------------------------
    # split_ldif_records
    # ------------------------------------------------------------------
    def test_split_ldif_records_drops_version_and_groups_by_blank(self) -> None:
        records = u.Ldif.split_ldif_records(
            "version: 1\ndn: cn=a\ncn: a\n\ndn: cn=b\ncn: b",
        )

        assert records == [["dn: cn=a", "cn: a"], ["dn: cn=b", "cn: b"]]

    # ------------------------------------------------------------------
    # parse_ldif_record
    # ------------------------------------------------------------------
    def test_parse_ldif_record_builds_entry_from_valid_record(self) -> None:
        result = u.Ldif.parse_ldif_record([
            "dn: cn=alice,dc=example,dc=com",
            "cn: alice",
            "objectClass: person",
        ])

        entry = u.Tests.assert_success(result)
        assert entry.dn is not None
        assert entry.attributes is not None
        tm.that(entry.dn.value, eq="cn=alice,dc=example,dc=com")
        assert entry.attributes.attributes["cn"] == ["alice"]
        assert entry.attributes.attributes["objectClass"] == ["person"]

    def test_parse_ldif_record_fails_without_dn(self) -> None:
        result = u.Ldif.parse_ldif_record(["cn: alice", "sn: smith"])

        error = u.Tests.assert_failure(result)
        assert "DN" in error
