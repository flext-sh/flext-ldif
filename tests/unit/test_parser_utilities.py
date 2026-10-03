"""Behavioral tests for the public LDIF parser utility contract.

Every test exercises ``FlextLdifUtilities.Ldif`` public methods through their
observable return values: ``r[T]`` outcomes, plain return values, and public
model fields. No private attribute access, no internal-collaborator spying.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests import c, u


class TestsFlextLdifParserUtilities:
    """Public-contract behavior of the LDIF parser utilities."""

    # ------------------------------------------------------------------
    # extract_oid
    # ------------------------------------------------------------------
    @staticmethod
    @pytest.mark.parametrize(
        "definition",
        ["", "( NAME 'cn' DESC 'no oid' )", "not-an-oid NAME 'x'"],
    )
    def test_extract_oid_fails_without_leading_oid(definition: str) -> None:
        """Test extract oid fails without leading oid."""
        result = u.Ldif.extract_oid(definition)

        u.Tests.assert_failure(result)

    @staticmethod
    @pytest.mark.parametrize(
        ("definition", "expected_oid"),
        [
            ("( 1.2.840.113556.1.4.221 NAME 'x' )", "1.2.840.113556.1.4.221"),
            ("  ( 2.5.4.3 NAME 'cn' )  ", "2.5.4.3"),
            ("( 2.5.6.6 NAME 'person' STRUCTURAL MUST cn )", "2.5.6.6"),
        ],
    )
    def test_extract_oid_returns_leading_oid(
        definition: str,
        expected_oid: str,
    ) -> None:
        """Test extract oid returns leading oid."""
        result = u.Ldif.extract_oid(definition)

        value = u.Tests.assert_success(result)
        tm.that(value, eq=expected_oid)

    # ------------------------------------------------------------------
    # parse_attribute_line
    # ------------------------------------------------------------------
    @staticmethod
    def test_parse_attribute_line_fails_without_colon() -> None:
        """Test parse attribute line fails without colon."""
        result = u.Ldif.parse_attribute_line("cn value")

        u.Tests.assert_failure(result)

    @staticmethod
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
        line: str,
        expected: tuple[str, str, bool],
    ) -> None:
        """Test parse attribute line splits name value and base64 flag."""
        result = u.Ldif.parse_attribute_line(line)

        value = u.Tests.assert_success(result)
        tm.that(value, eq=expected)

    # ------------------------------------------------------------------
    # decode_value
    # ------------------------------------------------------------------
    @staticmethod
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
        remainder: str,
        expected_value: str,
        expected_origin: c.Ldif.ValueOrigin,
        expected_raw: str,
    ) -> None:
        """Test decode value classifies origin and decodes."""
        decoded, origin, raw = u.Ldif.decode_value(remainder)

        tm.that(decoded, eq=expected_value)
        tm.that(origin, eq=expected_origin)
        tm.that(raw, eq=expected_raw)

    # ------------------------------------------------------------------
    # build_control
    # ------------------------------------------------------------------
    @staticmethod
    @pytest.mark.parametrize(
        ("payload", "expected_type", "expected_criticality", "expected_value"),
        [
            ("1.2.3.4 true payload", "1.2.3.4", True, "payload"),
            ("1.2.3.4 false", "1.2.3.4", False, None),
            ("1.2.3.4", "1.2.3.4", None, None),
        ],
    )
    def test_build_control_parses_control_fields(
        payload: str,
        expected_type: str,
        *,
        expected_criticality: bool | None,
        expected_value: str | None,
    ) -> None:
        """Test build control parses control fields."""
        control = u.Ldif.build_control(payload)

        tm.that(control.control_type, eq=expected_type)
        tm.that(control.criticality, eq=expected_criticality)
        tm.that(control.value, eq=expected_value)

    # ------------------------------------------------------------------
    # extract_boolean_flag / extract_optional_field
    # ------------------------------------------------------------------
    @staticmethod
    @pytest.mark.parametrize(
        ("definition", "expected"),
        [
            ("( 1.1 NAME 'x' SINGLE-VALUE )", True),
            ("( 1.1 NAME 'x' )", False),
            ("", False),
        ],
    )
    def test_extract_boolean_flag_detects_token(
        definition: str,
        *,
        expected: bool,
    ) -> None:
        """Test extract boolean flag detects token."""
        assert u.Ldif.extract_boolean_flag(definition, "SINGLE-VALUE") is expected

    @staticmethod
    def test_extract_optional_field_returns_match_when_present() -> None:
        """Test extract optional field returns match when present."""
        value = u.Ldif.extract_optional_field(
            "( 1.1 NAME 'x' DESC 'hello world' )",
            c.Ldif.SCHEMA_DESC_FLEX_RE,
        )

        tm.that(value, eq="hello world")

    @staticmethod
    def test_extract_optional_field_returns_default_on_empty() -> None:
        """Test extract optional field returns default on empty."""
        value = u.Ldif.extract_optional_field(
            "",
            c.Ldif.SCHEMA_DESC_FLEX_RE,
            default="fallback",
        )

        tm.that(value, eq="fallback")

    # ------------------------------------------------------------------
    # extract_extensions
    # ------------------------------------------------------------------
    @staticmethod
    def test_extract_extensions_captures_x_tokens_and_desc() -> None:
        """Test extract extensions captures x tokens and desc."""
        extensions = u.Ldif.extract_extensions(
            "( 1.1 NAME 'x' DESC 'hi there' X-ORIGIN 'user' )",
        )

        tm.that(extensions["X-ORIGIN"], eq=["user"])
        tm.that(extensions["DESC"], eq=["hi there"])

    @staticmethod
    def test_extract_extensions_empty_definition_returns_empty_mapping() -> None:
        """Test extract extensions empty definition returns empty mapping."""
        tm.that(u.Ldif.extract_extensions(""), eq={})

    # ------------------------------------------------------------------
    # unfold_lines
    # ------------------------------------------------------------------
    @staticmethod
    def test_unfold_lines_merges_continuation_lines() -> None:
        """Test unfold lines merges continuation lines."""
        unfolded = u.Ldif.unfold_lines("cn: hello\n world\nsn: last")

        # RFC 2849 folding: the single leading space is stripped and the
        # remainder is concatenated verbatim onto the previous line.
        tm.that(unfolded, eq=["cn: helloworld", "sn: last"])

    @staticmethod
    def test_unfold_lines_preserves_record_separating_blank() -> None:
        """Test unfold lines preserves record separating blank."""
        unfolded = u.Ldif.unfold_lines("dn: cn=a\n\ndn: cn=b")

        tm.that(unfolded, eq=["dn: cn=a", "", "dn: cn=b"])

    # ------------------------------------------------------------------
    # split_ldif_records
    # ------------------------------------------------------------------
    @staticmethod
    def test_split_ldif_records_drops_version_and_groups_by_blank() -> None:
        """Test split ldif records drops version and groups by blank."""
        records = u.Ldif.split_ldif_records(
            "version: 1\ndn: cn=a\ncn: a\n\ndn: cn=b\ncn: b",
        )

        tm.that(records, eq=[["dn: cn=a", "cn: a"], ["dn: cn=b", "cn: b"]])

    # ------------------------------------------------------------------
    # parse_ldif_record
    # ------------------------------------------------------------------
    @staticmethod
    def test_parse_ldif_record_builds_entry_from_valid_record() -> None:
        """Test parse ldif record builds entry from valid record."""
        result = u.Ldif.parse_ldif_record([
            "dn: cn=alice,dc=example,dc=com",
            "cn: alice",
            "objectClass: person",
        ])

        entry = u.Tests.assert_success(result)
        assert entry.dn is not None
        assert entry.attributes is not None
        tm.that(entry.dn.value, eq="cn=alice,dc=example,dc=com")
        tm.that(entry.attributes.attributes["cn"], eq=["alice"])
        tm.that(entry.attributes.attributes["objectClass"], eq=["person"])

    @staticmethod
    def test_parse_ldif_record_fails_without_dn() -> None:
        """Test parse ldif record fails without dn."""
        result = u.Ldif.parse_ldif_record(["cn: alice", "sn: smith"])

        error = u.Tests.assert_failure(result)
        tm.that(error, has="DN")
