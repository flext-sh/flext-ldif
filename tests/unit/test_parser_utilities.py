"""Behavioral tests for the public LDIF parser utility contract.

Every test exercises ``FlextLdifUtilities.Ldif`` public methods through their
observable return values: ``r[T]`` outcomes, plain return values, and public
model fields. No private attribute access, no internal-collaborator spying.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from tests import c, p, tm, u


class TestsFlextLdifUtilitiesParser:
    """Public-contract behavior of the LDIF parser utilities."""

    @staticmethod
    @pytest.mark.parametrize(
        ("must_separator", "may_separator"), [("|", ","), (",", "|")]
    )
    def test_schema_field_separators_are_independent(
        must_separator: str,
        may_separator: str,
    ) -> None:
        """MUST and MAY use their supplied policies independently."""
        tm.that(
            u.Ldif.extract_objectclass_must_may(
                f"MUST ( cn{must_separator}sn ) MAY ( uid{may_separator}mail )",
                must_separator=must_separator,
                may_separator=may_separator,
            ),
            eq=(["cn", "sn"], ["uid", "mail"]),
        )

    # ------------------------------------------------------------------
    # extract_oid
    # ------------------------------------------------------------------
    @staticmethod
    @pytest.mark.parametrize(
        "definition",
        [
            "",
            "   ",
            "( NAME 'cn' DESC 'no oid' )",
            "not-an-oid NAME 'x'",
            "prefix ( 1.2.3 NAME 'x' )",
        ],
    )
    def test_extract_oid_fails_without_leading_oid(definition: str) -> None:
        """Test extract oid fails without leading oid."""
        result = u.Ldif.extract_oid(definition)

        u.Tests.assert_failure(result)
        if not definition:
            tm.that(result.error, eq=c.Ldif.SCHEMA_OID_EMPTY_ERROR)

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
        tm.fail(u.Ldif.parse_attribute_line("cn value"))

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
        value = tm.ok(u.Ldif.parse_attribute_line(line))
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
        control: p.Ldif.Control = u.Ldif.build_control(payload)

        tm.that(control.control_type, eq=expected_type)
        tm.that(control.criticality, eq=expected_criticality)
        tm.that(control.control_value, eq=expected_value)

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
        tm.ok(u.Ldif.extract_boolean_flag(definition, "SINGLE-VALUE") is expected)

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

        tm.that(extensions["X-ORIGIN"], eq=[c.ContextScope.USER])
        tm.that(extensions["DESC"], eq=["hi there"])

    @staticmethod
    def test_extract_extensions_empty_definition_returns_empty_mapping() -> None:
        """Test extract extensions empty definition returns empty mapping."""
        tm.that(u.Ldif.extract_extensions(""), eq={})

    # ------------------------------------------------------------------
    # unfold_lines
    # ------------------------------------------------------------------
    @staticmethod
    @pytest.mark.parametrize(
        ("content", "expected"),
        [
            ("cn: hello\n world\nsn: last", ["cn: helloworld", "sn: last"]),
            ("dn: cn=a\n\ndn: cn=b", ["dn: cn=a", "", "dn: cn=b"]),
        ],
    )
    def test_unfold_lines(content: str, expected: Sequence[str]) -> None:
        """Unfold continuations while preserving record-separating blank lines."""
        # RFC 2849 folding: the single leading space is stripped and the
        # remainder is concatenated verbatim onto the previous line.
        tm.that(u.Ldif.unfold_lines(content), eq=expected)

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
    @pytest.mark.parametrize("fill", ["", " ", "   "])
    def test_modify_record_preserves_operations_with_rfc_fill(fill: str) -> None:
        """RFC 2849 permits zero or more spaces after the changetype colon."""
        entry = u.Ldif.parse_ldif_record([
            "dn: cn=schema",
            f"changetype:{fill}modify",
            "add: description",
            "description: schema change",
            "-",
        ]).unwrap()
        tm.that(entry.changetype, eq=c.Ldif.ChangeType.MODIFY)
        tm.that(entry.record_kind, eq=c.Ldif.RecordKind.CHANGE)
        tm.that(len(entry.change_operations), eq=1)
        operation = entry.change_operations[0]
        tm.that(operation.attribute, eq="description")
        tm.that([value.value for value in operation.values], eq=["schema change"])
        tm.that(entry.attributes_dict, lacks="add")

    @staticmethod
    def test_parse_ldif_record_builds_entry_from_valid_record() -> None:
        """Test parse ldif record builds entry from valid record."""
        entry = tm.ok(
            u.Ldif.parse_ldif_record([
                "dn: cn=alice,dc=example,dc=com",
                "cn: alice",
                "objectClass: person",
            ]),
        )
        dn = tm.not_none(entry.dn)
        attributes = tm.not_none(entry.attributes)
        tm.that(dn.value, eq="cn=alice,dc=example,dc=com")
        tm.that(attributes.attributes["cn"], eq=["alice"])
        tm.that(attributes.attributes["objectClass"], eq=["person"])

    @staticmethod
    def test_parse_ldif_record_decodes_base64_dn_to_utf8() -> None:
        """A ``dn::`` record decodes to its UTF-8 DN and flags the origin.

        Regression: the dn branch stored the raw value-spec (``: <b64>``)
        without decoding, so every base64 DN (accented production data)
        failed DN validation and the record was silently dropped.

        """
        entry = tm.ok(
            u.Ldif.parse_ldif_record([
                "dn:: Y249bWFyY2Vsby5hcmHDumpvLGRjPWV4YW1wbGUsZGM9Y29t",
                "cn: marcelo.araújo",
                "objectClass: person",
            ]),
        )
        dn = tm.not_none(entry.dn)
        metadata = tm.not_none(entry.metadata)
        tm.that(dn.value, eq="cn=marcelo.araújo,dc=example,dc=com")
        flag = metadata.extensions[c.Ldif.META_DN_WAS_BASE64]
        match flag:
            case list():
                tm.that(list(flag), eq=[True])
            case _:
                tm.reject()

    @staticmethod
    def test_parse_ldif_record_preserves_significant_dn_whitespace() -> None:
        """Decoded DN values keep significant interior whitespace bytes.

        Production dumps carry CNs with trailing tabs/NBSPs inside the
        base64-encoded DN; the parsed DN must address the same server
        entry byte-for-byte, never silently normalize it.
        """
        entry = tm.ok(
            u.Ldif.parse_ldif_record([
                "dn:: Y249c3BvdAksZGM9ZXhhbXBsZSxkYz1jb20=",
                "cn: spot",
                "objectClass: person",
            ]),
        )
        dn = tm.not_none(entry.dn)
        tm.that(dn.value, eq="cn=spot\t,dc=example,dc=com")

    @staticmethod
    def test_parse_ldif_record_fails_without_dn() -> None:
        """Test parse ldif record fails without dn."""
        error = tm.fail(u.Ldif.parse_ldif_record(["cn: alice", "sn: smith"]))
        tm.that(error, has="DN")
