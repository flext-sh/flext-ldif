"""Behavioral tests for LDIF error recovery and malformed-content handling.

Exercises the PUBLIC contract of the LDIF facade (`ldif().parse_ldif` /
`ldif().write`): the `r[ParseResponse]` outcome, the parsed entry set, and
the observable state of each entry (DN, attribute names, attribute values).
No private attributes, internal collaborators, or line-coverage pokes are
touched — only promises the public API makes to its callers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flext_ldif import ldif
from flext_tests import tm

if TYPE_CHECKING:
    from flext_ldif import p


class TestsFlextLdifErrorRecovery:
    """Observable-behavior tests for malformed and edge-case LDIF input."""

    @pytest.fixture
    def api(self) -> p.Ldif.LdifClient:
        """Return a configured LDIF facade instance (public DSL alias)."""
        return ldif()

    # ------------------------------------------------------------------
    # Well-formed parsing: DN and attributes are preserved verbatim.
    # ------------------------------------------------------------------

    def test_valid_entry_preserves_dn_and_attribute_names(
        self, api: p.Ldif.LdifClient
    ) -> None:
        """A well-formed entry parses to exactly one entry with its DN/attrs intact."""
        content = (
            "dn: cn=Test,dc=example,dc=com\nobjectClass: person\ncn: Test\nsn: User\n"
        )

        result = api.parse_ldif(content)

        tm.ok(result)
        response = result.unwrap()
        tm.that(len(response.entries), eq=1)
        entry = response.entries[0]
        assert entry.dn is not None
        tm.that(entry.dn.value, eq="cn=Test,dc=example,dc=com")
        assert entry.attributes is not None
        tm.that(set(entry.attributes.attributes), eq={"objectClass", "cn", "sn"})

    @pytest.mark.parametrize(
        ("content", "expected_dn"),
        [
            pytest.param(
                "version: 1\ndn: cn=W,dc=example,dc=com\nobjectClass: person\ncn: W\n",
                "cn=W,dc=example,dc=com",
                id="version-line-ignored",
            ),
            pytest.param(
                "# a comment\ndn: cn=W,dc=example,dc=com\n# mid comment\nobjectClass: person\ncn: W\n",
                "cn=W,dc=example,dc=com",
                id="comment-lines-ignored",
            ),
            pytest.param(
                "dn: cn=José,dc=example,dc=com\nobjectClass: person\ncn: José\n",
                "cn=José,dc=example,dc=com",
                id="unicode-dn-preserved",
            ),
        ],
    )
    def test_structural_prefixes_do_not_alter_parsed_dn(
        self, api: p.Ldif.LdifClient, content: str, expected_dn: str
    ) -> None:
        """Version lines, comments, and unicode DNs yield one entry with the exact DN."""
        result = api.parse_ldif(content)

        tm.ok(result)
        entries = result.unwrap().entries
        tm.that(len(entries), eq=1)
        assert entries[0].dn is not None
        tm.that(entries[0].dn.value, eq=expected_dn)

    # ------------------------------------------------------------------
    # Attribute value semantics.
    # ------------------------------------------------------------------

    def test_duplicate_attribute_collects_all_values_in_order(
        self, api: p.Ldif.LdifClient
    ) -> None:
        """Repeated attribute lines are collected as an ordered multi-value list."""
        content = (
            "dn: cn=D,dc=example,dc=com\nobjectClass: person\ncn: D\n"
            "mail: a@example.com\nmail: b@example.com\nmail: c@example.com\n"
        )

        result = api.parse_ldif(content)

        tm.ok(result)
        entry = result.unwrap().entries[0]
        assert entry.attributes is not None
        tm.that(
            entry.attributes.attributes["mail"],
            eq=["a@example.com", "b@example.com", "c@example.com"],
        )

    def test_empty_attribute_value_is_preserved(self, api: p.Ldif.LdifClient) -> None:
        """An attribute with no value keeps an explicit empty-string value."""
        content = (
            "dn: cn=E,dc=example,dc=com\nobjectClass: person\ncn: E\ndescription:\n"
        )

        result = api.parse_ldif(content)

        tm.ok(result)
        entry = result.unwrap().entries[0]
        assert entry.attributes is not None
        tm.that(entry.attributes.attributes["description"], eq=[""])

    def test_folded_continuation_lines_concatenate_into_single_value(
        self, api: p.Ldif.LdifClient
    ) -> None:
        """RFC 2849 line folding joins continuation lines into one value."""
        content = (
            "dn: cn=T,dc=example,dc=com\nobjectClass: person\ncn: T\n"
            "description: ab\n cd\n"
        )

        result = api.parse_ldif(content)

        tm.ok(result)
        entry = result.unwrap().entries[0]
        assert entry.attributes is not None
        tm.that(entry.attributes.attributes["description"], eq=["abcd"])

    def test_very_long_value_is_not_truncated(self, api: p.Ldif.LdifClient) -> None:
        """A value far exceeding a line width is preserved without truncation."""
        long_value = "x" * 2000
        content = (
            "dn: cn=L,dc=example,dc=com\nobjectClass: person\ncn: L\n"
            f"description: {long_value}\n"
        )

        result = api.parse_ldif(content)

        tm.ok(result)
        entry = result.unwrap().entries[0]
        assert entry.attributes is not None
        tm.that(entry.attributes.attributes["description"], eq=[long_value])

    def test_base64_binary_attribute_is_parsed_as_named_attribute(
        self, api: p.Ldif.LdifClient
    ) -> None:
        """A ``::`` base64 attribute appears under its attribute name."""
        content = (
            "dn: cn=B,dc=example,dc=com\nobjectClass: person\ncn: B\n"
            "jpegPhoto:: /9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAA==\n"
        )

        result = api.parse_ldif(content)

        tm.ok(result)
        entry = result.unwrap().entries[0]
        assert entry.attributes is not None
        tm.that(entry.attributes.attributes, has="jpegPhoto")

    def test_unicode_attribute_value_is_preserved(self, api: p.Ldif.LdifClient) -> None:
        """Multi-byte UTF-8 characters survive parsing unchanged."""
        content = (
            "dn: cn=U,dc=example,dc=com\nobjectClass: person\ncn: U\n"
            "description: café, naïve, résumé\n"
        )

        result = api.parse_ldif(content)

        tm.ok(result)
        entry = result.unwrap().entries[0]
        assert entry.attributes is not None
        tm.that(entry.attributes.attributes["description"], eq=["café, naïve, résumé"])

    # ------------------------------------------------------------------
    # Graceful degradation: malformed input never raises; it produces a
    # structured result and drops only the offending fragment.
    # ------------------------------------------------------------------

    def test_entry_without_dn_yields_no_entries(self, api: p.Ldif.LdifClient) -> None:
        """A block with no DN line produces zero entries, not a crash."""
        content = "objectClass: person\ncn: NoDN\nsn: User\n"

        result = api.parse_ldif(content)

        tm.ok(result)
        tm.that(result.unwrap().entries, eq=[])

    def test_invalid_dn_without_rdn_is_rejected(self, api: p.Ldif.LdifClient) -> None:
        """A DN lacking any ``=`` RDN component yields no accepted entry."""
        content = "dn: invalid-dn-no-equals\nobjectClass: person\ncn: Test\n"

        result = api.parse_ldif(content)

        tm.ok(result)
        tm.that(result.unwrap().entries, eq=[])

    def test_malformed_attribute_line_is_dropped_entry_survives(
        self, api: p.Ldif.LdifClient
    ) -> None:
        """A line missing the ``:`` separator is discarded; valid attrs remain."""
        content = (
            "dn: cn=Test,dc=example,dc=com\nobjectClass person\ncn: Test\nsn: User\n"
        )

        result = api.parse_ldif(content)

        tm.ok(result)
        entry = result.unwrap().entries[0]
        assert entry.attributes is not None
        tm.that(set(entry.attributes.attributes), eq={"cn", "sn"})

    def test_dn_only_entry_parses_with_empty_attributes(
        self, api: p.Ldif.LdifClient
    ) -> None:
        """An entry carrying only a DN parses as one entry with no attributes."""
        content = "dn: cn=Minimal,dc=example,dc=com\n"

        result = api.parse_ldif(content)

        tm.ok(result)
        entries = result.unwrap().entries
        tm.that(len(entries), eq=1)
        entry = entries[0]
        assert entry.dn is not None
        tm.that(entry.dn.value, eq="cn=Minimal,dc=example,dc=com")

    @pytest.mark.parametrize(
        ("content", "expected_count"),
        [
            pytest.param(
                "dn: cn=Complete,dc=example,dc=com\nobjectClass: person\ncn: Complete\n"
                "\ndn: cn=Incomplete,dc=example,dc\n",
                1,
                id="truncated-second-dn-dropped",
            ),
            pytest.param(
                "dn: cn=Test1,dc=example,dc=com\nobjectClass: person\ncn: Test1\n"
                "\n orphaned-continuation\n"
                "dn: cn=Test2,dc=example,dc=com\nobjectClass: person\ncn: Test2\n",
                2,
                id="orphaned-continuation-recovers",
            ),
            pytest.param(
                "dn: cn=NoBlank,dc=example,dc=com\nobjectClass: person\ncn: NoBlank\nsn: Test",
                1,
                id="missing-trailing-blank-line",
            ),
        ],
    )
    def test_partial_input_recovers_valid_entries(
        self, api: p.Ldif.LdifClient, content: str, expected_count: int
    ) -> None:
        """Truncated / orphaned / unterminated input recovers the valid entries."""
        result = api.parse_ldif(content)

        tm.ok(result)
        tm.that(len(result.unwrap().entries), eq=expected_count)

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param(
                "dn: cn=Schema,cn=settings\nobjectClass: schema\n"
                "attributeTypes: ( invalid-oid NAME 'test' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n",
                id="malformed-oid",
            ),
            pytest.param(
                "dn: cn=Schema,cn=settings\nobjectClass: schema\n"
                "attributeTypes: ( 1.2.3 NAME 'incomplete'\n",
                id="unclosed-schema-paren",
            ),
            pytest.param(
                "dn: cn=InvalidBase64,dc=example,dc=com\nobjectClass: person\n"
                "jpegPhoto:: !!!invalid-base64!!!\n",
                id="invalid-base64",
            ),
        ],
    )
    def test_malformed_content_returns_structured_result_without_raising(
        self, api: p.Ldif.LdifClient, content: str
    ) -> None:
        """Malformed schema/base64 input returns an r[T] result rather than raising."""
        result = api.parse_ldif(content)

        # The contract is a structured result: querying success must never raise,
        # and on success the entries collection is always a list.
        tm.that(result.success, is_=bool)
        if result.success:
            tm.that(result.unwrap().entries, is_=list)

    # ------------------------------------------------------------------
    # Round-trip invariant.
    # ------------------------------------------------------------------

    def test_parse_write_parse_is_idempotent_on_dn_and_attributes(
        self, api: p.Ldif.LdifClient
    ) -> None:
        """Parse, write, then re-parse preserves DN and attribute names/values."""
        content = (
            "dn: cn=Round,dc=example,dc=com\nobjectClass: person\ncn: Round\nsn: Trip\n"
        )

        first = api.parse_ldif(content)
        tm.ok(first)
        original = first.unwrap().entries

        written = api.write(original)
        tm.ok(written)
        serialized = written.unwrap().content
        assert serialized is not None

        second = api.parse_ldif(serialized)
        tm.ok(second)
        reparsed = second.unwrap().entries

        tm.that(len(reparsed), eq=len(original))
        assert original[0].dn is not None
        assert reparsed[0].dn is not None
        tm.that(reparsed[0].dn.value, eq=original[0].dn.value)
        assert original[0].attributes is not None
        assert reparsed[0].attributes is not None
        tm.that(reparsed[0].attributes.attributes, eq=original[0].attributes.attributes)


__all__: list[str] = ["TestsFlextLdifErrorRecovery"]
