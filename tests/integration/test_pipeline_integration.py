"""Behavioral integration tests for the ``ldif`` public facade.

Exercises the observable parse/validate/write contract of :class:`FlextLdif`
through its public API only: fallible operations are asserted via the
``FlextResult`` outcome (``.success`` / ``.unwrap`` / ``.error`` / combinators),
public model state via published fields, and pipeline invariants such as
parse-write-parse idempotence.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flext_ldif import ldif

if TYPE_CHECKING:
    from collections.abc import MutableMapping, MutableSequence
    from pathlib import Path

    from flext_ldif._models.domain_entry import FlextLdifModelsDomainEntry

    type _Entry = FlextLdifModelsDomainEntry.Entry
    type _Attributes = MutableMapping[str, MutableSequence[str]]


SINGLE_ENTRY = (
    "dn: cn=test,dc=example,dc=com\n"
    "objectClass: person\n"
    "cn: test\n"
    "sn: Test\n"
    "mail: test@example.com\n"
)
THREE_ENTRIES = (
    "dn: cn=user1,dc=example,dc=com\nobjectClass: person\ncn: user1\nsn: User1\n\n"
    "dn: cn=user2,dc=example,dc=com\nobjectClass: person\ncn: user2\nsn: User2\n\n"
    "dn: cn=user3,dc=example,dc=com\nobjectClass: person\ncn: user3\nsn: User3\n"
)
GROUP_ENTRY = (
    "dn: cn=group,dc=example,dc=com\n"
    "objectClass: groupOfNames\n"
    "cn: group\n"
    "member: cn=user1,dc=example,dc=com\n"
    "member: cn=user2,dc=example,dc=com\n"
    "member: cn=user3,dc=example,dc=com\n"
)
WITH_HEADER = (
    "version: 1\n"
    "# Comment line\n"
    "dn: cn=test,dc=example,dc=com\n"
    "objectClass: person\n"
    "cn: test\n"
    "sn: Test\n"
)


class TestsFlextLdifPipelineIntegration:
    """Behavioral contract tests for ``ldif`` facade workflows."""

    @staticmethod
    def _dn_value(entry: _Entry) -> str:
        """Return the public DN string, asserting the contract populated it."""
        assert entry.dn is not None
        return entry.dn.value

    @staticmethod
    def _attributes(entry: _Entry) -> _Attributes:
        """Return the public attribute mapping, asserting it was populated."""
        assert entry.attributes is not None
        return entry.attributes.attributes

    @pytest.mark.parametrize(
        ("content", "expected_count"),
        [
            (SINGLE_ENTRY, 1),
            (THREE_ENTRIES, 3),
            (GROUP_ENTRY, 1),
            (WITH_HEADER, 1),
            ("", 0),
        ],
    )
    def test_parse_ldif_returns_expected_entry_count(
        self, content: str, expected_count: int
    ) -> None:
        """parse_ldif succeeds and yields the expected number of entries."""
        result = ldif().parse_ldif(content)

        assert result.success
        assert len(result.unwrap().entries) == expected_count

    def test_parse_ldif_preserves_distinguished_name(self) -> None:
        """The parsed entry exposes the source DN through its public value."""
        response = ldif().parse_ldif(SINGLE_ENTRY).unwrap()

        assert self._dn_value(response.entries[0]) == "cn=test,dc=example,dc=com"

    def test_parse_ldif_preserves_attribute_values(self) -> None:
        """Parsed attributes are exposed verbatim via the public mapping."""
        response = ldif().parse_ldif(SINGLE_ENTRY).unwrap()

        attributes = self._attributes(response.entries[0])
        assert attributes["cn"] == ["test"]
        assert attributes["sn"] == ["Test"]
        assert attributes["mail"] == ["test@example.com"]

    def test_parse_ldif_preserves_multivalued_attribute_ordering(self) -> None:
        """Repeated attributes surface as an ordered list of every value."""
        response = ldif().parse_ldif(GROUP_ENTRY).unwrap()

        members = self._attributes(response.entries[0])["member"]
        assert members == [
            "cn=user1,dc=example,dc=com",
            "cn=user2,dc=example,dc=com",
            "cn=user3,dc=example,dc=com",
        ]

    def test_parse_ldif_ignores_version_and_comment_header(self) -> None:
        """RFC header lines are consumed without becoming entry attributes."""
        response = ldif().parse_ldif(WITH_HEADER).unwrap()

        attributes = self._attributes(response.entries[0])
        assert "cn" in attributes
        assert "version" not in attributes

    def test_parse_ldif_reports_detected_server_type(self) -> None:
        """A generic document is detected as the RFC server type."""
        response = ldif().parse_ldif(SINGLE_ENTRY).unwrap()

        assert response.detected_server_type == "rfc"

    def test_parse_ldif_statistics_match_entry_count(self) -> None:
        """The response statistics agree with the observable entry list."""
        response = ldif().parse_ldif(THREE_ENTRIES).unwrap()

        assert response.statistics.total_entries == len(response.entries)

    def test_parse_ldif_from_file_path(self, tmp_path: Path) -> None:
        """Parsing a filesystem path yields the same entries as a string."""
        ldif_file = tmp_path / "test.ldif"
        ldif_file.write_text(SINGLE_ENTRY)

        response = ldif().parse_ldif(ldif_file).unwrap()

        assert len(response.entries) == 1
        assert self._dn_value(response.entries[0]) == "cn=test,dc=example,dc=com"

    def test_parse_ldif_missing_file_fails_with_error(self, tmp_path: Path) -> None:
        """A non-existent path yields a failure carrying a descriptive error."""
        missing = tmp_path / "does-not-exist.ldif"

        result = ldif().parse_ldif(missing)

        assert result.success is False
        assert result.error is not None
        assert "not found" in result.error.lower()

    def test_parse_map_combinator_projects_entry_count(self) -> None:
        """FlextResult.map transforms the success value without unwrapping."""
        count = ldif().parse_ldif(THREE_ENTRIES).map(lambda r: len(r.entries))

        assert count.success
        assert count.unwrap() == 3

    def test_validate_entries_accepts_wellformed_entries(self) -> None:
        """Validation of parsed entries succeeds through the public API."""
        api = ldif()
        entries = api.parse_ldif(SINGLE_ENTRY).unwrap().entries

        assert api.validate_entries(entries).success

    def test_write_produces_content_and_statistics(self) -> None:
        """Writing entries returns serialized content plus matching statistics."""
        api = ldif()
        entries = api.parse_ldif(SINGLE_ENTRY).unwrap().entries

        written = api.write(entries).unwrap()

        assert written.content is not None
        assert "dn: cn=test,dc=example,dc=com" in written.content
        assert written.statistics.total_entries == 1

    @pytest.mark.parametrize(
        "content", [SINGLE_ENTRY, THREE_ENTRIES, GROUP_ENTRY]
    )
    def test_parse_write_parse_roundtrip_is_idempotent(self, content: str) -> None:
        """Re-parsing serialized output reproduces DNs and attributes exactly."""
        api = ldif()
        original = api.parse_ldif(content).unwrap().entries

        serialized = api.write_to_string(original).unwrap()
        reparsed = api.parse_ldif(serialized).unwrap().entries

        assert [self._dn_value(e) for e in reparsed] == [
            self._dn_value(e) for e in original
        ]
        assert [self._attributes(e) for e in reparsed] == [
            self._attributes(e) for e in original
        ]
