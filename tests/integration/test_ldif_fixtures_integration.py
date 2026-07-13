"""Behavioral integration tests for LDIF fixtures across all servers.

Exercises the public FlextLdif contract (parse/write/validate) against the
real fixture corpus for RFC, OID, OUD, and OpenLDAP2. Every assertion targets
observable behavior: the ``r[T]`` outcome, public response models, and the
public state of parsed ``Entry`` models -- never private attributes or
internal collaborators.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flext_ldif import ldif
from tests.constants import c

if TYPE_CHECKING:
    from pathlib import Path

    from tests.protocols import p


class TestsFlextLdifLdifFixturesIntegration:
    """Behavioral tests for the public LDIF parse/write/validate contract."""

    # (server subdirectory, fixture filename, minimum entry count)
    _FIXTURE_CASES: tuple[tuple[str, str, int], ...] = (
        (c.Tests.RFC, "rfc_entries_fixtures.ldif", 14),
        (c.Tests.OID, "oid_entries_fixtures.ldif", 1),
        (c.Tests.OUD, "oud_entries_fixtures.ldif", 1),
        ("openldap2", "openldap2_entries_fixtures.ldif", 1),
        ("openldap2", "openldap2_integration_fixtures.ldif", 45),
    )

    @pytest.fixture
    def ldif_client(self) -> p.Ldif.LdifClient:
        """Provide the public FlextLdif facade under test."""
        return ldif

    def _fixture_path(self, subdir: str, filename: str) -> Path:
        """Resolve a fixture path from its server subdirectory and filename."""
        fixture_path: Path = c.Tests.FIXTURES_DIR / subdir / filename
        return fixture_path

    @pytest.mark.parametrize(("subdir", "filename", "min_entries"), _FIXTURE_CASES)
    def test_parse_succeeds_and_yields_expected_minimum_entries(
        self,
        ldif_client: p.Ldif.LdifClient,
        subdir: str,
        filename: str,
        min_entries: int,
    ) -> None:
        """Parsing a valid fixture succeeds and returns at least the expected entries."""
        result = ldif_client.parse_ldif(self._fixture_path(subdir, filename))

        assert result.success, f"parse failed for {filename}: {result.error}"
        entries = result.value.entries
        assert len(entries) >= min_entries, (
            f"Expected >= {min_entries} entries from {filename}, got {len(entries)}"
        )

    @pytest.mark.parametrize(("subdir", "filename", "min_entries"), _FIXTURE_CASES)
    def test_every_parsed_entry_exposes_a_wellformed_dn(
        self,
        ldif_client: p.Ldif.LdifClient,
        subdir: str,
        filename: str,
        min_entries: int,
    ) -> None:
        """Every parsed entry publishes a non-empty, attribute=value shaped DN."""
        result = ldif_client.parse_ldif(self._fixture_path(subdir, filename))

        assert result.success
        for entry in result.value.entries:
            assert entry.dn is not None, f"entry in {filename} missing DN"
            dn_value = entry.dn.value
            assert dn_value, f"entry in {filename} has empty DN"
            assert entry.dn_str == dn_value
            assert "=" in dn_value, f"DN {dn_value!r} in {filename} is not RFC-shaped"

    @pytest.mark.parametrize(("subdir", "filename", "min_entries"), _FIXTURE_CASES)
    def test_statistics_total_matches_returned_entry_count(
        self,
        ldif_client: p.Ldif.LdifClient,
        subdir: str,
        filename: str,
        min_entries: int,
    ) -> None:
        """Reported statistics agree with the number of entries returned."""
        response = ldif_client.parse_ldif(self._fixture_path(subdir, filename)).value

        assert response.statistics.total_entries == len(response.entries)
        assert response.detected_server_type

    @pytest.mark.parametrize(("subdir", "filename", "min_entries"), _FIXTURE_CASES)
    def test_write_then_reparse_preserves_entry_count(
        self,
        ldif_client: p.Ldif.LdifClient,
        subdir: str,
        filename: str,
        min_entries: int,
    ) -> None:
        """Writing parsed entries and reparsing the output round-trips the count."""
        parsed = ldif_client.parse_ldif(self._fixture_path(subdir, filename))
        assert parsed.success
        original = parsed.value.entries

        written = ldif_client.write(original)
        assert written.success, f"write failed for {filename}: {written.error}"
        content = written.value.content
        assert content, f"write produced empty content for {filename}"

        reparsed = ldif_client.parse_string(content)
        assert reparsed.success, f"reparse failed for {filename}: {reparsed.error}"
        assert len(reparsed.value.entries) == len(original)

    @pytest.mark.parametrize(("subdir", "filename", "min_entries"), _FIXTURE_CASES)
    def test_validate_entries_reports_success_for_wellformed_fixtures(
        self,
        ldif_client: p.Ldif.LdifClient,
        subdir: str,
        filename: str,
        min_entries: int,
    ) -> None:
        """Validating well-formed fixture entries yields a passing validation result."""
        entries = ldif_client.parse_ldif(
            self._fixture_path(subdir, filename)
        ).value.entries

        validation = ldif_client.validate_entries(entries)

        assert validation.success, (
            f"validation errored for {filename}: {validation.error}"
        )
        report = validation.value
        assert report.valid, f"fixture {filename} unexpectedly invalid: {report.errors}"
        assert report.total_entries == len(entries)
        assert not report.invalid_entries

    def test_parse_string_matches_parse_ldif_for_same_content(
        self,
        ldif_client: p.Ldif.LdifClient,
    ) -> None:
        """Parsing a file and parsing its written content produce identical DNs."""
        path = self._fixture_path(c.Tests.RFC, "rfc_entries_fixtures.ldif")
        from_file = ldif_client.parse_ldif(path)
        assert from_file.success

        content = ldif_client.write(from_file.value.entries).value.content
        assert content is not None
        from_string = ldif_client.parse_string(content)
        assert from_string.success

        assert [e.dn_str for e in from_string.value.entries] == [
            e.dn_str for e in from_file.value.entries
        ]

    def test_parse_missing_file_fails_with_informative_error(
        self,
        ldif_client: p.Ldif.LdifClient,
    ) -> None:
        """Parsing a nonexistent fixture returns a failure naming the missing path."""
        missing = self._fixture_path(c.Tests.RFC, "does_not_exist.ldif")

        result = ldif_client.parse_ldif(missing)

        assert not result.success
        assert result.error is not None
        assert "does_not_exist.ldif" in result.error
