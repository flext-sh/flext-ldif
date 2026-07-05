"""Behavioral integration tests for LDIF settings and railway composition.

Test suite verifying OBSERVABLE PUBLIC BEHAVIOR:
    - FlextLdifSettings public configuration contract (encoding, strict flag)
    - Global worker-capacity invariant exposed via FlextSettings
    - Railway-oriented r composition (write -> parse -> validate) round-trip
    - Write/parse idempotence preserving DN and attribute payloads
    - Failure channel for unreadable sources and empty-input edge case

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import codecs
from typing import TYPE_CHECKING

import pytest

from flext_core import FlextSettings
from flext_ldif import ldif
from tests.models import m

if TYPE_CHECKING:
    from pathlib import Path

    from tests.protocols import p


@pytest.mark.integration
class TestsFlextLdifRealLdapConfig:
    """Public-contract tests for LDIF settings and railway composition."""

    @pytest.fixture
    def flext_api(self) -> p.Ldif.LdifClient:
        """Ldif API instance under test."""
        return ldif()

    @pytest.fixture
    def sample_entry(self) -> m.Ldif.Entry:
        """A valid inetOrgPerson entry built through the public model API."""
        result = m.Ldif.Entry.create(
            dn="cn=RailwayTest,ou=people,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["RailwayTest"],
                "sn": ["Test"],
                "mail": ["railway@example.com"],
            },
            metadata=None,
        )
        assert result.success, result.error
        entry: m.Ldif.Entry = result.value
        return entry

    # -- settings contract ------------------------------------------------

    def test_settings_encoding_is_a_usable_codec(
        self,
        flext_api: p.Ldif.LdifClient,
    ) -> None:
        """The configured LDIF encoding resolves to a real Python codec."""
        encoding: str = str(flext_api.settings.Ldif.ldif_encoding)

        # A settings value that is not a resolvable codec is a broken contract.
        assert codecs.lookup(encoding).name

    def test_settings_strict_validation_is_boolean(
        self,
        flext_api: p.Ldif.LdifClient,
    ) -> None:
        """The strict-validation flag is exposed as a plain bool."""
        assert isinstance(flext_api.settings.Ldif.ldif_strict_validation, bool)

    def test_global_settings_expose_positive_worker_capacity(self) -> None:
        """Global settings always advertise at least one worker."""
        assert FlextSettings.fetch_global().max_workers >= 1

    # -- railway composition ----------------------------------------------

    def test_railway_write_parse_validate_preserves_entry(
        self,
        flext_api: p.Ldif.LdifClient,
        sample_entry: m.Ldif.Entry,
        tmp_path: Path,
    ) -> None:
        """Write, parse, then validate yields the original entry intact."""
        output_file = tmp_path / "railway.ldif"

        result = (
            flext_api
            .write_ldif_file([sample_entry], output_file)
            .flat_map(lambda _: flext_api.parse_ldif(output_file))
            .flat_map(
                lambda parsed: flext_api.validate_entries(parsed.entries).map(
                    lambda _: parsed,
                ),
            )
        )

        assert result.success, result.error
        parsed_entries = result.value.entries
        assert len(parsed_entries) == 1
        round_tripped = parsed_entries[0]
        assert round_tripped.dn_str == sample_entry.dn_str
        assert round_tripped.attributes_dict["mail"] == ["railway@example.com"]

    def test_write_to_string_then_parse_is_idempotent(
        self,
        flext_api: p.Ldif.LdifClient,
        sample_entry: m.Ldif.Entry,
    ) -> None:
        """Serialize-to-string then parse-back preserves DN and attributes."""
        parsed = flext_api.write_to_string([sample_entry]).flat_map(
            flext_api.parse_string,
        )

        assert parsed.success, parsed.error
        entries = parsed.value.entries
        assert len(entries) == 1
        assert entries[0].dn_str == sample_entry.dn_str
        assert (
            entries[0].attributes_dict["objectClass"]
            == sample_entry.attributes_dict["objectClass"]
        )

    def test_validate_entries_reports_full_success(
        self,
        flext_api: p.Ldif.LdifClient,
        sample_entry: m.Ldif.Entry,
    ) -> None:
        """Validating a well-formed entry yields a passing ValidationResult."""
        result = flext_api.validate_entries([sample_entry])

        assert result.success, result.error
        validation = result.value
        assert validation.valid is True
        assert validation.total_entries == 1
        assert validation.errors == []

    # -- edge cases and failure channel -----------------------------------

    def test_parse_missing_file_fails_with_descriptive_error(
        self,
        flext_api: p.Ldif.LdifClient,
        tmp_path: Path,
    ) -> None:
        """Parsing a nonexistent path returns a failure, never a fake success."""
        missing = tmp_path / "does_not_exist.ldif"

        result = flext_api.parse_ldif(missing)

        assert not result.success
        assert result.error is not None
        assert "not found" in result.error.lower()

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("", id="empty-string"),
            pytest.param("\n\n", id="blank-lines-only"),
            pytest.param("# only a comment\n", id="comment-only"),
        ],
    )
    def test_parse_content_without_entries_succeeds_empty(
        self,
        flext_api: p.Ldif.LdifClient,
        content: str,
    ) -> None:
        """Content carrying no records parses to a successful empty result."""
        result = flext_api.parse_string(content)

        assert result.success, result.error
        assert result.value.entries == []


__all__: list[str] = ["TestsFlextLdifRealLdapConfig"]
