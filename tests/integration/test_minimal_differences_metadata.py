"""Behavioral tests for minimal-differences metadata tracking.

Exercises the public contract of the LDIF parse -> Entry(metadata) -> write
pipeline: fallible ``r[T]`` outcomes, ``Entry.metadata`` public fields, the
boolean-conversion metadata payload, verbatim DN preservation, and round-trip
``write()`` output. No private attributes, collaborators, or internal call
spying are touched -- only observable public behavior.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from flext_ldif import ldif, m
from flext_ldif.services.parser import FlextLdifParser
from tests.constants import c

if TYPE_CHECKING:
    from tests.protocols import p


class TestsFlextLdifMinimalDifferencesMetadata:
    """Public-contract tests for minimal-differences metadata capture."""

    @pytest.fixture
    def parser(self) -> FlextLdifParser:
        """Provide a parser instance."""
        return FlextLdifParser()

    @pytest.fixture
    def writer(self) -> p.Ldif.LdifClient:
        """Provide a writer client via the public ``ldif()`` entry point."""
        return ldif()

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        """Locate the shared LDIF fixtures directory."""
        return Path(__file__).parent.parent / "fixtures"

    # -- server_type propagation ------------------------------------------

    @pytest.mark.parametrize(
        ("server_type", "effective_server_type"),
        [
            (c.Tests.OID, c.Tests.OID),
            (c.Tests.OUD, c.Tests.RFC),
            (c.Tests.RFC, c.Tests.RFC),
        ],
    )
    def test_parsed_entry_metadata_reports_effective_server_type(
        self,
        parser: FlextLdifParser,
        server_type: str,
        effective_server_type: str,
    ) -> None:
        """Entry metadata records the effective (normalized) server family.

        OUD is RFC-compliant, so its metadata normalizes to ``rfc``; OID keeps
        its own identity.
        """
        content = (
            "dn: cn=test,dc=example,dc=com\n"
            "objectClass: top\n"
            "objectClass: person\n"
            "cn: test\n"
        )

        result = parser.parse_string(content=content, server_type=server_type)

        assert result.success, result.error
        entries = result.value.entries
        assert len(entries) == 1
        metadata = entries[0].metadata
        assert metadata is not None
        assert str(metadata.server_type) == effective_server_type

    # -- fixture-driven capture -------------------------------------------

    @pytest.mark.parametrize(
        ("server_type", "effective_server_type", "fixture_name"),
        [
            (c.Tests.OID, c.Tests.OID, "oid_entries_fixtures.ldif"),
            (c.Tests.OUD, c.Tests.RFC, "oud_entries_fixtures.ldif"),
        ],
    )
    def test_fixture_entries_all_carry_matching_server_metadata(
        self,
        parser: FlextLdifParser,
        fixtures_dir: Path,
        server_type: str,
        effective_server_type: str,
        fixture_name: str,
    ) -> None:
        """Every entry parsed from a server fixture carries its effective type."""
        fixture_path = fixtures_dir / server_type / fixture_name

        result = parser.parse_ldif_file(path=fixture_path, server_type=server_type)

        assert result.success, result.error
        entries = result.value.entries
        assert entries, f"No entries parsed from {fixture_path}"
        for entry in entries:
            assert entry.metadata is not None, f"Entry {entry.dn} missing metadata"
            assert str(entry.metadata.server_type) == effective_server_type

    # -- original DN capture ----------------------------------------------

    def test_oid_parse_captures_complete_original_dn(
        self,
        parser: FlextLdifParser,
    ) -> None:
        """OID parsing records the complete original DN under extensions."""
        content = (
            "dn: cn=test,dc=example,dc=com\n"
            "objectClass: top\n"
            "cn: test\n"
        )

        result = parser.parse_string(content=content, server_type=c.Tests.OID)

        assert result.success, result.error
        metadata = result.value.entries[0].metadata
        assert metadata is not None
        assert metadata.extensions["original_dn_complete"] == "cn=test,dc=example,dc=com"

    def test_dn_whitespace_preserved_verbatim_on_parse(
        self,
        parser: FlextLdifParser,
    ) -> None:
        """DN spacing is preserved exactly as written through the parse."""
        content = (
            "dn: cn=test, dc=example, dc=com\n"
            "objectClass: top\n"
            "cn: test\n"
        )

        result = parser.parse_string(content=content, server_type=c.Tests.RFC)

        assert result.success, result.error
        entry = result.value.entries[0]
        assert str(entry.dn) == "cn=test, dc=example, dc=com"

    # -- boolean conversion metadata --------------------------------------

    @pytest.mark.parametrize(
        ("attribute", "raw_value", "converted_value"),
        [
            ("orcldasisenabled", "1", "TRUE"),
            ("pwdlockout", "0", "FALSE"),
        ],
    )
    def test_oid_boolean_conversion_recorded_in_metadata(
        self,
        parser: FlextLdifParser,
        attribute: str,
        raw_value: str,
        converted_value: str,
    ) -> None:
        """OID 0/1 booleans are recorded with original and converted values."""
        content = (
            "dn: cn=test,dc=example,dc=com\n"
            "objectClass: top\n"
            "cn: test\n"
            f"{attribute}: {raw_value}\n"
        )

        result = parser.parse_string(content=content, server_type=c.Tests.OID)

        assert result.success, result.error
        metadata = result.value.entries[0].metadata
        assert metadata is not None
        converted = m.Ldif.DynamicMetadata.model_validate(
            metadata.extensions[c.Ldif.CONVERTED_ATTRIBUTES],
        )
        boolean_conversions = m.Ldif.DynamicMetadata.model_validate(
            converted[c.Ldif.CONVERSION_BOOLEAN_CONVERSIONS],
        )
        assert attribute in boolean_conversions
        entry_conversion = m.Ldif.DynamicMetadata.model_validate(
            boolean_conversions[attribute],
        )
        assert entry_conversion[c.Ldif.CONVERSION_ORIGINAL_VALUE] == [raw_value]
        assert entry_conversion[c.Ldif.CONVERSION_CONVERTED_VALUE] == [converted_value]

    # -- round-trip write --------------------------------------------------

    def test_round_trip_write_emits_converted_boolean_value(
        self,
        parser: FlextLdifParser,
        writer: p.Ldif.LdifClient,
    ) -> None:
        """OID -> write converts the boolean and preserves the DN in output."""
        content = (
            "dn: cn=test,dc=example,dc=com\n"
            "objectClass: top\n"
            "cn: test\n"
            "orcldasisenabled: 1\n"
        )
        parse_result = parser.parse_string(content=content, server_type=c.Tests.OID)
        assert parse_result.success, parse_result.error
        entry = m.Ldif.Entry.model_validate(parse_result.value.entries[0])

        write_result = writer.write(entries=[entry])

        assert write_result.success, write_result.error
        written = write_result.value.content
        assert written is not None
        assert "dn: cn=test,dc=example,dc=com" in written
        assert "orcldasisenabled: TRUE" in written

    # -- operational attribute preservation -------------------------------

    @pytest.mark.parametrize(
        ("attribute", "value"),
        [
            ("creatorsName", "cn=Directory Manager"),
            ("createTimestamp", "20250101000000Z"),
        ],
    )
    def test_operational_attributes_preserved_through_parse(
        self,
        parser: FlextLdifParser,
        attribute: str,
        value: str,
    ) -> None:
        """Operational attributes survive parsing and stay publicly readable."""
        content = (
            "dn: cn=test,dc=example,dc=com\n"
            "objectClass: top\n"
            "cn: test\n"
            "creatorsName: cn=Directory Manager\n"
            "createTimestamp: 20250101000000Z\n"
        )

        result = parser.parse_string(content=content, server_type=c.Tests.RFC)

        assert result.success, result.error
        entry = result.value.entries[0]
        assert entry.metadata is not None
        assert entry.attributes is not None
        assert entry.attributes.get(attribute) == [value]

    # -- invariants and error paths ---------------------------------------

    def test_metadata_capture_is_idempotent_across_repeated_parses(
        self,
        parser: FlextLdifParser,
    ) -> None:
        """Parsing identical content twice yields identical metadata."""
        content = (
            "dn: cn=test,dc=example,dc=com\n"
            "objectClass: top\n"
            "cn: test\n"
            "orcldasisenabled: 1\n"
        )

        first = parser.parse_string(content=content, server_type=c.Tests.OID)
        second = parser.parse_string(content=content, server_type=c.Tests.OID)

        assert first.success and second.success
        first_meta = first.value.entries[0].metadata
        second_meta = second.value.entries[0].metadata
        assert first_meta is not None
        assert second_meta is not None
        assert str(first_meta.server_type) == str(second_meta.server_type)
        assert first_meta.extensions == second_meta.extensions

    def test_unknown_server_type_returns_failure_with_reason(
        self,
        parser: FlextLdifParser,
    ) -> None:
        """An unknown server_type fails with a descriptive error, not a crash."""
        content = "dn: cn=test,dc=example,dc=com\ncn: test\n"

        result = parser.parse_string(content=content, server_type="nonexistent_server")

        assert not result.success
        assert result.error is not None
        assert "nonexistent_server" in result.error


__all__: list[str] = ["TestsFlextLdifMinimalDifferencesMetadata"]
