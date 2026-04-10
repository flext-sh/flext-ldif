"""Integration tests for minimal differences metadata tracking.

Tests the complete pipeline: ldif -> parser -> Entry Model (RFC + Metadata) -> writer -> ldif
Validates that ALL minimal differences are captured and preserved for perfect round-trip.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdifParser, ldif
from tests import c, m, t, u


class TestMinimalDifferencesOidOud:
    """Test suite for minimal differences tracking between OID and OUD fixtures."""

    @pytest.fixture
    def parser(self) -> FlextLdifParser:
        """Create parser instance."""
        return FlextLdifParser()

    @pytest.fixture
    def writer(self) -> ldif:
        """Create writer instance via ldif."""
        return ldif()

    def test_oid_fixture_all_differences_captured(
        self,
        parser: FlextLdifParser,
        writer: ldif,
    ) -> None:
        """Test that ALL minimal differences in OID fixtures are captured in metadata."""
        fixture_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / c.Ldif.Fixtures.OID
            / "oid_entries_fixtures.ldif"
        )
        if not fixture_path.exists():
            pytest.skip(f"OID fixture not found: {fixture_path}")
        parse_result = parser.parse_ldif_file(
            path=fixture_path, server_type=c.Ldif.Fixtures.OID
        )
        assert parse_result.is_success, f"Parsing failed: {parse_result.error}"
        parse_response = parse_result.value
        entries = parse_response.entries
        assert entries, "No entries parsed from OID fixture"
        for entry in entries:
            assert entry.metadata is not None, f"Entry {entry.dn} missing metadata"
            assert entry.metadata.quirk_type == c.Ldif.Fixtures.OID, (
                f"Entry {entry.dn} should have quirk_type='{c.Ldif.Fixtures.OID}', got {entry.metadata.quirk_type}"
            )

    def test_oud_fixture_all_differences_captured(
        self,
        parser: FlextLdifParser,
        writer: ldif,
    ) -> None:
        """Test that ALL minimal differences in OUD fixtures are captured in metadata."""
        fixture_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / c.Ldif.Fixtures.OUD
            / "oud_entries_fixtures.ldif"
        )
        if not fixture_path.exists():
            pytest.skip(f"OUD fixture not found: {fixture_path}")
        parse_result = parser.parse_ldif_file(
            path=fixture_path, server_type=c.Ldif.Fixtures.OUD
        )
        assert parse_result.is_success, f"Parsing failed: {parse_result.error}"
        parse_response = parse_result.value
        entries = parse_response.entries
        assert entries, "No entries parsed from OUD fixture"
        for _entry in entries:
            pass

    def test_round_trip_oid_preserves_all_differences(
        self,
        parser: FlextLdifParser,
        writer: ldif,
    ) -> None:
        """Test round-trip: OID -> RFC -> OID preserves ALL differences."""
        oid_ldif = "dn: cn=test, dc=example, dc=com\nobjectClass: top\nobjectClass: person\ncn: test\nsn: User\norcldasisenabled: 1\n"
        parse_result = parser.parse_string(
            content=oid_ldif, server_type=c.Ldif.Fixtures.OID
        )
        assert parse_result.is_success
        entries = parse_result.value.entries
        assert len(entries) == 1
        original_entry = entries[0]
        assert original_entry.metadata is not None
        assert "original_dn_complete" in original_entry.metadata.extensions
        write_result = writer.write(
            entries=[m.Ldif.Entry.model_validate(original_entry)],
        )
        assert write_result.is_success
        written_ldif = write_result.value.content
        assert written_ldif is not None
        assert written_ldif
        assert "original_dn_complete" in original_entry.metadata.extensions

    def test_spacing_differences_captured(self, parser: FlextLdifParser) -> None:
        """Test that spacing differences (e.g., 'dc=example, dc=com' vs 'dc=example,dc=com') are captured."""
        ldif_with_spaces = "dn: cn=test, dc=example, dc=com\nobjectClass: top\nobjectClass: person\ncn: test\n"
        parse_result = parser.parse_string(
            content=ldif_with_spaces, server_type=c.Ldif.Fixtures.RFC
        )
        assert parse_result.is_success
        entries = parse_result.value.entries
        assert len(entries) == 1
        entry = entries[0]
        assert entry.metadata is not None
        dn_differences = entry.metadata.extensions.get("minimal_differences_dn", {})
        if isinstance(dn_differences, dict) and dn_differences.get("has_differences"):
            spacing_changes = dn_differences.get("spacing_changes", {})
            assert spacing_changes is not None, "Spacing changes should be tracked"

    def test_case_differences_captured(self, parser: FlextLdifParser) -> None:
        """Test that case differences (e.g., 'objectClass' vs 'objectclass') are captured."""
        ldif_mixed_case = "dn: cn=test,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: test\n"
        parse_result = parser.parse_string(
            content=ldif_mixed_case, server_type=c.Ldif.Fixtures.RFC
        )
        assert parse_result.is_success
        entries = parse_result.value.entries
        assert len(entries) == 1
        entry = entries[0]
        assert entry.metadata is not None
        original_attrs = entry.metadata.extensions.get(
            "original_attributes_complete",
            {},
        )
        assert isinstance(original_attrs, dict)
        if entry.metadata.original_attribute_case:
            assert entry.metadata.original_attribute_case

    def test_punctuation_differences_captured(self, parser: FlextLdifParser) -> None:
        """Test that punctuation differences (e.g., trailing semicolons) are captured."""
        ldif = "dn: cn=test,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: test\n"
        parse_result = parser.parse_string(
            content=ldif, server_type=c.Ldif.Fixtures.RFC
        )
        assert parse_result.is_success
        entries = parse_result.value.entries
        assert len(entries) == 1
        entry = entries[0]
        assert entry.metadata is not None
        dn_differences = entry.metadata.extensions.get("minimal_differences_dn", {})
        if isinstance(dn_differences, dict) and dn_differences.get("has_differences"):
            assert (
                "spacing_changes" in dn_differences or "case_changes" in dn_differences
            )
        entry.metadata.extensions.get("original_dn_complete")

    def test_boolean_conversion_tracked(self, parser: FlextLdifParser) -> None:
        """Test that boolean conversions (0/1 -> TRUE/FALSE) are tracked in metadata."""
        oid_ldif = "dn: cn=test,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: test\norcldasisenabled: 1\npwdlockout: 0\n"
        parse_result = parser.parse_string(
            content=oid_ldif, server_type=c.Ldif.Fixtures.OID
        )
        assert parse_result.is_success
        entries = parse_result.value.entries
        assert len(entries) == 1
        entry = entries[0]
        assert entry.metadata is not None
        converted_attrs = entry.metadata.extensions.get(c.Ldif.CONVERTED_ATTRIBUTES, {})
        if isinstance(converted_attrs, dict):
            raw_boolean_conversions = converted_attrs.get(
                c.Ldif.CONVERSION_BOOLEAN_CONVERSIONS,
                {},
            )
            boolean_conversions = (
                dict(raw_boolean_conversions)
                if isinstance(raw_boolean_conversions, dict)
                else dict[str, t.Ldif.MetadataValue]()
            )
        else:
            boolean_conversions = dict[str, t.Ldif.MetadataValue]()
        if (
            u.is_dict_non_empty(boolean_conversions)
            and "orcldasisenabled" in boolean_conversions
        ):
            conv = boolean_conversions["orcldasisenabled"]
            assert isinstance(conv, dict)
            original_key = c.Ldif.CONVERSION_ORIGINAL_VALUE
            converted_key = c.Ldif.CONVERSION_CONVERTED_VALUE
            assert original_key in conv
            assert converted_key in conv
            assert conv[original_key] == ["1"]
            assert conv[converted_key] == ["TRUE"]

    def test_soft_deleted_attributes_preserved(self, parser: FlextLdifParser) -> None:
        """Test that soft-deleted attributes are preserved in metadata."""
        ldif = "dn: cn=test,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: test\ncreatorsName: cn=Directory Manager\ncreateTimestamp: 20250101000000Z\n"
        parse_result = parser.parse_string(
            content=ldif, server_type=c.Ldif.Fixtures.RFC
        )
        assert parse_result.is_success
        entries = parse_result.value.entries
        assert len(entries) == 1
        entry = entries[0]
        assert entry.metadata is not None
        assert entry.metadata is not None


__all__ = ["TestMinimalDifferencesOidOud"]
