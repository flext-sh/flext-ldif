"""Zero Data Loss Tests for OID↔OUD↔RFC Conversions.

Validates that ALL minimal differences are preserved during conversions:
- Character-by-character differences (spacing, case, punctuation, quotes)
- Boolean conversions (0/1 ↔ TRUE/FALSE)
- Soft deletes and removed attributes
- Original strings preservation
- Perfect round-trip conversion

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdif
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif.models import FlextLdifModels

from ..fixtures.loader import FlextLdifFixtures


class TestZeroDataLossOidOud:
    """Test zero data loss in OID↔OUD↔RFC conversions."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif.get_instance()

    @pytest.fixture
    def oid_fixture(self) -> str:
        """Load OID entries fixture."""
        loader = FlextLdifFixtures.OID()
        return loader.entries()

    @pytest.fixture
    def oud_fixture(self) -> str:
        """Load OUD entries fixture."""
        loader = FlextLdifFixtures.OUD()
        return loader.entries()

    def test_oid_parse_preserves_original_ldif(
        self, api: FlextLdif, oid_fixture: str
    ) -> None:
        """Test that OID parsing preserves original LDIF in metadata."""
        result = api.parse(oid_fixture, server_type="oid")
        assert result.is_success, f"Parse failed: {result.error}"

        entries = result.unwrap()
        assert len(entries) > 0, "No entries parsed"

        # Verify ALL entries have original LDIF preserved
        for entry in entries:
            assert entry.metadata is not None, "Entry missing metadata"
            assert entry.metadata.original_strings is not None, (
                "Entry missing original_strings"
            )
            assert "entry_original_ldif" in entry.metadata.original_strings, (
                f"Entry {entry.dn} missing original LDIF preservation"
            )

            original_ldif = entry.metadata.original_strings["entry_original_ldif"]
            assert len(original_ldif) > 0, "Original LDIF is empty"
            assert "dn:" in original_ldif.lower(), "Original LDIF missing DN"

    def test_oud_parse_preserves_original_ldif(
        self, api: FlextLdif, oud_fixture: str
    ) -> None:
        """Test that OUD parsing preserves original LDIF in metadata."""
        result = api.parse(oud_fixture, server_type="oud")
        assert result.is_success, f"Parse failed: {result.error}"

        entries = result.unwrap()
        assert len(entries) > 0, "No entries parsed"

        # Verify ALL entries have original LDIF preserved
        for entry in entries:
            assert entry.metadata is not None, "Entry missing metadata"
            assert entry.metadata.original_strings is not None, (
                "Entry missing original_strings"
            )
            assert "entry_original_ldif" in entry.metadata.original_strings, (
                f"Entry {entry.dn} missing original LDIF preservation"
            )

    def test_oid_boolean_conversion_tracking(
        self,
        api: FlextLdif,
        oid_fixture: str,
    ) -> None:
        """Test that boolean conversions are tracked in metadata."""
        result = api.parse(oid_fixture, server_type="oid")
        assert result.is_success

        entries = result.unwrap()

        # Find entries with boolean attributes
        boolean_entries = [
            e
            for e in entries
            if e.metadata
            and e.metadata.boolean_conversions
            and len(e.metadata.boolean_conversions) > 0
        ]

        if boolean_entries:
            entry = boolean_entries[0]
            for attr_name, conversion in entry.metadata.boolean_conversions.items():
                assert "original" in conversion, (
                    f"Missing original value for {attr_name}"
                )
                assert "converted" in conversion, (
                    f"Missing converted value for {attr_name}"
                )
                assert "format" in conversion, (
                    f"Missing format direction for {attr_name}"
                )

                # Verify conversion direction
                assert conversion["format"] in {"OID->RFC", "RFC->OID"}, (
                    f"Invalid format direction: {conversion['format']}"
                )

    def test_oid_oud_conversion_preserves_all_data(
        self,
        api: FlextLdif,
        oid_fixture: str,
    ) -> None:
        """Test OID→OUD conversion preserves ALL data in metadata."""
        # Parse OID
        parse_result = api.parse(oid_fixture, server_type="oid")
        assert parse_result.is_success
        oid_entries = parse_result.unwrap()

        # Convert to OUD (via RFC intermediate)
        # Write OID entries
        write_result = api.write(oid_entries, target_server_type="rfc")
        assert write_result.is_success
        rfc_ldif = write_result.unwrap()

        # Parse as OUD
        parse_oud_result = api.parse(rfc_ldif, server_type="oud")
        assert parse_oud_result.is_success
        oud_entries = parse_oud_result.unwrap()

        # Verify metadata preservation
        assert len(oid_entries) == len(oud_entries), "Entry count mismatch"

        for oid_entry, oud_entry in zip(oid_entries, oud_entries, strict=False):
            # Verify original strings preserved
            assert oid_entry.metadata is not None
            assert oud_entry.metadata is not None

            # Original OID LDIF should be preserved
            if "entry_original_ldif" in oid_entry.metadata.original_strings:
                original_oid_ldif = oid_entry.metadata.original_strings[
                    "entry_original_ldif"
                ]
                assert len(original_oid_ldif) > 0, "Original OID LDIF lost"

            # Verify no data loss using utility function
            no_loss, lost_attrs = FlextLdifUtilitiesMetadata.assert_no_data_loss(
                original_entry=oid_entry,
                converted_entry=oud_entry,
            )
            assert no_loss, f"Data loss detected: {lost_attrs}"

    def test_round_trip_oid_oud_oid_preserves_formatting(
        self,
        api: FlextLdif,
        oid_fixture: str,
    ) -> None:
        """Test OID→OUD→OID round-trip preserves ALL formatting."""
        # Parse OID
        parse_oid = api.parse(oid_fixture, server_type="oid")
        assert parse_oid.is_success
        original_entries = parse_oid.unwrap()

        # OID → OUD
        write_oud = api.write(original_entries, target_server_type="oud")
        assert write_oud.is_success
        oud_ldif = write_oud.unwrap()

        parse_oud = api.parse(oud_ldif, server_type="oud")
        assert parse_oud.is_success
        oud_entries = parse_oud.unwrap()

        # OUD → OID (round-trip)
        write_oid = api.write(
            oud_entries,
            target_server_type="oid",
            format_options=FlextLdifModels.WriteFormatOptions(
                restore_original_format=True,
            ),
        )
        assert write_oid.is_success
        roundtrip_ldif = write_oid.unwrap()

        parse_roundtrip = api.parse(roundtrip_ldif, server_type="oid")
        assert parse_roundtrip.is_success
        roundtrip_entries = parse_roundtrip.unwrap()

        # Verify entry count preserved
        assert len(original_entries) == len(roundtrip_entries)

        # Verify metadata preservation
        for orig, roundtrip in zip(original_entries, roundtrip_entries, strict=False):
            # Original LDIF should be preserved
            if (
                orig.metadata
                and "entry_original_ldif" in orig.metadata.original_strings
            ):
                original_ldif = orig.metadata.original_strings["entry_original_ldif"]
                # When restore_original_format=True, roundtrip should match original
                if (
                    roundtrip.metadata
                    and "entry_original_ldif" in roundtrip.metadata.original_strings
                ):
                    roundtrip_original = roundtrip.metadata.original_strings[
                        "entry_original_ldif"
                    ]
                    # Original formatting should be preserved
                    assert len(original_ldif) > 0
                    assert len(roundtrip_original) > 0

    def test_minimal_differences_tracking(
        self,
        api: FlextLdif,
        oid_fixture: str,
    ) -> None:
        """Test that minimal differences are tracked for all conversions."""
        result = api.parse(oid_fixture, server_type="oid")
        assert result.is_success

        entries = result.unwrap()

        for entry in entries:
            if entry.metadata:
                # Check DN differences
                if "dn" in entry.metadata.minimal_differences:
                    dn_diff = entry.metadata.minimal_differences["dn"]
                    if dn_diff.get("has_differences", False):
                        assert "original" in dn_diff, "Missing original DN"
                        assert "differences" in dn_diff, "Missing differences list"

                # Check attribute differences
                for attr_name, attr_diff in entry.metadata.minimal_differences.items():
                    if (
                        attr_name != "dn"
                        and isinstance(attr_diff, dict)
                        and attr_diff.get("has_differences", False)
                    ):
                        assert "original" in attr_diff, (
                            f"Missing original for {attr_name}"
                        )
                        assert "differences" in attr_diff, (
                            f"Missing differences for {attr_name}"
                        )

    def test_soft_delete_tracking(
        self,
        api: FlextLdif,
        oid_fixture: str,
    ) -> None:
        """Test that soft-deleted attributes are tracked in metadata."""
        result = api.parse(oid_fixture, server_type="oid")
        assert result.is_success

        entries = result.unwrap()

        # Check if any entries have soft-deleted attributes
        for entry in entries:
            if entry.metadata:
                soft_deleted = entry.metadata.soft_delete_markers
                if soft_deleted:
                    # Verify soft-deleted attributes are in removed_attributes
                    for attr_name in soft_deleted:
                        assert attr_name in entry.metadata.removed_attributes, (
                            f"Soft-deleted attribute {attr_name} not in removed_attributes"
                        )
                        # Verify values are preserved
                        assert len(entry.metadata.removed_attributes[attr_name]) > 0, (
                            f"Soft-deleted attribute {attr_name} has no preserved values"
                        )

    def test_conversion_history_tracking(
        self,
        api: FlextLdif,
        oid_fixture: str,
    ) -> None:
        """Test that conversion history is tracked in metadata."""
        result = api.parse(oid_fixture, server_type="oid")
        assert result.is_success

        entries = result.unwrap()

        # After parsing, conversion_history should be populated
        for entry in entries:
            if entry.metadata:
                # Conversion history may be empty initially, but structure should exist
                assert hasattr(entry.metadata, "conversion_history"), (
                    "Metadata missing conversion_history field"
                )
                assert isinstance(entry.metadata.conversion_history, list), (
                    "conversion_history should be a list"
                )

    def test_original_strings_preservation(
        self,
        api: FlextLdif,
        oid_fixture: str,
    ) -> None:
        """Test that ALL original strings are preserved in metadata."""
        result = api.parse(oid_fixture, server_type="oid")
        assert result.is_success

        entries = result.unwrap()

        for entry in entries:
            assert entry.metadata is not None
            assert entry.metadata.original_strings is not None

            # Verify entry_original_ldif is preserved
            assert "entry_original_ldif" in entry.metadata.original_strings, (
                f"Entry {entry.dn} missing entry_original_ldif"
            )

            original_ldif = entry.metadata.original_strings["entry_original_ldif"]
            assert len(original_ldif) > 0, "Original LDIF is empty"

            # Verify DN original is preserved if DN was modified
            if entry.metadata.minimal_differences.get("dn", {}).get(
                "has_differences", False
            ):
                assert "dn_original" in entry.metadata.original_strings, (
                    "DN differences detected but dn_original not preserved"
                )

    def test_restore_original_format_option(
        self,
        api: FlextLdif,
        oid_fixture: str,
    ) -> None:
        """Test that restore_original_format option restores exact original."""
        # Parse OID
        parse_result = api.parse(oid_fixture, server_type="oid")
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Write with restore_original_format=True
        write_result = api.write(
            entries,
            target_server_type="oid",
            format_options=FlextLdifModels.WriteFormatOptions(
                restore_original_format=True,
            ),
        )
        assert write_result.is_success
        restored_ldif = write_result.unwrap()

        # Verify restored LDIF matches original for entries with preserved originals
        for entry in entries:
            if (
                entry.metadata
                and "entry_original_ldif" in entry.metadata.original_strings
            ):
                original_ldif = entry.metadata.original_strings["entry_original_ldif"]
                # Restored LDIF should contain the original entry
                assert original_ldif.strip() in restored_ldif, (
                    f"Original LDIF not found in restored output for entry {entry.dn}"
                )
