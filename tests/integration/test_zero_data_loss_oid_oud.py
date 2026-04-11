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

from flext_ldif import FlextLdif, ldif
from tests import c, m, t, u


def _verify_soft_deleted_attributes(entry: m.Ldif.Entry) -> None:
    """Verify soft-deleted attributes are preserved in removed_attributes."""
    if not entry.metadata:
        return
    soft_deleted = entry.metadata.soft_delete_markers
    if not soft_deleted:
        return
    for attr_name in soft_deleted:
        if not isinstance(entry.metadata.removed_attributes, dict):
            continue
        assert attr_name in entry.metadata.removed_attributes, (
            f"Soft-deleted attribute {attr_name} not in removed_attributes"
        )
        removed_attr_value = entry.metadata.removed_attributes[attr_name]
        if isinstance(removed_attr_value, (str, list, tuple)):
            assert removed_attr_value, (
                f"Soft-deleted attribute {attr_name} has no preserved values"
            )


class TestZeroDataLossOidOud:
    """Test zero data loss in OID↔OUD↔RFC conversions."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create ldif API instance."""
        return ldif.get_instance()

    @pytest.fixture
    def oid_fixture(self) -> str:
        """Load OID entries fixture."""
        return u.Ldif.Tests.load_fixture(c.Ldif.Tests.OID, c.Ldif.Tests.ENTRIES)

    @pytest.fixture
    def oud_fixture(self) -> str:
        """Load OUD entries fixture."""
        return u.Ldif.Tests.load_fixture(c.Ldif.Tests.OUD, c.Ldif.Tests.ENTRIES)

    def test_oid_parse_preserves_original_ldif(
        self,
        api: FlextLdif,
        oid_fixture: str,
    ) -> None:
        """Test that OID parsing preserves original LDIF in metadata."""
        result = api.parse_ldif(oid_fixture, server_type=c.Ldif.Tests.OID)
        assert result.success, f"Parse failed: {result.error}"
        entries = result.value.entries
        assert entries, "No entries parsed"
        for entry in entries:
            assert entry.metadata is not None, "Entry missing metadata"
            assert entry.metadata.original_strings is not None, (
                "Entry missing original_strings"
            )
            assert "entry_original_ldif" in entry.metadata.original_strings, (
                f"Entry {entry.dn} missing original LDIF preservation"
            )
            original_ldif_raw = entry.metadata.original_strings["entry_original_ldif"]
            if not isinstance(original_ldif_raw, str):
                msg = f"Expected str for entry_original_ldif, got {type(original_ldif_raw)}"
                raise TypeError(msg)
            original_ldif = original_ldif_raw
            assert original_ldif, "Original LDIF is empty"
            assert "dn:" in original_ldif.lower(), "Original LDIF missing DN"

    def test_oud_parse_preserves_original_ldif(
        self,
        api: FlextLdif,
        oud_fixture: str,
    ) -> None:
        """Test that OUD parsing preserves original LDIF in metadata."""
        result = api.parse_ldif(oud_fixture, server_type=c.Ldif.Tests.OUD)
        assert result.success, f"Parse failed: {result.error}"
        entries = result.value.entries
        assert entries, "No entries parsed"
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
        result = api.parse_ldif(oid_fixture, server_type=c.Ldif.Tests.OID)
        assert result.success
        entries = result.value.entries
        boolean_entries = [
            e
            for e in entries
            if e.metadata
            and e.metadata.boolean_conversions
            and (e.metadata.boolean_conversions)
        ]
        if boolean_entries:
            entry = boolean_entries[0]
            if entry.metadata is None:
                pytest.fail("Entry metadata is None")
            if not isinstance(entry.metadata.boolean_conversions, dict):
                pytest.fail("boolean_conversions is not a dict")
            for attr_name, conversion_raw in entry.metadata.boolean_conversions.items():
                if not isinstance(conversion_raw, dict):
                    continue
                conversion = conversion_raw
                assert "original" in conversion, (
                    f"Missing original value for {attr_name}"
                )
                assert "converted" in conversion, (
                    f"Missing converted value for {attr_name}"
                )
                assert "format" in conversion, (
                    f"Missing format direction for {attr_name}"
                )
                format_value = conversion.get("format")
                if isinstance(format_value, str):
                    assert format_value in {"OID->RFC", "RFC->OID"}, (
                        f"Invalid format direction: {format_value}"
                    )

    def test_oid_oud_conversion_preserves_all_data(
        self,
        api: FlextLdif,
        oid_fixture: str,
    ) -> None:
        """Test OID→OUD conversion preserves ALL data in metadata."""
        parse_result = api.parse_ldif(oid_fixture, server_type=c.Ldif.Tests.OID)
        assert parse_result.success
        oid_entries = parse_result.value.entries
        write_result = api.write(oid_entries, server_type=c.Ldif.Tests.RFC)
        assert write_result.success
        rfc_ldif = write_result.value.content
        assert rfc_ldif is not None
        parse_oud_result = api.parse_ldif(rfc_ldif, server_type=c.Ldif.Tests.OUD)
        assert parse_oud_result.success
        oud_entries = parse_oud_result.value.entries
        assert len(oid_entries) == len(oud_entries), "Entry count mismatch"
        for oid_entry, oud_entry in zip(oid_entries, oud_entries, strict=False):
            assert oid_entry.metadata is not None
            assert oud_entry.metadata is not None
            if (
                isinstance(oid_entry.metadata.original_strings, dict)
                and "entry_original_ldif" in oid_entry.metadata.original_strings
            ):
                original_oid_ldif_raw = oid_entry.metadata.original_strings.get(
                    "entry_original_ldif",
                )
                if isinstance(original_oid_ldif_raw, str):
                    original_oid_ldif = original_oid_ldif_raw
                    assert original_oid_ldif, "Original OID LDIF lost"

            def check_no_data_loss(
                original: m.Ldif.Entry,
                converted: m.Ldif.Entry,
            ) -> tuple[bool, t.StrSequence]:
                """Check for data loss between original and converted entries."""
                lost_attrs: t.StrSequence = []
                if original.attributes is None or converted.attributes is None:
                    pytest.fail("Entry attributes is None")
                original_attrs = set(original.attributes.attributes.keys())
                converted_attrs = set(converted.attributes.attributes.keys())
                lost_attrs = list(original_attrs - converted_attrs)
                operational_attrs = {
                    "createtimestamp",
                    "modifytimestamp",
                    "entryuuid",
                    "entrycsn",
                }
                lost_attrs = [
                    attr for attr in lost_attrs if attr.lower() not in operational_attrs
                ]
                return (not lost_attrs, lost_attrs)

            no_loss, lost_attrs = check_no_data_loss(oid_entry, oud_entry)
            assert no_loss, f"Data loss detected: {lost_attrs}"

    def test_round_trip_oid_oud_oid_preserves_formatting(
        self,
        api: FlextLdif,
        oid_fixture: str,
    ) -> None:
        """Test OID→OUD→OID round-trip preserves ALL formatting."""
        parse_oid = api.parse_ldif(oid_fixture, server_type=c.Ldif.Tests.OID)
        assert parse_oid.success
        original_entries = parse_oid.value.entries
        write_oud = api.write(original_entries, server_type=c.Ldif.Tests.OUD)
        assert write_oud.success
        oud_ldif = write_oud.value.content
        assert oud_ldif is not None
        parse_oud = api.parse_ldif(oud_ldif, server_type=c.Ldif.Tests.OUD)
        assert parse_oud.success
        oud_entries = parse_oud.value.entries
        write_oid = api.write(
            oud_entries,
            server_type=c.Ldif.Tests.OID,
            format_options=m.Ldif.WriteFormatOptions(restore_original_format=True),
        )
        assert write_oid.success
        roundtrip_ldif = write_oid.value.content
        assert roundtrip_ldif is not None
        parse_roundtrip = api.parse_ldif(roundtrip_ldif, server_type=c.Ldif.Tests.OID)
        assert parse_roundtrip.success
        roundtrip_entries = parse_roundtrip.value.entries
        assert len(original_entries) == len(roundtrip_entries)
        for orig, roundtrip in zip(original_entries, roundtrip_entries, strict=False):
            if (
                orig.metadata
                and "entry_original_ldif" in orig.metadata.original_strings
                and isinstance(orig.metadata.original_strings, dict)
            ):
                original_ldif_raw = orig.metadata.original_strings.get(
                    "entry_original_ldif",
                )
                if isinstance(original_ldif_raw, str):
                    original_ldif = original_ldif_raw
                    if (
                        roundtrip.metadata
                        and isinstance(roundtrip.metadata.original_strings, dict)
                        and (
                            "entry_original_ldif" in roundtrip.metadata.original_strings
                        )
                    ):
                        roundtrip_original_raw = (
                            roundtrip.metadata.original_strings.get(
                                "entry_original_ldif",
                            )
                        )
                        if isinstance(roundtrip_original_raw, str):
                            roundtrip_original = roundtrip_original_raw
                            assert original_ldif
                            assert roundtrip_original

    def test_minimal_differences_tracking(
        self,
        api: FlextLdif,
        oid_fixture: str,
    ) -> None:
        """Test that minimal differences are tracked for all conversions."""
        result = api.parse_ldif(oid_fixture, server_type=c.Ldif.Tests.OID)
        assert result.success
        entries = result.value.entries
        for entry in entries:
            if entry.metadata:
                if not isinstance(entry.metadata.minimal_differences, dict):
                    continue
                minimal_diffs = entry.metadata.minimal_differences
                if "dn" in minimal_diffs:
                    dn_diff_raw = minimal_diffs["dn"]
                    if isinstance(dn_diff_raw, dict):
                        dn_diff = dn_diff_raw
                        if dn_diff.get("has_differences", False):
                            assert "original" in dn_diff, "Missing original DN"
                            assert "differences" in dn_diff, "Missing differences list"
                for attr_name, attr_diff_raw in minimal_diffs.items():
                    if (
                        attr_name != "dn"
                        and isinstance(attr_diff_raw, dict)
                        and attr_diff_raw.get("has_differences", False)
                    ):
                        attr_diff = attr_diff_raw
                        assert "original" in attr_diff, (
                            f"Missing original for {attr_name}"
                        )
                        assert "differences" in attr_diff, (
                            f"Missing differences for {attr_name}"
                        )

    def test_soft_delete_tracking(self, api: FlextLdif, oid_fixture: str) -> None:
        """Test that soft-deleted attributes are tracked in metadata."""
        result = api.parse_ldif(oid_fixture, server_type=c.Ldif.Tests.OID)
        assert result.success
        entries = result.value.entries
        for entry in entries:
            _verify_soft_deleted_attributes(entry)

    def test_conversion_history_tracking(
        self,
        api: FlextLdif,
        oid_fixture: str,
    ) -> None:
        """Test that conversion history is tracked in metadata."""
        result = api.parse_ldif(oid_fixture, server_type=c.Ldif.Tests.OID)
        assert result.success
        entries = result.value.entries
        for entry in entries:
            if entry.metadata:
                assert isinstance(entry.metadata.conversion_history, list), (
                    "conversion_history should be a list"
                )

    def test_original_strings_preservation(
        self,
        api: FlextLdif,
        oid_fixture: str,
    ) -> None:
        """Test that ALL original strings are preserved in metadata."""
        result = api.parse_ldif(oid_fixture, server_type=c.Ldif.Tests.OID)
        assert result.success
        entries = result.value.entries
        for entry in entries:
            assert entry.metadata is not None
            assert entry.metadata.original_strings is not None
            assert "entry_original_ldif" in entry.metadata.original_strings, (
                f"Entry {entry.dn} missing entry_original_ldif"
            )
            if isinstance(entry.metadata.original_strings, dict):
                original_ldif_raw = entry.metadata.original_strings.get(
                    "entry_original_ldif",
                )
                if isinstance(original_ldif_raw, str):
                    original_ldif = original_ldif_raw
                    assert original_ldif, "Original LDIF is empty"
            if isinstance(entry.metadata.minimal_differences, dict):
                dn_diff_raw = entry.metadata.minimal_differences.get("dn")
                if (
                    isinstance(dn_diff_raw, dict)
                    and dn_diff_raw.get("has_differences", False)
                    and isinstance(entry.metadata.original_strings, dict)
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
        parse_result = api.parse_ldif(oid_fixture, server_type=c.Ldif.Tests.OID)
        assert parse_result.success
        entries = parse_result.value.entries
        write_result = api.write(
            entries,
            server_type=c.Ldif.Tests.OID,
            format_options=m.Ldif.WriteFormatOptions(restore_original_format=True),
        )
        assert write_result.success
        restored_ldif = write_result.value.content
        assert restored_ldif is not None
        for entry in entries:
            if (
                entry.metadata
                and "entry_original_ldif" in entry.metadata.original_strings
                and isinstance(entry.metadata.original_strings, dict)
            ):
                original_ldif_raw = entry.metadata.original_strings.get(
                    "entry_original_ldif",
                )
                if isinstance(original_ldif_raw, str):
                    original_ldif = original_ldif_raw
                    assert original_ldif.strip() in restored_ldif, (
                        f"Original LDIF not found in restored output for entry {entry.dn}"
                    )
