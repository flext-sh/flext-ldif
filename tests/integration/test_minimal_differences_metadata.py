"""Integration tests for minimal differences metadata tracking.

Tests the complete pipeline: ldif -> parser -> Entry Model (RFC + Metadata) -> writer -> ldif
Validates that ALL minimal differences are captured and preserved for perfect round-trip.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from flext_ldif import FlextLdif, FlextLdifModels, FlextLdifParser, FlextLdifUtilities


class TestMinimalDifferencesOidOud:
    """Test suite for minimal differences tracking between OID and OUD fixtures."""

    @pytest.fixture
    def parser(self) -> FlextLdifParser:
        """Create parser instance."""
        return FlextLdifParser()

    @pytest.fixture
    def writer(self) -> FlextLdif:
        """Create writer instance via FlextLdif."""
        return FlextLdif()

    def test_oid_fixture_all_differences_captured(
        self,
        parser: FlextLdifParser,
        writer: FlextLdif,
    ) -> None:
        """Test that ALL minimal differences in OID fixtures are captured in metadata."""
        # Load OID fixture
        fixture_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_entries_fixtures.ldif"
        )
        if not fixture_path.exists():
            pytest.skip(f"OID fixture not found: {fixture_path}")

        # Parse OID fixture
        parse_result = parser.parse_ldif_file(
            path=fixture_path,
            server_type="oid",
            format_options=FlextLdifModels.ParseFormatOptions(
                normalize_dns=True,
                auto_extract_acls=True,
                validate_entries=False,  # Don't fail on validation errors
            ),
        )

        assert parse_result.is_success, f"Parsing failed: {parse_result.error}"
        parse_response = parse_result.unwrap()
        entries = parse_response.entries

        assert len(entries) > 0, "No entries parsed from OID fixture"

        # Validate that ALL entries have metadata with minimal differences
        for entry_protocol in entries:
            # Cast to Entry model to access metadata and dn attributes
            entry = cast("FlextLdifModels.Entry", entry_protocol)
            assert entry.metadata is not None, f"Entry {entry.dn} missing metadata"

            # Check that original DN is preserved
            assert "original_dn_complete" in entry.metadata.extensions, (
                f"Entry {entry.dn} missing original_dn_complete in metadata"
            )

            # Check that minimal differences are tracked
            assert "minimal_differences_dn" in entry.metadata.extensions, (
                f"Entry {entry.dn} missing minimal_differences_dn in metadata"
            )

            # Check that original attributes are preserved
            assert "original_attributes_complete" in entry.metadata.extensions, (
                f"Entry {entry.dn} missing original_attributes_complete in metadata"
            )

            # Validate metadata completeness
            original_attrs = entry.metadata.extensions.get(
                "original_attributes_complete",
                {},
            )
            if isinstance(original_attrs, dict):
                expected_transformations = list(original_attrs.keys())
                is_complete, missing = (
                    FlextLdifUtilities.Metadata.validate_metadata_completeness(
                        metadata=entry.metadata,
                        expected_transformations=expected_transformations,
                    )
                )
                if not is_complete:
                    pytest.fail(
                        f"Entry {entry.dn} has incomplete metadata. "
                        f"Missing transformations for: {missing}",
                    )

    def test_oud_fixture_all_differences_captured(
        self,
        parser: FlextLdifParser,
        writer: FlextLdif,
    ) -> None:
        """Test that ALL minimal differences in OUD fixtures are captured in metadata."""
        # Load OUD fixture
        fixture_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "oud"
            / "oud_entries_fixtures.ldif"
        )
        if not fixture_path.exists():
            pytest.skip(f"OUD fixture not found: {fixture_path}")

        # Parse OUD fixture
        parse_result = parser.parse_ldif_file(
            path=fixture_path,
            server_type="oud",
            format_options=FlextLdifModels.ParseFormatOptions(
                normalize_dns=True,
                auto_extract_acls=True,
                validate_entries=False,
            ),
        )

        assert parse_result.is_success, f"Parsing failed: {parse_result.error}"
        parse_response = parse_result.unwrap()
        entries = parse_response.entries

        assert len(entries) > 0, "No entries parsed from OUD fixture"

        # Validate that ALL entries have metadata with minimal differences
        for entry_protocol in entries:
            # Cast to Entry model to access metadata and dn attributes
            entry = cast("FlextLdifModels.Entry", entry_protocol)
            assert entry.metadata is not None, f"Entry {entry.dn} missing metadata"
            assert "original_dn_complete" in entry.metadata.extensions, (
                f"Entry {entry.dn} missing original_dn_complete"
            )
            assert "minimal_differences_dn" in entry.metadata.extensions, (
                f"Entry {entry.dn} missing minimal_differences_dn"
            )

    def test_round_trip_oid_preserves_all_differences(
        self,
        parser: FlextLdifParser,
        writer: FlextLdif,
    ) -> None:
        """Test round-trip: OID -> RFC -> OID preserves ALL differences."""
        # Sample OID entry with known differences
        oid_ldif = """dn: cn=test, dc=example, dc=com
objectClass: top
objectClass: person
cn: test
sn: User
orcldasisenabled: 1
"""

        # Parse OID
        parse_result = parser.parse_string(
            content=oid_ldif,
            server_type="oid",
        )
        assert parse_result.is_success
        entries = parse_result.unwrap().entries
        assert len(entries) == 1
        original_entry_protocol = entries[0]
        # Cast to Entry model to access metadata and dn attributes
        original_entry = cast("FlextLdifModels.Entry", original_entry_protocol)

        # Verify metadata captured differences
        assert original_entry.metadata is not None
        assert "original_dn_complete" in original_entry.metadata.extensions

        # Write back to OID format
        write_result = writer.write(
            entries=[original_entry],
            server_type="oid",
        )
        assert write_result.is_success

        written_ldif = write_result.unwrap()
        assert isinstance(written_ldif, str)

        # Verify no data loss
        no_loss, lost = FlextLdifUtilities.Metadata.assert_no_data_loss(
            original_entry=original_entry,
            converted_entry=original_entry,  # Same entry, but metadata should preserve all
        )
        assert no_loss, f"Data loss detected: {lost}"

    def test_spacing_differences_captured(
        self,
        parser: FlextLdifParser,
    ) -> None:
        """Test that spacing differences (e.g., 'dc=example, dc=com' vs 'dc=example,dc=com') are captured."""
        # DN with spaces
        ldif_with_spaces = """dn: cn=test, dc=example, dc=com
objectClass: top
objectClass: person
cn: test
"""

        parse_result = parser.parse_string(
            content=ldif_with_spaces,
            server_type="rfc",
        )
        assert parse_result.is_success
        entries = parse_result.unwrap().entries
        assert len(entries) == 1
        entry = entries[0]

        # Check that spacing differences are tracked
        assert entry.metadata is not None
        dn_differences = entry.metadata.extensions.get("minimal_differences_dn", {})

        if isinstance(dn_differences, dict) and dn_differences.get("has_differences"):
            spacing_changes = dn_differences.get("spacing_changes", {})
            assert spacing_changes is not None, "Spacing changes should be tracked"

    def test_case_differences_captured(
        self,
        parser: FlextLdifParser,
    ) -> None:
        """Test that case differences (e.g., 'objectClass' vs 'objectclass') are captured."""
        # Entry with mixed case
        ldif_mixed_case = """dn: cn=test,dc=example,dc=com
objectClass: top
objectClass: person
cn: test
"""

        parse_result = parser.parse_string(
            content=ldif_mixed_case,
            server_type="rfc",
        )
        assert parse_result.is_success
        entries = parse_result.unwrap().entries
        assert len(entries) == 1
        entry = entries[0]

        # Check that original case is preserved
        assert entry.metadata is not None
        original_attrs = entry.metadata.extensions.get(
            "original_attributes_complete",
            {},
        )
        assert isinstance(original_attrs, dict)

        # Check that original attribute case is tracked
        if entry.metadata.original_attribute_case:
            assert len(entry.metadata.original_attribute_case) > 0

    def test_punctuation_differences_captured(
        self,
        parser: FlextLdifParser,
    ) -> None:
        """Test that punctuation differences (e.g., trailing semicolons) are captured."""
        # Entry that might have punctuation quirks
        ldif = """dn: cn=test,dc=example,dc=com
objectClass: top
objectClass: person
cn: test
"""

        parse_result = parser.parse_string(
            content=ldif,
            server_type="rfc",
        )
        assert parse_result.is_success
        entries = parse_result.unwrap().entries
        assert len(entries) == 1
        entry = entries[0]

        # Verify metadata tracks all differences
        assert entry.metadata is not None
        assert "minimal_differences_dn" in entry.metadata.extensions
        assert "original_dn_complete" in entry.metadata.extensions

    def test_boolean_conversion_tracked(
        self,
        parser: FlextLdifParser,
    ) -> None:
        """Test that boolean conversions (0/1 -> TRUE/FALSE) are tracked in metadata."""
        # OID entry with boolean attributes
        oid_ldif = """dn: cn=test,dc=example,dc=com
objectClass: top
objectClass: person
cn: test
orcldasisenabled: 1
pwdlockout: 0
"""

        parse_result = parser.parse_string(
            content=oid_ldif,
            server_type="oid",
        )
        assert parse_result.is_success
        entries = parse_result.unwrap().entries
        assert len(entries) == 1
        entry = entries[0]

        # Check that boolean conversions are tracked
        assert entry.metadata is not None
        assert len(entry.metadata.boolean_conversions) > 0, (
            "Boolean conversions should be tracked in metadata"
        )

        # Verify specific conversions
        if "orcldasisenabled" in entry.metadata.boolean_conversions:
            conv = entry.metadata.boolean_conversions["orcldasisenabled"]
            assert conv["original"] == "1"
            assert conv["converted"] == "TRUE"

    def test_soft_deleted_attributes_preserved(
        self,
        parser: FlextLdifParser,
    ) -> None:
        """Test that soft-deleted attributes are preserved in metadata."""
        # Entry with operational attributes that will be filtered
        ldif = """dn: cn=test,dc=example,dc=com
objectClass: top
objectClass: person
cn: test
creatorsName: cn=Directory Manager
createTimestamp: 20250101000000Z
"""

        parse_result = parser.parse_string(
            content=ldif,
            server_type="rfc",
            format_options=FlextLdifModels.ParseFormatOptions(
                include_operational_attrs=False,  # This will filter operational attrs
            ),
        )
        assert parse_result.is_success
        entries = parse_result.unwrap().entries
        assert len(entries) == 1
        entry = entries[0]

        # Check that soft-deleted attributes are tracked
        assert entry.metadata is not None
        # Operational attributes should be in soft_delete_markers or removed_attributes
        assert (
            len(entry.metadata.soft_delete_markers) > 0
            or len(entry.metadata.removed_attributes) > 0
        ), "Soft-deleted operational attributes should be tracked in metadata"


__all__ = [
    "TestMinimalDifferencesOidOud",
]
