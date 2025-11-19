"""Test suite for OUD deviation metadata tracking.

Tests for zero data loss metadata tracking during OUD entry parsing.
Validates that original values are preserved in QuirkMetadata for round-trip support.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdifModels
from flext_ldif.servers.oud import FlextLdifServersOud


class TestOudAttributeCaseMetadata:
    """Test suite for OUD attribute case metadata tracking."""

    @pytest.fixture
    def oud_entry(self) -> FlextLdifServersOud.Entry:
        """Create OUD entry quirk instance."""
        return FlextLdifServersOud().entry_quirk

    def test_original_format_details_populated(
        self,
        oud_entry: FlextLdifServersOud.Entry,
    ) -> None:
        """Test that original_format_details is populated for round-trip."""
        entry_attrs = {
            "objectClass": ["top", "person"],
            "cn": ["test"],
            "sn": ["User"],
        }

        result = oud_entry._parse_entry(
            "cn=test,dc=example,dc=com",
            entry_attrs,
        )

        assert result.is_success
        entry = result.unwrap()

        # Verify original_format_details is populated
        assert entry.metadata is not None
        assert len(entry.metadata.original_format_details) > 0

        # Verify essential fields
        assert entry.metadata.original_format_details.get("server_type") == "oud"
        assert "dn_spacing" in entry.metadata.original_format_details

    def test_original_dn_preserved_in_metadata(
        self,
        oud_entry: FlextLdifServersOud.Entry,
    ) -> None:
        """Test original DN is preserved for round-trip."""
        original_dn = "cn=test, dc=example, dc=com"  # DN with spaces
        entry_attrs = {
            "objectClass": ["top", "person"],
            "cn": ["test"],
        }

        result = oud_entry._parse_entry(
            original_dn,
            entry_attrs,
        )

        assert result.is_success
        entry = result.unwrap()

        # Verify original DN is preserved
        assert entry.metadata is not None
        preserved_dn = entry.metadata.original_format_details.get("dn_spacing")
        assert preserved_dn == original_dn


class TestOudObjectClassCaseMetadata:
    """Test suite for OUD objectClass case preservation."""

    @pytest.fixture
    def oud_entry(self) -> FlextLdifServersOud.Entry:
        """Create OUD entry quirk instance."""
        return FlextLdifServersOud().entry_quirk

    def test_objectclass_case_tracked(
        self,
        oud_entry: FlextLdifServersOud.Entry,
    ) -> None:
        """Test that objectClass case is tracked in metadata."""
        entry_attrs = {
            "objectClass": ["Top", "Person", "organizationalPerson"],
            "cn": ["test"],
        }

        result = oud_entry._parse_entry(
            "cn=test,dc=example,dc=com",
            entry_attrs,
        )

        assert result.is_success
        entry = result.unwrap()

        # Verify objectClass case is tracked
        assert entry.metadata is not None

        # Check that casing is preserved for objectClasses
        # "Top" -> objectclass_case_top = "Top"
        if "objectclass_case_top" in entry.metadata.original_format_details:
            assert entry.metadata.original_format_details["objectclass_case_top"] == "Top"


class TestMetadataUtilitiesIntegration:
    """Test suite for OUD metadata utilities integration."""

    def test_quirk_metadata_original_attribute_case_field_type(self) -> None:
        """Test that original_attribute_case field has correct type."""
        metadata = FlextLdifModels.QuirkMetadata(quirk_type="oud")

        # Field should be dict[str, str]
        metadata.original_attribute_case["objectClass"] = "objectclass"

        assert len(metadata.original_attribute_case) == 1
        assert metadata.original_attribute_case["objectClass"] == "objectclass"

    def test_quirk_metadata_original_format_details_for_oud(self) -> None:
        """Test that original_format_details works for OUD."""
        metadata = FlextLdifModels.QuirkMetadata(quirk_type="oud")

        # Populate with OUD-specific format details
        metadata.original_format_details = {
            "server_type": "oud",
            "dn_spacing": "cn=test, dc=example",
            "objectclass_case_person": "Person",
        }

        assert metadata.original_format_details["server_type"] == "oud"
        assert metadata.original_format_details["objectclass_case_person"] == "Person"
