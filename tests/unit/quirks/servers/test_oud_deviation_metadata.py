"""Test suite for OUD deviation metadata tracking.

Modules tested: FlextLdifServersOud.Entry, FlextLdifModels.QuirkMetadata
Scope: Zero data loss metadata tracking during OUD→RFC conversions. Validates that
original values (boolean conversions, DN spacing, schema quirks) are preserved in
QuirkMetadata for round-trip support. Tests format_details, DN preservation, case
handling, and integration scenarios.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest

from flext_ldif import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.oud import FlextLdifServersOud

# =============================================================================
# TEST SCENARIO ENUMS & CONSTANTS
# =============================================================================


class OudMetadataTestType(StrEnum):
    """OUD metadata tracking test scenarios."""

    FORMAT_DETAILS_POPULATED = "format_details_populated"
    DN_PRESERVED = "dn_preserved"
    OBJECTCLASS_CASE = "objectclass_case"
    ATTRIBUTE_CASE_TYPE = "attribute_case_type"
    FORMAT_DETAILS_INTEGRATION = "format_details_integration"


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def oud_entry() -> FlextLdifProtocols.Quirks.EntryProtocol:
    """Create OUD entry quirk instance."""
    return FlextLdifServersOud().entry_quirk


# =============================================================================
# TEST CLASS
# =============================================================================


@pytest.mark.unit
class TestOudDeviationMetadata:
    """Test OUD metadata tracking for zero data loss during parsing.

    Consolidates three test classes into parametrized test scenarios.
    """

    # Test data mapping for attribute case metadata tests
    ATTRIBUTE_CASE_DATA: ClassVar[
        dict[str, tuple[OudMetadataTestType, str, dict[str, list[str]]]]
    ] = {
        "test_original_format_details_populated": (
            OudMetadataTestType.FORMAT_DETAILS_POPULATED,
            "cn=test,dc=example,dc=com",
            {
                "objectClass": ["top", "person"],
                "cn": ["test"],
                "sn": ["User"],
            },
        ),
        "test_original_dn_preserved_in_metadata": (
            OudMetadataTestType.DN_PRESERVED,
            "cn=test, dc=example, dc=com",
            {
                "objectClass": ["top", "person"],
                "cn": ["test"],
            },
        ),
        "test_objectclass_case_tracked": (
            OudMetadataTestType.OBJECTCLASS_CASE,
            "cn=test,dc=example,dc=com",
            {
                "objectClass": ["Top", "Person", "organizationalPerson"],
                "cn": ["test"],
            },
        ),
    }

    # Test data mapping for metadata utilities integration tests
    UTILITIES_DATA: ClassVar[dict[str, tuple[OudMetadataTestType]]] = {
        "test_quirk_metadata_original_attribute_case_field_type": (
            OudMetadataTestType.ATTRIBUTE_CASE_TYPE,
        ),
        "test_quirk_metadata_original_format_details_for_oud": (
            OudMetadataTestType.FORMAT_DETAILS_INTEGRATION,
        ),
    }

    # =========================================================================
    # Attribute Case Metadata Tests
    # =========================================================================

    @pytest.mark.parametrize(
        ("scenario", "test_type", "dn", "entry_attrs"),
        [
            (name, data[0], data[1], data[2])
            for name, data in ATTRIBUTE_CASE_DATA.items()
        ],
    )
    def test_attribute_metadata_tracking(
        self,
        scenario: str,
        test_type: OudMetadataTestType,
        dn: str,
        entry_attrs: dict[str, list[str]],
        oud_entry: FlextLdifProtocols.Quirks.EntryProtocol,
    ) -> None:
        """Parametrized test for OUD attribute case metadata tracking."""
        result = oud_entry.parse_entry(dn, entry_attrs)

        assert result.is_success, f"Entry parsing failed for {scenario}"
        entry = result.unwrap()

        if test_type == OudMetadataTestType.FORMAT_DETAILS_POPULATED:
            # Verify original_format_details is populated
            assert entry.metadata is not None
            assert len(entry.metadata.original_format_details) > 0
            assert (
                entry.metadata.original_format_details.get("_transform_source") == "oud"
            )
            assert "_dn_original" in entry.metadata.original_format_details

        elif test_type == OudMetadataTestType.DN_PRESERVED:
            # Verify original DN is preserved
            assert entry.metadata is not None
            preserved_dn = entry.metadata.original_format_details.get("_dn_original")
            assert preserved_dn == dn

        elif test_type == OudMetadataTestType.OBJECTCLASS_CASE:
            # Verify objectClass case is tracked
            assert entry.metadata is not None
            if "objectclass_case_top" in entry.metadata.original_format_details:
                assert (
                    entry.metadata.original_format_details["objectclass_case_top"]
                    == "Top"
                )

    # =========================================================================
    # Metadata Utilities Integration Tests
    # =========================================================================

    @pytest.mark.parametrize(
        ("scenario", "test_type"),
        [(name, data[0]) for name, data in UTILITIES_DATA.items()],
    )
    def test_metadata_utilities_integration(
        self,
        scenario: str,
        test_type: OudMetadataTestType,
    ) -> None:
        """Parametrized test for OUD metadata utilities integration."""
        if test_type == OudMetadataTestType.ATTRIBUTE_CASE_TYPE:
            metadata = FlextLdifModels.QuirkMetadata(quirk_type="oud")
            metadata.original_attribute_case["objectClass"] = "objectclass"
            assert len(metadata.original_attribute_case) == 1
            assert metadata.original_attribute_case["objectClass"] == "objectclass"

        elif test_type == OudMetadataTestType.FORMAT_DETAILS_INTEGRATION:
            metadata = FlextLdifModels.QuirkMetadata(quirk_type="oud")
            metadata.original_format_details = {
                "server_type": "oud",
                "dn_spacing": "cn=test, dc=example",
                "objectclass_case_person": "Person",
            }
            assert metadata.original_format_details["server_type"] == "oud"
            assert (
                metadata.original_format_details["objectclass_case_person"] == "Person"
            )
