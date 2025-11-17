"""Fixture test helpers to eliminate massive code duplication.

Provides high-level methods for loading and working with LDIF fixture files.
Each method replaces 10-20+ lines of duplicated test code.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flext_ldif import FlextLdif
    from flext_ldif.models import FlextLdifModels

from pathlib import Path

from tests.helpers.test_assertions import TestAssertions


class FixtureTestHelpers:
    """High-level fixture test helpers that replace entire test functions."""

    @staticmethod
    def load_fixture_entries(
        ldif_api: FlextLdif,
        server_type: str,
        fixture_filename: str,
        expected_min_count: int | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Load fixture LDIF file and return parsed entries.

        Replaces entire test function.

        This method replaces 8-15 lines of duplicated test code:
        - Loads fixture file
        - Parses LDIF content
        - Validates entries
        - Returns parsed entries

        Args:
            ldif_api: FlextLdif API instance
            server_type: Server type identifier (e.g., 'rfc', 'oud', 'oid')
            fixture_filename: Name of fixture file (e.g., 'rfc_schema_fixtures.ldif')
            expected_min_count: Optional minimum expected entry count

        Returns:
            List of parsed entries

        Example:
            # Replaces entire test function:
            entries = FixtureTestHelpers.load_fixture_entries(
                ldif_api,
                "rfc",
                "rfc_schema_fixtures.ldif",
                expected_min_count=1
            )
            assert len(entries) > 0

        """
        from tests.unit.quirks.servers.test_utils import FlextLdifTestUtils

        entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            server_type,
            fixture_filename,
        )

        assert entries is not None, f"Failed to load fixture {fixture_filename}"
        assert len(entries) > 0, f"Fixture {fixture_filename} has no entries"

        if expected_min_count is not None:
            assert len(entries) >= expected_min_count, (
                f"Expected at least {expected_min_count} entries, got {len(entries)}"
            )

        TestAssertions.assert_entries_valid(entries)
        return entries

    @staticmethod
    def load_fixture_and_validate_structure(
        ldif_api: FlextLdif,
        server_type: str,
        fixture_filename: str,
        *,
        expected_has_dn: bool = True,
        expected_has_attributes: bool = True,
        expected_has_objectclass: bool | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Load fixture and validate entry structure - replaces entire test function.

        This method replaces 15-25 lines of duplicated test code:
        - Loads fixture
        - Validates DN presence
        - Validates attributes presence
        - Optionally validates objectClass presence

        Args:
            ldif_api: FlextLdif API instance
            server_type: Server type identifier
            fixture_filename: Name of the fixture file
            expected_has_dn: Whether entries should have DNs (default: True)
            expected_has_attributes: Whether entries should have attributes
                (default: True)
            expected_has_objectclass: Optional whether entries should have objectClass

        Returns:
            List of parsed entries

        Example:
            # Replaces entire test function:
            entries = FixtureTestHelpers.load_fixture_and_validate_structure(
                ldif_api,
                "rfc",
                "rfc_entries_fixtures.ldif",
                expected_has_objectclass=True
            )

        """
        entries = FixtureTestHelpers.load_fixture_entries(
            ldif_api,
            server_type,
            fixture_filename,
        )

        for entry in entries:
            if expected_has_dn:
                assert entry.dn is not None, "Entry must have DN"
                assert entry.dn.value, "Entry DN must not be empty"

            if expected_has_attributes:
                assert entry.attributes is not None, "Entry must have attributes"
                assert len(entry.attributes) > 0, (
                    "Entry must have at least one attribute"
                )

            if expected_has_objectclass is not None:
                assert entry.attributes is not None, "Entry must have attributes"
                attr_names = {name.lower() for name in entry.attributes}
                has_objectclass = "objectclass" in attr_names
                assert has_objectclass == expected_has_objectclass, (
                    f"Expected has_objectclass={expected_has_objectclass}, "
                    f"got {has_objectclass}"
                )

        return entries

    @staticmethod
    def run_fixture_roundtrip(
        ldif_api: FlextLdif,
        server_type: str,
        fixture_filename: str,
        tmp_path: Path,
        *,
        validate_identical: bool = True,
    ) -> tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry], bool]:
        """Run roundtrip test on fixture - replaces entire test function.

        This method replaces 20-35 lines of duplicated test code:
        - Loads original fixture
        - Writes entries back
        - Parses written LDIF
        - Compares original vs roundtrip
        - Returns comparison results

        Args:
            ldif_api: FlextLdif API instance
            server_type: Server type identifier
            fixture_filename: Name of the fixture file
            tmp_path: Temporary directory for intermediate files
            validate_identical: Whether to assert entries are identical (default: True)

        Returns:
            Tuple of (original_entries, roundtrip_entries, is_identical)

        Example:
            # Replaces entire test function:
            orig, roundtrip, identical = FixtureTestHelpers.run_fixture_roundtrip(
                ldif_api,
                "rfc",
                "rfc_entries_fixtures.ldif",
                tmp_path
            )
            assert identical, "Roundtrip should preserve entries"

        """
        from tests.unit.quirks.servers.test_utils import FlextLdifTestUtils

        original_entries, roundtrip_entries, is_identical = (
            FlextLdifTestUtils.run_roundtrip_test(
                ldif_api,
                server_type,
                fixture_filename,
                tmp_path,
            )
        )

        if validate_identical:
            assert is_identical, "Roundtrip should produce identical entries"

        return original_entries, roundtrip_entries, is_identical


__all__ = ["FixtureTestHelpers"]
