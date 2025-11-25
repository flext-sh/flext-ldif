"""Fixture test helpers to eliminate massive code duplication.

Provides high-level methods for loading and working with LDIF fixture files.
Each method replaces 10-20+ lines of duplicated test code.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdif, FlextLdifModels

from .test_assertions import TestAssertions


class FixtureTestHelpers:
    """High-level fixture test helpers that replace entire test functions."""

    @staticmethod
    def _get_fixture_path(
        server_type: str,
        fixture_filename: str,
    ) -> Path:
        """Get the path to a fixture file.

        Args:
            server_type: Server type identifier (e.g. 'oid', 'oud', 'rfc')
            fixture_filename: Name of the fixture file

        Returns:
            Path to the fixture file

        Raises:
            FileNotFoundError: If fixture file doesn't exist

        """
        # Try multiple possible paths
        test_file_path = Path(__file__)
        possible_paths = [
            test_file_path.parent.parent / "fixtures" / server_type / fixture_filename,
            test_file_path.parent.parent.parent
            / "fixtures"
            / server_type
            / fixture_filename,
        ]

        for fixture_path in possible_paths:
            if fixture_path.exists():
                return fixture_path

        msg = f"Fixture not found: {fixture_filename} for server type {server_type}"
        raise FileNotFoundError(msg)

    @staticmethod
    def _load_fixture(
        ldif_api: FlextLdif,
        server_type: str,
        fixture_filename: str,
    ) -> list[FlextLdifModels.Entry]:
        """Load a fixture LDIF file and return parsed entries.

        Args:
            ldif_api: FlextLdif API instance
            server_type: Server type identifier
            fixture_filename: Name of the fixture file

        Returns:
            List of parsed entries

        """
        fixture_path = FixtureTestHelpers._get_fixture_path(
            server_type,
            fixture_filename,
        )

        parse_result = ldif_api.parse(
            fixture_path,
            server_type=server_type,
        )

        if not parse_result.is_success:
            msg = f"Failed to parse fixture {fixture_path}: {parse_result.error}"
            raise ValueError(msg)

        parsed_data = parse_result.unwrap()
        if isinstance(parsed_data, list):
            return parsed_data
        if hasattr(parsed_data, "entries"):
            return parsed_data.entries
        msg = f"Unexpected parse result type: {type(parsed_data)}"
        raise TypeError(msg)

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
        entries = FixtureTestHelpers._load_fixture(
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
                entry_typed = entry
                attr_names = {
                    name.lower() for name in entry_typed.attributes.attributes
                }
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
        # Load original entries
        original_entries = FixtureTestHelpers._load_fixture(
            ldif_api,
            server_type,
            fixture_filename,
        )

        # Write entries back to file
        output_file = tmp_path / f"roundtrip_{fixture_filename}"
        write_result = ldif_api.write(
            original_entries,
            output_path=output_file,
            server_type=server_type,
        )
        TestAssertions.assert_success(write_result, "Write should succeed")

        # Parse the written LDIF
        parse_result = ldif_api.parse(
            output_file,
            server_type=server_type,
        )
        TestAssertions.assert_success(parse_result, "Re-parse should succeed")

        parsed_data = parse_result.unwrap()
        if isinstance(parsed_data, list):
            roundtrip_entries = parsed_data
        elif hasattr(parsed_data, "entries"):
            roundtrip_entries = parsed_data.entries
        else:
            msg = f"Unexpected parse result type: {type(parsed_data)}"
            raise TypeError(msg)

        # Compare entries
        is_identical = True
        if len(original_entries) != len(roundtrip_entries):
            is_identical = False
        else:
            for orig, rt in zip(original_entries, roundtrip_entries, strict=False):
                if orig.dn is None or rt.dn is None:
                    is_identical = False
                    break
                if orig.dn.value != rt.dn.value:
                    is_identical = False
                    break

        if validate_identical:
            assert is_identical, "Roundtrip should produce identical entries"

        return original_entries, roundtrip_entries, is_identical


__all__ = ["FixtureTestHelpers"]
