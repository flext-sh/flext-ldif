"""Test utilities for server quirks testing.

This module provides utility functions and fixtures for testing server-specific
quirks implementations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif.api import FlextLdif
from flext_ldif.models import FlextLdifModels


class FlextLdifTestUtils:
    """Utilities for FlextLdif testing."""

    @staticmethod
    def get_fixture_path(
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
            test_file_path.parent.parent.parent.parent
            / "fixtures"
            / server_type
            / fixture_filename,
            test_file_path.parent.parent.parent
            / "fixtures"
            / server_type
            / fixture_filename,
            test_file_path.parent / "fixtures" / server_type / fixture_filename,
        ]

        for fixture_path in possible_paths:
            if fixture_path.exists():
                return fixture_path

        msg = f"Fixture not found: {fixture_filename} for server type {server_type}"
        raise FileNotFoundError(msg)

    @staticmethod
    def load_fixture(
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
        # Get fixture path using helper method
        fixture_path = FlextLdifTestUtils.get_fixture_path(
            server_type, fixture_filename
        )

        # Parse the fixture
        parse_result = ldif_api.parse(
            fixture_path,
            server_type=server_type,
        )

        if not parse_result.is_success:
            msg = f"Failed to parse fixture {fixture_path}: {parse_result.error}"
            raise ValueError(msg)

        # Return entries from the result
        parsed_data = parse_result.unwrap()
        if isinstance(parsed_data, list):
            return parsed_data
        if hasattr(parsed_data, "entries"):
            return parsed_data.entries
        msg = f"Unexpected parse result type: {type(parsed_data)}"
        raise TypeError(msg)

    @staticmethod
    def run_roundtrip_test(
        ldif_api: FlextLdif,
        server_type: str,
        fixture_filename: str,
        tmp_path: Path | None = None,
    ) -> tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry], bool]:
        """Run a roundtrip test on a fixture.

        Parse -> Write -> Parse and compare original vs roundtrip entries.

        Args:
            ldif_api: FlextLdif API instance
            server_type: Server type identifier
            fixture_filename: Name of the fixture file
            tmp_path: Optional temporary path for writing intermediate files (not used in current implementation)

        Returns:
            Tuple of (original_entries, roundtrip_entries, is_identical)

        """
        # Load original entries
        original_entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            server_type,
            fixture_filename,
        )

        # Write entries back to LDIF
        write_result = ldif_api.write(
            original_entries,
            server_type=server_type,
        )

        if not write_result.is_success:
            msg = f"Failed to write entries: {write_result.error}"
            raise ValueError(msg)

        ldif_content = write_result.unwrap()

        # Parse the written LDIF
        roundtrip_result = ldif_api.parse(
            ldif_content,
            server_type=server_type,
        )

        if not roundtrip_result.is_success:
            msg = f"Failed to parse roundtrip LDIF: {roundtrip_result.error}"
            raise ValueError(msg)

        roundtrip_entries = roundtrip_result.unwrap()
        if not isinstance(roundtrip_entries, list):
            msg = f"Unexpected roundtrip result type: {type(roundtrip_entries)}"
            raise TypeError(msg)

        # Compare entries
        is_identical, _differences = FlextLdifTestUtils.compare_entries(
            original_entries,
            roundtrip_entries,
        )

        return original_entries, roundtrip_entries, is_identical

    @staticmethod
    def compare_entries(
        original_entries: list[FlextLdifModels.Entry],
        roundtrip_entries: list[FlextLdifModels.Entry],
    ) -> tuple[bool, list[str]]:
        """Compare two lists of entries for differences.

        Args:
            original_entries: Original list of entries
            roundtrip_entries: Roundtrip list of entries

        Returns:
            Tuple of (is_identical, list_of_differences)

        """
        differences = []

        # Check entry count
        if len(original_entries) != len(roundtrip_entries):
            differences.append(
                f"Entry count mismatch: {len(original_entries)} vs {len(roundtrip_entries)}",
            )
            return False, differences

        # Compare each entry
        for i, (orig, roundtrip) in enumerate(
            zip(original_entries, roundtrip_entries, strict=True)
        ):
            # Compare DNs
            orig_dn = str(orig.dn) if orig.dn else ""
            roundtrip_dn = str(roundtrip.dn) if roundtrip.dn else ""
            if orig_dn.lower() != roundtrip_dn.lower():
                differences.append(
                    f"Entry {i}: DN mismatch: '{orig_dn}' vs '{roundtrip_dn}'",
                )

            # Compare attributes
            orig_attrs = orig.attributes.attributes if orig.attributes else {}
            roundtrip_attrs = (
                roundtrip.attributes.attributes if roundtrip.attributes else {}
            )

            # Exclude LDIF metadata attributes that are added during formatting
            ldif_metadata_attrs = {"changetype", "modifytimestamp", "modifiersname"}
            orig_keys = {
                k.lower() for k in orig_attrs if k.lower() not in ldif_metadata_attrs
            }
            roundtrip_keys = {
                k.lower()
                for k in roundtrip_attrs
                if k.lower() not in ldif_metadata_attrs
            }

            if orig_keys != roundtrip_keys:
                missing = orig_keys - roundtrip_keys
                extra = roundtrip_keys - orig_keys
                if missing:
                    differences.append(
                        f"Entry {i}: Missing attributes in roundtrip: {sorted(missing)}",
                    )
                if extra:
                    differences.append(
                        f"Entry {i}: Extra attributes in roundtrip: {sorted(extra)}",
                    )

            # Compare attribute values for common attributes (excluding LDIF metadata)
            common_attrs = orig_keys & roundtrip_keys
            for attr_name_lower in common_attrs:
                # Find the original case of the attribute name
                orig_attr_name = next(
                    k for k in orig_attrs if k.lower() == attr_name_lower
                )
                roundtrip_attr_name = next(
                    k for k in roundtrip_attrs if k.lower() == attr_name_lower
                )

                orig_val = orig_attrs[orig_attr_name]
                roundtrip_val = roundtrip_attrs[roundtrip_attr_name]

                # Normalize values for comparison
                orig_set = set(orig_val) if isinstance(orig_val, list) else {orig_val}
                roundtrip_set = (
                    set(roundtrip_val)
                    if isinstance(roundtrip_val, list)
                    else {roundtrip_val}
                )

                if orig_set != roundtrip_set:
                    differences.append(
                        f"Entry {i}: Attribute '{attr_name}' value mismatch",
                    )

        is_identical = len(differences) == 0
        return is_identical, differences


__all__ = ["FlextLdifTestUtils"]
