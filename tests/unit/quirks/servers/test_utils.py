from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdif
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import m
from tests import m


class FlextLdifTestUtils:
    """Utilities for FlextLdif testing."""

    @staticmethod
    def get_fixture_path(
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
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
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
        fixture_filename: str,
    ) -> list[m.Entry]:
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
            server_type,
            fixture_filename,
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
    def load_fixture_entries(
        ldif_api: FlextLdif,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
        fixture_filename: str,
        expected_min_count: int | None = None,
    ) -> list[m.Entry]:
        """Load fixture LDIF file and return parsed entries with validation.

        Args:
            ldif_api: FlextLdif API instance
            server_type: Server type identifier
            fixture_filename: Name of the fixture file
            expected_min_count: Optional minimum expected entry count

        Returns:
            List of parsed entries

        """
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
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
        fixture_filename: str,
        *,
        expected_has_dn: bool = True,
        expected_has_attributes: bool = True,
        expected_has_objectclass: bool | None = None,
    ) -> list[m.Entry]:
        """Load fixture and validate entry structure.

        Args:
            ldif_api: FlextLdif API instance
            server_type: Server type identifier
            fixture_filename: Name of the fixture file
            expected_has_dn: Whether entries should have DNs (default: True)
            expected_has_attributes: Whether entries should have attributes (default: True)
            expected_has_objectclass: Optional whether entries should have objectClass

        Returns:
            List of parsed entries

        """
        entries = FlextLdifTestUtils.load_fixture_entries(
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
                assert len(entry.attributes.attributes) > 0, (
                    "Entry must have at least one attribute"
                )

            if expected_has_objectclass is not None:
                assert entry.attributes is not None
                attr_names = {name.lower() for name in entry.attributes.attributes}
                has_objectclass = "objectclass" in attr_names
                assert has_objectclass == expected_has_objectclass, (
                    f"Expected has_objectclass={expected_has_objectclass}, got {has_objectclass}"
                )

        return entries

    @staticmethod
    def run_fixture_roundtrip(
        ldif_api: FlextLdif,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
        fixture_filename: str,
        tmp_path: Path,
        *,
        validate_identical: bool = True,
    ) -> tuple[list[m.Entry], list[m.Entry], bool]:
        """Run roundtrip test on fixture.

        Args:
            ldif_api: FlextLdif API instance
            server_type: Server type identifier
            fixture_filename: Name of the fixture file
            tmp_path: Temporary path for written file
            validate_identical: Whether to validate entries are identical (default: True)

        Returns:
            Tuple of (original_entries, roundtripped_entries, is_identical)

        """
        original_entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            server_type,
            fixture_filename,
        )

        output_file = tmp_path / f"roundtrip_{fixture_filename}"
        write_result = ldif_api.write(
            original_entries,
            output_path=output_file,
            server_type=server_type,
        )
        self.assert_success(write_result, "Write should succeed")

        parse_result = ldif_api.parse(
            output_file,
            server_type=server_type,
        )
        self.assert_success(parse_result, "Re-parse should succeed")

        parsed_data = parse_result.unwrap()
        if isinstance(parsed_data, list):
            roundtripped_entries = parsed_data
        elif hasattr(parsed_data, "entries"):
            roundtripped_entries = parsed_data.entries
        else:
            msg = f"Unexpected parse result type: {type(parsed_data)}"
            raise TypeError(msg)

        is_identical = True
        if validate_identical:
            if len(original_entries) != len(roundtripped_entries):
                is_identical = False
            else:
                for orig, rt in zip(
                    original_entries,
                    roundtripped_entries,
                    strict=False,
                ):
                    if orig.dn is None or rt.dn is None:
                        is_identical = False
                        break
                    if orig.dn.value != rt.dn.value:
                        is_identical = False
                        break

        return original_entries, roundtripped_entries, is_identical

    @staticmethod
    def run_roundtrip_test(
        ldif_api: FlextLdif,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
        fixture_filename: str,
        tmp_path: Path | None = None,
    ) -> tuple[list[m.Entry], list[m.Entry], bool]:
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
        original_entries: list[m.Entry],
        roundtrip_entries: list[m.Entry],
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
            zip(original_entries, roundtrip_entries, strict=True),
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
                        f"Entry {i}: Attribute '{orig_attr_name}' value mismatch",
                    )

        is_identical = len(differences) == 0
        return is_identical, differences


__all__ = ["FlextLdifTestUtils"]
