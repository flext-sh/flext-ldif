from pathlib import Path

from flext_ldif.api import FlextLdif
from flext_ldif.models import FlextLdifModels


class FlextLdifTestUtils:
    """Test utilities for FlextLdif."""

    @staticmethod
    def get_fixture_path(server_type: str, fixture_name: str) -> Path:
        """Get the full path to a fixture file."""
        # Path from this file: ../../../../fixtures/{server_type}/{fixture_name}
        return (
            Path(__file__).parent.parent.parent.parent
            / "fixtures"
            / server_type
            / fixture_name
        )

    @staticmethod
    def load_fixture(
        api: FlextLdif, server_type: str, fixture_name: str
    ) -> list[FlextLdifModels.Entry]:
        """Load and parse a fixture file."""
        fixture_path = FlextLdifTestUtils.get_fixture_path(server_type, fixture_name)
        result = api.parse(fixture_path, server_type=server_type)
        assert result.is_success, (
            f"Failed to parse fixture: {fixture_path} - {result.error}"
        )
        return result.unwrap()

    @staticmethod
    def compare_entries(
        original: list[FlextLdifModels.Entry],
        roundtripped: list[FlextLdifModels.Entry],
    ) -> tuple[bool, list[str]]:
        """Compare two lists of entries for semantic equality.

        Returns:
            (is_equal, differences): Tuple of boolean and list of difference descriptions

        """
        differences = []

        if len(original) != len(roundtripped):
            differences.append(
                f"Entry count mismatch: {len(original)} vs {len(roundtripped)}"
            )
            return False, differences

        for idx, (orig_entry, rt_entry) in enumerate(
            zip(original, roundtripped, strict=False)
        ):
            # Compare DNs
            if orig_entry.dn.value != rt_entry.dn.value:
                differences.append(
                    f"Entry {idx}: DN mismatch: '{orig_entry.dn.value}' vs '{rt_entry.dn.value}'"
                )

            # Compare attribute counts
            if len(orig_entry.attributes) != len(rt_entry.attributes):
                differences.append(
                    f"Entry {idx} ({orig_entry.dn.value}): Attribute count mismatch: "
                    f"{len(orig_entry.attributes)} vs {len(rt_entry.attributes)}"
                )

            # Compare attribute names (case-insensitive per LDAP spec)
            orig_attr_names = {name.lower() for name in orig_entry.attributes}
            rt_attr_names = {name.lower() for name in rt_entry.attributes}

            if orig_attr_names != rt_attr_names:
                missing = orig_attr_names - rt_attr_names
                extra = rt_attr_names - orig_attr_names
                if missing:
                    differences.append(
                        f"Entry {idx} ({orig_entry.dn.value}): Missing attributes: {missing}"
                    )
                if extra:
                    differences.append(
                        f"Entry {idx} ({orig_entry.dn.value}): Extra attributes: {extra}"
                    )

            # Compare attribute values (case-insensitive for attribute names)
            for attr_name in orig_attr_names:
                # Find matching attribute in roundtripped (case-insensitive)
                orig_values = None
                rt_values = None

                for orig_key, orig_val in orig_entry.attributes.items():
                    if orig_key.lower() == attr_name:
                        if isinstance(orig_val, list):
                            orig_values = orig_val
                        elif hasattr(orig_val, "values"):
                            orig_values = orig_val.values
                        else:
                            orig_values = [orig_val]
                        break

                for rt_key, rt_val in rt_entry.attributes.items():
                    if rt_key.lower() == attr_name:
                        if isinstance(rt_val, list):
                            rt_values = rt_val
                        elif hasattr(rt_val, "values"):
                            rt_values = rt_val.values
                        else:
                            rt_values = [rt_val]
                        break

                if orig_values is None or rt_values is None:
                    continue

                # Compare value counts
                if len(orig_values) != len(rt_values):
                    differences.append(
                        f"Entry {idx} ({orig_entry.dn.value}), attr '{attr_name}': "
                        f"Value count mismatch: {len(orig_values)} vs {len(rt_values)}"
                    )

        return len(differences) == 0, differences

    @staticmethod
    def run_roundtrip_test(
        api: FlextLdif,
        server_type: str,
        fixture_name: str,
        output_dir: Path,
    ) -> None:
        """Perform a roundtrip test for a given fixture."""
        entries = FlextLdifTestUtils.load_fixture(api, server_type, fixture_name)
        output_path = output_dir / f"{fixture_name}.roundtrip"
        write_result = api.write(
            entries, output_path=output_path, server_type=server_type
        )
        assert write_result.is_success, (
            f"Failed to write fixture: {output_path} - {write_result.error}"
        )

        re_read_result = api.parse(output_path, server_type=server_type)
        assert re_read_result.is_success, (
            f"Failed to re-read fixture: {output_path} - {re_read_result.error}"
        )
        re_read_entries = re_read_result.unwrap()

        # Use semantic comparison
        is_equal, differences = FlextLdifTestUtils.compare_entries(
            entries, re_read_entries
        )
        assert is_equal, "Roundtrip comparison failed:\n" + "\n".join(differences)
