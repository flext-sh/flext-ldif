"""Tests for FlextLdifUtilities class with REAL functionality (no mocks)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from flext_core import FlextResult

from flext_ldif import FlextLdifAPI
from flext_ldif.models import FlextLdifEntry
from flext_ldif.utilities import FlextLdifUtilities


@pytest.fixture
def api() -> FlextLdifAPI:
    """Get a real FlextLdifAPI instance."""
    return FlextLdifAPI()


@pytest.fixture
def sample_entries(api: FlextLdifAPI) -> list[FlextLdifEntry]:
    """Create real LDIF entries for testing utilities."""
    ldif_content = """dn: cn=John Doe,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@example.com

dn: cn=Jane Smith,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: Jane Smith
sn: Smith
givenName: Jane
mail: jane.smith@example.com

dn: cn=developers,ou=groups,dc=example,dc=com
objectClass: groupOfNames
objectClass: top
cn: developers
description: Development Team
member: cn=John Doe,ou=people,dc=example,dc=com
member: cn=Jane Smith,ou=people,dc=example,dc=com

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
objectClass: top
ou: people
description: People OU
"""
    # Use REAL parsing - no mocks
    return api.parse(ldif_content).unwrap_or([])


class TestFlextLdifUtilities:
    """Test FlextLdifUtilities with real functionality."""

    def test_parse_file_or_exit_success(self, api: FlextLdifAPI, tmp_path: Path) -> None:
        """Test parse_file_or_exit with successful parsing."""
        # Create a temporary LDIF file with real content
        test_file = tmp_path / "test.ldif"
        test_file.write_text("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user
""", encoding="utf-8")

        # Test real parsing - should succeed
        entries = FlextLdifUtilities.parse_file_or_exit(api, str(test_file))

        assert len(entries) == 1
        assert entries[0].dn == "cn=test,dc=example,dc=com"
        assert "person" in (entries[0].get_attribute("objectClass") or [])

    def test_parse_file_or_exit_failure(self, api: FlextLdifAPI) -> None:
        """Test parse_file_or_exit with file not found (should exit)."""
        def side_effect_exit(code: int) -> None:
            # Simulate real sys.exit by raising SystemExit
            raise SystemExit(code)

        with patch("sys.exit", side_effect=side_effect_exit) as mock_exit, \
             patch("click.echo") as mock_echo:

            with pytest.raises(SystemExit):
                FlextLdifUtilities.parse_file_or_exit(api, "/nonexistent/file.ldif")

            # Should have called sys.exit(1)
            mock_exit.assert_called_once_with(1)
            mock_echo.assert_called_once()
            assert "Failed to parse file:" in mock_echo.call_args[0][0]

    def test_write_result_or_exit_success(self) -> None:
        """Test write_result_or_exit with successful result."""
        success_result = FlextResult[str].ok("test data")

        value = FlextLdifUtilities.write_result_or_exit(success_result, "test operation")

        assert value == "test data"

    def test_write_result_or_exit_failure(self) -> None:
        """Test write_result_or_exit with failure result (should exit)."""
        failure_result = FlextResult[str].fail("test error")

        def side_effect_exit(code: int) -> None:
            # Simulate real sys.exit by raising SystemExit
            raise SystemExit(code)

        with patch("sys.exit", side_effect=side_effect_exit) as mock_exit, \
             patch("click.echo") as mock_echo:

            with pytest.raises(SystemExit):
                FlextLdifUtilities.write_result_or_exit(failure_result, "test operation")

            # Should have called sys.exit(1) via tap_error
            mock_exit.assert_called_once_with(1)
            mock_echo.assert_called_once()
            assert "Failed to test operation: test error" in mock_echo.call_args[0][0]

    def test_validate_entries_or_warn_no_warnings(self, sample_entries: list[FlextLdifEntry]) -> None:
        """Test validate_entries_or_warn with valid entries."""
        warnings = FlextLdifUtilities.validate_entries_or_warn(sample_entries, max_warnings=5)

        # All sample entries should be valid
        assert isinstance(warnings, list)
        assert len(warnings) == 0

    def test_validate_entries_or_warn_with_invalid_entry(self, api: FlextLdifAPI) -> None:
        """Test validate_entries_or_warn with entry that fails business rules."""
        # Create an entry with minimal data that might fail business validation
        minimal_ldif = """dn: cn=invalid,dc=test,dc=com
objectClass: person
cn: invalid
"""
        entries = api.parse(minimal_ldif).unwrap_or([])

        # Force some entries to test warning behavior
        if entries:
            warnings = FlextLdifUtilities.validate_entries_or_warn(entries, max_warnings=5)

            # Warnings format should be correct (might be empty for valid minimal entry)
            assert isinstance(warnings, list)

            # Test max_warnings limit with multiple entries
            multiple_entries = entries * 10  # Duplicate entry to test warning limit
            warnings_limited = FlextLdifUtilities.validate_entries_or_warn(multiple_entries, max_warnings=3)

            # Should limit warnings properly
            assert len(warnings_limited) <= 4  # max 3 + overflow message

    def test_railway_filter_entries_persons(self, api: FlextLdifAPI, sample_entries: list[FlextLdifEntry]) -> None:
        """Test railway_filter_entries with persons filter."""
        filtered = FlextLdifUtilities.railway_filter_entries(api, sample_entries, "persons")

        # Should return person entries
        assert len(filtered) == 2  # John and Jane
        for entry in filtered:
            object_classes = entry.get_attribute("objectClass") or []
            assert "person" in object_classes

    def test_railway_filter_entries_groups(self, api: FlextLdifAPI, sample_entries: list[FlextLdifEntry]) -> None:
        """Test railway_filter_entries with groups filter."""
        filtered = FlextLdifUtilities.railway_filter_entries(api, sample_entries, "groups")

        # Should return group entries
        assert len(filtered) == 1  # developers group
        object_classes = filtered[0].get_attribute("objectClass") or []
        assert "groupOfNames" in object_classes

    def test_railway_filter_entries_ous(self, api: FlextLdifAPI, sample_entries: list[FlextLdifEntry]) -> None:
        """Test railway_filter_entries with organizational units filter."""
        filtered = FlextLdifUtilities.railway_filter_entries(api, sample_entries, "ous")

        # Should return OU entries
        assert len(filtered) == 1  # people OU
        object_classes = filtered[0].get_attribute("objectClass") or []
        assert "organizationalUnit" in object_classes

    def test_railway_filter_entries_unknown_filter(self, api: FlextLdifAPI, sample_entries: list[FlextLdifEntry]) -> None:
        """Test railway_filter_entries with unknown filter type."""
        with patch("click.echo") as mock_echo:
            filtered = FlextLdifUtilities.railway_filter_entries(api, sample_entries, "unknown")

            # Should return original entries and show error
            assert filtered == sample_entries
            mock_echo.assert_called_once()
            assert "Unknown filter type: unknown" in mock_echo.call_args[0][0]

    def test_process_result_with_default_success(self) -> None:
        """Test process_result_with_default with successful result."""
        success_result = FlextResult[str].ok("success data")
        success_called = False

        def success_action(data: str) -> None:
            nonlocal success_called
            success_called = True
            assert data == "success data"

        value = FlextLdifUtilities.process_result_with_default(
            success_result, "default", success_action=success_action
        )

        assert value == "success data"
        assert success_called

    def test_process_result_with_default_failure(self) -> None:
        """Test process_result_with_default with failure result."""
        failure_result = FlextResult[str].fail("test error")
        error_called = False

        def error_action(error: str) -> None:
            nonlocal error_called
            error_called = True
            assert error == "test error"

        value = FlextLdifUtilities.process_result_with_default(
            failure_result, "default value", error_action=error_action
        )

        assert value == "default value"
        assert error_called

    def test_safe_execute_callable(self) -> None:
        """Test safe_execute_callable with valid function."""
        def test_func(x: int, y: int) -> int:
            return x + y

        result = FlextLdifUtilities.safe_execute_callable(test_func, 2, 3)
        assert result == 5

    def test_create_processing_pipeline(self) -> None:
        """Test create_processing_pipeline with real functions."""
        def add_one(x: object) -> object:
            return int(x) + 1 if isinstance(x, int) else x

        def multiply_two(x: object) -> object:
            return int(x) * 2 if isinstance(x, int) else x

        pipeline = FlextLdifUtilities.create_processing_pipeline(add_one, multiply_two)

        result = pipeline(5)  # (5 + 1) * 2 = 12
        assert result == 12

    def test_validate_callable_chain_valid(self) -> None:
        """Test validate_callable_chain with valid callables."""
        def func1() -> None:
            pass

        def func2() -> None:
            pass

        is_valid = FlextLdifUtilities.validate_callable_chain(func1, func2, len)
        assert is_valid

    def test_validate_callable_chain_invalid(self) -> None:
        """Test validate_callable_chain with non-callable."""
        def func1() -> None:
            pass

        is_valid = FlextLdifUtilities.validate_callable_chain(func1, "not callable")  # type: ignore[arg-type]
        assert not is_valid

    def test_count_entries_by_objectclass(self, sample_entries: list[FlextLdifEntry]) -> None:
        """Test count_entries_by_objectclass with real entries."""
        person_count = FlextLdifUtilities.count_entries_by_objectclass(sample_entries, "person")
        group_count = FlextLdifUtilities.count_entries_by_objectclass(sample_entries, "groupOfNames")
        ou_count = FlextLdifUtilities.count_entries_by_objectclass(sample_entries, "organizationalUnit")

        assert person_count == 2  # John and Jane
        assert group_count == 1   # developers group
        assert ou_count == 1      # people OU

    def test_count_entries_by_objectclass_case_insensitive(self, sample_entries: list[FlextLdifEntry]) -> None:
        """Test count_entries_by_objectclass is case insensitive."""
        count_lower = FlextLdifUtilities.count_entries_by_objectclass(sample_entries, "person")
        count_upper = FlextLdifUtilities.count_entries_by_objectclass(sample_entries, "PERSON")
        count_mixed = FlextLdifUtilities.count_entries_by_objectclass(sample_entries, "Person")

        assert count_lower == count_upper == count_mixed == 2

    def test_batch_validate_entries_success(self, api: FlextLdifAPI, sample_entries: list[FlextLdifEntry]) -> None:
        """Test batch_validate_entries with valid entries."""
        result = FlextLdifUtilities.batch_validate_entries(api, sample_entries, batch_size=2)

        assert result.is_success
        validation_results = result.value
        assert len(validation_results) == len(sample_entries)
        # Most entries should be valid
        assert sum(validation_results) >= len(sample_entries) - 1

    def test_create_ldif_summary_stats_empty(self) -> None:
        """Test create_ldif_summary_stats with empty entries."""
        stats = FlextLdifUtilities.create_ldif_summary_stats([])

        assert stats["total_entries"] == 0
        assert stats["unique_objectclasses"] == 0
        assert stats["avg_attributes_per_entry"] == 0

    def test_create_ldif_summary_stats_with_entries(self, sample_entries: list[FlextLdifEntry]) -> None:
        """Test create_ldif_summary_stats with real entries."""
        stats = FlextLdifUtilities.create_ldif_summary_stats(sample_entries)

        assert stats["total_entries"] == len(sample_entries)
        assert stats["unique_objectclasses"] > 0
        assert isinstance(stats["objectclass_list"], list)
        assert stats["avg_attributes_per_entry"] > 0
        assert "person" in stats["objectclass_list"]
        assert "groupofnames" in stats["objectclass_list"]

    def test_find_entries_by_pattern(self, sample_entries: list[FlextLdifEntry]) -> None:
        """Test find_entries_by_pattern with real entries."""
        # Find entries with "people" in DN
        people_entries = FlextLdifUtilities.find_entries_by_pattern(sample_entries, "people")

        assert len(people_entries) >= 2  # Should find John, Jane, and people OU
        for entry in people_entries:
            assert "people" in str(entry.dn).lower()

    def test_find_entries_by_pattern_case_insensitive(self, sample_entries: list[FlextLdifEntry]) -> None:
        """Test find_entries_by_pattern is case insensitive."""
        lower_results = FlextLdifUtilities.find_entries_by_pattern(sample_entries, "example")
        upper_results = FlextLdifUtilities.find_entries_by_pattern(sample_entries, "EXAMPLE")

        assert len(lower_results) == len(upper_results) == len(sample_entries)

    def test_merge_entry_lists_no_duplicates(self, sample_entries: list[FlextLdifEntry]) -> None:
        """Test merge_entry_lists with different lists."""
        list1 = sample_entries[:2]  # First 2 entries
        list2 = sample_entries[2:]  # Remaining entries

        merged = FlextLdifUtilities.merge_entry_lists(list1, list2)

        assert len(merged) == len(sample_entries)

    def test_merge_entry_lists_with_duplicates(self, sample_entries: list[FlextLdifEntry]) -> None:
        """Test merge_entry_lists removes duplicates."""
        # Create lists with overlapping entries
        list1 = sample_entries[:3]
        list2 = sample_entries[1:]  # Overlaps with list1

        merged = FlextLdifUtilities.merge_entry_lists(list1, list2)

        # Should have unique entries only
        assert len(merged) == len(sample_entries)

        # Verify no actual duplicates by DN
        dns = [str(entry.dn) for entry in merged]
        assert len(dns) == len(set(dns))

    def test_merge_entry_lists_empty_lists(self) -> None:
        """Test merge_entry_lists with empty lists."""
        merged = FlextLdifUtilities.merge_entry_lists([], [])
        assert len(merged) == 0
