"""Tests for improving API coverage.

Tests specifically designed to cover edge cases and error conditions
that are not covered by existing enterprise tests.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from flext_ldif import FlextLdifAPI, FlextLdifConfig


class TestApiCoverage:
    """Tests to improve API test coverage."""

    def test_api_parse_with_empty_data(self) -> None:
        """Test API parse with empty data."""
        api = FlextLdifAPI()

        # Empty content should parse successfully but return empty list
        result = api.parse("")
        assert result.is_success
        assert result.data == []

    def test_api_parse_file_with_invalid_path(self) -> None:
        """Test API parse_file with invalid path."""
        api = FlextLdifAPI()
        result = api.parse_file("/nonexistent/path.ldif")
        assert not result.is_success
        assert "File not found" in result.error

    def test_api_parse_file_with_too_many_entries(self) -> None:
        """Test API parse_file with too many entries."""
        config = FlextLdifConfig(max_entries=1)
        api = FlextLdifAPI(config)

        # Create a temp file with multiple entries
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("""dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1

dn: cn=user2,dc=example,dc=com
objectClass: person
cn: user2
""")
            temp_path = f.name

        try:
            result = api.parse_file(temp_path)
            assert not result.is_success
            assert (
                "Too many entries" in result.error
                or "exceeds configured limit" in result.error
            )
        finally:
            Path(temp_path).unlink()

    def test_api_write_to_file_success(self) -> None:
        """Test API write to file successfully."""
        api = FlextLdifAPI()

        # Parse some entries first
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
"""
        parse_result = api.parse(ldif_content)
        assert parse_result.is_success

        # Write to file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            temp_path = f.name

        try:
            result = api.write(parse_result.data, temp_path)
            assert result.is_success
            assert (
                f"Written to {temp_path}" in result.data
                or f"written successfully to {temp_path}" in result.data
            )

            # Verify file was created
            assert Path(temp_path).exists()
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_api_write_to_file_failure(self) -> None:
        """Test API write to file with failure."""
        api = FlextLdifAPI()

        # Try to write to invalid path
        result = api.write([], "/invalid/path/file.ldif")
        assert not result.is_success
        assert (
            "Write failed" in result.error
            or "File write failed" in result.error
            or "Failed to create directory" in result.error
            or "Permission denied" in result.error
        )

    def test_api_filter_persons_error(self) -> None:
        """Test API filter_persons with error condition."""
        api = FlextLdifAPI()

        # Pass invalid data type to trigger exception
        result = api.filter_persons(None)
        assert not result.is_success
        assert "Entries list cannot be None" in result.error

    def test_api_filter_valid_error(self) -> None:
        """Test API filter_valid with error condition."""
        api = FlextLdifAPI()

        # Pass invalid data type to trigger exception
        result = api.filter_valid(None)
        assert not result.is_success
        assert "Entries list cannot be None" in result.error

    def test_api_sort_hierarchically_error(self) -> None:
        """Test API sort_hierarchically with error condition."""
        api = FlextLdifAPI()

        # Pass invalid data type to trigger exception
        result = api.sort_hierarchically(None)
        assert not result.is_success
        assert "Entries list cannot be None" in result.error

    def test_api_filter_groups_error(self) -> None:
        """Test API filter_groups with error condition."""
        api = FlextLdifAPI()

        # Pass invalid data type to trigger exception
        result = api.filter_groups(None)
        assert not result.is_success
        assert "Entries list cannot be None" in result.error

    def test_api_filter_organizational_units_error(self) -> None:
        """Test API filter_organizational_units with error condition."""
        api = FlextLdifAPI()

        # Pass invalid data type to trigger exception
        result = api.filter_organizational_units(None)
        assert not result.is_success
        assert "Entries list cannot be None" in result.error

    def test_api_filter_change_records_error(self) -> None:
        """Test API filter_change_records with error condition."""
        api = FlextLdifAPI()

        # Pass invalid data type to trigger exception
        result = api.filter_change_records(None)
        assert not result.is_success
        assert "Entries list cannot be None" in result.error

    def test_api_get_entry_statistics_with_mixed_entries(self) -> None:
        """Test API get_entry_statistics with various entry types."""
        api = FlextLdifAPI()

        # Create mixed LDIF content
        ldif_content = """dn: cn=person,dc=example,dc=com
objectClass: person
cn: person

dn: cn=group,dc=example,dc=com
objectClass: groupOfNames
cn: group
member: cn=person,dc=example,dc=com

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

dn: cn=changerecord,dc=example,dc=com
changetype: add
objectClass: person
cn: changerecord
"""

        parse_result = api.parse(ldif_content)
        assert parse_result.is_success

        stats_result = api.get_entry_statistics(parse_result.data)
        assert stats_result.is_success
        stats = stats_result.data
        assert stats["total_entries"] == 4
        assert stats["person_entries"] >= 1
        assert stats["group_entries"] >= 1
        assert stats["ou_entries"] >= 1
        assert stats["change_records"] >= 1

    def test_api_entries_to_ldif(self) -> None:
        """Test API entries_to_ldif method."""
        api = FlextLdifAPI()

        # Parse some entries first
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
"""
        parse_result = api.parse(ldif_content)
        assert parse_result.is_success

        # Convert back to LDIF
        ldif_result = api.entries_to_ldif(parse_result.data)
        assert ldif_result.is_success
        ldif_output = ldif_result.data
        assert isinstance(ldif_output, str)
        assert "cn=test,dc=example,dc=com" in ldif_output

    def test_api_find_entry_by_dn_found(self) -> None:
        """Test API find_entry_by_dn when entry is found."""
        api = FlextLdifAPI()

        # Parse entries
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test

dn: cn=other,dc=example,dc=com
objectClass: person
cn: other
"""
        parse_result = api.parse(ldif_content)
        assert parse_result.is_success

        # Find specific entry
        entry_result = api.find_entry_by_dn(
            parse_result.data, "cn=test,dc=example,dc=com",
        )
        assert entry_result.is_success
        assert entry_result.data is not None
        entry = entry_result.data
        assert str(entry.dn) == "cn=test,dc=example,dc=com"

    def test_api_find_entry_by_dn_not_found(self) -> None:
        """Test API find_entry_by_dn when entry is not found."""
        api = FlextLdifAPI()

        # Parse entries
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
"""
        parse_result = api.parse(ldif_content)
        assert parse_result.is_success

        # Try to find non-existent entry
        entry_result = api.find_entry_by_dn(
            parse_result.data,
            "cn=nonexistent,dc=example,dc=com",
        )
        assert entry_result.is_success
        assert entry_result.data is None

    def test_api_filter_by_objectclass(self) -> None:
        """Test API filter_by_objectclass."""
        api = FlextLdifAPI()

        # Parse mixed entries
        ldif_content = """dn: cn=person,dc=example,dc=com
objectClass: person
cn: person

dn: cn=group,dc=example,dc=com
objectClass: groupOfNames
cn: group
"""
        parse_result = api.parse(ldif_content)
        assert parse_result.is_success

        # Filter by objectClass
        person_result = api.filter_by_objectclass(parse_result.data, "person")
        assert person_result.is_success
        person_entries = person_result.data
        assert len(person_entries) == 1
        assert str(person_entries[0].dn) == "cn=person,dc=example,dc=com"

    def test_convenience_functions_error_handling(self) -> None:
        """Test convenience functions error handling."""
        from flext_ldif import flext_ldif_parse, flext_ldif_validate, flext_ldif_write

        # Test parse with invalid content
        result = flext_ldif_parse("invalid ldif content")
        assert isinstance(result, list)

        # Test validate with invalid content
        result = flext_ldif_validate("invalid ldif content")
        assert isinstance(result, bool)

        # Test write with empty entries
        result = flext_ldif_write([])
        assert isinstance(result, str)

    def test_global_api_reuse(self) -> None:
        """Test that global API instance is reused."""
        from flext_ldif import flext_ldif_get_api

        api1 = flext_ldif_get_api()
        api2 = flext_ldif_get_api()
        assert api1 is api2

        # Test with new config
        config = FlextLdifConfig(max_entries=100)
        api3 = flext_ldif_get_api(config)
        assert api3 is not api1
