"""Advanced API integration tests with edge cases and error handling."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from flext_ldif import (
    FlextLdifAPI,
    FlextLdifConfig,
    FlextLdifEntry,
)


class TestAdvancedAPIFeatures:
    """Test advanced API features and edge cases."""

    @pytest.fixture
    def api_with_config(self) -> FlextLdifAPI:
        """Create API with custom configuration."""
        config = FlextLdifConfig(
            max_entries=100,
            strict_validation=True,
            sort_attributes=True,
        )
        return FlextLdifAPI(config)

    def test_api_with_large_entries(self, api_with_config: FlextLdifAPI) -> None:
        """Test API with large number of entries."""
        # Generate large LDIF content
        entries = []
        for i in range(50):
            entry = FlextLdifEntry.model_validate(
                {
                    "id": f"user-{i:03d}",
                    "dn": f"cn=user{i:03d},ou=people,dc=example,dc=com",
                    "attributes": {
                        "cn": [f"user{i:03d}"],
                        "objectClass": ["person", "inetOrgPerson"],
                        "mail": [f"user{i:03d}@example.com"],
                    },
                }
            )
            entries.append(entry)

        # Test validation
        validate_result = api_with_config.validate(entries)
        assert validate_result.is_success

        # Test statistics
        stats_result = api_with_config.get_entry_statistics(entries)
        assert stats_result.is_success
        assert stats_result.value is not None
        assert stats_result.value["total_entries"] == 50

    def test_api_error_handling_edge_cases(self, api_with_config: FlextLdifAPI) -> None:
        """Test API error handling with various edge cases."""
        # Test with empty content (returns empty list, which is valid)
        result = api_with_config.parse("")
        assert result.is_success
        assert result.value == []

        # Test with malformed LDIF
        malformed_ldif = """dn cn=invalid,dc=example,dc=com
objectClass person
cn invalid"""
        result = api_with_config.parse(malformed_ldif)
        assert not result.is_success

        # Test with invalid file path
        result = api_with_config.parse_file(Path("/totally/invalid/path/file.ldif"))
        assert not result.is_success

    def test_api_filtering_capabilities(self, api_with_config: FlextLdifAPI) -> None:
        """Test advanced filtering capabilities."""
        ldif_content = """dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
objectClass: person
objectClass: inetOrgPerson

dn: cn=Jane Smith,ou=people,dc=example,dc=com
cn: Jane Smith
objectClass: person
objectClass: organizationalPerson

dn: ou=people,dc=example,dc=com
ou: people
objectClass: organizationalUnit

dn: cn=Developers,ou=groups,dc=example,dc=com
cn: Developers
objectClass: groupOfNames
"""
        # Parse entries
        parse_result = api_with_config.parse(ldif_content)
        assert parse_result.is_success
        entries = parse_result.value

        # Test filtering by objectClass
        person_result = api_with_config.filter_by_objectclass(entries, "person")
        assert person_result.is_success
        assert len(person_result.value) == 2

        inet_result = api_with_config.filter_by_objectclass(entries, "inetOrgPerson")
        assert inet_result.is_success
        assert len(inet_result.value) == 1

        ou_result = api_with_config.filter_by_objectclass(entries, "organizationalUnit")
        assert ou_result.is_success
        assert len(ou_result.value) == 1

    def test_api_file_operations_advanced(self, api_with_config: FlextLdifAPI) -> None:
        """Test advanced file operations."""
        content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write(content)
            temp_file = Path(f.name)

        try:
            # Test parse file
            parse_result = api_with_config.parse_file(temp_file)
            assert parse_result.is_success
            assert len(parse_result.value) == 1

            # Test write file
            output_file = temp_file.with_suffix(".output.ldif")
            write_result = api_with_config.write_file(
                parse_result.value,
                str(output_file),
            )
            assert write_result.is_success
            assert output_file.exists()

            # Verify content
            output_content = output_file.read_text()
            assert "cn=test,dc=example,dc=com" in output_content

            # Clean up
            output_file.unlink()
        finally:
            temp_file.unlink()

    def test_api_performance_monitoring(self, api_with_config: FlextLdifAPI) -> None:
        """Test API performance monitoring capabilities."""
        # Generate moderately large content
        content_parts = [
            f"""dn: cn=user{i:02d},ou=people,dc=example,dc=com
cn: user{i:02d}
objectClass: person
objectClass: inetOrgPerson
mail: user{i:02d}@example.com
"""
            for i in range(20)
        ]

        large_content = "\n".join(content_parts)

        # Test parsing performance
        parse_result = api_with_config.parse(large_content)
        assert parse_result.is_success
        assert len(parse_result.value) == 20

        # Test validation performance
        validate_result = api_with_config.validate(parse_result.value)
        assert validate_result.is_success

        # Test writing performance
        write_result = api_with_config.write(parse_result.value)
        assert write_result.is_success
        assert write_result.value is not None
