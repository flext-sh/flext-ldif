"""End-to-end tests for complete FLEXT-LDIF workflows."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from flext_ldif import (
    FlextLDIFAPI,
    FlextLDIFCore,
    FlextLDIFFormatHandler,
)


class TestCompleteWorkflows:
    """Test complete end-to-end workflows."""

    @pytest.fixture
    def complex_ldif_content(self) -> str:
        """Complex LDIF content for testing."""
        return """dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: ou=people,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people
description: Container for person entries

dn: ou=groups,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: groups
description: Container for group entries

dn: cn=John Doe,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@example.com
telephoneNumber: +1-555-123-4567
description: Software Engineer

dn: cn=Jane Smith,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: Jane Smith
sn: Smith
givenName: Jane
mail: jane.smith@example.com
telephoneNumber: +1-555-987-6543
description: Project Manager

dn: cn=Developers,ou=groups,dc=example,dc=com
objectClass: top
objectClass: groupOfNames
cn: Developers
description: Software Development Team
member: cn=John Doe,ou=people,dc=example,dc=com
"""

    def test_complete_api_workflow(self, complex_ldif_content: str) -> None:
        """Test complete workflow using FlextLDIFAPI."""
        api = FlextLDIFAPI()

        # Step 1: Parse LDIF content
        parse_result = api.parse(complex_ldif_content)
        assert parse_result.is_success
        assert parse_result.value is not None
        entries = parse_result.value
        assert len(entries) == 6

        # Step 2: Validate all entries
        validate_result = api.validate(entries)
        assert validate_result.is_success

        # Step 3: Filter specific entries
        people_filter = api.filter_by_objectclass(entries, "inetOrgPerson")
        assert people_filter.is_success
        assert people_filter.value is not None
        assert len(people_filter.value) == 2

        # Step 4: Find specific entry
        john_result = api.find_entry_by_dn(
            entries,
            "cn=John Doe,ou=people,dc=example,dc=com",
        )
        assert john_result.is_success
        assert john_result.value is not None
        assert john_result.value.get_attribute("givenName") == ["John"]

        # Step 5: Get statistics
        stats_result = api.get_entry_statistics(entries)
        assert stats_result.is_success
        assert stats_result.value is not None
        assert "total_entries" in stats_result.value
        assert stats_result.value["total_entries"] == 6

        # Step 6: Write back to LDIF
        write_result = api.write(entries)
        assert write_result.is_success
        assert write_result.value is not None
        assert "cn=John Doe,ou=people,dc=example,dc=com" in write_result.value

    def test_complete_convenience_functions_workflow(
        self,
        complex_ldif_content: str,
    ) -> None:
        """Test complete workflow using convenience functions."""
        # Step 1: Parse using convenience function
        entries = FlextLDIFFormatHandler.parse_ldif(
            complex_ldif_content
        ).unwrap_or_raise()
        assert len(entries) == 6

        # Step 2: Validate using convenience function
        is_valid = FlextLDIFCore().validate_entries(entries).unwrap_or_raise()
        assert is_valid is True

        # Step 3: Write using convenience function
        ldif_output = FlextLDIFFormatHandler.write_ldif(entries).unwrap_or_raise()
        assert isinstance(ldif_output, str)
        assert "cn=John Doe,ou=people,dc=example,dc=com" in ldif_output

    def test_file_processing_workflow(self, complex_ldif_content: str) -> None:
        """Test complete file processing workflow."""
        api = FlextLDIFAPI()

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as input_file:
            input_file.write(complex_ldif_content)
            input_path = Path(input_file.name)

        try:
            # Step 1: Parse from file
            parse_result = api.parse_file(input_path)
            assert parse_result.is_success
            assert parse_result.value is not None
            entries = parse_result.value

            # Step 2: Process entries (filter and modify)
            people_result = api.filter_by_objectclass(entries, "inetOrgPerson")
            assert people_result.is_success
            people_entries = people_result.value

            # Step 3: Write processed entries to new file
            output_path = input_path.with_suffix(".processed.ldif")
            write_result = api.write_file(people_entries, str(output_path))
            assert write_result.is_success

            # Step 4: Verify output file
            assert output_path.exists()
            output_content = output_path.read_text()
            assert "cn=John Doe,ou=people,dc=example,dc=com" in output_content
            assert "cn=Jane Smith,ou=people,dc=example,dc=com" in output_content
            # Should not contain organizational units or groups as separate entries
            assert "dn: ou=people,dc=example,dc=com" not in output_content
            assert "dn: cn=Developers,ou=groups,dc=example,dc=com" not in output_content

            # Clean up
            output_path.unlink()
        finally:
            input_path.unlink()

    def test_error_recovery_workflow(self) -> None:
        """Test error handling and recovery in workflows."""
        api = FlextLDIFAPI()

        # Test with invalid LDIF
        invalid_ldif = """invalid ldif
without proper format
missing dns"""

        parse_result = api.parse(invalid_ldif)
        assert not parse_result.is_success
        assert parse_result.error is not None

        # Test with non-existent file
        file_result = api.parse_file(Path("/non/existent/file.ldif"))
        assert not file_result.is_success

    def test_performance_workflow(self) -> None:
        """Test workflow performance with larger dataset."""
        api = FlextLDIFAPI()

        # Generate larger LDIF content
        large_ldif_parts = ["dn: dc=example,dc=com\nobjectClass: domain\ndc: example\n"]

        for i in range(50):
            entry = f"""dn: cn=User{i:03d},ou=people,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: User{i:03d}
sn: User{i:03d}
mail: user{i:03d}@example.com
"""
            large_ldif_parts.append(entry)

        large_ldif_content = "\n".join(large_ldif_parts)

        # Test parsing performance
        parse_result = api.parse(large_ldif_content)
        assert parse_result.is_success
        assert parse_result.value is not None
        assert len(parse_result.value) == 51  # 1 domain + 50 users

        # Test filtering performance
        filter_result = api.filter_by_objectclass(parse_result.value, "inetOrgPerson")
        assert filter_result.is_success
        assert filter_result.value is not None
        assert len(filter_result.value) == 50

        # Test writing performance
        write_result = api.write(parse_result.value)
        assert write_result.is_success
        assert write_result.value is not None
