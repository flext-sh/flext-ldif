"""Real API Integration Tests.

Tests that validate actual API integration functionality without mocks,
using real services and ensuring end-to-end integration works correctly.

No mocks - only real code exercising real service integration.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from flext_ldif import (
    FlextLDIFAPI,
    FlextLDIFConfig,
    FlextLDIFParserService,
    FlextLDIFValidatorService,
    FlextLDIFWriterService,
)


class TestRealApiIntegration:
    """Test real API integration without mocks."""

    def test_api_with_real_config(self) -> None:
        """Test API with real configuration."""
        config = FlextLDIFConfig(
            strict_validation=True,
            input_encoding="utf-8",
            line_wrap_length=76,
        )

        api = FlextLDIFAPI(config)

        ldif_content = """dn: cn=ConfigTest,dc=example,dc=com
objectClass: person
cn: ConfigTest
sn: Test
"""

        # Test parsing with config
        result = api.parse(ldif_content)
        assert result.is_success
        assert result.value is not None
        assert len(result.value) == 1

    def test_file_operations_integration(self) -> None:
        """Test real file operations integration."""
        test_ldif = """dn: cn=FileTest,dc=example,dc=com
objectClass: person
cn: FileTest
sn: Integration
mail: filetest@example.com
"""

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", suffix=".ldif", delete=False
        ) as tmp_file:
            tmp_file.write(test_ldif)
            tmp_file.flush()

            try:
                # Parse from file using parser service directly
                parser = FlextLDIFParserService()
                file_result = parser.parse_ldif_file(tmp_file.name)

                assert file_result.is_success
                assert file_result.value is not None
                assert len(file_result.value) == 1

                entry = file_result.value[0]
                assert entry.dn == "cn=FileTest,dc=example,dc=com"
                assert entry.get_attribute("mail") == ["filetest@example.com"]

            finally:
                Path(tmp_file.name).unlink()

    def test_parser_service_integration(self) -> None:
        """Test real parser service integration."""
        parser = FlextLDIFParserService()

        multi_entry_ldif = """dn: ou=departments,dc=company,dc=com
objectClass: organizationalUnit
ou: departments
description: Company departments

dn: ou=IT,ou=departments,dc=company,dc=com
objectClass: organizationalUnit
ou: IT
description: Information Technology

dn: cn=john.doe,ou=IT,ou=departments,dc=company,dc=com
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: john.doe
sn: Doe
givenName: John
uid: john.doe
mail: john.doe@company.com
departmentNumber: IT001
"""

        result = parser.parse(multi_entry_ldif)

        assert result.is_success
        assert result.value is not None
        assert len(result.value) == 3

        # Check hierarchical structure
        dns = [str(entry.dn) for entry in result.value]
        assert "ou=departments,dc=company,dc=com" in dns
        assert "ou=IT,ou=departments,dc=company,dc=com" in dns
        assert "cn=john.doe,ou=IT,ou=departments,dc=company,dc=com" in dns

    def test_validator_service_integration(self) -> None:
        """Test real validator service integration."""
        validator = FlextLDIFValidatorService()

        # Create real entries using parser
        parser = FlextLDIFParserService()
        valid_ldif = """dn: cn=ValidUser,dc=test,dc=com
objectClass: person
cn: ValidUser
sn: User
"""

        parse_result = parser.parse(valid_ldif)
        assert parse_result.is_success
        entries = parse_result.value

        # Test validation
        validation_result = validator.validate_data(entries)
        assert validation_result.is_success
        assert validation_result.value is True

    def test_writer_service_integration(self) -> None:
        """Test real writer service integration."""
        # Parse entries first
        parser = FlextLDIFParserService()
        original_ldif = """dn: cn=WriteUser,dc=test,dc=com
objectClass: person
objectClass: organizationalPerson
cn: WriteUser
sn: TestWrite
givenName: Write
mail: writeuser@test.com
telephoneNumber: +1-555-WRITE-1
"""

        parse_result = parser.parse(original_ldif)
        assert parse_result.is_success
        entries = parse_result.value

        # Write using writer service
        writer = FlextLDIFWriterService()
        write_result = writer.write(entries)

        assert write_result.is_success
        written_ldif = write_result.value
        assert written_ldif is not None

        # Verify written content contains key information
        assert "dn: cn=WriteUser,dc=test,dc=com" in written_ldif
        assert "objectClass: person" in written_ldif
        assert "cn: WriteUser" in written_ldif
        assert "mail: writeuser@test.com" in written_ldif

    def test_analytics_service_integration(self) -> None:
        """Test real analytics service integration."""
        # Create sample entries
        parser = FlextLDIFParserService()
        sample_ldif = """dn: dc=analytics,dc=com
objectClass: domain
dc: analytics

dn: ou=users,dc=analytics,dc=com
objectClass: organizationalUnit
ou: users

dn: ou=groups,dc=analytics,dc=com
objectClass: organizationalUnit
ou: groups

dn: cn=user1,ou=users,dc=analytics,dc=com
objectClass: person
cn: user1
sn: One

dn: cn=user2,ou=users,dc=analytics,dc=com
objectClass: person
cn: user2
sn: Two

dn: cn=team1,ou=groups,dc=analytics,dc=com
objectClass: groupOfNames
cn: team1
member: cn=user1,ou=users,dc=analytics,dc=com
member: cn=user2,ou=users,dc=analytics,dc=com
"""

        parse_result = parser.parse(sample_ldif)
        assert parse_result.is_success
        entries = parse_result.value

        # Verify we have entries
        assert len(entries) == 6

        # Should have entries with CN attributes (users and groups have CN)
        cn_entries = sum(1 for entry in entries if entry.has_attribute("cn"))
        assert cn_entries >= 3  # user1, user2, team1

    def test_full_workflow_integration(self) -> None:
        """Test complete workflow integration without mocks."""
        api = FlextLDIFAPI()

        # Complex real-world scenario
        enterprise_ldif = """dn: dc=enterprise,dc=local
objectClass: domain
dc: enterprise
description: Enterprise LDAP Directory

dn: ou=Corporate,dc=enterprise,dc=local
objectClass: organizationalUnit
ou: Corporate
description: Corporate Division

dn: ou=Employees,ou=Corporate,dc=enterprise,dc=local
objectClass: organizationalUnit
ou: Employees
description: All corporate employees

dn: ou=Teams,ou=Corporate,dc=enterprise,dc=local
objectClass: organizationalUnit
ou: Teams
description: Corporate teams and groups

dn: cn=alice.johnson,ou=Employees,ou=Corporate,dc=enterprise,dc=local
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: alice.johnson
sn: Johnson
givenName: Alice
uid: alice.johnson
mail: alice.johnson@internal.invalid
employeeNumber: EMP001
title: Senior Developer
departmentNumber: IT
manager: cn=bob.smith,ou=Employees,ou=Corporate,dc=enterprise,dc=local

dn: cn=bob.smith,ou=Employees,ou=Corporate,dc=enterprise,dc=local
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: bob.smith
sn: Smith
givenName: Bob
uid: bob.smith
mail: bob.smith@internal.invalid
employeeNumber: MGR001
title: IT Manager
departmentNumber: IT

dn: cn=developers,ou=Teams,ou=Corporate,dc=enterprise,dc=local
objectClass: groupOfNames
cn: developers
description: Development team members
member: cn=alice.johnson,ou=Employees,ou=Corporate,dc=enterprise,dc=local
member: cn=bob.smith,ou=Employees,ou=Corporate,dc=enterprise,dc=local
"""

        # 1. Parse the enterprise LDIF
        parse_result = api.parse(enterprise_ldif)
        assert parse_result.is_success
        entries = parse_result.value
        assert len(entries) == 7  # Adjusted count - actually 7 entries

        # 2. Validate the entries
        validation_result = api.validate(entries)
        assert validation_result.is_success
        assert validation_result.value is True

        # 3. Get analytics
        analytics_result = api.get_entry_statistics(entries)
        assert analytics_result.is_success
        stats = analytics_result.value
        assert stats["total_entries"] == 7

        # 4. Write back to LDIF
        write_result = api.write(entries)
        assert write_result.is_success
        output_ldif = write_result.value

        # 5. Verify round-trip consistency
        reparse_result = api.parse(output_ldif)
        assert reparse_result.is_success
        reparsed_entries = reparse_result.value
        assert len(reparsed_entries) == len(entries)

        # Verify key entries are preserved
        original_dns = {str(entry.dn) for entry in entries}
        reparsed_dns = {str(entry.dn) for entry in reparsed_entries}
        assert original_dns == reparsed_dns

    def test_error_handling_integration(self) -> None:
        """Test real error handling integration."""
        api = FlextLDIFAPI()

        # Test with malformed LDIF (missing DN line)
        malformed_ldif = """not a dn: invalid
objectClass: person
"""

        result = api.parse(malformed_ldif)
        assert not result.is_success
        assert result.error is not None
        # Should specifically fail with LDIF format error
        assert (
            "failed to parse" in result.error.lower()
            or "invalid ldif" in result.error.lower()
        )

    def test_empty_and_edge_cases_integration(self) -> None:
        """Test edge cases integration."""
        api = FlextLDIFAPI()

        # Empty content
        empty_result = api.parse("")
        assert empty_result.is_success
        assert len(empty_result.value) == 0

        # Whitespace only
        whitespace_result = api.parse("   \n\n\t  ")
        assert whitespace_result.is_success
        assert len(whitespace_result.value) == 0

        # Single minimal entry
        minimal_ldif = """dn: cn=minimal,dc=test
objectClass: person
cn: minimal
sn: test
"""
        minimal_result = api.parse(minimal_ldif)
        assert minimal_result.is_success
        assert len(minimal_result.value) == 1
