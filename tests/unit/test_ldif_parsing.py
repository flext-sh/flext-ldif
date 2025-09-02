"""Test Real LDIF Parsing Functionality.

Tests that validate actual LDIF parsing without mocks, using real data and
ensuring end-to-end functionality works correctly.

No mocks - only real code exercising real functionality.
"""

from __future__ import annotations

import pytest

from flext_ldif import (
    FlextLDIFAPI,
    FlextLDIFCore,
    FlextLDIFFormatHandler,
)


class TestRealLdifParsing:
    """Test real LDIF parsing functionality without mocks."""

    def test_parse_simple_person_entry(self) -> None:
        """Test parsing a real person entry."""
        ldif_content = """dn: cn=John Doe,ou=people,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@example.com
telephoneNumber: +1-555-123-4567
"""

        # Test using class-based interface
        parse_result = FlextLDIFFormatHandler.parse_ldif(ldif_content)
        assert parse_result.is_success
        entries = parse_result.value

        # Validate results
        assert len(entries) == 1
        entry = entries[0]

        assert entry.dn == "cn=John Doe,ou=people,dc=example,dc=com"
        object_classes = entry.get_attribute("objectClass") or []
        assert "person" in object_classes
        assert "organizationalPerson" in object_classes
        assert entry.get_attribute("cn") == ["John Doe"]
        assert entry.get_attribute("sn") == ["Doe"]
        assert entry.get_attribute("givenName") == ["John"]
        assert entry.get_attribute("mail") == ["john.doe@example.com"]
        assert entry.get_attribute("telephoneNumber") == ["+1-555-123-4567"]

    def test_parse_multiple_entries(self) -> None:
        """Test parsing multiple LDIF entries."""
        ldif_content = """dn: cn=Admin,ou=people,dc=example,dc=com
objectClass: person
cn: Admin
sn: Administrator

dn: cn=User,ou=people,dc=example,dc=com
objectClass: person
cn: User
sn: Regular
"""

        entries = FlextLDIFFormatHandler.parse_ldif(ldif_content).unwrap_or_raise()

        assert len(entries) == 2

        # Check first entry
        REDACTED_LDAP_BIND_PASSWORD = entries[0]
        assert REDACTED_LDAP_BIND_PASSWORD.dn == "cn=Admin,ou=people,dc=example,dc=com"
        assert REDACTED_LDAP_BIND_PASSWORD.get_attribute("cn") == ["Admin"]
        assert REDACTED_LDAP_BIND_PASSWORD.get_attribute("sn") == ["Administrator"]

        # Check second entry
        user = entries[1]
        assert user.dn == "cn=User,ou=people,dc=example,dc=com"
        assert user.get_attribute("cn") == ["User"]
        assert user.get_attribute("sn") == ["Regular"]

    def test_parse_group_entry(self) -> None:
        """Test parsing a group entry with members."""
        ldif_content = """dn: cn=developers,ou=groups,dc=example,dc=com
objectClass: groupOfNames
cn: developers
description: Development Team
member: cn=John Doe,ou=people,dc=example,dc=com
member: cn=Jane Smith,ou=people,dc=example,dc=com
"""

        entries = FlextLDIFFormatHandler.parse_ldif(ldif_content).unwrap_or_raise()

        assert len(entries) == 1
        group = entries[0]

        assert group.dn == "cn=developers,ou=groups,dc=example,dc=com"
        assert group.get_attribute("objectClass") == ["groupOfNames"]
        assert group.get_attribute("cn") == ["developers"]
        assert group.get_attribute("description") == ["Development Team"]

        members = group.get_attribute("member") or []
        assert len(members) == 2
        assert "cn=John Doe,ou=people,dc=example,dc=com" in members
        assert "cn=Jane Smith,ou=people,dc=example,dc=com" in members

    def test_parse_organizational_unit(self) -> None:
        """Test parsing organizational unit entry."""
        ldif_content = """dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people
description: All users in the organization
"""

        entries = FlextLDIFFormatHandler.parse_ldif(ldif_content).unwrap_or_raise()

        assert len(entries) == 1
        ou = entries[0]

        assert ou.dn == "ou=people,dc=example,dc=com"
        assert ou.get_attribute("objectClass") == ["organizationalUnit"]
        assert ou.get_attribute("ou") == ["people"]
        assert ou.get_attribute("description") == ["All users in the organization"]

    def test_validate_real_entries(self) -> None:
        """Test validation of real parsed entries."""
        ldif_content = """dn: cn=TestUser,dc=example,dc=com
objectClass: person
cn: TestUser
sn: User
"""

        entries = FlextLDIFFormatHandler.parse_ldif(ldif_content).unwrap_or_raise()

        # Test validation using convenience function
        is_valid = FlextLDIFCore().validate_entries(entries).unwrap_or_raise()
        assert is_valid is True

    def test_write_real_entries(self) -> None:
        """Test writing real entries back to LDIF format."""
        original_ldif = """dn: cn=WriteTest,dc=example,dc=com
objectClass: person
cn: WriteTest
sn: Test
"""

        # Parse original
        entries = FlextLDIFFormatHandler.parse_ldif(original_ldif).unwrap_or_raise()

        # Write back to LDIF
        written_ldif = FlextLDIFFormatHandler.write_ldif(entries).unwrap_or_raise()

        # Should contain the essential data
        assert "dn: cn=WriteTest,dc=example,dc=com" in written_ldif
        assert "objectClass: person" in written_ldif
        assert "cn: WriteTest" in written_ldif
        assert "sn: Test" in written_ldif

        # Parse the written LDIF to verify it's valid
        reparsed_entries = FlextLDIFFormatHandler.parse_ldif(
            written_ldif
        ).unwrap_or_raise()
        assert len(reparsed_entries) == 1
        assert reparsed_entries[0].dn == entries[0].dn

    def test_api_class_directly(self) -> None:
        """Test using FlextLDIFAPI class directly."""
        api = FlextLDIFAPI()

        ldif_content = """dn: cn=APITest,dc=example,dc=com
objectClass: person
cn: APITest
sn: Direct
"""

        # Test parsing
        parse_result = api.parse(ldif_content)
        assert parse_result.is_success
        assert parse_result.value is not None
        assert len(parse_result.value) == 1

        entries = parse_result.value

        # Test validation
        validate_result = api.validate(entries)
        assert validate_result.is_success
        assert validate_result.value is True

        # Test writing
        write_result = api.write(entries)
        assert write_result.is_success
        assert write_result.value is not None
        assert "cn=APITest" in write_result.value

    def test_complex_real_ldif(self) -> None:
        """Test parsing complex real-world LDIF with multiple entry types."""
        complex_ldif = """dn: dc=example,dc=com
objectClass: domain
dc: example
description: Example Organization

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people
description: All users

dn: ou=groups,dc=example,dc=com
objectClass: organizationalUnit
ou: groups
description: All groups

dn: cn=REDACTED_LDAP_BIND_PASSWORD,ou=people,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: REDACTED_LDAP_BIND_PASSWORD
sn: Administrator
givenName: System
uid: REDACTED_LDAP_BIND_PASSWORD
userPassword: {SSHA}hashedPassword
mail: REDACTED_LDAP_BIND_PASSWORD@example.com

dn: cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com
objectClass: groupOfNames
cn: REDACTED_LDAP_BIND_PASSWORDs
description: System Administrators
member: cn=REDACTED_LDAP_BIND_PASSWORD,ou=people,dc=example,dc=com
"""

        entries = FlextLDIFFormatHandler.parse_ldif(complex_ldif).unwrap_or_raise()

        # Should have 5 entries
        assert len(entries) == 5

        # Validate all entry types are parsed correctly
        dns = [str(entry.dn) for entry in entries]
        expected_dns = [
            "dc=example,dc=com",
            "ou=people,dc=example,dc=com",
            "ou=groups,dc=example,dc=com",
            "cn=REDACTED_LDAP_BIND_PASSWORD,ou=people,dc=example,dc=com",
            "cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com",
        ]

        for expected_dn in expected_dns:
            assert expected_dn in dns

        # Check specific entries
        REDACTED_LDAP_BIND_PASSWORD_entry = next(e for e in entries if "cn=REDACTED_LDAP_BIND_PASSWORD" in str(e.dn))
        REDACTED_LDAP_BIND_PASSWORD_object_classes = REDACTED_LDAP_BIND_PASSWORD_entry.get_attribute("objectClass") or []
        assert "inetOrgPerson" in REDACTED_LDAP_BIND_PASSWORD_object_classes
        assert REDACTED_LDAP_BIND_PASSWORD_entry.get_attribute("uid") == ["REDACTED_LDAP_BIND_PASSWORD"]

        REDACTED_LDAP_BIND_PASSWORD_group = next(e for e in entries if "cn=REDACTED_LDAP_BIND_PASSWORDs" in str(e.dn))
        assert REDACTED_LDAP_BIND_PASSWORD_group.get_attribute("member") == [
            "cn=REDACTED_LDAP_BIND_PASSWORD,ou=people,dc=example,dc=com"
        ]

    def test_empty_ldif_content(self) -> None:
        """Test handling empty LDIF content."""
        empty_entries = FlextLDIFFormatHandler.parse_ldif("").unwrap_or_raise()
        assert len(empty_entries) == 0

        whitespace_entries = FlextLDIFFormatHandler.parse_ldif(
            "   \n\n   "
        ).unwrap_or_raise()
        assert len(whitespace_entries) == 0

    def test_invalid_ldif_raises_error(self) -> None:
        """Test that invalid LDIF raises appropriate errors."""
        invalid_ldif = """invalid: not a dn
objectClass: person
"""

        with pytest.raises(Exception):  # Should raise FlextLDIFParseError
            FlextLDIFFormatHandler.parse_ldif(invalid_ldif).unwrap_or_raise()

    def test_roundtrip_consistency(self) -> None:
        """Test that parse -> write -> parse maintains data consistency."""
        original_ldif = """dn: cn=RoundTrip,dc=test,dc=com
objectClass: person
objectClass: organizationalPerson
cn: RoundTrip
sn: Test
givenName: Round
mail: roundtrip@test.com
description: Multi-line description
 that continues on the next line
telephoneNumber: +1-555-999-8888
"""

        # First parse
        entries1 = FlextLDIFFormatHandler.parse_ldif(original_ldif).unwrap_or_raise()

        # Write to LDIF
        written_ldif = FlextLDIFFormatHandler.write_ldif(entries1).unwrap_or_raise()

        # Parse again
        entries2 = FlextLDIFFormatHandler.parse_ldif(written_ldif).unwrap_or_raise()

        # Should have same number of entries
        assert len(entries1) == len(entries2) == 1

        # Should have same DN
        assert entries1[0].dn == entries2[0].dn

        # Should have same core attributes
        entry1 = entries1[0]
        entry2 = entries2[0]

        for key in ["objectClass", "cn", "sn", "mail"]:
            assert entry1.get_attribute(key) == entry2.get_attribute(key)
