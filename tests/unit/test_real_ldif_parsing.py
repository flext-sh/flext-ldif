"""Test Real LDIF Parsing Functionality.

Tests that validate actual LDIF parsing without mocks, using real data and
ensuring end-to-end functionality works correctly.

No mocks - only real code exercising real functionality.
"""

from __future__ import annotations

import pytest

from flext_ldif import (
    FlextLdifAPI,
    flext_ldif_parse,
    flext_ldif_validate,
    flext_ldif_write,
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

        # Test using convenience function
        entries = flext_ldif_parse(ldif_content)

        # Validate results
        assert len(entries) == 1
        entry = entries[0]

        assert entry.dn.value == "cn=John Doe,ou=people,dc=example,dc=com"
        assert "person" in entry.attributes.attributes["objectClass"]
        assert "organizationalPerson" in entry.attributes.attributes["objectClass"]
        assert entry.attributes.attributes["cn"] == ["John Doe"]
        assert entry.attributes.attributes["sn"] == ["Doe"]
        assert entry.attributes.attributes["givenName"] == ["John"]
        assert entry.attributes.attributes["mail"] == ["john.doe@example.com"]
        assert entry.attributes.attributes["telephoneNumber"] == ["+1-555-123-4567"]

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

        entries = flext_ldif_parse(ldif_content)

        assert len(entries) == 2

        # Check first entry
        admin = entries[0]
        assert admin.dn.value == "cn=Admin,ou=people,dc=example,dc=com"
        assert admin.attributes.attributes["cn"] == ["Admin"]
        assert admin.attributes.attributes["sn"] == ["Administrator"]

        # Check second entry
        user = entries[1]
        assert user.dn.value == "cn=User,ou=people,dc=example,dc=com"
        assert user.attributes.attributes["cn"] == ["User"]
        assert user.attributes.attributes["sn"] == ["Regular"]

    def test_parse_group_entry(self) -> None:
        """Test parsing a group entry with members."""
        ldif_content = """dn: cn=developers,ou=groups,dc=example,dc=com
objectClass: groupOfNames
cn: developers
description: Development Team
member: cn=John Doe,ou=people,dc=example,dc=com
member: cn=Jane Smith,ou=people,dc=example,dc=com
"""

        entries = flext_ldif_parse(ldif_content)

        assert len(entries) == 1
        group = entries[0]

        assert group.dn.value == "cn=developers,ou=groups,dc=example,dc=com"
        assert group.attributes.attributes["objectClass"] == ["groupOfNames"]
        assert group.attributes.attributes["cn"] == ["developers"]
        assert group.attributes.attributes["description"] == ["Development Team"]

        members = group.attributes.attributes["member"]
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

        entries = flext_ldif_parse(ldif_content)

        assert len(entries) == 1
        ou = entries[0]

        assert ou.dn.value == "ou=people,dc=example,dc=com"
        assert ou.attributes.attributes["objectClass"] == ["organizationalUnit"]
        assert ou.attributes.attributes["ou"] == ["people"]
        assert ou.attributes.attributes["description"] == [
            "All users in the organization"
        ]

    def test_validate_real_entries(self) -> None:
        """Test validation of real parsed entries."""
        ldif_content = """dn: cn=TestUser,dc=example,dc=com
objectClass: person
cn: TestUser
sn: User
"""

        entries = flext_ldif_parse(ldif_content)

        # Test validation using convenience function
        is_valid = flext_ldif_validate(entries)
        assert is_valid is True

    def test_write_real_entries(self) -> None:
        """Test writing real entries back to LDIF format."""
        original_ldif = """dn: cn=WriteTest,dc=example,dc=com
objectClass: person
cn: WriteTest
sn: Test
"""

        # Parse original
        entries = flext_ldif_parse(original_ldif)

        # Write back to LDIF
        written_ldif = flext_ldif_write(entries)

        # Should contain the essential data
        assert "dn: cn=WriteTest,dc=example,dc=com" in written_ldif
        assert "objectClass: person" in written_ldif
        assert "cn: WriteTest" in written_ldif
        assert "sn: Test" in written_ldif

        # Parse the written LDIF to verify it's valid
        reparsed_entries = flext_ldif_parse(written_ldif)
        assert len(reparsed_entries) == 1
        assert reparsed_entries[0].dn.value == entries[0].dn.value

    def test_api_class_directly(self) -> None:
        """Test using FlextLdifAPI class directly."""
        api = FlextLdifAPI()

        ldif_content = """dn: cn=APITest,dc=example,dc=com
objectClass: person
cn: APITest
sn: Direct
"""

        # Test parsing
        parse_result = api.parse(ldif_content)
        assert parse_result.success
        assert parse_result.value is not None
        assert len(parse_result.value) == 1

        entries = parse_result.value

        # Test validation
        validate_result = api.validate(entries)
        assert validate_result.success
        assert validate_result.value is True

        # Test writing
        write_result = api.write(entries)
        assert write_result.success
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

dn: cn=admin,ou=people,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: admin
sn: Administrator
givenName: System
uid: admin
userPassword: {SSHA}hashedPassword
mail: admin@example.com

dn: cn=admins,ou=groups,dc=example,dc=com
objectClass: groupOfNames
cn: admins
description: System Administrators
member: cn=admin,ou=people,dc=example,dc=com
"""

        entries = flext_ldif_parse(complex_ldif)

        # Should have 5 entries
        assert len(entries) == 5

        # Validate all entry types are parsed correctly
        dns = [entry.dn.value for entry in entries]
        expected_dns = [
            "dc=example,dc=com",
            "ou=people,dc=example,dc=com",
            "ou=groups,dc=example,dc=com",
            "cn=admin,ou=people,dc=example,dc=com",
            "cn=admins,ou=groups,dc=example,dc=com",
        ]

        for expected_dn in expected_dns:
            assert expected_dn in dns

        # Check specific entries
        admin_entry = next(e for e in entries if "cn=admin" in e.dn.value)
        assert "inetOrgPerson" in admin_entry.attributes.attributes["objectClass"]
        assert admin_entry.attributes.attributes["uid"] == ["admin"]

        admin_group = next(e for e in entries if "cn=admins" in e.dn.value)
        assert admin_group.attributes.attributes["member"] == [
            "cn=admin,ou=people,dc=example,dc=com"
        ]

    def test_empty_ldif_content(self) -> None:
        """Test handling empty LDIF content."""
        empty_entries = flext_ldif_parse("")
        assert len(empty_entries) == 0

        whitespace_entries = flext_ldif_parse("   \n\n   ")
        assert len(whitespace_entries) == 0

    def test_invalid_ldif_raises_error(self) -> None:
        """Test that invalid LDIF raises appropriate errors."""
        invalid_ldif = """invalid: not a dn
objectClass: person
"""

        with pytest.raises(Exception):  # Should raise FlextLdifParseError
            flext_ldif_parse(invalid_ldif)

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
        entries1 = flext_ldif_parse(original_ldif)

        # Write to LDIF
        written_ldif = flext_ldif_write(entries1)

        # Parse again
        entries2 = flext_ldif_parse(written_ldif)

        # Should have same number of entries
        assert len(entries1) == len(entries2) == 1

        # Should have same DN
        assert entries1[0].dn.value == entries2[0].dn.value

        # Should have same core attributes
        entry1_attrs = entries1[0].attributes.attributes
        entry2_attrs = entries2[0].attributes.attributes

        for key in ["objectClass", "cn", "sn", "mail"]:
            assert entry1_attrs[key] == entry2_attrs[key]
