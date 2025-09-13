"""Unit tests for LDIF parsing functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldif import (
    FlextLDIFAPI,
    FlextLDIFFormatHandler,
)
from flext_ldif.services import FlextLDIFServices


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

        # Test using REAL instance-based interface (not class method)
        handler = FlextLDIFFormatHandler()
        parse_result = handler.parse_ldif(ldif_content)
        assert parse_result.is_success
        entries = parse_result.value

        # Validate results
        assert len(entries) == 1
        entry = entries[0]

        assert entry.dn.value == "cn=John Doe,ou=people,dc=example,dc=com"
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

        handler = FlextLDIFFormatHandler()
        entries = FlextResult.unwrap_or_raise(handler.parse_ldif(ldif_content))

        assert len(entries) == 2

        # Check first entry
        admin = entries[0]
        assert admin.dn.value == "cn=Admin,ou=people,dc=example,dc=com"
        assert admin.get_attribute("cn") == ["Admin"]
        assert admin.get_attribute("sn") == ["Administrator"]

        # Check second entry
        user = entries[1]
        assert user.dn.value == "cn=User,ou=people,dc=example,dc=com"
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

        handler = FlextLDIFFormatHandler()
        entries = FlextResult.unwrap_or_raise(handler.parse_ldif(ldif_content))

        assert len(entries) == 1
        group = entries[0]

        assert group.dn.value == "cn=developers,ou=groups,dc=example,dc=com"
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

        handler = FlextLDIFFormatHandler()
        entries = FlextResult.unwrap_or_raise(handler.parse_ldif(ldif_content))

        assert len(entries) == 1
        ou = entries[0]

        assert ou.dn.value == "ou=people,dc=example,dc=com"
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

        handler = FlextLDIFFormatHandler()
        entries = FlextResult.unwrap_or_raise(handler.parse_ldif(ldif_content))

        # Test validation using services instead of core wrapper
        validator_service = FlextLDIFServices().validator
        validated_entries = FlextResult.unwrap_or_raise(
            validator_service.validate_entries(entries)
        )
        assert len(validated_entries) == 1

    def test_write_real_entries(self) -> None:
        """Test writing real entries back to LDIF format."""
        original_ldif = """dn: cn=WriteTest,dc=example,dc=com
objectClass: person
cn: WriteTest
sn: Test
"""

        # Parse original
        handler = FlextLDIFFormatHandler()
        entries = FlextResult.unwrap_or_raise(handler.parse_ldif(original_ldif))

        # Write back to LDIF
        written_ldif = FlextResult.unwrap_or_raise(handler.write_ldif(entries))

        # Should contain the essential data
        assert "dn: cn=WriteTest,dc=example,dc=com" in written_ldif
        assert "objectClass: person" in written_ldif
        assert "cn: WriteTest" in written_ldif
        assert "sn: Test" in written_ldif

        # Parse the written LDIF to verify it's valid
        reparsed_entries = FlextResult.unwrap_or_raise(handler.parse_ldif(written_ldif))
        assert len(reparsed_entries) == 1
        assert reparsed_entries[0].dn.value == entries[0].dn.value

    def test_api_class_directly(self) -> None:
        """Test using FlextLDIFAPI class directly."""
        api = FlextLDIFAPI()

        ldif_content = """dn: cn=APITest,dc=example,dc=com
objectClass: person
cn: APITest
sn: Direct
"""

        # Test parsing
        parse_result = api._operations.parse_string(ldif_content)
        assert parse_result.is_success
        assert parse_result.value is not None
        assert len(parse_result.value) == 1

        entries = parse_result.value

        # Test validation
        validate_result = api._operations.validate_entries(entries)
        assert validate_result.is_success
        assert validate_result.value is True

        # Test writing
        write_result = api._operations.write_string(entries)
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

        handler = FlextLDIFFormatHandler()
        entries = FlextResult.unwrap_or_raise(handler.parse_ldif(complex_ldif))

        # Should have 5 entries
        assert len(entries) == 5

        # Validate all entry types are parsed correctly
        dns = [str(entry.dn) for entry in entries]
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
        admin_entry = next(e for e in entries if "cn=admin" in str(e.dn))
        admin_object_classes = admin_entry.get_attribute("objectClass") or []
        assert "inetOrgPerson" in admin_object_classes
        assert admin_entry.get_attribute("uid") == ["admin"]

        admin_group = next(e for e in entries if "cn=admins" in str(e.dn))
        assert admin_group.get_attribute("member") == [
            "cn=admin,ou=people,dc=example,dc=com"
        ]

    def test_empty_ldif_content(self) -> None:
        """Test handling empty LDIF content."""
        handler = FlextLDIFFormatHandler()
        empty_entries = FlextResult.unwrap_or_raise(handler.parse_ldif(""))
        assert len(empty_entries) == 0

        whitespace_entries = FlextResult.unwrap_or_raise(
            handler.parse_ldif("   \n\n   ")
        )
        assert len(whitespace_entries) == 0

    def test_invalid_ldif_raises_error(self) -> None:
        """Test that invalid LDIF raises appropriate errors."""
        invalid_ldif = """invalid: not a dn
objectClass: person
"""

        handler = FlextLDIFFormatHandler()
        with pytest.raises(Exception):  # Should raise FlextLDIFParseError
            FlextResult.unwrap_or_raise(handler.parse_ldif(invalid_ldif))

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
        handler = FlextLDIFFormatHandler()
        entries1 = FlextResult.unwrap_or_raise(handler.parse_ldif(original_ldif))

        # Write to LDIF
        written_ldif = FlextResult.unwrap_or_raise(handler.write_ldif(entries1))

        # Parse again
        entries2 = FlextResult.unwrap_or_raise(handler.parse_ldif(written_ldif))

        # Should have same number of entries
        assert len(entries1) == len(entries2) == 1

        # Should have same DN
        assert entries1[0].dn.value == entries2[0].dn.value

        # Should have same core attributes
        entry1 = entries1[0]
        entry2 = entries2[0]

        for key in ["objectClass", "cn", "sn", "mail"]:
            assert entry1.get_attribute(key) == entry2.get_attribute(key)
