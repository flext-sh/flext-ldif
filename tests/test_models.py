"""Tests for LDIF models."""

from __future__ import annotations

import pytest

# Use simplified imports from root level
from flext_ldif import LDIFEntry


class TestLDIFEntry:
    """Test LDIFEntry functionality."""

    def test_ldif_entry_creation(self) -> None:
        """Test basic LDIF entry creation."""
        dn = "cn=test,dc=example,dc=com"
        attributes = {
            "cn": ["test"],
            "objectClass": ["person"],
        }

        entry = LDIFEntry(dn=dn, attributes=attributes)

        assert entry.dn == dn
        assert entry.attributes == attributes

    def test_ldif_entry_default_attributes(self) -> None:
        """Test LDIF entry creation with default attributes."""
        dn = "cn=test,dc=example,dc=com"
        entry = LDIFEntry(dn=dn)

        assert entry.dn == dn
        assert entry.attributes == {}

    def test_get_attribute_exists(self) -> None:
        """Test getting an existing attribute."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "mail": ["test@example.com", "test2@example.com"],
            },
        )

        assert entry.get_attribute("cn") == ["test"]
        assert entry.get_attribute("mail") == ["test@example.com", "test2@example.com"]

    def test_get_attribute_not_exists(self) -> None:
        """Test getting a non-existing attribute."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
        )

        assert entry.get_attribute("nonexistent") is None

    def test_set_attribute(self) -> None:
        """Test setting an attribute."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
        )

        entry.set_attribute("mail", ["test@example.com"])

        assert entry.get_attribute("mail") == ["test@example.com"]
        assert entry.get_attribute("cn") == ["test"]  # Original should remain

    def test_set_attribute_overwrites(self) -> None:
        """Test setting an attribute overwrites existing values."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
        )

        entry.set_attribute("cn", ["new_value"])

        assert entry.get_attribute("cn") == ["new_value"]

    def test_has_attribute_true(self) -> None:
        """Test has_attribute returns True for existing attribute."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
        )

        assert entry.has_attribute("cn") is True

    def test_has_attribute_false(self) -> None:
        """Test has_attribute returns False for non-existing attribute."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
        )

        assert entry.has_attribute("nonexistent") is False

    def test_get_single_attribute_exists(self) -> None:
        """Test getting single attribute value when it exists."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "mail": ["test@example.com", "test2@example.com"],
            },
        )

        assert entry.get_single_attribute("cn") == "test"
        assert entry.get_single_attribute("mail") == "test@example.com"  # First value

    def test_get_single_attribute_not_exists(self) -> None:
        """Test getting single attribute value when it doesn't exist."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
        )

        assert entry.get_single_attribute("nonexistent") is None

    def test_get_single_attribute_empty_list(self) -> None:
        """Test getting single attribute value from empty list."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={"empty": []},
        )

        assert entry.get_single_attribute("empty") is None

    def test_to_ldif(self) -> None:
        """Test converting entry to LDIF string."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["person", "inetOrgPerson"],
                "mail": ["test@example.com"],
            },
        )

        ldif_str = entry.to_ldif()

        assert "dn: cn=test,dc=example,dc=com" in ldif_str
        assert "cn: test" in ldif_str
        assert "objectClass: person" in ldif_str
        assert "objectClass: inetOrgPerson" in ldif_str
        assert "mail: test@example.com" in ldif_str
        assert ldif_str.endswith("\n")

    def test_from_ldif_block_valid(self) -> None:
        """Test creating entry from valid LDIF block."""
        ldif_block = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
objectClass: inetOrgPerson
mail: test@example.com"""

        entry = LDIFEntry.from_ldif_block(ldif_block)

        assert entry.dn == "cn=test,dc=example,dc=com"
        assert entry.get_attribute("cn") == ["test"]
        assert entry.get_attribute("objectClass") == ["person", "inetOrgPerson"]
        assert entry.get_attribute("mail") == ["test@example.com"]

    def test_from_ldif_block_empty(self) -> None:
        """Test creating entry from empty LDIF block."""
        with pytest.raises(ValueError, match="LDIF block cannot be empty"):
            LDIFEntry.from_ldif_block("")

    def test_from_ldif_block_whitespace_only(self) -> None:
        """Test creating entry from whitespace-only LDIF block."""
        with pytest.raises(ValueError, match="LDIF block cannot be empty"):
            LDIFEntry.from_ldif_block("   \n   \n   ")

    def test_from_ldif_block_no_dn(self) -> None:
        """Test creating entry from LDIF block without DN."""
        ldif_block = """cn: test
objectClass: person"""

        with pytest.raises(ValueError, match="First line must be DN"):
            LDIFEntry.from_ldif_block(ldif_block)

    def test_from_ldif_block_dn_only(self) -> None:
        """Test creating entry from LDIF block with DN only."""
        ldif_block = "dn: cn=test,dc=example,dc=com"

        entry = LDIFEntry.from_ldif_block(ldif_block)

        assert entry.dn == "cn=test,dc=example,dc=com"
        assert entry.attributes == {}

    def test_from_ldif_block_with_whitespace(self) -> None:
        """Test creating entry from LDIF block with extra whitespace."""
        ldif_block = """
        dn: cn=test,dc=example,dc=com
        cn: test
        objectClass: person

        """

        entry = LDIFEntry.from_ldif_block(ldif_block)

        assert entry.dn == "cn=test,dc=example,dc=com"
        assert entry.get_attribute("cn") == ["test"]
        assert entry.get_attribute("objectClass") == ["person"]

    def test_from_ldif_block_multiple_values(self) -> None:
        """Test creating entry with multiple values for same attribute."""
        ldif_block = """dn: cn=test,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
mail: test@example.com
mail: test2@example.com"""

        entry = LDIFEntry.from_ldif_block(ldif_block)

        assert entry.get_attribute("objectClass") == ["person", "inetOrgPerson"]
        assert entry.get_attribute("mail") == ["test@example.com", "test2@example.com"]

    def test_from_ldif_block_colon_in_value(self) -> None:
        """Test creating entry with colon in attribute value."""
        ldif_block = """dn: cn=test,dc=example,dc=com
description: This is a test: with colon
url: http://example.com:8080/path"""

        entry = LDIFEntry.from_ldif_block(ldif_block)

        assert entry.get_attribute("description") == ["This is a test: with colon"]
        assert entry.get_attribute("url") == ["http://example.com:8080/path"]

    def test_from_ldif_block_invalid_line_no_colon(self) -> None:
        """Test creating entry from LDIF block with line without colon."""
        ldif_block = """dn: cn=test,dc=example,dc=com
cn: test
invalid line without colon"""

        # Should ignore lines without colons
        entry = LDIFEntry.from_ldif_block(ldif_block)

        assert entry.dn == "cn=test,dc=example,dc=com"
        assert entry.get_attribute("cn") == ["test"]
