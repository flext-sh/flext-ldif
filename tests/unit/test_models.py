"""FLEXT-LDIF Domain Models Test Suite.

Comprehensive test suite for FLEXT-LDIF domain models including FlextLdifEntry,
FlextLdifDistinguishedName, and FlextLdifAttributes, validating business logic,
domain rules, and value object behaviors following Clean Architecture patterns.

Test Coverage:
    - Domain entity validation and business rules
    - Value object immutability and validation
    - Distinguished Name parsing and hierarchy operations
    - Attribute collection management and operations
    - Model serialization and deserialization patterns

Architecture:
    Tests the Domain Layer components in isolation, ensuring business logic
    correctness without external dependencies, following enterprise testing
    standards with comprehensive edge case coverage.

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

import pytest
from flext_core.exceptions import FlextValidationError

# Use proper import from root level
from flext_ldif import FlextLdifEntry

# Alias for backward compatibility in test
LDIFEntry = FlextLdifEntry


class TestLDIFEntry:
    """Test LDIFEntry functionality."""

    def test_ldif_entry_creation(self) -> None:
        """Test basic LDIF entry creation."""
        dn = "cn=test,dc=example,dc=com"
        attributes = {
            "cn": ["test"],
            "objectClass": ["person"],
        }

        entry = LDIFEntry.model_validate({"dn": dn, "attributes": attributes})

        if entry.dn.value != dn:
            msg: str = f"Expected {dn}, got {entry.dn.value}"
            raise AssertionError(msg)
        assert entry.attributes.attributes == attributes

    def test_ldif_entry_default_attributes(self) -> None:
        """Test LDIF entry creation with default attributes."""
        dn = "cn=test,dc=example,dc=com"
        entry = LDIFEntry.model_validate({"dn": dn})

        if entry.dn.value != dn:
            msg: str = f"Expected {dn}, got {entry.dn.value}"
            raise AssertionError(msg)
        assert entry.attributes.attributes == {}

    def test_get_attribute_exists(self) -> None:
        """Test getting an existing attribute."""
        entry = LDIFEntry.model_validate(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {
                    "cn": ["test"],
                    "mail": ["test@example.com", "test2@example.com"],
                },
            },
        )

        if entry.get_attribute("cn") != ["test"]:
            msg: str = f"Expected {['test']}, got {entry.get_attribute('cn')}"
            raise AssertionError(
                msg,
            )
        assert entry.get_attribute("mail") == ["test@example.com", "test2@example.com"]

    def test_get_attribute_not_exists(self) -> None:
        """Test getting a non-existing attribute."""
        entry = LDIFEntry.model_validate(
            {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}},
        )

        assert entry.get_attribute("nonexistent") is None

    def test_set_attribute(self) -> None:
        """Test setting an attribute."""
        entry = LDIFEntry.model_validate(
            {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}},
        )

        entry.set_attribute("mail", ["test@example.com"])

        if entry.get_attribute("mail") != ["test@example.com"]:
            msg: str = (
                f"Expected {['test@example.com']}, got {entry.get_attribute('mail')}"
            )
            raise AssertionError(
                msg,
            )
        assert entry.get_attribute("cn") == ["test"]  # Original should remain

    def test_set_attribute_overwrites(self) -> None:
        """Test setting an attribute overwrites existing values."""
        entry = LDIFEntry.model_validate(
            {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}},
        )

        entry.set_attribute("cn", ["new_value"])

        if entry.get_attribute("cn") != ["new_value"]:
            msg: str = f"Expected {['new_value']}, got {entry.get_attribute('cn')}"
            raise AssertionError(
                msg,
            )

    def test_has_attribute_true(self) -> None:
        """Test has_attribute returns True for existing attribute."""
        entry = LDIFEntry.model_validate(
            {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}},
        )

        if not (entry.has_attribute("cn")):
            msg: str = f"Expected True, got {entry.has_attribute('cn')}"
            raise AssertionError(msg)

    def test_has_attribute_false(self) -> None:
        """Test has_attribute returns False for non-existing attribute."""
        entry = LDIFEntry.model_validate(
            {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}},
        )

        if entry.has_attribute("nonexistent"):
            msg: str = f"Expected False, got {entry.has_attribute('nonexistent')}"
            raise AssertionError(
                msg,
            )

    def test_get_single_attribute_exists(self) -> None:
        """Test getting single attribute value when it exists."""
        entry = LDIFEntry.model_validate(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {
                    "cn": ["test"],
                    "mail": ["test@example.com", "test2@example.com"],
                },
            },
        )

        if entry.get_single_attribute("cn") != "test":
            msg: str = f"Expected {'test'}, got {entry.get_single_attribute('cn')}"
            raise AssertionError(
                msg,
            )
        assert entry.get_single_attribute("mail") == "test@example.com"  # First value

    def test_get_single_attribute_not_exists(self) -> None:
        """Test getting single attribute value when it doesn't exist."""
        entry = LDIFEntry.model_validate(
            {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}},
        )

        assert entry.get_single_attribute("nonexistent") is None

    def test_get_single_attribute_empty_list(self) -> None:
        """Test getting single attribute value from empty list."""
        entry = LDIFEntry.model_validate(
            {"dn": "cn=test,dc=example,dc=com", "attributes": {"empty": []}},
        )

        assert entry.get_single_attribute("empty") is None

    def test_to_ldif(self) -> None:
        """Test converting entry to LDIF string."""
        entry = LDIFEntry.model_validate(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {
                    "cn": ["test"],
                    "objectClass": ["person", "inetOrgPerson"],
                    "mail": ["test@example.com"],
                },
            },
        )

        ldif_str = entry.to_ldif()

        if "dn: cn=test,dc=example,dc=com" not in ldif_str:
            msg: str = f"Expected {'dn: cn=test,dc=example,dc=com'} in {ldif_str}"
            raise AssertionError(
                msg,
            )
        assert "cn: test" in ldif_str
        if "objectClass: person" not in ldif_str:
            msg: str = f"Expected {'objectClass: person'} in {ldif_str}"
            raise AssertionError(msg)
        assert "objectClass: inetOrgPerson" in ldif_str
        if "mail: test@example.com" not in ldif_str:
            msg: str = f"Expected {'mail: test@example.com'} in {ldif_str}"
            raise AssertionError(msg)
        assert ldif_str.endswith("\n")

    def test_from_ldif_block_valid(self) -> None:
        """Test creating entry from valid LDIF block."""
        ldif_block = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
objectClass: inetOrgPerson
mail: test@example.com"""

        entry = LDIFEntry.from_ldif_block(ldif_block)

        # SOLID fix: use correct DN value property instead of object comparison
        if entry.dn.value != "cn=test,dc=example,dc=com":
            msg: str = f"Expected {'cn=test,dc=example,dc=com'}, got {entry.dn.value}"
            raise AssertionError(
                msg,
            )
        assert entry.get_attribute("cn") == ["test"]
        if entry.get_attribute("objectClass") != ["person", "inetOrgPerson"]:
            msg: str = f"Expected {['person', 'inetOrgPerson']}, got {entry.get_attribute('objectClass')}"
            raise AssertionError(
                msg,
            )
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

        with pytest.raises(FlextValidationError, match="LDIF block must start with DN"):
            LDIFEntry.from_ldif_block(ldif_block)

    def test_from_ldif_block_dn_only(self) -> None:
        """Test creating entry from LDIF block with DN only."""
        ldif_block = "dn: cn=test,dc=example,dc=com"

        entry = LDIFEntry.from_ldif_block(ldif_block)

        if entry.dn.value != "cn=test,dc=example,dc=com":
            msg: str = f"Expected {'cn=test,dc=example,dc=com'}, got {entry.dn.value}"
            raise AssertionError(
                msg,
            )
        assert entry.attributes.attributes == {}

    def test_from_ldif_block_with_whitespace(self) -> None:
        """Test creating entry from LDIF block with extra whitespace."""
        ldif_block = """
        dn: cn=test,dc=example,dc=com
        cn: test
        objectClass: person

        """

        entry = LDIFEntry.from_ldif_block(ldif_block)

        if entry.dn.value != "cn=test,dc=example,dc=com":
            msg: str = f"Expected {'cn=test,dc=example,dc=com'}, got {entry.dn.value}"
            raise AssertionError(
                msg,
            )
        assert entry.get_attribute("cn") == ["test"]
        if entry.get_attribute("objectClass") != ["person"]:
            msg: str = (
                f"Expected {['person']}, got {entry.get_attribute('objectClass')}"
            )
            raise AssertionError(
                msg,
            )

    def test_from_ldif_block_multiple_values(self) -> None:
        """Test creating entry with multiple values for same attribute."""
        ldif_block = """dn: cn=test,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
mail: test@example.com
mail: test2@example.com"""

        entry = LDIFEntry.from_ldif_block(ldif_block)

        if entry.get_attribute("objectClass") != ["person", "inetOrgPerson"]:
            msg: str = f"Expected {['person', 'inetOrgPerson']}, got {entry.get_attribute('objectClass')}"
            raise AssertionError(
                msg,
            )
        assert entry.get_attribute("mail") == ["test@example.com", "test2@example.com"]

    def test_from_ldif_block_colon_in_value(self) -> None:
        """Test creating entry with colon in attribute value."""
        ldif_block = """dn: cn=test,dc=example,dc=com
description: This is a test: with colon
url: http://example.com:8080/path"""

        entry = LDIFEntry.from_ldif_block(ldif_block)

        if entry.get_attribute("description") != ["This is a test: with colon"]:
            msg: str = f"Expected {['This is a test: with colon']}, got {entry.get_attribute('description')}"
            raise AssertionError(
                msg,
            )
        assert entry.get_attribute("url") == ["http://example.com:8080/path"]

    def test_from_ldif_block_invalid_line_no_colon(self) -> None:
        """Test creating entry from LDIF block with line without colon."""
        ldif_block = """dn: cn=test,dc=example,dc=com
cn: test
invalid line without colon"""

        # Should ignore lines without colons
        entry = LDIFEntry.from_ldif_block(ldif_block)

        if entry.dn.value != "cn=test,dc=example,dc=com":
            msg: str = f"Expected {'cn=test,dc=example,dc=com'}, got {entry.dn.value}"
            raise AssertionError(
                msg,
            )
        assert entry.get_attribute("cn") == ["test"]
