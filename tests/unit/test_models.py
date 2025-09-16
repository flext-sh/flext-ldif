"""Test LDIF models functionality using FlextTests patterns."""

from __future__ import annotations

import pytest

from flext_ldif import FlextLDIFModels


class TestFlextLDIFModelsEntry:
    """Test FlextLDIFModels.Entry functionality using FlextTests patterns."""

    def test_ldif_entry_creation(self, ldif_test_entries: list[dict[str, object]]) -> None:
        """Test basic LDIF entry creation using FlextTests patterns."""
        # Use test data from fixtures
        test_entry_data = ldif_test_entries[0]
        dn = test_entry_data["dn"]
        attributes = test_entry_data["attributes"]

        entry = FlextLDIFModels.Entry.model_validate(
            {
                "dn": dn,
                "attributes": attributes,
            }
        )

        # Use FlextTestsMatchers for assertions
        assert entry.dn.value == dn
        assert entry.attributes.data == attributes

    def test_ldif_entry_default_attributes(self) -> None:
        """Test LDIF entry creation with default attributes."""
        dn = "cn=test,dc=example,dc=com"
        entry = FlextLDIFModels.Entry.model_validate({"dn": dn})

        assert entry.dn.value == dn
        assert entry.attributes.data == {}

    def test_get_attribute_exists(
        self, ldif_test_entries: list[dict[str, object]]
    ) -> None:
        """Test getting an existing attribute using test data."""
        # Use realistic test data from fixtures
        test_entry_data = ldif_test_entries[0]
        entry = FlextLDIFModels.Entry.model_validate(test_entry_data)

        # Test getting existing attributes
        cn_values = entry.get_attribute("cn")
        mail_values = entry.get_attribute("mail")

        assert cn_values is not None
        assert mail_values is not None
        assert len(cn_values) > 0
        assert len(mail_values) > 0

    def test_get_attribute_not_exists(
        self, ldif_test_entries: list[dict[str, object]]
    ) -> None:
        """Test getting a non-existing attribute."""
        entry = FlextLDIFModels.Entry.model_validate(ldif_test_entries[0])

        assert entry.get_attribute("nonexistent") is None

    def test_set_attribute(self, ldif_test_entries: list[dict[str, object]]) -> None:
        """Test setting an attribute using FlextTests patterns."""
        entry = FlextLDIFModels.Entry.model_validate(ldif_test_entries[0])

        original_cn = entry.get_attribute("cn")
        entry.set_attribute("description", ["Test description"])

        assert entry.get_attribute("description") == ["Test description"]
        assert entry.get_attribute("cn") == original_cn  # Original should remain

    def test_set_attribute_overwrites(
        self, ldif_test_entries: list[dict[str, object]]
    ) -> None:
        """Test setting an attribute overwrites existing values."""
        entry = FlextLDIFModels.Entry.model_validate(ldif_test_entries[0])

        entry.set_attribute("cn", ["new_value"])

        assert entry.get_attribute("cn") == ["new_value"]

    def test_has_attribute_true(self, ldif_test_entries: list[dict[str, object]]) -> None:
        """Test has_attribute returns True for existing attribute."""
        entry = FlextLDIFModels.Entry.model_validate(ldif_test_entries[0])

        assert entry.has_attribute("cn")  # Should exist in test data
        assert entry.has_attribute("objectClass")  # Should exist in test data

    def test_has_attribute_false(self, ldif_test_entries: list[dict[str, object]]) -> None:
        """Test has_attribute returns False for non-existing attribute."""
        entry = FlextLDIFModels.Entry.model_validate(ldif_test_entries[0])

        assert not entry.has_attribute("nonexistent")
        assert not entry.has_attribute("imaginaryAttribute")

    def test_get_single_attribute_exists(
        self, ldif_test_entries: list[dict[str, object]]
    ) -> None:
        """Test getting single attribute value when it exists."""
        entry = FlextLDIFModels.Entry.model_validate(ldif_test_entries[0])

        cn_value = entry.get_single_attribute("cn")
        mail_value = entry.get_single_attribute("mail")

        assert cn_value is not None
        assert isinstance(cn_value, str)
        assert mail_value is not None
        assert isinstance(mail_value, str)  # Should return first value

    def test_get_single_attribute_not_exists(
        self, ldif_test_entries: list[dict[str, object]]
    ) -> None:
        """Test getting single attribute value when it doesn't exist."""
        entry = FlextLDIFModels.Entry.model_validate(ldif_test_entries[0])

        assert entry.get_single_attribute("nonexistent") is None

    def test_get_single_attribute_empty_list(self) -> None:
        """Test getting single attribute value from empty list."""
        entry = FlextLDIFModels.Entry.model_validate(
            {"dn": "cn=test,dc=example,dc=com", "attributes": {"empty": []}},
        )

        assert entry.get_single_attribute("empty") is None

    def test_to_ldif(self, ldif_test_entries: list[dict[str, object]]) -> None:
        """Test converting entry to LDIF string using test fixtures."""
        entry = FlextLDIFModels.Entry.model_validate(ldif_test_entries[0])

        ldif_str = entry.to_ldif()
        entry_dn = entry.dn.value

        # Verify LDIF format contains expected components
        assert f"dn: {entry_dn}" in ldif_str

        # Verify attributes are included
        for attr_name in entry.attributes.data:
            assert f"{attr_name}:" in ldif_str

        # Verify LDIF formatting
        assert ldif_str.endswith("\n")

    def test_from_ldif_block_valid(self) -> None:
        """Test creating entry from valid LDIF block."""
        ldif_block = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
objectClass: inetOrgPerson
mail: test@example.com"""

        entry = FlextLDIFModels.Entry.from_ldif_block(ldif_block)

        # SOLID fix: use correct DN value property instead of object comparison
        if entry.dn.value != "cn=test,dc=example,dc=com":
            dn_value_msg: str = (
                f"Expected {'cn=test,dc=example,dc=com'}, got {entry.dn.value}"
            )
            raise AssertionError(
                dn_value_msg,
            )
        assert entry.get_attribute("cn") == ["test"]
        if entry.get_attribute("objectClass") != ["person", "inetOrgPerson"]:
            oc_value_msg: str = f"Expected {['person', 'inetOrgPerson']}, got {entry.get_attribute('objectClass')}"
            raise AssertionError(
                oc_value_msg,
            )
        assert entry.get_attribute("mail") == ["test@example.com"]

    def test_from_ldif_block_empty(self) -> None:
        """Test creating entry from empty LDIF block."""
        with pytest.raises(ValueError, match="Missing DN"):
            FlextLDIFModels.Entry.from_ldif_block("")

    def test_from_ldif_block_whitespace_only(self) -> None:
        """Test creating entry from whitespace-only LDIF block."""
        with pytest.raises(ValueError, match="Missing DN"):
            FlextLDIFModels.Entry.from_ldif_block("   \n   \n   ")

    def test_from_ldif_block_no_dn(self) -> None:
        """Test creating entry from LDIF block without DN."""
        ldif_block = """cn: test
objectClass: person"""

        with pytest.raises(ValueError, match="Missing DN"):
            FlextLDIFModels.Entry.from_ldif_block(ldif_block)

    def test_from_ldif_block_dn_only(self) -> None:
        """Test creating entry from LDIF block with DN only."""
        ldif_block = "dn: cn=test,dc=example,dc=com"

        entry = FlextLDIFModels.Entry.from_ldif_block(ldif_block)

        if entry.dn.value != "cn=test,dc=example,dc=com":
            msg: str = f"Expected {'cn=test,dc=example,dc=com'}, got {entry.dn.value}"
            raise AssertionError(
                msg,
            )
        assert entry.attributes.data == {}

    def test_from_ldif_block_with_whitespace(self) -> None:
        """Test creating entry from LDIF block with extra whitespace."""
        ldif_block = """

      dn: cn=test,dc=example,dc=com
      cn: test
      objectClass: person

      """

        entry = FlextLDIFModels.Entry.from_ldif_block(ldif_block)

        if entry.dn.value != "cn=test,dc=example,dc=com":
            dn_whitespace_msg: str = (
                f"Expected {'cn=test,dc=example,dc=com'}, got {entry.dn.value}"
            )
            raise AssertionError(
                dn_whitespace_msg,
            )
        assert entry.get_attribute("cn") == ["test"]
        if entry.get_attribute("objectClass") != ["person"]:
            oc_whitespace_msg: str = (
                f"Expected {['person']}, got {entry.get_attribute('objectClass')}"
            )
            raise AssertionError(
                oc_whitespace_msg,
            )

    def test_from_ldif_block_multiple_values(self) -> None:
        """Test creating entry with multiple values for same attribute."""
        ldif_block = """dn: cn=test,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
mail: test@example.com
mail: test2@example.com"""

        entry = FlextLDIFModels.Entry.from_ldif_block(ldif_block)

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

        entry = FlextLDIFModels.Entry.from_ldif_block(ldif_block)

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
        entry = FlextLDIFModels.Entry.from_ldif_block(ldif_block)

        if entry.dn.value != "cn=test,dc=example,dc=com":
            msg: str = f"Expected {'cn=test,dc=example,dc=com'}, got {entry.dn.value}"
            raise AssertionError(
                msg,
            )
        assert entry.get_attribute("cn") == ["test"]
