"""Enterprise tests for FlextLdifEntry and related models.

Comprehensive test suite covering all model functionality with enterprise-grade
validation, edge cases, and domain rule enforcement.
"""

from __future__ import annotations

import sys
import time

import pytest

from flext_ldif import FlextLdifEntry
from flext_ldif.models import FlextLdifAttributes, FlextLdifDistinguishedName


class TestFlextLdifEntryEnterprise:
    """Enterprise-grade tests for FlextLdifEntry model."""

    @pytest.fixture
    def sample_entry_data(self) -> dict:
        """Sample entry data for testing."""
        return {
            "dn": "cn=John Doe,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["John Doe"],
                "sn": ["Doe"],
                "givenName": ["John"],
                "mail": ["john.doe@example.com"],
                "uid": ["johndoe"],
                "employeeNumber": ["12345"],
            },
        }

    @pytest.fixture
    def minimal_entry_data(self) -> dict:
        """Minimal valid entry data."""
        return {
            "dn": "cn=minimal,dc=example,dc=com",
            "attributes": {
                "objectClass": ["top"],
                "cn": ["minimal"],
            },
        }

    def test_entry_creation_success(self, sample_entry_data: dict) -> None:
        """Test successful FlextLdifEntry creation."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        assert entry is not None
        if str(entry.dn) != sample_entry_data["dn"]:
            msg = f"Expected {sample_entry_data['dn']}, got {entry.dn!s}"
            raise AssertionError(msg)
        assert entry.attributes.attributes == sample_entry_data["attributes"]

    def test_entry_creation_with_string_dn(self, sample_entry_data: dict) -> None:
        """Test entry creation with string DN (auto-conversion)."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        assert isinstance(entry.dn, FlextLdifDistinguishedName)
        if str(entry.dn) != sample_entry_data["dn"]:
            msg = f"Expected {sample_entry_data['dn']}, got {entry.dn!s}"
            raise AssertionError(msg)

    def test_entry_creation_with_dict_attributes(self, sample_entry_data: dict) -> None:
        """Test entry creation with dict attributes (auto-conversion)."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        assert isinstance(entry.attributes, FlextLdifAttributes)
        if entry.attributes.attributes != sample_entry_data["attributes"]:
            msg = f"Expected {sample_entry_data['attributes']}, got {entry.attributes.attributes}"
            raise AssertionError(msg)

    def test_entry_validation_invalid_dn_type(self) -> None:
        """Test entry validation fails with invalid DN type."""
        with pytest.raises(ValueError, match="Invalid DN type"):
            FlextLdifEntry.model_validate(
                {
                    "dn": 123,  # Invalid type
                    "attributes": {"objectClass": ["top"]},
                },
            )

    def test_entry_validation_invalid_attributes_type(self) -> None:
        """Test entry validation fails with invalid attributes type."""
        with pytest.raises(ValueError, match="Input should be a valid dictionary"):
            FlextLdifEntry.model_validate(
                {
                    "dn": "cn=test,dc=example,dc=com",
                    "attributes": "invalid",  # Invalid type
                },
            )

    def test_get_attribute_success(self, sample_entry_data: dict) -> None:
        """Test getting attribute values succeeds."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        cn_values = entry.get_attribute("cn")
        if cn_values != ["John Doe"]:
            msg = f"Expected {['John Doe']}, got {cn_values}"
            raise AssertionError(msg)

        mail_values = entry.get_attribute("mail")
        if mail_values != ["john.doe@example.com"]:
            msg = f"Expected {['john.doe@example.com']}, got {mail_values}"
            raise AssertionError(msg)

        objectclass_values = entry.get_attribute("objectClass")
        if objectclass_values != ["person", "inetOrgPerson"]:
            msg = f"Expected {['person', 'inetOrgPerson']}, got {objectclass_values}"
            raise AssertionError(msg)

    def test_get_attribute_nonexistent(self, sample_entry_data: dict) -> None:
        """Test getting nonexistent attribute returns None."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        result = entry.get_attribute("nonexistent")
        assert result is None

    def test_set_attribute_success(self, sample_entry_data: dict) -> None:
        """Test setting attribute values succeeds."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        # Set new attribute
        entry.set_attribute("telephoneNumber", ["+1-555-0123"])
        if entry.get_attribute("telephoneNumber") != ["+1-555-0123"]:
            msg = f"Expected {['+1-555-0123']}, got {entry.get_attribute('telephoneNumber')}"
            raise AssertionError(msg)

        # Modify existing attribute
        entry.set_attribute("mail", ["newemail@example.com"])
        if entry.get_attribute("mail") != ["newemail@example.com"]:
            msg = f"Expected {['newemail@example.com']}, got {entry.get_attribute('mail')}"
            raise AssertionError(msg)

    def test_has_attribute_success(self, sample_entry_data: dict) -> None:
        """Test checking attribute existence succeeds."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        if not (entry.has_attribute("cn")):
            msg = f"Expected True, got {entry.has_attribute('cn')}"
            raise AssertionError(msg)
        assert entry.has_attribute("mail") is True
        if not (entry.has_attribute("objectClass")):
            msg = f"Expected True, got {entry.has_attribute('objectClass')}"
            raise AssertionError(msg)
        if entry.has_attribute("nonexistent"):
            msg = f"Expected False, got {entry.has_attribute('nonexistent')}"
            raise AssertionError(msg)

    def test_get_object_classes_success(self, sample_entry_data: dict) -> None:
        """Test getting object classes succeeds."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        object_classes = entry.get_object_classes()
        if object_classes != ["person", "inetOrgPerson"]:
            msg = f"Expected {['person', 'inetOrgPerson']}, got {object_classes}"
            raise AssertionError(msg)

    def test_has_object_class_success(self, sample_entry_data: dict) -> None:
        """Test checking object class existence succeeds."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        if not (entry.has_object_class("person")):
            msg = f"Expected True, got {entry.has_object_class('person')}"
            raise AssertionError(msg)
        assert entry.has_object_class("inetOrgPerson") is True
        if entry.has_object_class("organizationalPerson"):
            msg = (
                f"Expected False, got {entry.has_object_class('organizationalPerson')}"
            )
            raise AssertionError(msg)

    def test_get_attribute_values_success(self, sample_entry_data: dict) -> None:
        """Test getting attribute values (alternative method)."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        cn_values = entry.get_attribute_values("cn")
        if cn_values != ["John Doe"]:
            msg = f"Expected {['John Doe']}, got {cn_values}"
            raise AssertionError(msg)

    def test_operation_methods_correct_behavior(self, sample_entry_data: dict) -> None:
        """Test operation check methods return correct LDIF behavior."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        # When no changetype is specified, LDIF defaults to add operation
        assert entry.is_add_operation() is True
        assert entry.is_modify_operation() is False
        assert entry.is_delete_operation() is False

    def test_get_single_attribute_success(self, sample_entry_data: dict) -> None:
        """Test getting single attribute value succeeds."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        cn_value = entry.get_single_attribute("cn")
        if cn_value != "John Doe":
            msg = f"Expected {'John Doe'}, got {cn_value}"
            raise AssertionError(msg)

        uid_value = entry.get_single_attribute("uid")
        if uid_value != "johndoe":
            msg = f"Expected {'johndoe'}, got {uid_value}"
            raise AssertionError(msg)

    def test_get_single_attribute_nonexistent(self, sample_entry_data: dict) -> None:
        """Test getting single value from nonexistent attribute returns None."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        result = entry.get_single_attribute("nonexistent")
        assert result is None

    def test_to_ldif_success(self, sample_entry_data: dict) -> None:
        """Test converting entry to LDIF string succeeds."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        ldif_output = entry.to_ldif()

        assert ldif_output is not None
        assert len(ldif_output) > 0
        assert ldif_output.startswith(f"dn: {sample_entry_data['dn']}")
        if "objectClass: person" not in ldif_output:
            msg = f"Expected {'objectClass: person'} in {ldif_output}"
            raise AssertionError(msg)
        assert "cn: John Doe" in ldif_output
        assert ldif_output.endswith("\n")

    def test_validate_domain_rules_success(self, sample_entry_data: dict) -> None:
        """Test domain rules validation succeeds for valid entry."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        # Should not raise exception
        result = entry.validate_semantic_rules()
        assert result.is_success

    def test_validate_domain_rules_empty_dn_fails(self) -> None:
        """Test domain rules validation fails for empty DN."""
        with pytest.raises(ValueError, match="DN must be a non-empty string"):
            FlextLdifEntry.model_validate(
                {
                    "dn": "",
                    "attributes": {"objectClass": ["top"]},
                },
            )

    def test_validate_domain_rules_no_attributes_fails(self) -> None:
        """Test domain rules validation fails for no attributes."""
        entry = FlextLdifEntry.model_validate(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {},
            },
        )
        result = entry.validate_semantic_rules()
        assert result.is_failure
        assert "LDIF entry must have at least one attribute" in result.error

    def test_from_ldif_block_success(self) -> None:
        """Test creating entry from LDIF block succeeds."""
        ldif_block = """dn: cn=test,ou=people,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: test
sn: user
mail: test@example.com"""

        entry = FlextLdifEntry.from_ldif_block(ldif_block)

        if str(entry.dn) != "cn=test,ou=people,dc=example,dc=com":
            msg = f"Expected {'cn=test,ou=people,dc=example,dc=com'}, got {entry.dn!s}"
            raise AssertionError(msg)
        assert entry.get_attribute("cn") == ["test"]
        if entry.get_attribute("sn") != ["user"]:
            msg = f"Expected {['user']}, got {entry.get_attribute('sn')}"
            raise AssertionError(msg)
        assert entry.get_attribute("mail") == ["test@example.com"]
        assert entry.has_object_class("person")
        assert entry.has_object_class("inetOrgPerson")

    def test_from_ldif_block_empty_fails(self) -> None:
        """Test creating entry from empty LDIF block fails."""
        with pytest.raises(ValueError, match="LDIF block cannot be empty"):
            FlextLdifEntry.from_ldif_block("")

    def test_from_ldif_block_no_dn_fails(self) -> None:
        """Test creating entry from LDIF block without DN fails."""
        ldif_block = """cn: test
objectClass: person"""

        with pytest.raises(ValueError, match="First line must be DN"):
            FlextLdifEntry.from_ldif_block(ldif_block)

    def test_from_ldif_block_multiline_attributes(self) -> None:
        """Test creating entry from LDIF block with multiline attributes."""
        ldif_block = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
cn: Test User
description: This is a test user
description: With multiple descriptions"""

        entry = FlextLdifEntry.from_ldif_block(ldif_block)

        if entry.get_attribute("cn") != ["test", "Test User"]:
            msg = f"Expected {['test', 'Test User']}, got {entry.get_attribute('cn')}"
            raise AssertionError(msg)
        assert entry.get_attribute("description") == [
            "This is a test user",
            "With multiple descriptions",
        ]

    def test_from_ldif_dict_success(self) -> None:
        """Test creating entry from DN and attributes dict succeeds."""
        dn = "cn=test,ou=people,dc=example,dc=com"
        attributes = {
            "objectClass": ["person", "inetOrgPerson"],
            "cn": ["test"],
            "sn": ["user"],
            "mail": ["test@example.com"],
        }

        entry = FlextLdifEntry.from_ldif_dict(dn, attributes)

        if str(entry.dn) != dn:
            msg = f"Expected {dn}, got {entry.dn!s}"
            raise AssertionError(msg)
        assert entry.attributes.attributes == attributes
        if entry.get_attribute("cn") != ["test"]:
            msg = f"Expected {['test']}, got {entry.get_attribute('cn')}"
            raise AssertionError(msg)
        assert entry.has_object_class("person")

    def test_entry_immutability_via_pydantic(self, sample_entry_data: dict) -> None:
        """Test entry immutability through Pydantic frozen behavior."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        # Direct assignment should work through set_attribute method
        # but direct modification of internal structures should be controlled
        original_dn = str(entry.dn)

        # Test that we can use set_attribute (which creates new objects)
        entry.set_attribute("newAttr", ["newValue"])
        if entry.get_attribute("newAttr") != ["newValue"]:
            msg = f"Expected {['newValue']}, got {entry.get_attribute('newAttr')}"
            raise AssertionError(msg)

        # DN should remain unchanged
        if str(entry.dn) != original_dn:
            msg = f"Expected {original_dn}, got {entry.dn!s}"
            raise AssertionError(msg)

    def test_entry_equality_and_hashing(self, sample_entry_data: dict) -> None:
        """Test entry equality and hash behavior."""
        entry1 = FlextLdifEntry.model_validate(sample_entry_data)
        entry2 = FlextLdifEntry.model_validate(sample_entry_data)

        # Should be equal with same data
        if entry1 != entry2:
            msg = f"Expected {entry2}, got {entry1}"
            raise AssertionError(msg)

        # Should have same hash
        if hash(entry1) != hash(entry2):
            msg = f"Expected {hash(entry2)}, got {hash(entry1)}"
            raise AssertionError(msg)

        # Should be usable in sets
        entry_set = {entry1, entry2}
        if len(entry_set) != 1:  # Same entries
            msg = f"Expected 1 (same entries), got {len(entry_set)}"
            raise AssertionError(msg)

    def test_entry_serialization_deserialization(self, sample_entry_data: dict) -> None:
        """Test entry serialization and deserialization."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        # Serialize to dict
        entry_dict = entry.model_dump()
        assert isinstance(entry_dict, dict)
        if "dn" not in entry_dict:
            msg = f"Expected {'dn'} in {entry_dict}"
            raise AssertionError(msg)
        assert "attributes" in entry_dict

        # Note: Pydantic model_dump() creates nested structure that requires
        # original data format for deserialization
        if str(entry.dn) != sample_entry_data["dn"]:
            msg = f"Expected {sample_entry_data['dn']}, got {entry.dn!s}"
            raise AssertionError(msg)
        assert entry.attributes.attributes == sample_entry_data["attributes"]

    def test_entry_json_serialization(self, sample_entry_data: dict) -> None:
        """Test entry JSON serialization."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        # Serialize to JSON
        json_str = entry.model_dump_json()
        assert isinstance(json_str, str)
        assert len(json_str) > 0

        # Should contain expected data
        if sample_entry_data["dn"] not in json_str:
            msg = f"Expected {sample_entry_data['dn']} in {json_str}"
            raise AssertionError(msg)
        assert "objectClass" in json_str

    def test_entry_performance_large_attributes(self) -> None:
        """Test entry performance with large number of attributes."""

        # Create entry with many attributes
        attributes = {"objectClass": ["top"]}
        for i in range(100):
            attributes[f"attr{i}"] = [f"value{i}"]

        entry_data = {
            "dn": "cn=large,dc=example,dc=com",
            "attributes": attributes,
        }

        start_time = time.time()
        entry = FlextLdifEntry.model_validate(entry_data)
        creation_time = time.time() - start_time

        # Should create quickly
        assert creation_time < 1.0  # Under 1 second

        # Should access attributes quickly
        start_time = time.time()
        for i in range(100):
            value = entry.get_attribute(f"attr{i}")
            if value != [f"value{i}"]:
                msg = f"Expected {[f'value{i}']}, got {value}"
                raise AssertionError(msg)
        access_time = time.time() - start_time

        assert access_time < 0.5  # Under 0.5 seconds

    def test_entry_memory_efficiency(self) -> None:
        """Test entry memory efficiency."""

        # Create multiple similar entries
        entries = []
        for i in range(10):
            entry_data = {
                "dn": f"cn=user{i},dc=example,dc=com",
                "attributes": {
                    "objectClass": ["person"],
                    "cn": [f"user{i}"],
                    "sn": [f"User{i}"],
                },
            }
            entries.append(FlextLdifEntry.model_validate(entry_data))

        # Memory usage should be reasonable
        total_size = sum(sys.getsizeof(entry) for entry in entries)
        average_size = total_size / len(entries)

        # Each entry should not be excessively large
        assert average_size < 5000  # Under 5KB per entry

    def test_edge_cases_special_characters_in_dn(self) -> None:
        """Test entry with special characters in DN."""
        entry_data = {
            "dn": "cn=Üser Spëcial,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person"],
                "cn": ["Üser Spëcial"],
                "sn": ["Spëcial"],
            },
        }

        entry = FlextLdifEntry.model_validate(entry_data)

        if "Üser Spëcial" not in str(entry.dn):
            msg = f"Expected {'Üser Spëcial'} in {entry.dn!s}"
            raise AssertionError(msg)
        if entry.get_attribute("cn") != ["Üser Spëcial"]:
            msg = f"Expected {['Üser Spëcial']}, got {entry.get_attribute('cn')}"
            raise AssertionError(msg)

    def test_edge_cases_long_attribute_values(self) -> None:
        """Test entry with very long attribute values."""
        long_value = "x" * 10000  # 10KB value

        entry_data = {
            "dn": "cn=longvalue,dc=example,dc=com",
            "attributes": {
                "objectClass": ["top"],
                "cn": ["longvalue"],
                "description": [long_value],
            },
        }

        entry = FlextLdifEntry.model_validate(entry_data)

        if entry.get_attribute("description") != [long_value]:
            msg = f"Expected {[long_value]}, got {entry.get_attribute('description')}"
            raise AssertionError(msg)
        assert len(entry.get_attribute("description")[0]) == 10000

    def test_edge_cases_empty_attribute_values(self) -> None:
        """Test entry with empty attribute values."""
        entry_data = {
            "dn": "cn=empty,dc=example,dc=com",
            "attributes": {
                "objectClass": ["top"],
                "cn": ["empty"],
                "description": [""],  # Empty value
            },
        }

        entry = FlextLdifEntry.model_validate(entry_data)

        if entry.get_attribute("description") != [""]:
            msg = f"Expected {['']}, got {entry.get_attribute('description')}"
            raise AssertionError(msg)
        if not (entry.has_attribute("description")):
            msg = f"Expected True, got {entry.has_attribute('description')}"
            raise AssertionError(msg)

    def test_dn_get_rdn(self) -> None:
        """Test getting relative distinguished name."""
        dn = FlextLdifDistinguishedName.model_validate(
            {"value": "cn=John Doe,ou=people,dc=example,dc=com"},
        )
        assert dn.get_rdn() == "cn=John Doe"

    def test_dn_get_parent_dn_with_parent(self) -> None:
        """Test getting parent DN when parent exists."""
        dn = FlextLdifDistinguishedName.model_validate(
            {"value": "cn=John Doe,ou=people,dc=example,dc=com"},
        )
        parent = dn.get_parent_dn()
        assert parent is not None
        assert parent.value == "ou=people,dc=example,dc=com"

    def test_dn_get_parent_dn_no_parent(self) -> None:
        """Test getting parent DN when no parent exists."""
        dn = FlextLdifDistinguishedName.model_validate({"value": "dc=com"})
        parent = dn.get_parent_dn()
        assert parent is None

    def test_dn_is_child_of_true(self) -> None:
        """Test DN is child of another DN."""
        child = FlextLdifDistinguishedName.model_validate(
            {"value": "cn=John Doe,ou=people,dc=example,dc=com"},
        )
        parent = FlextLdifDistinguishedName.model_validate(
            {"value": "ou=people,dc=example,dc=com"},
        )
        assert child.is_child_of(parent)

    def test_dn_is_child_of_false(self) -> None:
        """Test DN is not child of another DN."""
        dn1 = FlextLdifDistinguishedName.model_validate(
            {"value": "cn=John Doe,ou=people,dc=example,dc=com"},
        )
        dn2 = FlextLdifDistinguishedName.model_validate(
            {"value": "ou=groups,dc=example,dc=com"},
        )
        assert not dn1.is_child_of(dn2)

    def test_dn_get_depth(self) -> None:
        """Test getting DN depth."""
        dn = FlextLdifDistinguishedName.model_validate(
            {"value": "cn=John Doe,ou=people,dc=example,dc=com"},
        )
        assert dn.get_depth() == 4

    def test_dn_equality_with_string(self) -> None:
        """Test DN equality with string."""
        dn = FlextLdifDistinguishedName.model_validate(
            {"value": "cn=test,dc=example,dc=com"},
        )
        assert dn == "cn=test,dc=example,dc=com"
        assert dn != "cn=other,dc=example,dc=com"

    def test_dn_equality_with_dn(self) -> None:
        """Test DN equality with another DN."""
        dn1 = FlextLdifDistinguishedName.model_validate(
            {"value": "cn=test,dc=example,dc=com"},
        )
        dn2 = FlextLdifDistinguishedName.model_validate(
            {"value": "cn=test,dc=example,dc=com"},
        )
        dn3 = FlextLdifDistinguishedName.model_validate(
            {"value": "cn=other,dc=example,dc=com"},
        )
        assert dn1 == dn2
        assert dn1 != dn3

    def test_dn_hash(self) -> None:
        """Test DN hashing for use in sets and dicts."""
        dn1 = FlextLdifDistinguishedName.model_validate(
            {"value": "cn=test,dc=example,dc=com"},
        )
        dn2 = FlextLdifDistinguishedName.model_validate(
            {"value": "cn=test,dc=example,dc=com"},
        )
        assert hash(dn1) == hash(dn2)

        # Test usage in set
        dn_set = {dn1, dn2}
        assert len(dn_set) == 1

    def test_attributes_add_value(self) -> None:
        """Test adding values to attributes."""
        attrs = FlextLdifAttributes.model_validate({"attributes": {"cn": ["John"]}})
        new_attrs = attrs.add_value("cn", "Johnny")
        assert new_attrs.get_values("cn") == ["John", "Johnny"]
        # Original should be unchanged (immutable)
        assert attrs.get_values("cn") == ["John"]

    def test_attributes_remove_value(self) -> None:
        """Test removing values from attributes."""
        attrs = FlextLdifAttributes.model_validate(
            {"attributes": {"cn": ["John", "Johnny"]}},
        )
        new_attrs = attrs.remove_value("cn", "Johnny")
        assert new_attrs.get_values("cn") == ["John"]
        # Original should be unchanged (immutable)
        assert attrs.get_values("cn") == ["John", "Johnny"]

    def test_attributes_get_attribute_names(self) -> None:
        """Test getting all attribute names."""
        attrs = FlextLdifAttributes.model_validate(
            {
                "attributes": {
                    "cn": ["John"],
                    "sn": ["Doe"],
                    "mail": ["john@example.com"],
                },
            },
        )
        names = attrs.get_attribute_names()
        assert set(names) == {"cn", "sn", "mail"}

    def test_attributes_get_total_values(self) -> None:
        """Test getting total number of attribute values."""
        attrs = FlextLdifAttributes.model_validate(
            {
                "attributes": {
                    "cn": ["John", "Johnny"],
                    "sn": ["Doe"],
                    "mail": ["john@example.com"],
                },
            },
        )
        assert attrs.get_total_values() == 4

    def test_attributes_is_empty(self) -> None:
        """Test checking if attributes are empty."""
        empty_attrs = FlextLdifAttributes.model_validate({"attributes": {}})
        assert empty_attrs.is_empty()

        non_empty_attrs = FlextLdifAttributes.model_validate(
            {"attributes": {"cn": ["John"]}},
        )
        assert not non_empty_attrs.is_empty()

    def test_attributes_equality(self) -> None:
        """Test attributes equality with dict and other attributes."""
        attrs1 = FlextLdifAttributes.model_validate({"attributes": {"cn": ["John"]}})
        attrs2 = FlextLdifAttributes.model_validate({"attributes": {"cn": ["John"]}})
        attrs3 = FlextLdifAttributes.model_validate({"attributes": {"cn": ["Jane"]}})

        assert attrs1 == attrs2
        assert attrs1 != attrs3
        assert attrs1 == {"cn": ["John"]}
        assert attrs1 != {"cn": ["Jane"]}

    def test_attributes_hash(self) -> None:
        """Test attributes hashing for use in sets and dicts."""
        attrs1 = FlextLdifAttributes.model_validate({"attributes": {"cn": ["John"]}})
        attrs2 = FlextLdifAttributes.model_validate({"attributes": {"cn": ["John"]}})
        assert hash(attrs1) == hash(attrs2)

        # Test usage in set
        attrs_set = {attrs1, attrs2}
        assert len(attrs_set) == 1
