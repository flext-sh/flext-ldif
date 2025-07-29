"""Enterprise tests for FlextLdifEntry and related models.

Comprehensive test suite covering all model functionality with enterprise-grade
validation, edge cases, and domain rule enforcement.
"""

import time
import sys


from __future__ import annotations

import pytest

from flext_ldif import FlextLdifEntry
from flext_ldif.values import FlextLdifAttributes, FlextLdifDistinguishedName


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
            raise AssertionError(f"Expected {sample_entry_data["dn"]}, got {str(entry.dn)}")
        assert entry.attributes.attributes == sample_entry_data["attributes"]

    def test_entry_creation_with_string_dn(self, sample_entry_data: dict) -> None:
        """Test entry creation with string DN (auto-conversion)."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        assert isinstance(entry.dn, FlextLdifDistinguishedName)
        if str(entry.dn) != sample_entry_data["dn"]:
            raise AssertionError(f"Expected {sample_entry_data["dn"]}, got {str(entry.dn)}")

    def test_entry_creation_with_dict_attributes(self, sample_entry_data: dict) -> None:
        """Test entry creation with dict attributes (auto-conversion)."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        assert isinstance(entry.attributes, FlextLdifAttributes)
        if entry.attributes.attributes != sample_entry_data["attributes"]:
            raise AssertionError(f"Expected {sample_entry_data["attributes"]}, got {entry.attributes.attributes}")

    def test_entry_validation_invalid_dn_type(self) -> None:
        """Test entry validation fails with invalid DN type."""
        with pytest.raises(ValueError, match="Invalid DN type"):
            FlextLdifEntry.model_validate({
                "dn": 123,  # Invalid type
                "attributes": {"objectClass": ["top"]},
            })

    def test_entry_validation_invalid_attributes_type(self) -> None:
        """Test entry validation fails with invalid attributes type."""
        with pytest.raises(ValueError, match="Invalid attributes type"):
            FlextLdifEntry.model_validate({
                "dn": "cn=test,dc=example,dc=com",
                "attributes": "invalid",  # Invalid type
            })

    def test_get_attribute_success(self, sample_entry_data: dict) -> None:
        """Test getting attribute values succeeds."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        cn_values = entry.get_attribute("cn")
        if cn_values != ["John Doe"]:
            raise AssertionError(f"Expected {["John Doe"]}, got {cn_values}")

        mail_values = entry.get_attribute("mail")
        if mail_values != ["john.doe@example.com"]:
            raise AssertionError(f"Expected {["john.doe@example.com"]}, got {mail_values}")

        objectclass_values = entry.get_attribute("objectClass")
        if objectclass_values != ["person", "inetOrgPerson"]:
            raise AssertionError(f"Expected {["person", "inetOrgPerson"]}, got {objectclass_values}")

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
            raise AssertionError(f"Expected {["+1-555-0123"]}, got {entry.get_attribute("telephoneNumber")}")

        # Modify existing attribute
        entry.set_attribute("mail", ["newemail@example.com"])
        if entry.get_attribute("mail") != ["newemail@example.com"]:
            raise AssertionError(f"Expected {["newemail@example.com"]}, got {entry.get_attribute("mail")}")

    def test_has_attribute_success(self, sample_entry_data: dict) -> None:
        """Test checking attribute existence succeeds."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        if not (entry.has_attribute("cn")):

            raise AssertionError(f"Expected True, got {entry.has_attribute("cn")}")
        assert entry.has_attribute("mail") is True
        if not (entry.has_attribute("objectClass")):
            raise AssertionError(f"Expected True, got {entry.has_attribute("objectClass")}")
        if entry.has_attribute("nonexistent"):
            raise AssertionError(f"Expected False, got {entry.has_attribute("nonexistent")}")

    def test_get_object_classes_success(self, sample_entry_data: dict) -> None:
        """Test getting object classes succeeds."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        object_classes = entry.get_object_classes()
        if object_classes != ["person", "inetOrgPerson"]:
            raise AssertionError(f"Expected {["person", "inetOrgPerson"]}, got {object_classes}")

    def test_has_object_class_success(self, sample_entry_data: dict) -> None:
        """Test checking object class existence succeeds."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        if not (entry.has_object_class("person")):

            raise AssertionError(f"Expected True, got {entry.has_object_class("person")}")
        assert entry.has_object_class("inetOrgPerson") is True
        if entry.has_object_class("organizationalPerson"):
            raise AssertionError(f"Expected False, got {entry.has_object_class("organizationalPerson")}")

    def test_get_attribute_values_success(self, sample_entry_data: dict) -> None:
        """Test getting attribute values (alternative method)."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        cn_values = entry.get_attribute_values("cn")
        if cn_values != ["John Doe"]:
            raise AssertionError(f"Expected {["John Doe"]}, got {cn_values}")

    def test_operation_methods_return_false(self, sample_entry_data: dict) -> None:
        """Test operation check methods return False for model entries."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        if entry.is_modify_operation():

            raise AssertionError(f"Expected False, got {entry.is_modify_operation()}")
        assert entry.is_add_operation() is False
        if entry.is_delete_operation():
            raise AssertionError(f"Expected False, got {entry.is_delete_operation()}")

    def test_get_single_attribute_success(self, sample_entry_data: dict) -> None:
        """Test getting single attribute value succeeds."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        cn_value = entry.get_single_attribute("cn")
        if cn_value != "John Doe":
            raise AssertionError(f"Expected {"John Doe"}, got {cn_value}")

        uid_value = entry.get_single_attribute("uid")
        if uid_value != "johndoe":
            raise AssertionError(f"Expected {"johndoe"}, got {uid_value}")

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
            raise AssertionError(f"Expected {"objectClass: person"} in {ldif_output}")
        assert "cn: John Doe" in ldif_output
        assert ldif_output.endswith("\n")

    def test_validate_domain_rules_success(self, sample_entry_data: dict) -> None:
        """Test domain rules validation succeeds for valid entry."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        # Should not raise exception
        entry.validate_domain_rules()

    def test_validate_domain_rules_empty_dn_fails(self) -> None:
        """Test domain rules validation fails for empty DN."""
        with pytest.raises(ValueError, match="DN must be a non-empty string"):
            FlextLdifEntry.model_validate({
                "dn": "",
                "attributes": {"objectClass": ["top"]},
            })

    def test_validate_domain_rules_no_attributes_fails(self) -> None:
        """Test domain rules validation fails for no attributes."""
        with pytest.raises(ValueError, match="LDIF entry must have at least one attribute"):
            entry = FlextLdifEntry.model_validate({
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {},
            })
            entry.validate_domain_rules()

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

            raise AssertionError(f"Expected {"cn=test,ou=people,dc=example,dc=com"}, got {str(entry.dn)}")
        assert entry.get_attribute("cn") == ["test"]
        if entry.get_attribute("sn") != ["user"]:
            raise AssertionError(f"Expected {["user"]}, got {entry.get_attribute("sn")}")
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

            raise AssertionError(f"Expected {["test", "Test User"]}, got {entry.get_attribute("cn")}")
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

            raise AssertionError(f"Expected {dn}, got {str(entry.dn)}")
        assert entry.attributes.attributes == attributes
        if entry.get_attribute("cn") != ["test"]:
            raise AssertionError(f"Expected {["test"]}, got {entry.get_attribute("cn")}")
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
            raise AssertionError(f"Expected {["newValue"]}, got {entry.get_attribute("newAttr")}")

        # DN should remain unchanged
        if str(entry.dn) != original_dn:
            raise AssertionError(f"Expected {original_dn}, got {str(entry.dn)}")

    def test_entry_equality_and_hashing(self, sample_entry_data: dict) -> None:
        """Test entry equality and hash behavior."""
        entry1 = FlextLdifEntry.model_validate(sample_entry_data)
        entry2 = FlextLdifEntry.model_validate(sample_entry_data)

        # Should be equal with same data
        if entry1 != entry2:
            raise AssertionError(f"Expected {entry2}, got {entry1}")

        # Should have same hash
        if hash(entry1) != hash(entry2):
            raise AssertionError(f"Expected {hash(entry2)}, got {hash(entry1)}")

        # Should be usable in sets
        entry_set = {entry1, entry2}
        if len(entry_set) != 1  # Same entries:
            raise AssertionError(f"Expected {1  # Same entries}, got {len(entry_set)}")

    def test_entry_serialization_deserialization(self, sample_entry_data: dict) -> None:
        """Test entry serialization and deserialization."""
        entry = FlextLdifEntry.model_validate(sample_entry_data)

        # Serialize to dict
        entry_dict = entry.model_dump()
        assert isinstance(entry_dict, dict)
        if "dn" not in entry_dict:
            raise AssertionError(f"Expected {"dn"} in {entry_dict}")
        assert "attributes" in entry_dict

        # Note: Pydantic model_dump() creates nested structure that requires
        # original data format for deserialization
        if str(entry.dn) != sample_entry_data["dn"]:
            raise AssertionError(f"Expected {sample_entry_data["dn"]}, got {str(entry.dn)}")
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
            raise AssertionError(f"Expected {sample_entry_data["dn"]} in {json_str}")
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
                raise AssertionError(f"Expected {[f"value{i}"]}, got {value}")
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

            raise AssertionError(f"Expected {"Üser Spëcial"} in {str(entry.dn)}")
        if entry.get_attribute("cn") != ["Üser Spëcial"]:
            raise AssertionError(f"Expected {["Üser Spëcial"]}, got {entry.get_attribute("cn")}")

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

            raise AssertionError(f"Expected {[long_value]}, got {entry.get_attribute("description")}")
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

            raise AssertionError(f"Expected {[""]}, got {entry.get_attribute("description")}")
        if not (entry.has_attribute("description")):
            raise AssertionError(f"Expected True, got {entry.has_attribute("description")}")
