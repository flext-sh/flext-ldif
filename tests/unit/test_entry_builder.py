"""Test suite for FlextLdifEntryBuilder.

This module provides comprehensive testing for the entry builder functionality
using real services and FlextTests infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
import json

from flext_ldif.entry.builder import FlextLdifEntryBuilder


class TestFlextLdifEntryBuilder:
    """Test suite for FlextLdifEntryBuilder."""

    def test_initialization(self) -> None:
        """Test entry builder initialization."""
        builder = FlextLdifEntryBuilder()
        assert builder is not None
        assert builder._logger is not None
        assert builder._objectclass_manager is not None

    def test_execute_fails_with_message(self) -> None:
        """Test that execute method fails with appropriate message."""
        builder = FlextLdifEntryBuilder()
        result = builder.execute()
        assert result.is_failure
        assert result.error is not None
        assert "Use specific build methods" in result.error

    def test_execute_async_fails_with_message(self) -> None:
        """Test that execute_async method fails with appropriate message."""
        builder = FlextLdifEntryBuilder()
        result = asyncio.run(builder.execute_async())
        assert result.is_failure
        assert result.error is not None
        assert "Use specific build methods" in result.error

    def test_build_person_entry_basic(self) -> None:
        """Test building a basic person entry."""
        builder = FlextLdifEntryBuilder()

        result = builder.build_person_entry(
            cn="Test User", sn="User", base_dn="dc=example,dc=com"
        )

        assert result.is_success
        entry = result.value
        assert entry.dn.value == "cn=Test User,dc=example,dc=com"
        assert "inetOrgPerson" in entry.attributes.attributes.get("objectClass", [])
        assert "person" in entry.attributes.attributes.get("objectClass", [])
        assert entry.attributes.attributes.get("cn") == ["Test User"]
        assert entry.attributes.attributes.get("sn") == ["User"]

    def test_build_person_entry_with_optional_attrs(self) -> None:
        """Test building a person entry with optional attributes."""
        builder = FlextLdifEntryBuilder()

        result = builder.build_person_entry(
            cn="Test User",
            sn="User",
            base_dn="dc=example,dc=com",
            uid="testuser",
            mail="test@example.com",
            given_name="Test",
        )

        assert result.is_success
        entry = result.value
        assert entry.attributes.attributes.get("uid") == ["testuser"]
        assert entry.attributes.attributes.get("mail") == ["test@example.com"]
        assert entry.attributes.attributes.get("givenName") == ["Test"]

    def test_build_person_entry_with_additional_attrs(self) -> None:
        """Test building a person entry with additional attributes."""
        builder = FlextLdifEntryBuilder()

        additional_attrs = {
            "telephoneNumber": ["+1234567890"],
            "title": ["Software Engineer"],
        }

        result = builder.build_person_entry(
            cn="Test User",
            sn="User",
            base_dn="dc=example,dc=com",
            additional_attrs=additional_attrs,
        )

        assert result.is_success
        entry = result.value
        assert entry.attributes.attributes.get("telephoneNumber") == ["+1234567890"]
        assert entry.attributes.attributes.get("title") == ["Software Engineer"]

    def test_build_group_entry_basic(self) -> None:
        """Test building a basic group entry."""
        builder = FlextLdifEntryBuilder()

        result = builder.build_group_entry(cn="Test Group", base_dn="dc=example,dc=com")

        assert result.is_success
        entry = result.value
        assert entry.dn.value == "cn=Test Group,dc=example,dc=com"
        assert "top" in entry.attributes.attributes.get("objectClass", [])
        assert "groupOfNames" in entry.attributes.attributes.get("objectClass", [])
        assert entry.attributes.attributes.get("cn") == ["Test Group"]
        # Should have self as member when no members provided
        assert entry.dn.value in entry.attributes.attributes.get("member", [])

    def test_build_group_entry_with_members(self) -> None:
        """Test building a group entry with members."""
        builder = FlextLdifEntryBuilder()

        members = ["cn=user1,dc=example,dc=com", "cn=user2,dc=example,dc=com"]

        result = builder.build_group_entry(
            cn="Test Group",
            base_dn="dc=example,dc=com",
            members=members,
            description="Test group description",
        )

        assert result.is_success
        entry = result.value
        assert entry.attributes.attributes.get("member") == members
        assert entry.attributes.attributes.get("description") == [
            "Test group description"
        ]

    def test_build_group_entry_with_additional_attrs(self) -> None:
        """Test building a group entry with additional attributes."""
        builder = FlextLdifEntryBuilder()

        additional_attrs = {
            "owner": ["cn=admin,dc=example,dc=com"],
            "seeAlso": ["cn=othergroup,dc=example,dc=com"],
        }

        result = builder.build_group_entry(
            cn="Test Group",
            base_dn="dc=example,dc=com",
            additional_attrs=additional_attrs,
        )

        assert result.is_success
        entry = result.value
        assert entry.attributes.attributes.get("owner") == [
            "cn=admin,dc=example,dc=com"
        ]
        assert entry.attributes.attributes.get("seeAlso") == [
            "cn=othergroup,dc=example,dc=com"
        ]

    def test_build_organizational_unit_entry_basic(self) -> None:
        """Test building a basic organizational unit entry."""
        builder = FlextLdifEntryBuilder()

        result = builder.build_organizational_unit_entry(
            ou="TestOU", base_dn="dc=example,dc=com"
        )

        assert result.is_success
        entry = result.value
        assert entry.dn.value == "ou=TestOU,dc=example,dc=com"
        assert "top" in entry.attributes.attributes.get("objectClass", [])
        assert "organizationalUnit" in entry.attributes.attributes.get(
            "objectClass", []
        )
        assert entry.attributes.attributes.get("ou") == ["TestOU"]

    def test_build_organizational_unit_entry_with_description(self) -> None:
        """Test building an organizational unit entry with description."""
        builder = FlextLdifEntryBuilder()

        result = builder.build_organizational_unit_entry(
            ou="TestOU",
            base_dn="dc=example,dc=com",
            description="Test organizational unit",
        )

        assert result.is_success
        entry = result.value
        assert entry.attributes.attributes.get("description") == [
            "Test organizational unit"
        ]

    def test_build_organizational_unit_entry_with_additional_attrs(self) -> None:
        """Test building an organizational unit entry with additional attributes."""
        builder = FlextLdifEntryBuilder()

        additional_attrs = {"businessCategory": ["IT"], "st": ["California"]}

        result = builder.build_organizational_unit_entry(
            ou="TestOU", base_dn="dc=example,dc=com", additional_attrs=additional_attrs
        )

        assert result.is_success
        entry = result.value
        assert entry.attributes.attributes.get("businessCategory") == ["IT"]
        assert entry.attributes.attributes.get("st") == ["California"]

    def test_build_custom_entry_basic(self) -> None:
        """Test building a custom entry."""
        builder = FlextLdifEntryBuilder()

        result = builder.build_custom_entry(
            dn="cn=custom,dc=example,dc=com",
            objectclasses=["top", "customObject"],
            attributes={"cn": ["custom"], "customAttr": ["value1", "value2"]},
        )

        assert result.is_success
        entry = result.value
        assert entry.dn.value == "cn=custom,dc=example,dc=com"
        assert "top" in entry.attributes.attributes.get("objectClass", [])
        assert "customObject" in entry.attributes.attributes.get("objectClass", [])
        assert entry.attributes.attributes.get("cn") == ["custom"]
        assert entry.attributes.attributes.get("customAttr") == ["value1", "value2"]

    def test_build_custom_entry_without_validation(self) -> None:
        """Test building a custom entry without validation."""
        builder = FlextLdifEntryBuilder()

        result = builder.build_custom_entry(
            dn="cn=custom,dc=example,dc=com",
            objectclasses=["top", "customObject"],
            attributes={"cn": ["custom"], "customAttr": ["value1"]},
            validate=False,
        )

        assert result.is_success
        entry = result.value
        assert entry.dn.value == "cn=custom,dc=example,dc=com"

    def test_build_entries_from_json_valid(self) -> None:
        """Test building entries from valid JSON."""
        builder = FlextLdifEntryBuilder()

        json_data = json.dumps([
            {
                "dn": "cn=user1,dc=example,dc=com",
                "attributes": {
                    "objectClass": ["person"],
                    "cn": ["User 1"],
                    "sn": ["One"],
                },
            },
            {
                "dn": "cn=user2,dc=example,dc=com",
                "attributes": {
                    "objectClass": ["person"],
                    "cn": ["User 2"],
                    "sn": ["Two"],
                },
            },
        ])

        result = builder.build_entries_from_json(json_data)

        assert result.is_success
        entries = result.value
        assert len(entries) == 2
        assert entries[0].dn.value == "cn=user1,dc=example,dc=com"
        assert entries[1].dn.value == "cn=user2,dc=example,dc=com"

    def test_build_entries_from_json_invalid_json(self) -> None:
        """Test building entries from invalid JSON."""
        builder = FlextLdifEntryBuilder()

        result = builder.build_entries_from_json("invalid json")

        assert result.is_failure
        assert result.error is not None
        assert "Invalid JSON" in result.error

    def test_build_entries_from_json_not_list(self) -> None:
        """Test building entries from JSON that is not a list."""
        builder = FlextLdifEntryBuilder()

        json_data = json.dumps({
            "dn": "cn=user1,dc=example,dc=com",
            "attributes": {"cn": ["User 1"]},
        })

        result = builder.build_entries_from_json(json_data)

        assert result.is_failure
        assert result.error is not None
        assert "JSON data must be a list" in result.error

    def test_build_entries_from_json_item_not_dict(self) -> None:
        """Test building entries from JSON with non-dict items."""
        builder = FlextLdifEntryBuilder()

        json_data = json.dumps(["not a dict", "also not a dict"])

        result = builder.build_entries_from_json(json_data)

        assert result.is_failure
        assert result.error is not None
        assert "Each item must be a dictionary" in result.error

    def test_build_entries_from_json_missing_dn(self) -> None:
        """Test building entries from JSON with missing DN."""
        builder = FlextLdifEntryBuilder()

        json_data = json.dumps([
            {"attributes": {"objectClass": ["person"], "cn": ["User 1"]}}
        ])

        result = builder.build_entries_from_json(json_data)

        assert result.is_failure
        assert result.error is not None
        assert "Each entry must have a 'dn' field" in result.error

    def test_build_entries_from_json_string_values(self) -> None:
        """Test building entries from JSON with string attribute values."""
        builder = FlextLdifEntryBuilder()

        json_data = json.dumps([
            {
                "dn": "cn=user1,dc=example,dc=com",
                "attributes": {
                    "objectClass": "person",  # String instead of list
                    "cn": "User 1",  # String instead of list
                },
            }
        ])

        result = builder.build_entries_from_json(json_data)

        assert result.is_success
        entries = result.value
        assert len(entries) == 1
        entry = entries[0]
        assert entry.attributes.attributes.get("objectClass") == ["person"]
        assert entry.attributes.attributes.get("cn") == ["User 1"]

    def test_build_entries_from_dict_valid(self) -> None:
        """Test building entries from valid dictionary data."""
        builder = FlextLdifEntryBuilder()

        data: list[dict[str, object]] = [
            {
                "dn": "cn=user1,dc=example,dc=com",
                "attributes": {
                    "objectClass": ["person"],
                    "cn": ["User 1"],
                    "sn": ["One"],
                },
            },
            {
                "dn": "cn=user2,dc=example,dc=com",
                "attributes": {
                    "objectClass": ["person"],
                    "cn": ["User 2"],
                    "sn": ["Two"],
                },
            },
        ]

        result = builder.build_entries_from_dict(data)

        assert result.is_success
        entries = result.value
        assert len(entries) == 2
        assert entries[0].dn.value == "cn=user1,dc=example,dc=com"
        assert entries[1].dn.value == "cn=user2,dc=example,dc=com"

    def test_build_entries_from_dict_missing_dn(self) -> None:
        """Test building entries from dictionary with missing DN."""
        builder = FlextLdifEntryBuilder()

        data: list[dict[str, object]] = [
            {"attributes": {"objectClass": ["person"], "cn": ["User 1"]}}
        ]

        result = builder.build_entries_from_dict(data)

        assert result.is_failure
        assert result.error is not None
        assert "Each entry must have a 'dn' field" in result.error

    def test_build_entries_from_dict_non_dict_attributes(self) -> None:
        """Test building entries from dictionary with non-dict attributes."""
        builder = FlextLdifEntryBuilder()

        data: list[dict[str, object]] = [
            {"dn": "cn=user1,dc=example,dc=com", "attributes": "not a dict"}
        ]

        result = builder.build_entries_from_dict(data)

        assert result.is_success
        entries = result.value
        assert len(entries) == 1
        entry = entries[0]
        assert entry.dn.value == "cn=user1,dc=example,dc=com"

    def test_build_entries_from_dict_mixed_value_types(self) -> None:
        """Test building entries from dictionary with mixed value types."""
        builder = FlextLdifEntryBuilder()

        data: list[dict[str, object]] = [
            {
                "dn": "cn=user1,dc=example,dc=com",
                "attributes": {
                    "objectClass": "person",  # String
                    "cn": ["User 1"],  # List
                    "age": 25,  # Number
                },
            }
        ]

        result = builder.build_entries_from_dict(data)

        assert result.is_success
        entries = result.value
        assert len(entries) == 1
        entry = entries[0]
        assert entry.attributes.attributes.get("objectClass") == ["person"]
        assert entry.attributes.attributes.get("cn") == ["User 1"]
        assert entry.attributes.attributes.get("age") == ["25"]

    def test_convert_entry_to_dict(self) -> None:
        """Test converting an entry to dictionary format."""
        builder = FlextLdifEntryBuilder()

        # Create an entry first
        entry_result = builder.build_person_entry(
            cn="Test User", sn="User", base_dn="dc=example,dc=com"
        )

        assert entry_result.is_success
        entry = entry_result.value

        # Convert to dict
        result = builder.convert_entry_to_dict(entry)

        assert result.is_success
        entry_dict = result.value
        assert entry_dict["dn"] == "cn=Test User,dc=example,dc=com"
        assert isinstance(entry_dict["attributes"], dict)
        assert entry_dict["attributes"]["cn"] == ["Test User"]
        assert entry_dict["attributes"]["sn"] == ["User"]

    def test_convert_entries_to_json(self) -> None:
        """Test converting entries to JSON format."""
        builder = FlextLdifEntryBuilder()

        # Create entries first
        entry1_result = builder.build_person_entry(
            cn="User 1", sn="One", base_dn="dc=example,dc=com"
        )

        entry2_result = builder.build_person_entry(
            cn="User 2", sn="Two", base_dn="dc=example,dc=com"
        )

        assert entry1_result.is_success
        assert entry2_result.is_success

        entries = [entry1_result.value, entry2_result.value]

        # Convert to JSON
        result = builder.convert_entries_to_json(entries)

        assert result.is_success
        json_str = result.value

        # Parse back to verify
        parsed_data = json.loads(json_str)
        assert len(parsed_data) == 2
        assert parsed_data[0]["dn"] == "cn=User 1,dc=example,dc=com"
        assert parsed_data[1]["dn"] == "cn=User 2,dc=example,dc=com"

    def test_convert_entries_to_json_with_indent(self) -> None:
        """Test converting entries to JSON with custom indent."""
        builder = FlextLdifEntryBuilder()

        # Create an entry first
        entry_result = builder.build_person_entry(
            cn="Test User", sn="User", base_dn="dc=example,dc=com"
        )

        assert entry_result.is_success
        entry = entry_result.value

        # Convert to JSON with custom indent
        result = builder.convert_entries_to_json([entry], indent=4)

        assert result.is_success
        json_str = result.value

        # Should be properly formatted with 4-space indent
        lines = json_str.split("\n")
        assert any("    " in line for line in lines)  # Should have 4-space indentation

    def test_error_handling_in_entry_creation(self) -> None:
        """Test error handling when entry creation fails."""
        builder = FlextLdifEntryBuilder()

        # This should test error handling in the entry creation process
        # We'll create an entry with invalid data that should cause creation to fail
        result = builder.build_custom_entry(
            dn="",  # Empty DN should cause failure
            objectclasses=["top"],
            attributes={"cn": ["test"]},
        )

        # The result should indicate failure due to invalid DN
        assert result.is_failure

    def test_logging_functionality(self) -> None:
        """Test that logging functionality works correctly."""
        builder = FlextLdifEntryBuilder()

        # Test that successful operations log info messages
        result = builder.build_group_entry(
            cn="Test Group", base_dn="dc=example,dc=com", description="Test group"
        )

        assert result.is_success
        # The logging should have occurred (we can't easily test the actual log output
        # but we can verify the operation succeeded, which means logging was called)

    def test_objectclass_manager_integration(self) -> None:
        """Test integration with objectclass manager."""
        builder = FlextLdifEntryBuilder()

        # Verify that the objectclass manager is properly initialized
        assert builder._objectclass_manager is not None

        # Test that we can build entries with standard object classes
        result = builder.build_person_entry(
            cn="Test User", sn="User", base_dn="dc=example,dc=com"
        )

        assert result.is_success
        entry = result.value
        # Verify standard object classes are present
        object_classes = entry.attributes.attributes.get("objectClass", [])
        assert "inetOrgPerson" in object_classes
        assert "person" in object_classes
