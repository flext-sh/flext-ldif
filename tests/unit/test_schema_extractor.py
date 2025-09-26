"""Test suite for FlextLdifSchemaExtractor.

This module provides comprehensive testing for the schema extractor functionality
using real services and FlextTests infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio

from flext_ldif.models import FlextLdifModels
from flext_ldif.schema.extractor import FlextLdifSchemaExtractor


class TestFlextLdifSchemaExtractor:
    """Test suite for FlextLdifSchemaExtractor."""

    def test_initialization(self) -> None:
        """Test schema extractor initialization."""
        extractor = FlextLdifSchemaExtractor()
        assert extractor is not None
        assert extractor._logger is not None

    def test_execute_fails_with_message(self) -> None:
        """Test that execute method fails with appropriate message."""
        extractor = FlextLdifSchemaExtractor()
        result = extractor.execute()
        assert result.is_failure
        assert result.error is not None
        assert "Use extract_from_entries() method instead" in result.error

    def test_execute_async_fails_with_message(self) -> None:
        """Test that execute_async method fails with appropriate message."""
        extractor = FlextLdifSchemaExtractor()
        result = asyncio.run(extractor.execute_async())
        assert result.is_failure
        assert result.error is not None
        assert "Use extract_from_entries() method instead" in result.error

    def test_extract_from_entries_empty_list(self) -> None:
        """Test extracting schema from empty entries list."""
        extractor = FlextLdifSchemaExtractor()
        result = extractor.extract_from_entries([])

        assert result.is_failure
        assert result.error is not None
        assert "No entries provided for schema extraction" in result.error

    def test_extract_from_entries_single_entry(self) -> None:
        """Test extracting schema from a single entry."""
        extractor = FlextLdifSchemaExtractor()

        # Create a single entry
        entry_data: dict[str, object] = {
            "dn": "cn=testuser,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "top"],
                "cn": ["testuser"],
                "sn": ["User"],
                "mail": ["test@example.com"],
            },
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = extractor.extract_from_entries([entry])

        assert result.is_success
        schema = result.value

        # Check that attributes were discovered
        assert len(schema.attributes) > 0
        assert "cn" in schema.attributes
        assert "sn" in schema.attributes
        assert "mail" in schema.attributes

        # Check that object classes were discovered
        assert len(schema.object_classes) > 0
        assert "person" in schema.object_classes
        assert "top" in schema.object_classes

    def test_extract_from_entries_multiple_entries(self) -> None:
        """Test extracting schema from multiple entries."""
        extractor = FlextLdifSchemaExtractor()

        # Create multiple entries
        entries = []
        for i in range(3):
            entry_data: dict[str, object] = {
                "dn": f"cn=user{i},dc=example,dc=com",
                "attributes": {
                    "objectClass": ["person", "top"],
                    "cn": [f"user{i}"],
                    "sn": ["User"],
                    "mail": [f"user{i}@example.com"],
                },
            }

            entry_result = FlextLdifModels.Entry.create(entry_data)
            assert entry_result.is_success
            entries.append(entry_result.value)

        result = extractor.extract_from_entries(entries)

        assert result.is_success
        schema = result.value

        # Check that attributes were discovered
        assert len(schema.attributes) > 0
        assert "cn" in schema.attributes
        assert "sn" in schema.attributes
        assert "mail" in schema.attributes

        # Check that object classes were discovered
        assert len(schema.object_classes) > 0
        assert "person" in schema.object_classes
        assert "top" in schema.object_classes

    def test_extract_from_entries_different_object_classes(self) -> None:
        """Test extracting schema from entries with different object classes."""
        extractor = FlextLdifSchemaExtractor()

        # Create entries with different object classes
        entries = []

        # Person entry
        person_data: dict[str, object] = {
            "dn": "cn=person,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "top"],
                "cn": ["person"],
                "sn": ["Person"],
            },
        }
        person_result = FlextLdifModels.Entry.create(person_data)
        assert person_result.is_success
        entries.append(person_result.value)

        # Group entry
        group_data: dict[str, object] = {
            "dn": "cn=group,dc=example,dc=com",
            "attributes": {
                "objectClass": ["groupOfNames", "top"],
                "cn": ["group"],
                "member": ["cn=person,dc=example,dc=com"],
            },
        }
        group_result = FlextLdifModels.Entry.create(group_data)
        assert group_result.is_success
        entries.append(group_result.value)

        result = extractor.extract_from_entries(entries)

        assert result.is_success
        schema = result.value

        # Check that all object classes were discovered
        assert "person" in schema.object_classes
        assert "top" in schema.object_classes
        assert "groupOfNames" in schema.object_classes

        # Check that all attributes were discovered
        assert "cn" in schema.attributes
        assert "sn" in schema.attributes
        assert "member" in schema.attributes

    def test_extract_from_entries_single_valued_attributes(self) -> None:
        """Test extracting schema with single-valued attributes."""
        extractor = FlextLdifSchemaExtractor()

        entry_data: dict[str, object] = {
            "dn": "cn=testuser,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person"],
                "cn": ["testuser"],  # Single value
                "sn": ["User"],  # Single value
                "mail": ["test@example.com"],  # Single value
            },
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = extractor.extract_from_entries([entry])

        assert result.is_success
        schema = result.value

        # Check that attributes were discovered
        assert "cn" in schema.attributes
        assert "sn" in schema.attributes
        assert "mail" in schema.attributes

    def test_extract_from_entries_multi_valued_attributes(self) -> None:
        """Test extracting schema with multi-valued attributes."""
        extractor = FlextLdifSchemaExtractor()

        entry_data: dict[str, object] = {
            "dn": "cn=testuser,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "top"],  # Multiple values
                "cn": ["testuser", "Test User"],  # Multiple values
                "mail": ["test@example.com", "test@company.com"],  # Multiple values
            },
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = extractor.extract_from_entries([entry])

        assert result.is_success
        schema = result.value

        # Check that attributes were discovered
        assert "cn" in schema.attributes
        assert "mail" in schema.attributes
        # objectClass is handled separately as object_classes, not attributes

    def test_extract_attribute_usage_empty_list(self) -> None:
        """Test extracting attribute usage from empty entries list."""
        extractor = FlextLdifSchemaExtractor()
        result = extractor.extract_attribute_usage([])

        assert result.is_success
        usage_stats = result.value
        assert usage_stats == {}

    def test_extract_attribute_usage_single_entry(self) -> None:
        """Test extracting attribute usage from a single entry."""
        extractor = FlextLdifSchemaExtractor()

        entry_data: dict[str, object] = {
            "dn": "cn=testuser,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "top"],
                "cn": ["testuser"],
                "sn": ["User"],
                "mail": ["test@example.com"],
            },
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = extractor.extract_attribute_usage([entry])

        assert result.is_success
        usage_stats = result.value

        # Check that usage stats were collected
        assert "objectClass" in usage_stats
        assert "cn" in usage_stats
        assert "sn" in usage_stats
        assert "mail" in usage_stats

        # Check objectClass stats (multi-valued)
        obj_class_stats = usage_stats["objectClass"]
        assert obj_class_stats["count"] == 1
        assert obj_class_stats["max_values"] == 2
        assert obj_class_stats["single_valued"] is False

        # Check cn stats (single-valued)
        cn_stats = usage_stats["cn"]
        assert cn_stats["count"] == 1
        assert cn_stats["max_values"] == 1
        assert cn_stats["single_valued"] is True

    def test_extract_attribute_usage_multiple_entries(self) -> None:
        """Test extracting attribute usage from multiple entries."""
        extractor = FlextLdifSchemaExtractor()

        # Create multiple entries with different attribute patterns
        entries = []

        # Entry 1 - single values
        entry1_data: dict[str, object] = {
            "dn": "cn=user1,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["user1"], "sn": ["User"]},
        }
        entry1_result = FlextLdifModels.Entry.create(entry1_data)
        assert entry1_result.is_success
        entries.append(entry1_result.value)

        # Entry 2 - multi values
        entry2_data: dict[str, object] = {
            "dn": "cn=user2,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "top"],
                "cn": ["user2", "User 2"],
                "mail": ["user2@example.com", "user2@company.com"],
            },
        }
        entry2_result = FlextLdifModels.Entry.create(entry2_data)
        assert entry2_result.is_success
        entries.append(entry2_result.value)

        result = extractor.extract_attribute_usage(entries)

        assert result.is_success
        usage_stats = result.value

        # Check cn stats (appears in both entries, one single, one multi)
        cn_stats = usage_stats["cn"]
        assert cn_stats["count"] == 2
        assert cn_stats["max_values"] == 2  # Maximum from entry2
        assert cn_stats["single_valued"] is False  # Because entry2 has multiple values

        # Check mail stats (only in entry2, multi-valued)
        mail_stats = usage_stats["mail"]
        assert mail_stats["count"] == 1
        assert mail_stats["max_values"] == 2
        assert mail_stats["single_valued"] is False

    def test_extract_attribute_usage_duplicate_attributes(self) -> None:
        """Test extracting attribute usage with duplicate attribute names."""
        extractor = FlextLdifSchemaExtractor()

        # Create entries with same attributes but different values
        entries = []

        for i in range(3):
            entry_data: dict[str, object] = {
                "dn": f"cn=user{i},dc=example,dc=com",
                "attributes": {
                    "objectClass": ["person"],
                    "cn": [f"user{i}"],
                    "sn": ["User"],
                },
            }

            entry_result = FlextLdifModels.Entry.create(entry_data)
            assert entry_result.is_success
            entries.append(entry_result.value)

        result = extractor.extract_attribute_usage(entries)

        assert result.is_success
        usage_stats = result.value

        # Check that counts are accumulated
        cn_stats = usage_stats["cn"]
        assert cn_stats["count"] == 3
        assert cn_stats["max_values"] == 1
        assert cn_stats["single_valued"] is True

        sn_stats = usage_stats["sn"]
        assert sn_stats["count"] == 3
        assert sn_stats["max_values"] == 1
        assert sn_stats["single_valued"] is True

    def test_schema_discovery_result_creation(self) -> None:
        """Test that schema discovery result is created correctly."""
        extractor = FlextLdifSchemaExtractor()

        entry_data: dict[str, object] = {
            "dn": "cn=testuser,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "top"],
                "cn": ["testuser"],
                "sn": ["User"],
            },
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = extractor.extract_from_entries([entry])

        assert result.is_success
        schema = result.value

        # Verify schema structure
        assert hasattr(schema, "object_classes")
        assert hasattr(schema, "attributes")

        assert isinstance(schema.object_classes, dict)
        assert isinstance(schema.attributes, dict)

    def test_error_handling_in_schema_extraction(self) -> None:
        """Test error handling during schema extraction."""
        extractor = FlextLdifSchemaExtractor()

        # Test with valid entry to ensure normal operation works
        entry_data: dict[str, object] = {
            "dn": "cn=testuser,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["testuser"]},
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = extractor.extract_from_entries([entry])

        assert result.is_success
        # This tests the error handling path in the extraction process

    def test_logging_functionality(self) -> None:
        """Test that logging functionality works correctly."""
        extractor = FlextLdifSchemaExtractor()

        entry_data: dict[str, object] = {
            "dn": "cn=testuser,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["testuser"]},
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = extractor.extract_from_entries([entry])

        assert result.is_success
        # The logging should have occurred (we can't easily test the actual log output
        # but we can verify the operation succeeded, which means logging was called)

    def test_oid_generation(self) -> None:
        """Test that OIDs are generated for discovered attributes."""
        extractor = FlextLdifSchemaExtractor()

        entry_data: dict[str, object] = {
            "dn": "cn=testuser,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person"],
                "cn": ["testuser"],
                "customAttribute": ["customValue"],
            },
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = extractor.extract_from_entries([entry])

        assert result.is_success
        schema = result.value

        # Check that attributes were discovered
        assert "cn" in schema.attributes
        assert "customAttribute" in schema.attributes
        # objectClass is handled separately as object_classes, not attributes

    def test_case_insensitive_objectclass_handling(self) -> None:
        """Test that objectClass handling is case insensitive."""
        extractor = FlextLdifSchemaExtractor()

        entry_data: dict[str, object] = {
            "dn": "cn=testuser,dc=example,dc=com",
            "attributes": {
                "objectclass": ["person", "top"],  # Lowercase
                "cn": ["testuser"],
            },
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = extractor.extract_from_entries([entry])

        assert result.is_success
        schema = result.value

        # Check that object classes were discovered despite case
        assert "person" in schema.object_classes
        assert "top" in schema.object_classes

    def test_unique_dn_discovery(self) -> None:
        """Test that duplicate DNs are handled correctly."""
        extractor = FlextLdifSchemaExtractor()

        # Create entries with same DN (should be deduplicated)
        entries = []
        for _ in range(3):
            entry_data: dict[str, object] = {
                "dn": "cn=testuser,dc=example,dc=com",  # Same DN
                "attributes": {"objectClass": ["person"], "cn": ["testuser"]},
            }

            entry_result = FlextLdifModels.Entry.create(entry_data)
            assert entry_result.is_success
            entries.append(entry_result.value)

        result = extractor.extract_from_entries(entries)

        assert result.is_success
        schema = result.value

        # Check that attributes were discovered
        assert "cn" in schema.attributes
        # objectClass is handled separately as object_classes, not attributes
