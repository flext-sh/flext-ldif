"""Complete tests for FlextLdifRepositoryService - 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol

from flext_ldif.models import FlextLdifModels
from flext_ldif.repository_service import FlextLdifRepositoryService


class EntryProtocol(Protocol):
    """Protocol for Entry-like objects used in tests."""

    @property
    def dn(self) -> FlextLdifModels.DistinguishedName: ...

    @property
    def attributes(self) -> FlextLdifModels.LdifAttributes: ...

    def get_attribute(self, name: str) -> list[str] | None: ...

    def get_single_attribute(self, name: str) -> str | None: ...

    def has_attribute(self, name: str) -> bool: ...


class DNAccessError(Exception):
    """Custom exception for DN access errors in tests."""


class AttributeAccessError(Exception):
    """Custom exception for attribute access errors in tests."""


class TestFlextLdifRepositoryServiceComplete:
    """Complete tests for FlextLdifRepositoryService to achieve 100% coverage."""

    def test_repository_service_initialization(self) -> None:
        """Test repository service initialization."""
        service = FlextLdifRepositoryService()
        assert service is not None

    def test_find_entry_by_dn_success(self) -> None:
        """Test find_entry_by_dn with successful match."""
        service = FlextLdifRepositoryService()

        # Create test entries
        entry1_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry1 = FlextLdifModels.create_entry(entry1_data)

        entry2_data = {
            "dn": "uid=jane,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["Jane"]},
        }
        entry2 = FlextLdifModels.create_entry(entry2_data)

        entries = [entry1, entry2]

        result = service.find_entry_by_dn(
            entries, "uid=john,ou=people,dc=example,dc=com",
        )
        assert result.is_success is True
        assert result.value is not None
        assert result.value.dn.value == "uid=john,ou=people,dc=example,dc=com"

    def test_find_entry_by_dn_case_insensitive(self) -> None:
        """Test find_entry_by_dn with case insensitive match."""
        service = FlextLdifRepositoryService()

        # Create test entry
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        result = service.find_entry_by_dn(
            entries, "UID=JOHN,OU=PEOPLE,DC=EXAMPLE,DC=COM",
        )
        assert result.is_success is True
        assert result.value is not None
        assert result.value.dn.value == "uid=john,ou=people,dc=example,dc=com"

    def test_find_entry_by_dn_not_found(self) -> None:
        """Test find_entry_by_dn when entry not found."""
        service = FlextLdifRepositoryService()

        # Create test entry
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        result = service.find_entry_by_dn(
            entries, "uid=nonexistent,ou=people,dc=example,dc=com",
        )
        assert result.is_success is True
        assert result.value is None

    def test_find_entry_by_dn_empty_list(self) -> None:
        """Test find_entry_by_dn with empty list."""
        service = FlextLdifRepositoryService()

        result = service.find_entry_by_dn([], "uid=john,ou=people,dc=example,dc=com")
        assert result.is_success is True
        assert result.value is None

    def test_find_entry_by_dn_with_special_characters(self) -> None:
        """Test find_entry_by_dn with special characters in DN."""
        service = FlextLdifRepositoryService()

        # Create entry with special characters that could cause comparison issues
        dn = FlextLdifModels.DistinguishedName(
            value="cn=Tëst Üser,ou=pëople,dc=exämple,dc=com",
        )
        attributes = FlextLdifModels.LdifAttributes(
            data={"objectClass": ["person"], "cn": ["Tëst Üser"]},
        )
        entry = FlextLdifModels.Entry(dn=dn, attributes=attributes)

        entries = [entry]

        # Test case-insensitive matching with special characters
        result = service.find_entry_by_dn(
            entries, "CN=TËST ÜSER,OU=PËOPLE,DC=EXÄMPLE,DC=COM",
        )
        assert result.is_success is True
        assert result.value is not None
        assert (
            result.value.dn.value.lower() == "cn=tëst üser,ou=pëople,dc=exämple,dc=com"
        )

    def test_filter_entries_by_attribute_success(self) -> None:
        """Test filter_entries_by_attribute with successful match."""
        service = FlextLdifRepositoryService()

        # Create test entries
        entry1_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry1 = FlextLdifModels.create_entry(entry1_data)

        entry2_data = {
            "dn": "uid=jane,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["Jane"]},
        }
        entry2 = FlextLdifModels.create_entry(entry2_data)

        entries = [entry1, entry2]

        result = service.filter_entries_by_attribute(entries, "cn", "John")
        assert result.is_success is True
        assert len(result.value) == 1
        assert result.value[0].dn.value == "uid=john,ou=people,dc=example,dc=com"

    def test_filter_entries_by_attribute_presence(self) -> None:
        """Test filter_entries_by_attribute filtering by presence (no value)."""
        service = FlextLdifRepositoryService()

        # Create test entries
        entry1_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry1 = FlextLdifModels.create_entry(entry1_data)

        entry2_data = {
            "dn": "uid=jane,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"]},  # No cn attribute
        }
        entry2 = FlextLdifModels.create_entry(entry2_data)

        entries = [entry1, entry2]

        result = service.filter_entries_by_attribute(entries, "cn", None)
        assert result.is_success is True
        assert len(result.value) == 1
        assert result.value[0].dn.value == "uid=john,ou=people,dc=example,dc=com"

    def test_filter_entries_by_attribute_empty_name(self) -> None:
        """Test filter_entries_by_attribute with empty attribute name."""
        service = FlextLdifRepositoryService()

        # Create test entry
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        result = service.filter_entries_by_attribute(entries, "", "John")
        assert result.is_success is False
        assert (
            result.error is not None
            and "Attribute name cannot be empty" in result.error
        )

    def test_filter_entries_by_attribute_whitespace_name(self) -> None:
        """Test filter_entries_by_attribute with whitespace-only attribute name."""
        service = FlextLdifRepositoryService()

        # Create test entry
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        result = service.filter_entries_by_attribute(entries, "   ", "John")
        assert result.is_success is False
        assert (
            result.error is not None
            and "Attribute name cannot be empty" in result.error
        )

    def test_filter_entries_by_attribute_with_null_values(self) -> None:
        """Test filter_entries_by_attribute with null/None values in attributes."""
        service = FlextLdifRepositoryService()

        # Create entry using the factory method to avoid validation issues
        entry_data = {
            "dn": "cn=null-test,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["null-test"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        # Test filtering by attribute that doesn't exist
        result = service.filter_entries_by_attribute(entries, "description", None)
        assert result.is_success is True
        assert len(result.value) == 0  # Should not match when attribute doesn't exist

        # Test filtering by attribute that doesn't exist with specific value
        result = service.filter_entries_by_attribute(entries, "nonexistent", "value")
        assert result.is_success is True
        assert len(result.value) == 0

    def test_filter_entries_by_objectclass_success(self) -> None:
        """Test filter_entries_by_objectclass with successful match."""
        service = FlextLdifRepositoryService()

        # Create test entries
        entry1_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry1 = FlextLdifModels.create_entry(entry1_data)

        entry2_data = {
            "dn": "cn=group1,ou=groups,dc=example,dc=com",
            "attributes": {"objectClass": ["groupOfNames"], "cn": ["Group 1"]},
        }
        entry2 = FlextLdifModels.create_entry(entry2_data)

        entries = [entry1, entry2]

        result = service.filter_entries_by_objectclass(entries, "person")
        assert result.is_success is True
        assert len(result.value) == 1
        assert result.value[0].dn.value == "uid=john,ou=people,dc=example,dc=com"

    def test_filter_entries_by_objectclass_case_insensitive(self) -> None:
        """Test filter_entries_by_objectclass with case insensitive match."""
        service = FlextLdifRepositoryService()

        # Create test entry
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        result = service.filter_entries_by_objectclass(entries, "PERSON")
        assert result.is_success is True
        assert len(result.value) == 1

    def test_filter_entries_by_objectclass_empty_class(self) -> None:
        """Test filter_entries_by_objectclass with empty object class."""
        service = FlextLdifRepositoryService()

        # Create test entry
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        result = service.filter_entries_by_objectclass(entries, "")
        assert result.is_success is False
        assert (
            result.error is not None and "Object class cannot be empty" in result.error
        )

    def test_filter_entries_by_objectclass_whitespace_class(self) -> None:
        """Test filter_entries_by_objectclass with whitespace-only object class."""
        service = FlextLdifRepositoryService()

        # Create test entry
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        result = service.filter_entries_by_objectclass(entries, "   ")
        assert result.is_success is False
        assert (
            result.error is not None and "Object class cannot be empty" in result.error
        )

    def test_filter_entries_by_objectclass_with_missing_objectclass(self) -> None:
        """Test filter_entries_by_objectclass with entries missing objectClass attribute."""
        service = FlextLdifRepositoryService()

        # Create entry without objectClass attribute to test edge case
        dn = FlextLdifModels.DistinguishedName(
            value="cn=no-objectclass,dc=example,dc=com",
        )
        # Create attributes without objectClass - this might be an edge case
        attributes_data = {
            "cn": ["no-objectclass"],
            "description": ["Entry without objectClass"],
        }
        attributes = FlextLdifModels.LdifAttributes(data=attributes_data)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attributes)
        entries = [entry]

        # Test filtering by objectClass when entry doesn't have objectClass attribute
        result = service.filter_entries_by_objectclass(entries, "person")
        assert result.is_success is True
        assert len(result.value) == 0  # Should not match entries without objectClass

    def test_filter_entries_by_object_class_alias(self) -> None:
        """Test filter_entries_by_object_class alias method."""
        service = FlextLdifRepositoryService()

        # Create test entry
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        result = service.filter_entries_by_object_class(entries, "person")
        assert result.is_success is True
        assert len(result.value) == 1

    def test_get_statistics_success(self) -> None:
        """Test get_statistics with successful calculation."""
        service = FlextLdifRepositoryService()

        # Create test entries
        entry1_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry1 = FlextLdifModels.create_entry(entry1_data)

        entry2_data = {
            "dn": "cn=group1,ou=groups,dc=example,dc=com",
            "attributes": {"objectClass": ["groupOfNames"], "cn": ["Group 1"]},
        }
        entry2 = FlextLdifModels.create_entry(entry2_data)

        entries = [entry1, entry2]

        result = service.get_statistics(entries)
        assert result.is_success is True
        stats = result.value
        assert stats["total_entries"] == 2
        assert stats["unique_dns"] == 2
        assert stats["total_attributes"] == 4  # 2 attributes per entry
        assert stats["person_entries"] == 1
        assert stats["group_entries"] == 1
        assert stats["organizational_unit_entries"] == 0

    def test_get_statistics_empty_list(self) -> None:
        """Test get_statistics with empty list."""
        service = FlextLdifRepositoryService()

        result = service.get_statistics([])
        assert result.is_success is True
        stats = result.value
        assert stats["total_entries"] == 0
        assert stats["unique_dns"] == 0
        assert stats["total_attributes"] == 0
        assert stats["person_entries"] == 0
        assert stats["group_entries"] == 0
        assert stats["organizational_unit_entries"] == 0

    def test_get_statistics_with_complex_entries(self) -> None:
        """Test get_statistics with complex entry structures and edge cases."""
        service = FlextLdifRepositoryService()

        # Create entries with various complex scenarios
        entry1_data = {
            "dn": "cn=complex-user,ou=special chars,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "cn": ["complex-user"],
                "sn": ["User"],
                "description": ["User with multiple objectClasses"],
            },
        }
        entry1 = FlextLdifModels.create_entry(entry1_data)

        # Entry with minimal attributes
        entry2_data = {
            "dn": "cn=minimal,dc=example,dc=com",
            "attributes": {"objectClass": ["organizationalUnit"]},
        }
        entry2 = FlextLdifModels.create_entry(entry2_data)

        entries = [entry1, entry2]

        result = service.get_statistics(entries)
        assert result.is_success is True
        stats = result.value
        assert stats["total_entries"] == 2
        assert stats["unique_dns"] == 2
        assert (
            stats["total_attributes"] == 5
        )  # entry1: 4 attributes + entry2: 1 attribute
        assert stats["person_entries"] == 1  # entry1 has person objectClass
        assert stats["group_entries"] == 0
        assert (
            stats["organizational_unit_entries"] == 1
        )  # entry2 has organizationalUnit

    def test_get_config_info(self) -> None:
        """Test get_config_info method."""
        service = FlextLdifRepositoryService()

        config_info = service.get_config_info()
        assert isinstance(config_info, dict)
        assert config_info["service"] == "FlextLdifRepositoryService"
        assert "config" in config_info
        assert isinstance(config_info["config"], dict)
        # Test flexible config structure - repository may have different keys
        config = config_info["config"]
        assert isinstance(config, dict)
        # Repository service should have basic configuration
        assert len(config) > 0
