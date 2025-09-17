"""Complete tests for FlextLdifRepositoryService - 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Never

from flext_ldif.models import FlextLdifModels
from flext_ldif.repository_service import FlextLdifRepositoryService


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
            entries, "uid=john,ou=people,dc=example,dc=com"
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
            entries, "UID=JOHN,OU=PEOPLE,DC=EXAMPLE,DC=COM"
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
            entries, "uid=nonexistent,ou=people,dc=example,dc=com"
        )
        assert result.is_success is True
        assert result.value is None

    def test_find_entry_by_dn_empty_list(self) -> None:
        """Test find_entry_by_dn with empty list."""
        service = FlextLdifRepositoryService()

        result = service.find_entry_by_dn([], "uid=john,ou=people,dc=example,dc=com")
        assert result.is_success is True
        assert result.value is None

    def test_find_entry_by_dn_exception(self) -> None:
        """Test find_entry_by_dn when exception occurs."""
        service = FlextLdifRepositoryService()

        # Create mock entry that raises exception when accessing dn.value
        class MockEntry:
            def __init__(self) -> None:
                self._attributes = FlextLdifModels.LdifAttributes(
                    data={"objectClass": ["person"]}
                )

            @property
            def dn(self) -> Never:
                msg = "DN access error"
                raise DNAccessError(msg)

            @property
            def attributes(self) -> FlextLdifModels.LdifAttributes:
                return self._attributes

        mock_entry = MockEntry()
        entries = [mock_entry]

        result = service.find_entry_by_dn(
            entries, "uid=john,ou=people,dc=example,dc=com"
        )
        assert result.is_success is False
        assert "Find error" in result.error

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
        assert "Attribute name cannot be empty" in result.error

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
        assert "Attribute name cannot be empty" in result.error

    def test_filter_entries_by_attribute_exception(self) -> None:
        """Test filter_entries_by_attribute when exception occurs."""
        service = FlextLdifRepositoryService()

        # Create mock entry that raises exception when accessing get_attribute
        class MockEntry:
            def __init__(self) -> None:
                self._dn = FlextLdifModels.DistinguishedName(
                    value="uid=john,ou=people,dc=example,dc=com"
                )
                self._attributes = FlextLdifModels.LdifAttributes(
                    data={"objectClass": ["person"]}
                )

            @property
            def dn(self) -> FlextLdifModels.DistinguishedName:
                return self._dn

            @property
            def attributes(self) -> FlextLdifModels.LdifAttributes:
                return self._attributes

            def get_attribute(self, _name: str) -> Never:
                msg = "Attribute access error"
                raise AttributeAccessError(msg)

        mock_entry = MockEntry()
        entries = [mock_entry]

        result = service.filter_entries_by_attribute(entries, "cn", "John")
        assert result.is_success is False
        assert "Filter error" in result.error

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
        assert "Object class cannot be empty" in result.error

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
        assert "Object class cannot be empty" in result.error

    def test_filter_entries_by_objectclass_exception(self) -> None:
        """Test filter_entries_by_objectclass when exception occurs."""
        service = FlextLdifRepositoryService()

        # Create mock entry that raises exception when accessing get_attribute
        class MockEntry:
            def __init__(self) -> None:
                self._dn = FlextLdifModels.DistinguishedName(
                    value="uid=john,ou=people,dc=example,dc=com"
                )
                self._attributes = FlextLdifModels.LdifAttributes(
                    data={"objectClass": ["person"]}
                )

            @property
            def dn(self) -> FlextLdifModels.DistinguishedName:
                return self._dn

            @property
            def attributes(self) -> FlextLdifModels.LdifAttributes:
                return self._attributes

            def get_attribute(self, _name: str) -> Never:
                msg = "Attribute access error"
                raise AttributeAccessError(msg)

        mock_entry = MockEntry()
        entries = [mock_entry]

        result = service.filter_entries_by_objectclass(entries, "person")
        assert result.is_success is False
        assert "ObjectClass filter error" in result.error

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

    def test_get_statistics_exception(self) -> None:
        """Test get_statistics when exception occurs."""
        service = FlextLdifRepositoryService()

        # Create mock entry that raises exception when accessing dn.value
        class MockEntry:
            def __init__(self) -> None:
                self._attributes = FlextLdifModels.LdifAttributes(
                    data={"objectClass": ["person"]}
                )

            @property
            def dn(self) -> Never:
                msg = "DN access error"
                raise DNAccessError(msg)

            @property
            def attributes(self) -> FlextLdifModels.LdifAttributes:
                return self._attributes

            def is_person(self) -> bool:
                return True

            def is_group(self) -> bool:
                return False

            def get_attribute(self, _name: str) -> list[str]:
                return ["person"]

        mock_entry = MockEntry()
        entries = [mock_entry]

        result = service.get_statistics(entries)
        assert result.is_success is False
        assert "Statistics error" in result.error

    def test_get_config_info(self) -> None:
        """Test get_config_info method."""
        service = FlextLdifRepositoryService()

        config_info = service.get_config_info()
        assert isinstance(config_info, dict)
        assert config_info["service"] == "FlextLdifRepositoryService"
        assert "config" in config_info
        assert config_info["config"]["repository_enabled"] is True
        assert "supported_operations" in config_info["config"]
        assert "storage_backend" in config_info["config"]
