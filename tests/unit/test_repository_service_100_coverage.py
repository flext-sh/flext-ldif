"""Complete tests for FlextLdifRepositoryService - 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
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

    def get_single_value(self, name: str) -> str | None: ...

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

    def test_store_entries_empty_list(self) -> None:
        """Test store_entries with empty entry list."""
        service = FlextLdifRepositoryService()
        result = service.store_entries([])
        assert result.is_success is True
        assert result.value is True

    def test_store_entries_successful_storage(self) -> None:
        """Test store_entries with successful storage."""
        service = FlextLdifRepositoryService()

        # Create test entry
        entry_data: dict[str, object] = {
            "dn": "uid=test,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["test"], "uid": ["test"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        result = service.store_entries(entries)
        assert result.is_success is True
        assert result.value is True

    def test_store_entries_with_duplicates(self) -> None:
        """Test store_entries with duplicate entries."""
        service = FlextLdifRepositoryService()

        # Create test entry
        entry_data: dict[str, object] = {
            "dn": "uid=duplicate,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["duplicate"], "uid": ["duplicate"]},
        }
        entry1 = FlextLdifModels.create_entry(entry_data)
        entry2 = FlextLdifModels.create_entry(entry_data)  # Same DN
        entries = [entry1, entry2]

        result = service.store_entries(entries)
        assert result.is_success is True
        assert result.value is True

    def test_store_entries_large_dataset(self) -> None:
        """Test store_entries with large dataset triggering optimization."""
        service = FlextLdifRepositoryService()

        # Create many entries to trigger large dataset handling
        entries = []
        for i in range(50):  # Create enough entries to test large dataset path
            entry_data: dict[str, object] = {
                "dn": f"uid=user{i},ou=people,dc=example,dc=com",
                "attributes": {"objectClass": ["person"], "cn": [f"User {i}"], "uid": [f"user{i}"]},
            }
            entry = FlextLdifModels.create_entry(entry_data)
            entries.append(entry)

        result = service.store_entries(entries)
        assert result.is_success is True
        assert result.value is True

    def test_health_check_success(self) -> None:
        """Test health_check with successful check."""
        service = FlextLdifRepositoryService()

        result = service.health_check()
        assert result.is_success is True
        health_data = result.unwrap()
        assert "service" in health_data
        assert "status" in health_data

    def test_get_repository_metrics(self) -> None:
        """Test get_repository_metrics functionality."""
        service = FlextLdifRepositoryService()

        metrics = service.get_repository_metrics()
        assert isinstance(metrics, dict)
        assert "uptime_seconds" in metrics
        assert "storage" in metrics
        assert "performance" in metrics
        assert "caching" in metrics
        assert "indexing" in metrics
        assert "operation_breakdown" in metrics

        # Check nested structure
        assert "total_operations" in metrics["performance"]
        assert "total_entries" in metrics["storage"]
        assert "cache_hits" in metrics["caching"]

    def test_clear_cache(self) -> None:
        """Test clear_cache functionality."""
        service = FlextLdifRepositoryService()

        # Add some data first
        entry_data: dict[str, object] = {
            "dn": "uid=cache_test,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["cache_test"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        service.store_entries([entry])

        # Clear cache (returns None)
        service.clear_cache()

        # Verify cache was cleared by checking metrics
        metrics = service.get_repository_metrics()
        assert metrics["caching"]["cache_size"] == 0

    def test_store_entries_validation_failure(self) -> None:
        """Test store_entries with validation failures."""
        service = FlextLdifRepositoryService()

        # Create an entry with empty attributes to trigger validation failure
        invalid_entry_data: dict[str, object] = {
            "dn": "uid=test,ou=people,dc=example,dc=com",
            "attributes": {},  # Empty attributes to trigger validation error
        }
        entry = FlextLdifModels.create_entry(invalid_entry_data)

        result = service.store_entries([entry])
        assert result.is_failure
        assert "no attributes" in str(result.error)

    def test_store_entries_with_exception(self) -> None:
        """Test store_entries with internal exceptions."""
        service = FlextLdifRepositoryService()

        # Mock an exception during storage by corrupting internal state
        service._entries = None  # type: ignore[assignment]

        entry_data: dict[str, object] = {
            "dn": "uid=test,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["test"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)

        result = service.store_entries([entry])
        assert result.is_failure
        assert "Storage error" in str(result.error)

    def test_find_entry_by_dn_with_exception(self) -> None:
        """Test find_entry_by_dn when an exception occurs during entry processing."""
        service = FlextLdifRepositoryService()

        # Create a mock entry that will cause an exception when accessing dn.value
        class BrokenEntry:
            @property
            def dn(self) -> object:
                class BrokenDN:
                    @property
                    def value(self) -> str:
                        msg = "DN access error"
                        raise RuntimeError(msg)
                return BrokenDN()

        broken_entry = BrokenEntry()
        entries = [broken_entry]  # type: ignore[list-item]

        result = service.find_entry_by_dn(entries, "uid=test,ou=people,dc=example,dc=com")
        assert result.is_failure
        assert "Find error" in str(result.error)

    def test_filter_entries_by_attribute_empty_name(self) -> None:
        """Test filter_entries_by_attribute with empty attribute name."""
        service = FlextLdifRepositoryService()

        entry_data: dict[str, object] = {
            "dn": "uid=test,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["test"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)

        result = service.filter_entries_by_attribute([entry], "", "value")
        assert result.is_failure
        assert "Attribute name cannot be empty" in str(result.error)

    def test_filter_entries_by_attribute_with_exception(self) -> None:
        """Test filter_entries_by_attribute with internal exceptions."""
        service = FlextLdifRepositoryService()

        # Create a broken entry that will cause an exception when get_attribute is called
        class BrokenEntry:
            def get_attribute(self, _name: str) -> None:
                msg = "Attribute access error"
                raise RuntimeError(msg)

        broken_entry = BrokenEntry()
        entries = [broken_entry]  # type: ignore[list-item]

        result = service.filter_entries_by_attribute(entries, "cn", "test")
        assert result.is_failure
        assert "Filter error" in str(result.error)

    def test_filter_entries_by_objectclass_empty_class(self) -> None:
        """Test filter_entries_by_objectclass with empty object class."""
        service = FlextLdifRepositoryService()

        entry_data: dict[str, object] = {
            "dn": "uid=test,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["test"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)

        result = service.filter_entries_by_objectclass([entry], "")
        assert result.is_failure
        assert "Object class cannot be empty" in str(result.error)

    def test_filter_entries_by_objectclass_with_exception(self) -> None:
        """Test filter_entries_by_objectclass with internal exceptions."""
        service = FlextLdifRepositoryService()

        # Create a broken entry that will cause an exception when get_attribute is called
        class BrokenEntry:
            def get_attribute(self, _name: str) -> None:
                msg = "ObjectClass access error"
                raise RuntimeError(msg)

        broken_entry = BrokenEntry()
        entries = [broken_entry]  # type: ignore[list-item]

        result = service.filter_entries_by_objectclass(entries, "person")
        assert result.is_failure
        assert "ObjectClass filter error" in str(result.error)

    def test_get_statistics_with_exception(self) -> None:
        """Test get_statistics with internal exceptions."""
        service = FlextLdifRepositoryService()

        # Mock an exception during statistics calculation
        service._large_dataset_threshold = None  # type: ignore[assignment]

        entry_data: dict[str, object] = {
            "dn": "uid=test,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["test"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)

        result = service.get_statistics([entry])
        assert result.is_failure
        assert "Statistics error" in str(result.error)

    def test_rebuild_indices_with_exception(self) -> None:
        """Test rebuild_indices with internal exceptions."""
        service = FlextLdifRepositoryService()

        # Mock an exception during rebuild
        service._entries = None  # type: ignore[assignment]

        result = service.rebuild_indices()
        assert result.is_failure
        assert "Index rebuild error" in str(result.error)

    def test_health_check_with_exception(self) -> None:
        """Test health_check with internal exceptions."""
        service = FlextLdifRepositoryService()

        # Mock an exception during health check
        service._total_operations = None  # type: ignore[assignment]

        result = service.health_check()
        assert result.is_failure
        assert "Health check error" in str(result.error)

    def test_cache_functionality_comprehensive(self) -> None:
        """Test comprehensive caching functionality."""
        service = FlextLdifRepositoryService()

        # Add entries to build cache
        entry_data: dict[str, object] = {
            "dn": "uid=cache1,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["cache1"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        service.store_entries([entry])

        # Test cache hits with find operation
        result1 = service.find_entry_by_dn(service._entries, "uid=cache1,ou=people,dc=example,dc=com")
        assert result1.is_success

        # Second call should hit cache
        result2 = service.find_entry_by_dn(service._entries, "uid=cache1,ou=people,dc=example,dc=com")
        assert result2.is_success

        # Test cache hits with filter operations
        filter_result1 = service.filter_entries_by_attribute(service._entries, "cn", "cache1")
        assert filter_result1.is_success

        filter_result2 = service.filter_entries_by_attribute(service._entries, "cn", "cache1")
        assert filter_result2.is_success

    def test_memory_optimization_functionality(self) -> None:
        """Test memory optimization and garbage collection."""
        service = FlextLdifRepositoryService()

        # Set low GC threshold to trigger optimization
        service._gc_threshold = 1

        entry_data: dict[str, object] = {
            "dn": "uid=memory_test,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["memory_test"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)

        # This should trigger memory optimization due to low threshold
        result = service.store_entries([entry])
        assert result.is_success

    def test_large_dataset_processing(self) -> None:
        """Test processing of large datasets with indexing."""
        service = FlextLdifRepositoryService()

        # Set low threshold to simulate large dataset
        service._large_dataset_threshold = 1

        entries = []
        for i in range(3):
            entry_data: dict[str, object] = {
                "dn": f"uid=large{i},ou=people,dc=example,dc=com",
                "attributes": {"objectClass": ["person"], "cn": [f"large{i}"]},
            }
            entries.append(FlextLdifModels.create_entry(entry_data))

        # Store entries (should trigger large dataset handling)
        result = service.store_entries(entries)
        assert result.is_success

        # Test statistics with large dataset handling
        stats_result = service.get_statistics(service._entries)
        assert stats_result.is_success

    def test_duplicate_entries_handling(self) -> None:
        """Test handling of duplicate entries with DN updates."""
        service = FlextLdifRepositoryService()

        # Create original entry
        original_data: dict[str, object] = {
            "dn": "uid=duplicate,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["original"]},
        }
        original_entry = FlextLdifModels.create_entry(original_data)

        # Store original
        result1 = service.store_entries([original_entry])
        assert result1.is_success
        assert len(service._entries) == 1

        # Create duplicate with same DN but different attributes
        duplicate_data: dict[str, object] = {
            "dn": "uid=duplicate,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["updated"]},
        }
        duplicate_entry = FlextLdifModels.create_entry(duplicate_data)

        # Store duplicate (should update existing entry)
        result2 = service.store_entries([duplicate_entry])
        assert result2.is_success
        assert len(service._entries) == 1  # Should still be 1, updated not added

    def test_cache_expiration_and_cleanup(self) -> None:
        """Test cache expiration and cleanup functionality."""
        service = FlextLdifRepositoryService()

        # Set very short cache TTL
        service._cache_ttl = 0.001  # 1ms

        # Add entry and trigger cache
        entry_data: dict[str, object] = {
            "dn": "uid=expire_test,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["expire_test"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        service.store_entries([entry])

        # Trigger cache with find
        service.find_entry_by_dn(service._entries, "uid=expire_test,ou=people,dc=example,dc=com")

        # Wait for cache expiration
        time.sleep(0.002)

        # Next call should be cache miss due to expiration
        result = service.find_entry_by_dn(service._entries, "uid=expire_test,ou=people,dc=example,dc=com")
        assert result.is_success

    def test_health_check_with_degraded_conditions(self) -> None:
        """Test health check under degraded conditions."""
        service = FlextLdifRepositoryService()

        # Simulate degraded conditions
        service._operation_failures = 50
        service._total_operations = 100  # 50% failure rate

        # Add many entries to trigger storage warning
        for _ in range(1000):  # Simulate many entries
            service._entries.append(None)  # type: ignore[arg-type] # Just for count

        result = service.health_check()
        assert result.is_success

        health_data = result.unwrap()
        # With 50% failure rate and index corruption, should be unhealthy
        assert health_data["status"] == "unhealthy"

    def test_index_corruption_detection(self) -> None:
        """Test detection of index corruption in health check."""
        service = FlextLdifRepositoryService()

        # Add entry normally
        entry_data: dict[str, object] = {
            "dn": "uid=index_test,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["index_test"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        service.store_entries([entry])

        # Corrupt the DN index to simulate corruption
        service._dn_index.clear()  # Remove all indices while keeping entries

        result = service.health_check()
        assert result.is_success

        health_data = result.unwrap()
        # Should detect index corruption
        assert health_data["status"] == "unhealthy"

    def test_rebuild_indices(self) -> None:
        """Test rebuild_indices functionality."""
        service = FlextLdifRepositoryService()

        # Add some data first
        entry_data: dict[str, object] = {
            "dn": "uid=index_test,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["index_test"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        service.store_entries([entry])

        # Rebuild indices
        result = service.rebuild_indices()
        assert result.is_success is True

    def test_execute_method(self) -> None:
        """Test execute method."""
        service = FlextLdifRepositoryService()

        result = service.execute()
        assert result.is_success is True

    def test_find_entry_by_dn_success(self) -> None:
        """Test find_entry_by_dn with successful match."""
        service = FlextLdifRepositoryService()

        # Create test entries
        entry1_data: dict[str, object] = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry1 = FlextLdifModels.create_entry(entry1_data)

        entry2_data: dict[str, object] = {
            "dn": "uid=jane,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["Jane"]},
        }
        entry2 = FlextLdifModels.create_entry(entry2_data)

        entries = [entry1, entry2]

        result = service.find_entry_by_dn(
            entries,
            "uid=john,ou=people,dc=example,dc=com",
        )
        assert result.is_success is True
        assert result.value is not None
        assert result.value.dn.value == "uid=john,ou=people,dc=example,dc=com"

    def test_find_entry_by_dn_case_insensitive(self) -> None:
        """Test find_entry_by_dn with case insensitive match."""
        service = FlextLdifRepositoryService()

        # Create test entry
        entry_data: dict[str, object] = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        result = service.find_entry_by_dn(
            entries,
            "UID=JOHN,OU=PEOPLE,DC=EXAMPLE,DC=COM",
        )
        assert result.is_success is True
        assert result.value is not None
        assert result.value.dn.value == "uid=john,ou=people,dc=example,dc=com"

    def test_find_entry_by_dn_not_found(self) -> None:
        """Test find_entry_by_dn when entry not found."""
        service = FlextLdifRepositoryService()

        # Create test entry
        entry_data: dict[str, object] = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        result = service.find_entry_by_dn(
            entries,
            "uid=nonexistent,ou=people,dc=example,dc=com",
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
            entries,
            "CN=TËST ÜSER,OU=PËOPLE,DC=EXÄMPLE,DC=COM",
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
        entry1_data: dict[str, object] = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry1 = FlextLdifModels.create_entry(entry1_data)

        entry2_data: dict[str, object] = {
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
        entry1_data: dict[str, object] = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry1 = FlextLdifModels.create_entry(entry1_data)

        entry2_data: dict[str, object] = {
            "dn": "uid=jane,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"]},  # No cn attribute
        }
        entry2 = FlextLdifModels.create_entry(entry2_data)

        entries = [entry1, entry2]

        result = service.filter_entries_by_attribute(entries, "cn", None)
        assert result.is_success is True
        assert len(result.value) == 1
        assert result.value[0].dn.value == "uid=john,ou=people,dc=example,dc=com"


    def test_filter_entries_by_attribute_whitespace_name(self) -> None:
        """Test filter_entries_by_attribute with whitespace-only attribute name."""
        service = FlextLdifRepositoryService()

        # Create test entry
        entry_data: dict[str, object] = {
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
        entry_data: dict[str, object] = {
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
        entry1_data: dict[str, object] = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry1 = FlextLdifModels.create_entry(entry1_data)

        entry2_data: dict[str, object] = {
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
        entry_data: dict[str, object] = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        result = service.filter_entries_by_objectclass(entries, "PERSON")
        assert result.is_success is True
        assert len(result.value) == 1


    def test_filter_entries_by_objectclass_whitespace_class(self) -> None:
        """Test filter_entries_by_objectclass with whitespace-only object class."""
        service = FlextLdifRepositoryService()

        # Create test entry
        entry_data: dict[str, object] = {
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

    def test_filter_entries_by_objectclass_alias(self) -> None:
        """Test filter_entries_by_objectclass alias method."""
        service = FlextLdifRepositoryService()

        # Create test entry
        entry_data: dict[str, object] = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        result = service.filter_entries_by_objectclass(entries, "person")
        assert result.is_success is True
        assert len(result.value) == 1

    def test_get_statistics_success(self) -> None:
        """Test get_statistics with successful calculation."""
        service = FlextLdifRepositoryService()

        # Create test entries
        entry1_data: dict[str, object] = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry1 = FlextLdifModels.create_entry(entry1_data)

        entry2_data: dict[str, object] = {
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
        entry1_data: dict[str, object] = {
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
        entry2_data: dict[str, object] = {
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
