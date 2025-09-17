"""Complete tests for FlextLdifTransformerService - 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Never

from flext_ldif.models import FlextLdifModels
from flext_ldif.transformer_service import FlextLdifTransformerService


class TransformError(Exception):
    """Custom exception for transformation errors in tests."""


class DNAccessError(Exception):
    """Custom exception for DN access errors in tests."""


class IterationError(Exception):
    """Custom exception for iteration errors in tests."""


class TestFlextLdifTransformerServiceComplete:
    """Complete tests for FlextLdifTransformerService to achieve 100% coverage."""

    def test_transformer_service_initialization(self) -> None:
        """Test transformer service initialization."""
        service = FlextLdifTransformerService()
        assert service is not None

    def test_transform_entries_success(self) -> None:
        """Test transform_entries with successful transformation."""
        service = FlextLdifTransformerService()

        # Create test entries
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        # Define transformation function
        def transform_func(_entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            # Add a new attribute
            new_attributes = dict(entry.attributes.data)
            new_attributes["transformed"] = ["true"]
            return FlextLdifModels.Entry(
                dn=entry.dn,
                attributes=FlextLdifModels.LdifAttributes(data=new_attributes),
            )

        result = service.transform_entries(entries, transform_func)
        assert result.is_success is True
        transformed_entries = result.value
        assert len(transformed_entries) == 1
        assert "transformed" in transformed_entries[0].attributes.data

    def test_transform_entries_empty_list(self) -> None:
        """Test transform_entries with empty list."""
        service = FlextLdifTransformerService()

        def transform_func(_entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            return _entry

        result = service.transform_entries([], transform_func)
        assert result.is_success is True
        assert result.value == []

    def test_transform_entries_transform_function_exception(self) -> None:
        """Test transform_entries when transform function raises exception."""
        service = FlextLdifTransformerService()

        # Create test entry
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        # Define transformation function that raises exception
        def transform_func(_entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            msg = "Transform error"
            raise TransformError(msg)

        result = service.transform_entries(entries, transform_func)
        assert result.is_success is False
        assert "Transform error" in result.error

    def test_transform_entries_outer_exception(self) -> None:
        """Test transform_entries when outer loop raises exception."""
        service = FlextLdifTransformerService()

        # Create test entry
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        # Define transformation function that raises exception during iteration
        def transform_func(_entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            # This will cause an exception when trying to access the entry
            msg = "Outer transform error"
            raise TransformError(msg)

        result = service.transform_entries(entries, transform_func)
        assert result.is_success is False
        assert "Transform error" in result.error

    def test_normalize_dns_success(self) -> None:
        """Test normalize_dns with successful normalization."""
        service = FlextLdifTransformerService()

        # Create test entry with a valid DN format
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        result = service.normalize_dns(entries)
        assert result.is_success is True
        normalized_entries = result.value
        assert len(normalized_entries) == 1
        # DN should remain normalized (already properly formatted)
        assert normalized_entries[0].dn.value == "uid=john,ou=people,dc=example,dc=com"

    def test_normalize_dns_empty_list(self) -> None:
        """Test normalize_dns with empty list."""
        service = FlextLdifTransformerService()

        result = service.normalize_dns([])
        assert result.is_success is True
        assert result.value == []

    def test_normalize_dns_exception(self) -> None:
        """Test normalize_dns when exception occurs."""
        service = FlextLdifTransformerService()

        # Create a mock entry that will cause exception when accessing dn.value
        class MockEntry:
            def __init__(self) -> None:
                self._attributes = FlextLdifModels.LdifAttributes(
                    data={"objectClass": ["person"]}
                )

            @property
            def dn(self) -> Never:
                # This will raise an exception when trying to access value
                msg = "DN access error"
                raise DNAccessError(msg)

            @property
            def attributes(self) -> FlextLdifModels.LdifAttributes:
                return self._attributes

        mock_entry = MockEntry()
        entries = [mock_entry]

        result = service.normalize_dns(entries)
        assert result.is_success is False
        assert "DN normalization error" in result.error

    def test_execute_method(self) -> None:
        """Test execute method."""
        service = FlextLdifTransformerService()

        result = service.execute()
        assert result.is_success is True
        assert result.value == []

    def test_get_config_info(self) -> None:
        """Test get_config_info method."""
        service = FlextLdifTransformerService()

        config_info = service.get_config_info()
        assert isinstance(config_info, dict)
        assert config_info["service"] == "FlextLdifTransformerService"
        assert "config" in config_info
        assert config_info["config"]["service_type"] == "FlextLdifTransformerService"
        assert config_info["config"]["status"] == "ready"
        assert "operations" in config_info["config"]

    def test_get_service_info(self) -> None:
        """Test get_service_info method."""
        service = FlextLdifTransformerService()

        service_info = service.get_service_info()
        assert isinstance(service_info, dict)
        assert service_info["service_name"] == "FlextLdifTransformerService"
        assert service_info["service_type"] == "transformer"
        assert service_info["status"] == "ready"
        assert "capabilities" in service_info
        assert "transform_entries" in service_info["capabilities"]
        assert "normalize_dns" in service_info["capabilities"]
        assert "execute" in service_info["capabilities"]

    def test_transform_entries_iteration_exception(self) -> None:
        """Test transform_entries when iteration raises exception."""
        service = FlextLdifTransformerService()

        # Create mock entries that will cause exception during iteration
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

        # Create a mock that raises exception when accessed
        class MockEntries:
            def __iter__(self) -> Never:
                msg = "Outer iteration error"
                raise IterationError(msg)

        mock_entries = MockEntries()

        def transform_func(_entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            return _entry

        result = service.transform_entries(mock_entries, transform_func)
        assert result.is_success is False
        assert "Transform error" in result.error
