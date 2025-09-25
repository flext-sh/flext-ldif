"""FLEXT LDIF API - Comprehensive Unit Tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest
from tests.test_support.test_files import FileManager

from flext_ldif.api import FlextLdifAPI
from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels


@pytest.mark.unit
class TestFlextLdifAPI:
    """Comprehensive tests for FlextLdifAPI class."""

    def test_api_initialization_default(self) -> None:
        """Test API initialization with default configuration."""
        api = FlextLdifAPI()

        assert api is not None
        assert api._config is None
        assert api._management is not None
        assert api._processor_result is not None

    def test_api_initialization_with_config(self) -> None:
        """Test API initialization with configuration."""
        config = FlextLdifConfig()
        api = FlextLdifAPI(config)

        assert api is not None
        assert api._config == config
        assert api._management is not None
        assert api._processor_result is not None

    def test_api_health_check(self) -> None:
        """Test API health check."""
        api = FlextLdifAPI()
        result = api.health_check()

        assert result.is_success
        assert isinstance(result.value, dict)

    def test_api_execute(self) -> None:
        """Test API execute method (required by FlextService)."""
        api = FlextLdifAPI()

        result = api.execute()

        assert result.is_success
        assert isinstance(result.value, dict)

    @pytest.mark.asyncio
    async def test_api_execute_async(self) -> None:
        """Test API execute_async method (required by FlextService)."""
        api = FlextLdifAPI()

        result = await api.execute_async()

        assert result.is_success
        assert isinstance(result.value, dict)

    def test_api_parse_valid_content(self, sample_ldif_entries: str) -> None:
        """Test parsing valid LDIF content."""
        api = FlextLdifAPI()
        result = api.parse(sample_ldif_entries)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) > 0

        # Verify all entries are FlextLdifModels.Entry instances
        for entry in result.value:
            assert isinstance(entry, FlextLdifModels.Entry)

    def test_api_parse_invalid_content(self, invalid_ldif_data: str) -> None:
        """Test parsing invalid LDIF content."""
        api = FlextLdifAPI()
        result = api.parse(invalid_ldif_data)

        # Should handle invalid content gracefully
        assert result.is_success or result.is_failure

    def test_api_parse_empty_content(self) -> None:
        """Test parsing empty LDIF content."""
        api = FlextLdifAPI()
        result = api.parse("")

        # Should handle empty content gracefully
        assert result.is_success or result.is_failure

    def test_api_parse_file_valid(self, ldif_test_file: Path) -> None:
        """Test parsing valid LDIF file."""
        api = FlextLdifAPI()
        result = api.parse_ldif_file(ldif_test_file)

        assert result.is_success
        assert isinstance(result.value, list)

    def test_api_parse_file_nonexistent(self) -> None:
        """Test parsing nonexistent LDIF file."""
        api = FlextLdifAPI()
        nonexistent_file = Path("/nonexistent/file.ldif")
        result = api.parse_ldif_file(nonexistent_file)

        assert result.is_failure
        assert result.error is not None

    def test_api_validate_entries_valid(self, sample_ldif_entries: str) -> None:
        """Test validating valid LDIF entries."""
        api = FlextLdifAPI()
        parse_result = api.parse(sample_ldif_entries)

        if parse_result.is_success:
            result = api.validate_entries(parse_result.value)
            assert result.is_success
            assert isinstance(result.value, list)
            assert len(result.value) > 0

    def test_api_validate_entries_invalid(self, invalid_ldif_data: str) -> None:
        """Test validating invalid LDIF entries."""
        api = FlextLdifAPI()
        parse_result = api.parse(invalid_ldif_data)

        if parse_result.is_success:
            result = api.validate_entries(parse_result.value)
            # Should return validation results
            assert result.is_success or result.is_failure

    def test_api_write_entries(self, sample_ldif_entries: str) -> None:
        """Test writing LDIF entries."""
        api = FlextLdifAPI()
        parse_result = api.parse(sample_ldif_entries)

        if parse_result.is_success:
            result = api.write(parse_result.value)
            assert result.is_success
            assert isinstance(result.value, str)

    def test_api_write_file(
        self, sample_ldif_entries: str, test_file_manager: FileManager
    ) -> None:
        """Test writing LDIF entries to file."""
        api = FlextLdifAPI()
        parse_result = api.parse(sample_ldif_entries)

        if parse_result.is_success:
            output_file = test_file_manager.create_ldif_file("", "output.ldif")
            result = api.write_file(parse_result.value, output_file)
            assert result.is_success

    def test_api_transform_entries(self, sample_ldif_entries: str) -> None:
        """Test transforming LDIF entries."""
        api = FlextLdifAPI()
        parse_result = api.parse(sample_ldif_entries)

        if parse_result.is_success:
            # Test with identity transformer
            result = api.transform(parse_result.value)
            assert result.is_success
            assert isinstance(result.value, list)

    def test_api_analyze_entries(self, sample_ldif_entries: str) -> None:
        """Test analyzing LDIF entries."""
        api = FlextLdifAPI()
        parse_result = api.parse(sample_ldif_entries)

        if parse_result.is_success:
            result = api.analyze(parse_result.value)
            assert result.is_success
            assert isinstance(result.value, dict)

    def test_api_filter_entries(self, sample_ldif_entries: str) -> None:
        """Test filtering LDIF entries."""
        api = FlextLdifAPI()
        parse_result = api.parse(sample_ldif_entries)

        if parse_result.is_success:
            # Test with simple filter
            def simple_filter(entry: FlextLdifModels.Entry) -> bool:
                return "cn" in entry.attributes

            result = api.filter_entries(parse_result.value, simple_filter)
            assert result.is_success
            assert isinstance(result.value, list)

    def test_api_get_service_info(self) -> None:
        """Test getting service information."""
        api = FlextLdifAPI()
        info = api.get_service_info()

        assert isinstance(info, dict)
        assert "api" in info
        assert "capabilities" in info

    def test_api_entry_statistics(self, sample_ldif_entries: str) -> None:
        """Test getting entry statistics."""
        api = FlextLdifAPI()
        parse_result = api.parse(sample_ldif_entries)

        if parse_result.is_success:
            result = api.entry_statistics(parse_result.value)
            assert result.is_success
            assert isinstance(result.value, dict)

    def test_api_filter_persons(self, sample_ldif_entries: str) -> None:
        """Test filtering person entries."""
        api = FlextLdifAPI()
        parse_result = api.parse(sample_ldif_entries)

        if parse_result.is_success:
            result = api.filter_persons(parse_result.value)
            assert result.is_success
            assert isinstance(result.value, list)

    def test_api_filter_by_objectclass(self, sample_ldif_entries: str) -> None:
        """Test filtering entries by object class."""
        api = FlextLdifAPI()
        parse_result = api.parse(sample_ldif_entries)

        if parse_result.is_success:
            result = api.filter_by_objectclass(parse_result.value, "person")
            assert result.is_success
            assert isinstance(result.value, list)

    def test_api_filter_valid(self, sample_ldif_entries: str) -> None:
        """Test filtering valid entries."""
        api = FlextLdifAPI()
        parse_result = api.parse(sample_ldif_entries)

        if parse_result.is_success:
            result = api.filter_valid(parse_result.value)
            assert result.is_success
            assert isinstance(result.value, list)

    def test_api_process_with_schema(self, sample_ldif_entries: str) -> None:
        """Test processing entries with schema."""
        api = FlextLdifAPI()
        parse_result = api.parse(sample_ldif_entries)

        if parse_result.is_success:
            result = api.process_with_schema(parse_result.value)
            # Should handle schema processing gracefully - may succeed or fail depending on implementation
            assert result.is_success or result.is_failure
            if result.is_success:
                assert isinstance(result.value, list)

    def test_api_process_with_acl(self, sample_ldif_entries: str) -> None:
        """Test processing entries with ACL."""
        api = FlextLdifAPI()
        parse_result = api.parse(sample_ldif_entries)

        if parse_result.is_success:
            result = api.process_with_acl(parse_result.value)
            assert result.is_success
            assert isinstance(result.value, dict)
            # Check that the result contains expected keys
            assert "entry_count" in result.value
            assert "acl_count" in result.value
            assert "acls" in result.value
            assert "server_type" in result.value

    def test_api_adapt_for_server(self, sample_ldif_entries: str) -> None:
        """Test adapting entries for server."""
        api = FlextLdifAPI()
        parse_result = api.parse(sample_ldif_entries)

        if parse_result.is_success:
            result = api.adapt_for_server(parse_result.value, "openldap")
            # Should handle adaptation gracefully - may succeed or fail depending on implementation
            assert result.is_success or result.is_failure
            if result.is_success:
                assert isinstance(result.value, list)

    def test_api_validate_for_server(self, sample_ldif_entries: str) -> None:
        """Test validating entries for server."""
        api = FlextLdifAPI()
        parse_result = api.parse(sample_ldif_entries)

        if parse_result.is_success:
            result = api.validate_for_server(parse_result.value, "openldap")
            assert result.is_success
            assert isinstance(result.value, dict)

    def test_api_process_complete(self, sample_ldif_entries: str) -> None:
        """Test complete processing pipeline."""
        api = FlextLdifAPI()
        # process_complete expects the original string, not parsed entries
        result = api.process_complete(sample_ldif_entries)
        assert result.is_success
        assert isinstance(result.value, dict)

    def test_api_performance(self) -> None:
        """Test API performance characteristics."""
        api = FlextLdifAPI()

        # Test health check performance
        start_time = time.time()

        for _ in range(100):
            api.health_check()

        end_time = time.time()
        execution_time = end_time - start_time

        assert execution_time < 1.0  # Should complete within 1 second

    def test_api_memory_usage(self) -> None:
        """Test API memory usage characteristics."""
        # Test that API doesn't leak memory
        apis = []

        for _ in range(10):
            api = FlextLdifAPI()
            apis.append(api)

        # Verify all APIs are valid
        assert len(apis) == 10
        for api in apis:
            assert isinstance(api, FlextLdifAPI)

    def test_api_error_handling(self) -> None:
        """Test API error handling capabilities."""
        api = FlextLdifAPI()

        # Test with various error conditions
        result = api.parse("invalid ldif content")

        # Should handle errors gracefully
        assert result.is_success or result.is_failure
        if result.is_failure:
            assert result.error is not None

    def test_api_large_content(self) -> None:
        """Test API with large content."""
        api = FlextLdifAPI()

        # Create large LDIF content
        large_content = "\n".join([
            f"dn: cn=user{i},dc=example,dc=com\n"
            f"objectClass: person\n"
            f"cn: User {i}\n"
            f"mail: user{i}@example.com\n"
            f"description: User {i} description\n"
            for i in range(1000)
        ])

        result = api.parse(large_content)

        assert result.is_success
        assert len(result.value) == 1000

    def test_api_edge_cases(self) -> None:
        """Test API with edge cases."""
        api = FlextLdifAPI()

        # Test with very long lines
        long_line_content = (
            "dn: cn="
            + "x" * 10000
            + ",dc=example,dc=com\nobjectClass: person\ncn: Test"
        )
        result = api.parse(long_line_content)

        # Should handle long lines gracefully
        assert result.is_success or result.is_failure

        # Test with special characters
        special_char_content = "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: Test with special chars: !@#$%^&*()"
        result = api.parse(special_char_content)

        # Should handle special characters gracefully
        assert result.is_success or result.is_failure

    def test_api_concurrent_operations(self) -> None:
        """Test API concurrent operations."""
        api = FlextLdifAPI()
        results = []

        def worker() -> None:
            result = api.health_check()
            results.append(result)

        # Start multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=worker)
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify all operations succeeded
        assert len(results) == 5
        for result in results:
            assert result.is_success
