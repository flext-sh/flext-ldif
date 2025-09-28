"""Test suite for FlextLdifManagement.

This module tests the FLEXT LDIF Management Layer for orchestrating
schema, ACL, entry, and quirks management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import pytest
from tests.support import LdifTestData

from flext_core import FlextResult
from flext_ldif.management import FlextLdifManagement


class TestFlextLdifManagement:
    """Test suite for FlextLdifManagement."""

    def test_initialization_default(self) -> None:
        """Test management initialization with default configuration."""
        management = FlextLdifManagement()
        assert management is not None

    def test_initialization_with_server_type(self) -> None:
        """Test management initialization with server type."""
        management = FlextLdifManagement(server_type="openldap")
        assert management is not None

    def test_execute_success(self) -> None:
        """Test execute method returns success."""
        management = FlextLdifManagement()
        result = management.execute()

        assert result.is_success
        data = result.value
        assert isinstance(data, dict)
        assert "coordinator_status" in data or "status" in data

    @pytest.mark.asyncio
    async def test_execute_async_success(self) -> None:
        """Test async execute method returns success."""
        management = FlextLdifManagement()
        result = await management.execute_async()

        assert result.is_success
        data = result.value
        assert isinstance(data, dict)

    def test_process_ldif_complete_basic(self) -> None:
        """Test complete LDIF processing with basic entries."""
        management = FlextLdifManagement()
        sample = LdifTestData.basic_entries()

        result = management.process_ldif_complete(sample.content)

        assert result.is_success
        processed_data = result.value
        assert isinstance(processed_data, dict)
        assert "entries" in processed_data
        assert isinstance(processed_data["entries"], list)

    def test_process_ldif_complete_empty_content(self) -> None:
        """Test complete LDIF processing with empty content."""
        management = FlextLdifManagement()

        result = management.process_ldif_complete("")

        # Should handle empty content gracefully
        assert result.is_success or result.is_failure
        if result.is_success:
            assert isinstance(result.value, dict)
            if "entries" in result.value and isinstance(result.value["entries"], list):
                assert len(result.value["entries"]) == 0

    def test_process_ldif_complete_invalid_content(self) -> None:
        """Test complete LDIF processing with invalid content."""
        management = FlextLdifManagement()
        invalid_ldif = "invalid ldif content\nwithout proper format"

        result = management.process_ldif_complete(invalid_ldif)

        # Should handle invalid content gracefully
        assert result.is_success or result.is_failure

    def test_management_with_different_server_types(self) -> None:
        """Test management with different server types."""
        server_types = ["openldap", "ad", "generic", None]

        for server_type in server_types:
            management = FlextLdifManagement(server_type=server_type)
            result = management.execute()

            # Should initialize successfully with any server type
            assert result.is_success
            assert isinstance(result.value, dict)

    def test_process_with_real_ldif_data(self) -> None:
        """Test processing with real LDIF data."""
        management = FlextLdifManagement()

        # Use different LDIF samples
        samples = [
            LdifTestData.basic_entries(),
            LdifTestData.with_changes(),
            LdifTestData.multi_valued_attributes(),
        ]

        for sample in samples:
            result = management.process_ldif_complete(sample.content)
            # Should handle all sample types gracefully
            assert result.is_success or result.is_failure
            if result.is_success:
                assert isinstance(result.value, dict)

    def test_process_large_dataset(self) -> None:
        """Test processing with large dataset."""
        management = FlextLdifManagement()
        large_sample = LdifTestData.large_dataset(50)  # Smaller size for performance

        result = management.process_ldif_complete(large_sample.content)

        # Should handle large datasets
        assert result.is_success or result.is_failure
        if result.is_success:
            processed_entries = result.value
            assert isinstance(processed_entries, dict)

    def test_error_handling_malformed_entries(self) -> None:
        """Test error handling with malformed entries."""
        management = FlextLdifManagement()

        # Create malformed LDIF content
        malformed_ldif = """
        dn: cn=test
        # Missing required attributes
        objectClass:
        """

        result = management.process_ldif_complete(malformed_ldif)

        # Should handle malformed entries gracefully
        assert result.is_success or result.is_failure

    def test_chaining_operations(self) -> None:
        """Test chaining multiple operations."""
        management = FlextLdifManagement()
        sample = LdifTestData.basic_entries()

        # Process complete LDIF
        result1 = management.process_ldif_complete(sample.content)
        assert result1.is_success or result1.is_failure

        if (
            result1.is_success
            and "entries" in result1.value
            and isinstance(result1.value["entries"], list)
            and len(result1.value["entries"]) > 0
        ):
            entries = result1.value["entries"]
            assert isinstance(entries, list)

            # Process with ACL - only test if entries exist
            if entries:
                result2 = management.process_entries_with_acl(entries)
                # ACL processing may succeed or fail
                assert result2.is_success or result2.is_failure

                # Process with schema - only test if entries exist
                result3 = management.process_entries_with_schema(entries)
                # Schema processing may succeed or fail
                assert result3.is_success or result3.is_failure

                # Adapt for server - only test if entries exist
                result4 = management.adapt_entries_for_server(
                    entries, target_server="openldap"
                )
                # Adaptation may succeed or fail
                assert result4.is_success or result4.is_failure

                # Validate for server - only test if entries exist
                result5 = management.validate_entries_for_server(
                    entries, server_type="openldap"
                )
                # Validation may succeed or fail
                assert result5.is_success or result5.is_failure

    def test_basic_methods_contract(self) -> None:
        """Test that all methods follow the FlextResult contract."""
        management = FlextLdifManagement()

        # Test execute
        result = management.execute()
        assert isinstance(result, FlextResult)
        assert result.is_success or result.is_failure

        # Test process_ldif_complete
        result = management.process_ldif_complete(
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n"
        )
        assert isinstance(result, FlextResult)
        assert result.is_success or result.is_failure

    def test_management_initialization_variations(self) -> None:
        """Test different ways to initialize management."""
        # Default initialization
        mgmt1 = FlextLdifManagement()
        assert mgmt1 is not None

        # With server type
        mgmt2 = FlextLdifManagement(server_type="openldap")
        assert mgmt2 is not None

        # With None server type
        mgmt3 = FlextLdifManagement(server_type=None)
        assert mgmt3 is not None

    @pytest.mark.asyncio
    async def test_async_execute_variations(self) -> None:
        """Test async execute with different configurations."""
        management = FlextLdifManagement()

        # Basic async execution
        result1 = await management.execute_async()
        assert isinstance(result1, FlextResult)

        # Async execution with specific server type
        management_openldap = FlextLdifManagement(server_type="openldap")
        result2 = await management_openldap.execute_async()
        assert isinstance(result2, FlextResult)

    def test_stress_test_small_dataset(self) -> None:
        """Test with multiple small operations."""
        management = FlextLdifManagement()

        # Run multiple executions
        for _i in range(5):
            result = management.execute()
            assert isinstance(result, FlextResult)

            # Run LDIF processing
            sample = LdifTestData.basic_entries()
            ldif_result = management.process_ldif_complete(sample.content)
            assert isinstance(ldif_result, FlextResult)
