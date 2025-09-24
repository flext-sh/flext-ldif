"""Test coverage for processor module using flext-core patterns.

Tests the core LDIF processor functionality with comprehensive coverage
using real flext-core integration instead of mocking.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_core import FlextResult
from flext_ldif import FlextLdifModels, FlextLdifProcessor, processor


class TestFlextLdifProcessorCoverage:
    """Test coverage for FlextLdifProcessor using flext-core patterns."""

    def test_processor_module_import(self) -> None:
        """Test processor module can be imported with flext-core integration."""
        assert hasattr(processor, "FlextLdifProcessor")
        assert hasattr(processor, "__all__")
        assert "FlextLdifProcessor" in processor.__all__

    def test_processor_initialization(self) -> None:
        """Test processor can be initialized with flext-core patterns."""
        processor = FlextLdifProcessor()

        assert processor is not None
        assert hasattr(processor, "_logger")
        assert hasattr(processor, "_config")

    def test_processor_execute_method(self) -> None:
        """Test processor execute method returns FlextResult."""
        processor = FlextLdifProcessor()
        result = processor.execute()

        assert isinstance(result, FlextResult)
        assert result.is_success
        assert "status" in result.value
        assert result.value["status"] == "healthy"

    def test_processor_parsing_functionality(self) -> None:
        """Test processor parsing functionality with real FlextResult."""
        processor = FlextLdifProcessor()

        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
sn: Test User"""

        result = processor.parse_string(ldif_content)

        assert isinstance(result, FlextResult)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"

    def test_processor_validation_functionality(self) -> None:
        """Test processor validation functionality with real FlextResult."""
        processor = FlextLdifProcessor()

        # Create a valid entry
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"], "sn": ["Test"]},
        }
        entry_result = FlextLdifModels.Entry.create(
            cast("dict[str, object]", entry_data)
        )
        assert entry_result.is_success
        entry = entry_result.value

        result = processor.validate_entries([entry])

        assert isinstance(result, FlextResult)
        assert result.is_success
        # validate_entries returns FlextResult[list[Entry]] with validated entries
        assert result.value is not None
        assert len(result.value) == 1
        assert result.value[0].dn.value == "cn=test,dc=example,dc=com"

    def test_processor_transformation_functionality(self) -> None:
        """Test processor transformation functionality with real FlextResult."""
        processor = FlextLdifProcessor()

        # Create a test entry
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        }
        entry_result = FlextLdifModels.Entry.create(
            cast("dict[str, object]", entry_data)
        )
        assert entry_result.is_success
        entry = entry_result.value

        def transform_func(entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            entry.attributes.add_attribute("transformed", ["true"])
            return entry

        result = processor.transform_entries([entry], transform_func)

        assert isinstance(result, FlextResult)
        assert result.is_success
        transformed_entries = result.unwrap()
        assert len(transformed_entries) == 1
        assert transformed_entries[0].has_attribute("transformed")

    def test_processor_writing_functionality(self) -> None:
        """Test processor writing functionality with real FlextResult."""
        processor = FlextLdifProcessor()

        # Create a test entry
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        }
        entry_result = FlextLdifModels.Entry.create(
            cast("dict[str, object]", entry_data)
        )
        assert entry_result.is_success
        entry = entry_result.value

        result = processor.write_string([entry])

        assert isinstance(result, FlextResult)
        assert result.is_success
        ldif_content = result.unwrap()
        assert "dn: cn=test,dc=example,dc=com" in ldif_content
        assert "cn: test" in ldif_content

    def test_processor_health_check(self) -> None:
        """Test processor health check functionality."""
        processor = FlextLdifProcessor()
        result = processor.get_processor_health()

        assert isinstance(result, FlextResult)
        assert result.is_success
        health_data = result.unwrap()
        assert "status" in health_data
        assert "timestamp" in health_data
        assert "config" in health_data
        assert "capabilities" in health_data
        assert health_data["status"] == "healthy"

    def test_processor_config_info(self) -> None:
        """Test processor configuration information."""
        processor = FlextLdifProcessor()
        config_info = processor.get_config_info()

        assert isinstance(config_info, dict)
        assert "encoding" in config_info
        assert "max_entries" in config_info
        assert "strict_validation" in config_info
        assert "wrap_lines" in config_info

    def test_processor_error_handling(self) -> None:
        """Test processor error handling with FlextResult patterns."""
        processor = FlextLdifProcessor()

        # Test with invalid LDIF content
        invalid_content = "invalid ldif content without proper structure"
        result = processor.parse_string(invalid_content)

        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "Failed to parse entry" in result.error

    def test_processor_empty_input_handling(self) -> None:
        """Test processor handles empty input gracefully."""
        processor = FlextLdifProcessor()

        # Test with empty content
        result = processor.parse_string("")
        assert isinstance(result, FlextResult)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 0

        # Test with empty entries list
        result = processor.validate_entries([])
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert "No entries to validate" in result.error

    def test_processor_flext_result_composition(self) -> None:
        """Test processor uses FlextResult composition patterns."""
        processor = FlextLdifProcessor()

        # Test chaining operations
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
sn: Test
objectClass: person"""

        # Parse -> Validate -> Transform -> Write chain
        parse_result = processor.parse_string(ldif_content)
        assert parse_result.is_success

        entries = parse_result.unwrap()
        validate_result = processor.validate_entries(entries)
        assert validate_result.is_success

        # validate_entries returns FlextResult[None], so we use the original entries
        def transform_func(entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            entry.attributes.add_attribute("processed", ["true"])
            return entry

        transform_result = processor.transform_entries(entries, transform_func)
        assert transform_result.is_success

        transformed_entries = transform_result.unwrap()
        write_result = processor.write_string(transformed_entries)
        assert write_result.is_success

        # Verify the chain worked
        ldif_output = write_result.unwrap()
        assert "cn=test,dc=example,dc=com" in ldif_output
        assert "processed: true" in ldif_output
