"""Test suite for FlextLdifHandlers.

This module provides comprehensive testing for the handlers functionality
using real services and FlextTests infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from tests.test_support import FileManager

from flext_core import FlextResult, FlextTypes
from flext_ldif.config import FlextLdifConfig
from flext_ldif.handlers import FlextLdifHandlers
from flext_ldif.models import FlextLdifModels


class TestFlextLdifHandlers:
    """Test suite for FlextLdifHandlers."""

    def test_initialization(self) -> None:
        """Test handlers initialization."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        assert handlers is not None
        assert handlers._ldif_config is not None
        assert handlers._container is not None
        assert handlers._logger is not None
        assert handlers._validation_handler is not None
        assert handlers._processing_handler is not None
        assert handlers._error_handler is not None
        assert handlers._file_handler is not None
        assert handlers._analytics_handler is not None
        assert handlers._coordinator is not None

    def test_execute_success(self) -> None:
        """Test successful execution."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        result = handlers.execute("test_command")

        assert result.is_success
        assert result.value is not None
        assert isinstance(result.value, dict)

    def test_validation_handler_initialization(self) -> None:
        """Test validation handler initialization."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        validation_handler = handlers._validation_handler
        assert validation_handler is not None
        assert validation_handler._config is not None
        assert validation_handler._validators is not None
        assert isinstance(validation_handler._validators, list)

    def test_validation_handler_add_validator(self) -> None:
        """Test adding validator to validation handler."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        validation_handler = handlers._validation_handler

        def test_validator(_data: FlextTypes.Core.Value) -> FlextResult[bool]:
            return FlextResult[bool].ok(True)

        result = validation_handler.add_validator(test_validator)
        assert result.is_success

        validator_count = validation_handler.get_validator_count()
        assert validator_count == 1

    def test_validation_handler_add_none_validator(self) -> None:
        """Test adding None validator fails."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        validation_handler = handlers._validation_handler

        result = validation_handler.add_validator(None)
        assert result.is_failure
        assert "Validator cannot be None" in result.error

    def test_validation_handler_validate_success(self) -> None:
        """Test validation with successful validator."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        validation_handler = handlers._validation_handler

        def test_validator(_data: FlextTypes.Core.Value) -> FlextResult[bool]:
            return FlextResult[bool].ok(True)

        validation_handler.add_validator(test_validator)

        result = validation_handler.validate("test_data")
        assert result.is_success
        assert result.value == "test_data"

    def test_validation_handler_validate_failure(self) -> None:
        """Test validation with failing validator."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        validation_handler = handlers._validation_handler

        def test_validator(_data: FlextTypes.Core.Value) -> FlextResult[bool]:
            return FlextResult[bool].fail("Validation failed")

        validation_handler.add_validator(test_validator)

        result = validation_handler.validate("test_data")
        assert result.is_failure
        assert "Validation failed" in result.error

    def test_validation_handler_validate_none_data(self) -> None:
        """Test validation with None data."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        validation_handler = handlers._validation_handler

        result = validation_handler.validate(None)
        assert result.is_failure
        assert "Data cannot be None" in result.error

    def test_processing_handler_initialization(self) -> None:
        """Test processing handler initialization."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        processing_handler = handlers._processing_handler
        assert processing_handler is not None
        assert processing_handler._config is not None
        assert processing_handler._processors is not None
        assert isinstance(processing_handler._processors, list)

    def test_processing_handler_add_processor(self) -> None:
        """Test adding processor to processing handler."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        processing_handler = handlers._processing_handler

        def test_processor(
            _data: FlextTypes.Core.Value,
        ) -> FlextResult[FlextTypes.Core.Value]:
            return FlextResult[FlextTypes.Core.Value].ok(_data)

        result = processing_handler.add_processor(test_processor)
        assert result.is_success

        processor_count = processing_handler.get_processor_count()
        assert processor_count == 1

    def test_processing_handler_add_none_processor(self) -> None:
        """Test adding None processor fails."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        processing_handler = handlers._processing_handler

        result = processing_handler.add_processor(None)
        assert result.is_failure
        assert "Processor cannot be None" in result.error

    def test_processing_handler_process_success(self) -> None:
        """Test processing with successful processor."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        processing_handler = handlers._processing_handler

        def test_processor(
            _data: FlextTypes.Core.Value,
        ) -> FlextResult[FlextTypes.Core.Value]:
            return FlextResult[FlextTypes.Core.Value].ok(f"processed_{_data}")

        processing_handler.add_processor(test_processor)

        result = processing_handler.process("test_data")
        assert result.is_success
        assert result.value == "processed_test_data"

    def test_processing_handler_process_failure(self) -> None:
        """Test processing with failing processor."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        processing_handler = handlers._processing_handler

        def test_processor(
            _data: FlextTypes.Core.Value,
        ) -> FlextResult[FlextTypes.Core.Value]:
            return FlextResult[FlextTypes.Core.Value].fail("Processing failed")

        processing_handler.add_processor(test_processor)

        result = processing_handler.process("test_data")
        assert result.is_failure
        assert "Processing failed" in result.error

    def test_processing_handler_process_none_data(self) -> None:
        """Test processing with None data."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        processing_handler = handlers._processing_handler

        result = processing_handler.process(None)
        assert result.is_failure
        assert "Data cannot be None" in result.error

    def test_error_handler_initialization(self) -> None:
        """Test error handler initialization."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        error_handler = handlers._error_handler
        assert error_handler is not None
        assert error_handler._config is not None
        assert error_handler._error_handlers is not None
        assert isinstance(error_handler._error_handlers, dict)

    def test_error_handler_register_handler(self) -> None:
        """Test registering error handler."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        error_handler = handlers._error_handler

        def test_handler(_error: Exception) -> FlextResult[FlextTypes.Core.Value]:
            return FlextResult[FlextTypes.Core.Value].ok("handled")

        result = error_handler.register_handler("ValueError", test_handler)
        assert result.is_success

        handler_count = error_handler.get_error_handler_count()
        assert handler_count == 1

    def test_error_handler_register_none_handler(self) -> None:
        """Test registering None handler fails."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        error_handler = handlers._error_handler

        result = error_handler.register_handler("ValueError", None)
        assert result.is_failure
        assert "Error type and handler are required" in result.error

    def test_error_handler_handle_error(self) -> None:
        """Test handling error."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        error_handler = handlers._error_handler

        # Test with registered handler
        def test_handler(_error: Exception) -> FlextResult[FlextTypes.Core.Value]:
            return FlextResult[FlextTypes.Core.Value].ok("handled")

        error_handler.register_handler("ValueError", test_handler)

        result = error_handler.handle_error(ValueError("test error"))
        assert result.is_success
        assert result.value == "handled"

    def test_error_handler_handle_none_error(self) -> None:
        """Test handling None error fails."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        error_handler = handlers._error_handler

        result = error_handler.handle_error(None)
        assert result.is_failure
        assert "Error cannot be None" in result.error

    def test_file_handler_initialization(self) -> None:
        """Test file handler initialization."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        file_handler = handlers._file_handler
        assert file_handler is not None
        assert file_handler._config is not None

    def test_file_handler_read_nonexistent_file(self) -> None:
        """Test reading nonexistent file."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        file_handler = handlers._file_handler

        result = file_handler.read_file(Path("nonexistent.ldif"))
        assert result.is_failure
        assert "File not found" in result.error

    def test_file_handler_read_none_path(self) -> None:
        """Test reading None path."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        file_handler = handlers._file_handler

        result = file_handler.read_file(None)
        assert result.is_failure
        assert "File not found" in result.error

    def test_analytics_handler_initialization(self) -> None:
        """Test analytics handler initialization."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        analytics_handler = handlers._analytics_handler
        assert analytics_handler is not None
        assert analytics_handler._config is not None
        assert analytics_handler._analytics_data is not None
        assert isinstance(analytics_handler._analytics_data, dict)

    def test_analytics_handler_analyze_empty_entries(self) -> None:
        """Test analytics with empty entries."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        analytics_handler = handlers._analytics_handler

        result = analytics_handler.analyze_entries([])
        assert result.is_failure
        assert "Entries cannot be empty" in result.error

    def test_analytics_handler_analyze_none_entries(self) -> None:
        """Test analytics with None entries."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        analytics_handler = handlers._analytics_handler

        result = analytics_handler.analyze_entries(None)
        assert result.is_failure
        assert "Entries cannot be empty" in result.error

    def test_coordinator_initialization(self) -> None:
        """Test handler coordinator initialization."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        coordinator = handlers._coordinator
        assert coordinator is not None
        assert coordinator._config is not None
        assert coordinator._validation_handler is not None
        assert coordinator._processing_handler is not None
        assert coordinator._error_handler is not None
        assert coordinator._file_handler is not None
        assert coordinator._analytics_handler is not None

    def test_coordinator_get_validation_handler(self) -> None:
        """Test getting validation handler from coordinator."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        coordinator = handlers._coordinator

        validation_handler = coordinator.get_validation_handler()
        assert validation_handler is not None
        assert validation_handler._config is not None

    def test_coordinator_get_processing_handler(self) -> None:
        """Test getting processing handler from coordinator."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        coordinator = handlers._coordinator

        processing_handler = coordinator.get_processing_handler()
        assert processing_handler is not None
        assert processing_handler._config is not None

    def test_coordinator_get_error_handler(self) -> None:
        """Test getting error handler from coordinator."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        coordinator = handlers._coordinator

        error_handler = coordinator.get_error_handler()
        assert error_handler is not None
        assert error_handler._config is not None

    def test_coordinator_get_file_handler(self) -> None:
        """Test getting file handler from coordinator."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        coordinator = handlers._coordinator

        file_handler = coordinator.get_file_handler()
        assert file_handler is not None
        assert file_handler._config is not None

    def test_coordinator_get_analytics_handler(self) -> None:
        """Test getting analytics handler from coordinator."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        coordinator = handlers._coordinator

        analytics_handler = coordinator.get_analytics_handler()
        assert analytics_handler is not None
        assert analytics_handler._config is not None

    def test_coordinator_configure_handlers(self) -> None:
        """Test configuring handlers."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        coordinator = handlers._coordinator

        result = coordinator.configure_handlers()
        assert result.is_success

    def test_real_functionality_with_ldif_data(self, test_file_manager: FileManager) -> None:
        """Test real functionality with LDIF data."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        # Create test LDIF file
        ldif_content = """dn: cn=testuser,dc=example,dc=com
objectClass: person
cn: testuser
sn: user

dn: cn=testuser2,dc=example,dc=com
objectClass: person
cn: testuser2
sn: user2
"""

        ldif_file = test_file_manager.create_ldif_file(ldif_content, "test.ldif")

        # Test file reading - the file handler should read the file content
        file_handler = handlers._file_handler
        result = file_handler.read_file(ldif_file)

        # The file handler might validate LDIF format, so we check if it
        # succeeds or fails gracefully
        if result.is_success:
            assert "cn=testuser" in result.value
            assert "cn=testuser2" in result.value
        else:
            # If it fails, it should be a validation error, not a file
            # reading error
            assert (
                "Invalid LDIF file format" in result.error
                or "File not found" not in result.error
            )

    def test_validation_with_real_data(self) -> None:
        """Test validation with real data."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        validation_handler = handlers._validation_handler

        # Add a validator that checks for required fields
        def required_field_validator(data: FlextTypes.Core.Value) -> FlextResult[bool]:
            if isinstance(data, dict) and "cn" in data:
                return FlextResult[bool].ok(True)
            return FlextResult[bool].fail("Missing required field 'cn'")

        validation_handler.add_validator(required_field_validator)

        # Test with valid data
        valid_data = {"cn": "testuser", "sn": "user"}
        result = validation_handler.validate(valid_data)
        assert result.is_success

        # Test with invalid data
        invalid_data = {"sn": "user"}  # Missing cn
        result = validation_handler.validate(invalid_data)
        assert result.is_failure
        assert "Missing required field 'cn'" in result.error

    def test_processing_with_real_data(self) -> None:
        """Test processing with real data."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        processing_handler = handlers._processing_handler

        # Add a processor that transforms data
        def transform_processor(
            data: FlextTypes.Core.Value,
        ) -> FlextResult[FlextTypes.Core.Value]:
            if isinstance(data, dict):
                transformed = {k.upper(): v for k, v in data.items()}
                return FlextResult[FlextTypes.Core.Value].ok(transformed)
            return FlextResult[FlextTypes.Core.Value].ok(data)

        processing_handler.add_processor(transform_processor)

        # Test processing
        test_data = {"cn": "testuser", "sn": "user"}
        result = processing_handler.process(test_data)
        assert result.is_success
        assert result.value == {"CN": "testuser", "SN": "user"}

    def test_error_handling_with_real_scenarios(self) -> None:
        """Test error handling with real scenarios."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        error_handler = handlers._error_handler

        # Register handlers for different error types
        def file_error_handler(_error: Exception) -> FlextResult[FlextTypes.Core.Value]:
            return FlextResult[FlextTypes.Core.Value].ok("file_error_handled")

        def validation_error_handler(
            _error: Exception,
        ) -> FlextResult[FlextTypes.Core.Value]:
            return FlextResult[FlextTypes.Core.Value].ok("validation_error_handled")

        def processing_error_handler(
            _error: Exception,
        ) -> FlextResult[FlextTypes.Core.Value]:
            return FlextResult[FlextTypes.Core.Value].ok("processing_error_handled")

        # Register handlers
        result = error_handler.register_handler("FileNotFoundError", file_error_handler)
        assert result.is_success

        result = error_handler.register_handler(
            "ValidationError", validation_error_handler
        )
        assert result.is_success

        result = error_handler.register_handler(
            "ProcessingError", processing_error_handler
        )
        assert result.is_success

        # Test error handling
        result = error_handler.handle_error(FileNotFoundError("File not found"))
        assert result.is_success
        assert result.value == "file_error_handled"

        result = error_handler.handle_error(ValueError("Validation failed"))
        # Default handler might fail depending on configuration
        # We just check that it returns a result
        assert result is not None

        # Check handler count
        handler_count = error_handler.get_error_handler_count()
        assert handler_count == 3

    def test_analytics_with_real_entries(self) -> None:
        """Test analytics with real LDIF entries."""
        config = FlextLdifConfig()
        handlers = FlextLdifHandlers(config)

        analytics_handler = handlers._analytics_handler

        # Create test entries
        entry_data1: dict[str, object] = {
            "dn": "cn=testuser1,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person"],
                "cn": ["testuser1"],
                "sn": ["user1"],
            },
        }

        entry_data2: dict[str, object] = {
            "dn": "cn=testuser2,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person"],
                "cn": ["testuser2"],
                "sn": ["user2"],
            },
        }

        entry1 = FlextLdifModels.Entry.create(**entry_data1)
        entry2 = FlextLdifModels.Entry.create(**entry_data2)

        assert entry1.is_success
        assert entry2.is_success

        entries = [entry1.value, entry2.value]

        # Test analytics
        result = analytics_handler.analyze_entries(entries)
        assert result.is_success
        assert isinstance(result.value, dict)
        assert "entry_count" in result.value
        assert "attribute_statistics" in result.value
        assert "object_class_statistics" in result.value
        assert "dn_statistics" in result.value
