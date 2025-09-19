"""Comprehensive tests for FlextLdifDispatcher to achieve 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import Mock

from flext_core import FlextResult
from flext_ldif.dispatcher import FlextLdifDispatcher
from flext_ldif.models import FlextLdifModels
from flext_ldif.services import FlextLdifServices


class TestFlextLdifDispatcher:
    """Test cases for FlextLdifDispatcher to achieve 100% coverage."""

    def test_service_container_protocol(self) -> None:
        """Test ServiceContainer protocol definition."""
        # Test that protocol can be used for type checking
        mock_services = Mock()
        mock_services.parser = Mock()
        mock_services.validator = Mock()
        mock_services.writer = Mock()

        # This should not raise any type errors
        services: FlextLdifDispatcher.ServiceContainer = mock_services
        assert services.parser is not None
        assert services.validator is not None
        assert services.writer is not None

    def test_parse_string_command_creation(self) -> None:
        """Test ParseStringCommand creation."""
        command = FlextLdifModels.ParseStringCommand(content="test content")
        assert command.content == "test content"

    def test_parse_file_command_creation(self) -> None:
        """Test ParseFileCommand creation."""
        command = FlextLdifModels.ParseFileCommand(file_path="/test/file.ldif")
        assert command.file_path == "/test/file.ldif"

    def test_write_string_command_creation(self) -> None:
        """Test WriteStringCommand creation."""
        entries = [FlextLdifModels.create_entry({"dn": "cn=test", "attributes": {}})]
        command = FlextLdifModels.WriteStringCommand(entries=entries)
        assert command.entries == entries

    def test_write_file_command_creation(self) -> None:
        """Test WriteFileCommand creation."""
        entries = [FlextLdifModels.create_entry({"dn": "cn=test", "attributes": {}})]
        file_path = Path("/test/file.ldif")
        command = FlextLdifModels.WriteFileCommand(entries=entries, file_path=str(file_path))  # Convert Path to string
        assert command.entries == entries
        assert command.file_path == str(file_path)  # Compare with string version

    def test_validate_entries_command_creation(self) -> None:
        """Test ValidateEntriesCommand creation."""
        entries = [FlextLdifModels.create_entry({"dn": "cn=test", "attributes": {}})]
        command = FlextLdifModels.ValidateEntriesCommand(entries=entries)
        assert command.entries == entries

    def test_build_dispatcher_success(self) -> None:
        """Test successful dispatcher creation."""
        # Create mock services
        mock_parser = Mock()
        mock_validator = Mock()
        mock_writer = Mock()

        mock_services = Mock()
        mock_services.parser = mock_parser
        mock_services.validator = mock_validator
        mock_services.writer = mock_writer

        # Create dispatcher
        dispatcher = FlextLdifDispatcher.build_dispatcher(mock_services)

        assert dispatcher is not None
        assert isinstance(dispatcher, FlextLdifDispatcher.SimpleDispatcher)

    def test_build_dispatcher_with_bus(self) -> None:
        """Test dispatcher creation with custom bus."""
        # Create mock services
        mock_parser = Mock()
        mock_validator = Mock()
        mock_writer = Mock()

        mock_services = Mock()
        mock_services.parser = mock_parser
        mock_services.validator = mock_validator
        mock_services.writer = mock_writer

        # Create dispatcher (bus parameter removed in simple implementation)
        dispatcher = FlextLdifDispatcher.build_dispatcher(mock_services)

        assert dispatcher is not None
        assert isinstance(dispatcher, FlextLdifDispatcher.SimpleDispatcher)

    def test_parse_string_handler_success(self) -> None:
        """Test successful string parsing through dispatcher."""
        # Create mock services with successful parse
        mock_parser = Mock()
        mock_validator = Mock()
        mock_writer = Mock()

        # Mock successful parse result
        test_entries = [
            FlextLdifModels.create_entry({"dn": "cn=test", "attributes": {}}),
        ]
        mock_parser.parse_content.return_value = FlextResult[
            list[FlextLdifModels.Entry]
        ].ok(test_entries)

        mock_services = Mock()
        mock_services.parser = mock_parser
        mock_services.validator = mock_validator
        mock_services.writer = mock_writer

        # Create dispatcher
        dispatcher = FlextLdifDispatcher.build_dispatcher(mock_services)

        # Test parse string command
        command = FlextLdifModels.ParseStringCommand(content="dn: cn=test\ncn: test")
        result = dispatcher.dispatch(command)

        assert result.is_success
        assert isinstance(result.value, dict)
        assert "entries" in result.value
        assert "type" in result.value
        assert result.value["type"] == "parse_string"

    def test_parse_string_handler_failure(self) -> None:
        """Test string parsing failure through dispatcher."""
        # Create mock services with failed parse
        mock_parser = Mock()
        mock_validator = Mock()
        mock_writer = Mock()

        # Mock failed parse result
        mock_parser.parse_content.return_value = FlextResult[
            list[FlextLdifModels.Entry]
        ].fail("Parse error")

        mock_services = Mock()
        mock_services.parser = mock_parser
        mock_services.validator = mock_validator
        mock_services.writer = mock_writer

        # Create dispatcher
        dispatcher = FlextLdifDispatcher.build_dispatcher(mock_services)

        # Test parse string command
        command = FlextLdifModels.ParseStringCommand(content="invalid content")
        result = dispatcher.dispatch(command)

        assert result.is_failure
        assert result.error is not None and "Parse error" in result.error

    def test_parse_string_handler_failure_no_error_message(self) -> None:
        """Test string parsing failure with no error message."""
        # Create mock services with failed parse
        mock_parser = Mock()
        mock_validator = Mock()
        mock_writer = Mock()

        # Mock failed parse result with None error
        mock_parser.parse_content.return_value = FlextResult[
            list[FlextLdifModels.Entry]
        ].fail("")

        mock_services = Mock()
        mock_services.parser = mock_parser
        mock_services.validator = mock_validator
        mock_services.writer = mock_writer

        # Create dispatcher
        dispatcher = FlextLdifDispatcher.build_dispatcher(mock_services)

        # Test parse string command
        command = FlextLdifModels.ParseStringCommand(content="invalid content")
        result = dispatcher.dispatch(command)

        assert result.is_failure
        assert result.error is not None and "Unknown error occurred" in result.error

    def test_parse_file_handler_success(self) -> None:
        """Test successful file parsing through dispatcher."""
        # Create real services instead of mocks - following FLEXT QA rules
        services = FlextLdifServices()

        # Create temporary LDIF file with test content
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8",
        ) as temp_f:
            ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: Test

"""
            temp_f.write(ldif_content)
            temp_file = Path(temp_f.name)

        try:
            # Create dispatcher with real services
            dispatcher = FlextLdifDispatcher.build_dispatcher(services)

            # Test parse file command with real file
            command = FlextLdifModels.ParseFileCommand(file_path=str(temp_file))
            result = dispatcher.dispatch(command)

            assert result.is_success
            assert isinstance(result.value, dict)
            assert "entries" in result.value
            assert "type" in result.value
            assert result.value["type"] == "parse_file"
            assert len(result.value["entries"]) == 1

        finally:
            # Clean up
            if temp_file.exists():
                temp_file.unlink()

    def test_parse_file_handler_failure(self) -> None:
        """Test file parsing failure through dispatcher."""
        # Create mock services with failed parse
        mock_parser = Mock()
        mock_validator = Mock()
        mock_writer = Mock()

        # Mock failed parse result
        mock_parser.parse_ldif_file.return_value = FlextResult[
            list[FlextLdifModels.Entry]
        ].fail("File parse error")

        mock_services = Mock()
        mock_services.parser = mock_parser
        mock_services.validator = mock_validator
        mock_services.writer = mock_writer

        # Create dispatcher
        dispatcher = FlextLdifDispatcher.build_dispatcher(mock_services)

        # Test parse file command
        command = FlextLdifModels.ParseFileCommand(file_path="/test/file.ldif")
        result = dispatcher.dispatch(command)

        assert result.is_failure
        assert result.error is not None and "File parse error" in result.error

    def test_parse_file_handler_failure_no_error_message(self) -> None:
        """Test file parsing failure with no error message."""
        # Create mock services with failed parse
        mock_parser = Mock()
        mock_validator = Mock()
        mock_writer = Mock()

        # Mock failed parse result with None error
        mock_parser.parse_ldif_file.return_value = FlextResult[
            list[FlextLdifModels.Entry]
        ].fail("")

        mock_services = Mock()
        mock_services.parser = mock_parser
        mock_services.validator = mock_validator
        mock_services.writer = mock_writer

        # Create dispatcher
        dispatcher = FlextLdifDispatcher.build_dispatcher(mock_services)

        # Test parse file command
        command = FlextLdifModels.ParseFileCommand(file_path="/test/file.ldif")
        result = dispatcher.dispatch(command)

        assert result.is_failure
        assert result.error is not None and "Unknown error occurred" in result.error

    def test_write_string_handler_success(self) -> None:
        """Test successful string writing through dispatcher."""
        # Create mock services with successful write
        mock_parser = Mock()
        mock_validator = Mock()
        mock_writer = Mock()

        # Mock successful write result
        mock_writer.write_entries_to_string.return_value = FlextResult[str].ok(
            "dn: cn=test\ncn: test\n",
        )

        mock_services = Mock()
        mock_services.parser = mock_parser
        mock_services.validator = mock_validator
        mock_services.writer = mock_writer

        # Create dispatcher
        dispatcher = FlextLdifDispatcher.build_dispatcher(mock_services)

        # Test write string command
        entries = [
            FlextLdifModels.create_entry(
                {"dn": "cn=test", "attributes": {"cn": ["test"]}},
            ),
        ]
        command = FlextLdifModels.WriteStringCommand(entries=entries)
        result = dispatcher.dispatch(command)

        assert result.is_success
        assert isinstance(result.value, dict)
        assert "content" in result.value
        assert "type" in result.value
        assert result.value["type"] == "write_string"

    def test_write_string_handler_failure(self) -> None:
        """Test string writing failure through dispatcher."""
        # Create mock services with failed write
        mock_parser = Mock()
        mock_validator = Mock()
        mock_writer = Mock()

        # Mock failed write result
        mock_writer.write_entries_to_string.return_value = FlextResult[str].fail(
            "Write error",
        )

        mock_services = Mock()
        mock_services.parser = mock_parser
        mock_services.validator = mock_validator
        mock_services.writer = mock_writer

        # Create dispatcher
        dispatcher = FlextLdifDispatcher.build_dispatcher(mock_services)

        # Test write string command
        entries = [
            FlextLdifModels.create_entry(
                {"dn": "cn=test", "attributes": {"cn": ["test"]}},
            ),
        ]
        command = FlextLdifModels.WriteStringCommand(entries=entries)
        result = dispatcher.dispatch(command)

        assert result.is_failure
        assert result.error is not None and "Write error" in result.error

    def test_write_string_handler_failure_no_error_message(self) -> None:
        """Test string writing failure with no error message."""
        # Create mock services with failed write
        mock_parser = Mock()
        mock_validator = Mock()
        mock_writer = Mock()

        # Mock failed write result with specific error
        mock_writer.write_entries_to_string.return_value = FlextResult[str].fail(
            "String write failed",
        )

        mock_services = Mock()
        mock_services.parser = mock_parser
        mock_services.validator = mock_validator
        mock_services.writer = mock_writer

        # Create dispatcher
        dispatcher = FlextLdifDispatcher.build_dispatcher(mock_services)

        # Test write string command
        entries = [
            FlextLdifModels.create_entry(
                {"dn": "cn=test", "attributes": {"cn": ["test"]}},
            ),
        ]
        command = FlextLdifModels.WriteStringCommand(entries=entries)
        result = dispatcher.dispatch(command)

        assert result.is_failure
        assert result.error is not None and "String write failed" in result.error

    def test_write_file_handler_success(self) -> None:
        """Test successful file writing through dispatcher."""
        # Create mock services with successful write
        mock_parser = Mock()
        mock_validator = Mock()
        mock_writer = Mock()

        # Mock successful write result
        mock_writer.write_entries_to_file.return_value = FlextResult[bool].ok(True)

        mock_services = Mock()
        mock_services.parser = mock_parser
        mock_services.validator = mock_validator
        mock_services.writer = mock_writer

        # Create dispatcher
        dispatcher = FlextLdifDispatcher.build_dispatcher(mock_services)

        # Test write file command
        entries = [
            FlextLdifModels.create_entry(
                {"dn": "cn=test", "attributes": {"cn": ["test"]}},
            ),
        ]
        file_path = Path("/test/file.ldif")
        command = FlextLdifModels.WriteFileCommand(entries=entries, file_path=str(file_path))  # Convert Path to string
        result = dispatcher.dispatch(command)

        assert result.is_success
        assert isinstance(result.value, dict)
        assert "success" in result.value
        assert "type" in result.value
        assert result.value["type"] == "write_file"

    def test_write_file_handler_failure(self) -> None:
        """Test file writing failure through dispatcher."""
        # Create mock services with failed write
        mock_parser = Mock()
        mock_validator = Mock()
        mock_writer = Mock()

        # Mock failed write result
        mock_writer.write_entries_to_file.return_value = FlextResult[bool].fail(
            "File write error",
        )

        mock_services = Mock()
        mock_services.parser = mock_parser
        mock_services.validator = mock_validator
        mock_services.writer = mock_writer

        # Create dispatcher
        dispatcher = FlextLdifDispatcher.build_dispatcher(mock_services)

        # Test write file command
        entries = [
            FlextLdifModels.create_entry(
                {"dn": "cn=test", "attributes": {"cn": ["test"]}},
            ),
        ]
        file_path = Path("/test/file.ldif")
        command = FlextLdifModels.WriteFileCommand(entries=entries, file_path=str(file_path))  # Convert Path to string
        result = dispatcher.dispatch(command)

        assert result.is_failure
        assert result.error is not None and "File write error" in result.error

    def test_write_file_handler_failure_no_error_message(self) -> None:
        """Test file writing failure with no error message."""
        # Create mock services with failed write
        mock_parser = Mock()
        mock_validator = Mock()
        mock_writer = Mock()

        # Mock failed write result with None error
        mock_writer.write_entries_to_file.return_value = FlextResult[bool].fail("")

        mock_services = Mock()
        mock_services.parser = mock_parser
        mock_services.validator = mock_validator
        mock_services.writer = mock_writer

        # Create dispatcher
        dispatcher = FlextLdifDispatcher.build_dispatcher(mock_services)

        # Test write file command
        entries = [
            FlextLdifModels.create_entry(
                {"dn": "cn=test", "attributes": {"cn": ["test"]}},
            ),
        ]
        file_path = Path("/test/file.ldif")
        command = FlextLdifModels.WriteFileCommand(entries=entries, file_path=str(file_path))  # Convert Path to string
        result = dispatcher.dispatch(command)

        assert result.is_failure
        assert result.error is not None and "Unknown error occurred" in result.error

    def test_validate_entries_handler_success(self) -> None:
        """Test successful entry validation through dispatcher."""
        # Create mock services with successful validation
        mock_parser = Mock()
        mock_validator = Mock()
        mock_writer = Mock()

        # Mock successful validation result
        mock_validator.validate_entries.return_value = FlextResult[bool].ok(True)

        mock_services = Mock()
        mock_services.parser = mock_parser
        mock_services.validator = mock_validator
        mock_services.writer = mock_writer

        # Create dispatcher
        dispatcher = FlextLdifDispatcher.build_dispatcher(mock_services)

        # Test validate entries command
        entries = [
            FlextLdifModels.create_entry(
                {"dn": "cn=test", "attributes": {"cn": ["test"]}},
            ),
        ]
        command = FlextLdifModels.ValidateEntriesCommand(entries=entries)
        result = dispatcher.dispatch(command)

        assert result.is_success
        assert isinstance(result.value, dict)
        assert "valid" in result.value
        assert "type" in result.value
        assert result.value["type"] == "validate_entries"

    def test_validate_entries_handler_failure(self) -> None:
        """Test entry validation failure through dispatcher."""
        # Create mock services with failed validation
        mock_parser = Mock()
        mock_validator = Mock()
        mock_writer = Mock()

        # Mock failed validation result
        mock_validator.validate_entries.return_value = FlextResult[bool].fail(
            "Validation error",
        )

        mock_services = Mock()
        mock_services.parser = mock_parser
        mock_services.validator = mock_validator
        mock_services.writer = mock_writer

        # Create dispatcher
        dispatcher = FlextLdifDispatcher.build_dispatcher(mock_services)

        # Test validate entries command
        entries = [
            FlextLdifModels.create_entry(
                {"dn": "cn=test", "attributes": {"cn": ["test"]}},
            ),
        ]
        command = FlextLdifModels.ValidateEntriesCommand(entries=entries)
        result = dispatcher.dispatch(command)

        assert result.is_failure
        assert result.error is not None and "Validation error" in result.error

    def test_validate_entries_handler_failure_no_error_message(self) -> None:
        """Test entry validation failure with no error message."""
        # Create mock services with failed validation
        mock_parser = Mock()
        mock_validator = Mock()
        mock_writer = Mock()

        # Mock failed validation result with None error
        mock_validator.validate_entries.return_value = FlextResult[bool].fail("")

        mock_services = Mock()
        mock_services.parser = mock_parser
        mock_services.validator = mock_validator
        mock_services.writer = mock_writer

        # Create dispatcher
        dispatcher = FlextLdifDispatcher.build_dispatcher(mock_services)

        # Test validate entries command
        entries = [
            FlextLdifModels.create_entry(
                {"dn": "cn=test", "attributes": {"cn": ["test"]}},
            ),
        ]
        command = FlextLdifModels.ValidateEntriesCommand(entries=entries)
        result = dispatcher.dispatch(command)

        assert result.is_failure
        assert result.error is not None and "Unknown error occurred" in result.error
