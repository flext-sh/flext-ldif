"""Comprehensive unit tests for FlextLdifHandlers functionality.

Tests all handler classes and their methods with real validation.
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextResult
from tests.test_support.ldif_data import LdifTestData

from flext_ldif.handlers import FlextLdifHandlers
from flext_ldif.models import FlextLdifModels


class TestFlextLdifHandlersParseQueryHandler:
    """Test suite for ParseQueryHandler."""

    def test_handle_valid_ldif_content(self, ldif_test_data: LdifTestData) -> None:
        """Test handling valid LDIF content."""
        handler = FlextLdifHandlers.ParseQueryHandler()
        content = ldif_test_data.basic_entries().content

        query = FlextLdifModels.ParseQuery(
            source=content,
            format="rfc",
            encoding="utf-8",
            strict=True,
        )

        result = handler.handle(query)

        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) > 0

    def test_handle_invalid_ldif_content(self) -> None:
        """Test handling invalid LDIF content."""
        handler = FlextLdifHandlers.ParseQueryHandler()

        query = FlextLdifModels.ParseQuery(
            source="invalid content",
            format="rfc",
            encoding="utf-8",
            strict=True,
        )

        result = handler.handle(query)

        # Should handle gracefully
        assert isinstance(result, FlextResult)

    def test_handle_empty_content(self) -> None:
        """Test handling empty LDIF content."""
        handler = FlextLdifHandlers.ParseQueryHandler()

        query = FlextLdifModels.ParseQuery(
            source="",
            format="rfc",
            encoding="utf-8",
            strict=True,
        )

        result = handler.handle(query)

        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) == 0


class TestFlextLdifHandlersWriteCommandHandler:
    """Test suite for WriteCommandHandler."""

    def test_handle_write_to_string(self, ldif_test_data: LdifTestData) -> None:
        """Test writing entries to string."""
        handler = FlextLdifHandlers.WriteCommandHandler()

        # Get some entries first
        content = ldif_test_data.basic_entries().content
        parse_query = FlextLdifModels.ParseQuery(source=content)
        parse_handler = FlextLdifHandlers.ParseQueryHandler()
        parse_result = parse_handler.handle(parse_query)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        command = FlextLdifModels.WriteCommand(
            entries=entries,
            format="rfc",
            output=None,  # Write to string
            line_width=76,
        )

        result = handler.handle(command)

        assert result.is_success
        content = result.unwrap()
        assert isinstance(content, str)
        assert len(content) > 0
        assert "dn:" in content

    def test_handle_write_to_file(
        self, ldif_test_data: LdifTestData, test_ldif_dir: Path
    ) -> None:
        """Test writing entries to file."""
        handler = FlextLdifHandlers.WriteCommandHandler()

        # Get some entries first
        content = ldif_test_data.basic_entries().content
        parse_query = FlextLdifModels.ParseQuery(source=content)
        parse_handler = FlextLdifHandlers.ParseQueryHandler()
        parse_result = parse_handler.handle(parse_query)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        output_file = test_ldif_dir / "output.ldif"
        command = FlextLdifModels.WriteCommand(
            entries=entries,
            format="rfc",
            output=str(output_file),
            line_width=76,
        )

        result = handler.handle(command)

        assert result.is_success
        assert output_file.exists()
        file_content = output_file.read_text(encoding="utf-8")
        assert len(file_content) > 0
        assert "dn:" in file_content

    def test_handle_empty_entries(self) -> None:
        """Test writing empty entries list."""
        handler = FlextLdifHandlers.WriteCommandHandler()

        command = FlextLdifModels.WriteCommand(
            entries=[],
            format="rfc",
            output=None,
            line_width=76,
        )

        result = handler.handle(command)

        assert result.is_success
        content = result.unwrap()
        assert isinstance(content, str)
        assert len(content.strip()) == 0


class TestFlextLdifHandlersValidateQueryHandler:
    """Test suite for ValidateQueryHandler."""

    def test_handle_valid_entries(self, ldif_test_data: LdifTestData) -> None:
        """Test validating valid entries."""
        handler = FlextLdifHandlers.ValidateQueryHandler()

        # Get some entries
        content = ldif_test_data.basic_entries().content
        parse_query = FlextLdifModels.ParseQuery(source=content)
        parse_handler = FlextLdifHandlers.ParseQueryHandler()
        parse_result = parse_handler.handle(parse_query)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        query = FlextLdifModels.ValidateQuery(
            entries=entries,
            schema_config=None,
            strict=True,
        )

        result = handler.handle(query)

        assert result.is_success
        report = result.unwrap()
        assert isinstance(report, dict)

    def test_handle_empty_entries(self) -> None:
        """Test validating empty entries."""
        handler = FlextLdifHandlers.ValidateQueryHandler()

        query = FlextLdifModels.ValidateQuery(
            entries=[],
            schema_config=None,
            strict=True,
        )

        result = handler.handle(query)

        assert result.is_success
        report = result.unwrap()
        assert isinstance(report, dict)


class TestFlextLdifHandlersAnalyzeQueryHandler:
    """Test suite for AnalyzeQueryHandler."""

    def test_handle_basic_analysis(self, ldif_test_data: LdifTestData) -> None:
        """Test basic analysis of entries."""
        handler = FlextLdifHandlers.AnalyzeQueryHandler()

        # Get some entries
        content = ldif_test_data.basic_entries().content
        parse_query = FlextLdifModels.ParseQuery(source=content)
        parse_handler = FlextLdifHandlers.ParseQueryHandler()
        parse_result = parse_handler.handle(parse_query)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        query = FlextLdifModels.AnalyzeQuery(
            entries=entries,
            metrics=["object_class_count"],
            include_patterns=True,
        )

        result = handler.handle(query)

        assert result.is_success
        report = result.unwrap()
        assert isinstance(report, dict)

    def test_handle_empty_entries(self) -> None:
        """Test analyzing empty entries."""
        handler = FlextLdifHandlers.AnalyzeQueryHandler()

        query = FlextLdifModels.AnalyzeQuery(
            entries=[],
            metrics=[],
            include_patterns=False,
        )

        result = handler.handle(query)

        assert result.is_success
        report = result.unwrap()
        assert isinstance(report, dict)


class TestFlextLdifHandlersMigrateCommandHandler:
    """Test suite for MigrateCommandHandler."""

    def test_handle_basic_migration(self, ldif_test_data: LdifTestData) -> None:
        """Test basic migration between formats."""
        handler = FlextLdifHandlers.MigrateCommandHandler()

        # Get some entries
        content = ldif_test_data.basic_entries().content
        parse_query = FlextLdifModels.ParseQuery(source=content)
        parse_handler = FlextLdifHandlers.ParseQueryHandler()
        parse_result = parse_handler.handle(parse_query)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        command = FlextLdifModels.MigrateCommand(
            entries=entries,
            source_format="rfc",
            target_format="oid",
            migration_config=None,
        )

        result = handler.handle(command)

        assert isinstance(result, FlextResult)


class TestFlextLdifHandlersNamespace:
    """Test suite for the FlextLdifHandlers namespace."""

    def test_handlers_namespace_access(self) -> None:
        """Test accessing handlers through namespace."""
        # Test that all expected handler classes are available
        assert hasattr(FlextLdifHandlers, "ParseQueryHandler")
        assert hasattr(FlextLdifHandlers, "WriteCommandHandler")
        assert hasattr(FlextLdifHandlers, "ValidateQueryHandler")
        assert hasattr(FlextLdifHandlers, "AnalyzeQueryHandler")
        assert hasattr(FlextLdifHandlers, "MigrateCommandHandler")

    def test_handler_instantiation(self) -> None:
        """Test that handlers can be instantiated."""
        parse_handler = FlextLdifHandlers.ParseQueryHandler()
        assert parse_handler is not None

        write_handler = FlextLdifHandlers.WriteCommandHandler()
        assert write_handler is not None

        validate_handler = FlextLdifHandlers.ValidateQueryHandler()
        assert validate_handler is not None

        analyze_handler = FlextLdifHandlers.AnalyzeQueryHandler()
        assert analyze_handler is not None

        migrate_handler = FlextLdifHandlers.MigrateCommandHandler()
        assert migrate_handler is not None
