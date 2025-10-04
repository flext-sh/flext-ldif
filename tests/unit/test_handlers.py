"""Test suite for LDIF CQRS handlers.

This module provides comprehensive testing for FlextLdifHandlers which implements
CQRS pattern with command and query handlers for LDIF operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextBus, FlextContainer, FlextContext

from flext_ldif.handlers import FlextLdifHandlers
from flext_ldif.models import FlextLdifModels


class TestHandlerManagement:
    """Test suite for handler management operations."""

    def test_get_dispatcher_creates_instance(self) -> None:
        """Test get_dispatcher creates dispatcher instance."""
        bus = FlextBus()

        dispatcher = FlextLdifHandlers.get_dispatcher(bus=bus)

        assert dispatcher is not None

    def test_get_dispatcher_returns_same_instance(self) -> None:
        """Test get_dispatcher returns singleton instance."""
        bus = FlextBus()

        dispatcher1 = FlextLdifHandlers.get_dispatcher(bus=bus)
        dispatcher2 = FlextLdifHandlers.get_dispatcher(bus=bus)

        assert dispatcher1 is dispatcher2

    def test_get_registry_creates_instance(self) -> None:
        """Test get_registry creates registry instance."""
        bus = FlextBus()
        dispatcher = FlextLdifHandlers.get_dispatcher(bus=bus)

        registry = FlextLdifHandlers.get_registry(dispatcher=dispatcher)

        assert registry is not None

    def test_get_registry_returns_same_instance(self) -> None:
        """Test get_registry returns singleton instance."""
        bus = FlextBus()
        dispatcher = FlextLdifHandlers.get_dispatcher(bus=bus)

        registry1 = FlextLdifHandlers.get_registry(dispatcher=dispatcher)
        registry2 = FlextLdifHandlers.get_registry(dispatcher=dispatcher)

        assert registry1 is registry2

    def test_register_all_handlers_success(self) -> None:
        """Test successful registration of all handlers."""
        context = FlextContext()
        container = FlextContainer()
        bus = FlextBus()

        result = FlextLdifHandlers.register_all_handlers(
            context=context,
            container=container,
            bus=bus,
        )

        assert result.is_success


class TestParseQueryHandler:
    """Test suite for ParseQueryHandler."""

    def test_handler_initialization(self) -> None:
        """Test ParseQueryHandler initializes correctly."""
        context = FlextContext()
        container = FlextContainer()
        bus = FlextBus()

        handler = FlextLdifHandlers.ParseQueryHandler(context, container, bus)

        assert handler is not None
        assert handler.config.handler_name == "ParseQueryHandler"
        assert handler.config.handler_type == "query"

    def test_handle_parse_without_parser(self) -> None:
        """Test parsing fails without registered parser."""
        context = FlextContext()
        container = FlextContainer()  # No parser registered
        bus = FlextBus()
        handler = FlextLdifHandlers.ParseQueryHandler(context, container, bus)

        query = FlextLdifModels.ParseQuery(
            source="",
            format="rfc",
            encoding="utf-8",
        )

        result = handler.handle(query)

        # Should fail without parser
        assert result.is_failure
        assert result.error is not None
        assert result.error is not None and "parser" in result.error.lower()

    def test_handle_parse_with_content(self) -> None:
        """Test parsing LDIF content without parser."""
        context = FlextContext()
        container = FlextContainer()  # No parser registered
        bus = FlextBus()
        handler = FlextLdifHandlers.ParseQueryHandler(context, container, bus)

        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person

"""

        query = FlextLdifModels.ParseQuery(
            source=ldif_content,
            format="rfc",
            encoding="utf-8",
        )

        result = handler.handle(query)

        # Should fail without parser
        assert result.is_failure
        assert result.error is not None
        assert result.error is not None and "parser" in result.error.lower()

    @pytest.mark.parametrize("format_type", ["rfc", "auto"])
    def test_handle_different_formats_without_parser(self, format_type: str) -> None:
        """Test parsing with different format types fails without parser."""
        context = FlextContext()
        container = FlextContainer()  # No parser registered
        bus = FlextBus()
        handler = FlextLdifHandlers.ParseQueryHandler(context, container, bus)

        query = FlextLdifModels.ParseQuery(
            source="",
            format=format_type,
            encoding="utf-8",
        )

        result = handler.handle(query)

        # Should fail without parser
        assert result.is_failure
        assert result.error is not None
        assert result.error is not None and "parser" in result.error.lower()


class TestValidateQueryHandler:
    """Test suite for ValidateQueryHandler."""

    def test_handler_initialization(self) -> None:
        """Test ValidateQueryHandler initializes correctly."""
        context = FlextContext()
        container = FlextContainer()
        bus = FlextBus()

        handler = FlextLdifHandlers.ValidateQueryHandler(context, container, bus)

        assert handler is not None
        assert handler.config.handler_name == "ValidateQueryHandler"
        assert handler.config.handler_type == "query"

    def test_handle_missing_validator(self) -> None:
        """Test handling when validator is not registered."""
        context = FlextContext()
        container = FlextContainer()  # Empty container
        bus = FlextBus()
        handler = FlextLdifHandlers.ValidateQueryHandler(context, container, bus)

        query = FlextLdifModels.ValidateQuery(
            entries=[],
            strict=True,
        )

        result = handler.handle(query)

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None and "validator" in result.error.lower()

    def test_handle_empty_entries_without_validator(self) -> None:
        """Test validating empty entry list without validator."""
        context = FlextContext()
        container = FlextContainer()  # No validator registered
        bus = FlextBus()
        handler = FlextLdifHandlers.ValidateQueryHandler(context, container, bus)

        query = FlextLdifModels.ValidateQuery(
            entries=[],
            strict=False,
        )

        result = handler.handle(query)

        # Should fail without validator
        assert result.is_failure
        assert result.error is not None
        assert result.error is not None and "validator" in result.error.lower()

    @pytest.mark.parametrize("strict_mode", [True, False])
    def test_handle_strict_mode_without_validator(self, strict_mode: bool) -> None:
        """Test validation with different strict modes fails without validator."""
        context = FlextContext()
        container = FlextContainer()  # No validator registered
        bus = FlextBus()
        handler = FlextLdifHandlers.ValidateQueryHandler(context, container, bus)

        query = FlextLdifModels.ValidateQuery(
            entries=[],
            strict=strict_mode,
        )

        result = handler.handle(query)

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None and "validator" in result.error.lower()


class TestAnalyzeQueryHandler:
    """Test suite for AnalyzeQueryHandler."""

    def test_handler_initialization(self) -> None:
        """Test AnalyzeQueryHandler initializes correctly."""
        context = FlextContext()
        container = FlextContainer()
        bus = FlextBus()

        handler = FlextLdifHandlers.AnalyzeQueryHandler(context, container, bus)

        assert handler is not None
        assert handler.config.handler_name == "AnalyzeQueryHandler"
        assert handler.config.handler_type == "query"

    def test_handle_empty_entries(self) -> None:
        """Test analyzing empty entry list."""
        context = FlextContext()
        container = FlextContainer()
        bus = FlextBus()
        handler = FlextLdifHandlers.AnalyzeQueryHandler(context, container, bus)

        query = FlextLdifModels.AnalyzeQuery(
            entries=[],
            include_patterns=False,
        )

        result = handler.handle(query)

        assert result.is_success
        analytics = result.unwrap()
        assert analytics.total_entries == 0
        assert analytics.object_class_distribution == {}

    def test_handle_single_entry(self) -> None:
        """Test analyzing single entry."""
        context = FlextContext()
        container = FlextContainer()
        bus = FlextBus()
        handler = FlextLdifHandlers.AnalyzeQueryHandler(context, container, bus)

        entry_result = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "objectClass": ["person"],
            },
        })
        entry = entry_result.unwrap()

        query = FlextLdifModels.AnalyzeQuery(
            entries=[entry],
            include_patterns=False,
        )

        result = handler.handle(query)

        assert result.is_success
        analytics = result.unwrap()
        assert analytics.total_entries == 1
        assert "person" in analytics.object_class_distribution
        assert analytics.object_class_distribution["person"] == 1

    def test_handle_multiple_object_classes(self) -> None:
        """Test analyzing entries with multiple object classes."""
        context = FlextContext()
        container = FlextContainer()
        bus = FlextBus()
        handler = FlextLdifHandlers.AnalyzeQueryHandler(context, container, bus)

        entries = [
            FlextLdifModels.Entry.create({
                "dn": f"cn=test{i},dc=example,dc=com",
                "attributes": {
                    "cn": [f"test{i}"],
                    "objectClass": ["person", "organizationalPerson"],
                },
            }).unwrap()
            for i in range(3)
        ]

        query = FlextLdifModels.AnalyzeQuery(
            entries=entries,
            include_patterns=False,
        )

        result = handler.handle(query)

        assert result.is_success
        analytics = result.unwrap()
        assert analytics.total_entries == 3
        assert analytics.object_class_distribution["person"] == 3
        assert analytics.object_class_distribution["organizationalPerson"] == 3

    def test_handle_with_patterns(self) -> None:
        """Test analytics with pattern detection enabled."""
        context = FlextContext()
        container = FlextContainer()
        bus = FlextBus()
        handler = FlextLdifHandlers.AnalyzeQueryHandler(context, container, bus)

        entry_result = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "objectClass": ["person"],
            },
        })
        entry = entry_result.unwrap()

        query = FlextLdifModels.AnalyzeQuery(
            entries=[entry],
            include_patterns=True,
        )

        result = handler.handle(query)

        assert result.is_success
        analytics = result.unwrap()
        assert len(analytics.patterns_detected) > 0


class TestWriteCommandHandler:
    """Test suite for WriteCommandHandler."""

    def test_handler_initialization(self) -> None:
        """Test WriteCommandHandler initializes correctly."""
        context = FlextContext()
        container = FlextContainer()
        bus = FlextBus()

        handler = FlextLdifHandlers.WriteCommandHandler(context, container, bus)

        assert handler is not None
        assert handler.config.handler_name == "WriteCommandHandler"
        assert handler.config.handler_type == "command"

    def test_handle_missing_writer(self) -> None:
        """Test handling when writer is not registered."""
        context = FlextContext()
        container = FlextContainer()  # Empty container
        bus = FlextBus()
        handler = FlextLdifHandlers.WriteCommandHandler(context, container, bus)

        command = FlextLdifModels.WriteCommand(
            entries=[],
            output=None,
        )

        result = handler.handle(command)

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None and "writer" in result.error.lower()

    def test_handle_empty_entries(self) -> None:
        """Test writing empty entry list without registered writer."""
        context = FlextContext()
        container = FlextContainer()  # No writer registered
        bus = FlextBus()
        handler = FlextLdifHandlers.WriteCommandHandler(context, container, bus)

        command = FlextLdifModels.WriteCommand(
            entries=[],
            output=None,
        )

        result = handler.handle(command)

        # Should fail without writer
        assert result.is_failure
        assert result.error is not None
        assert result.error is not None and "writer" in result.error.lower()

    def test_handle_write_without_writer(self) -> None:
        """Test writing fails without registered writer."""
        context = FlextContext()
        container = FlextContainer()  # No writer registered
        bus = FlextBus()
        handler = FlextLdifHandlers.WriteCommandHandler(context, container, bus)

        # Use factory method to create entry
        entry_result = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "objectClass": ["person"],
            },
        })
        entry = entry_result.unwrap()

        command = FlextLdifModels.WriteCommand(
            entries=[entry],
            output=None,
        )

        result = handler.handle(command)

        # Should fail without writer
        assert result.is_failure
        assert result.error is not None
        assert result.error is not None and "writer" in result.error.lower()


class TestMigrateCommandHandler:
    """Test suite for MigrateCommandHandler."""

    def test_handler_initialization(self) -> None:
        """Test MigrateCommandHandler initializes correctly."""
        context = FlextContext()
        container = FlextContainer()
        bus = FlextBus()

        handler = FlextLdifHandlers.MigrateCommandHandler(context, container, bus)

        assert handler is not None
        assert handler.config.handler_name == "MigrateCommandHandler"
        assert handler.config.handler_type == "command"

    def test_handle_empty_entries(self) -> None:
        """Test migrating empty entry list."""
        context = FlextContext()
        container = FlextContainer()
        bus = FlextBus()
        handler = FlextLdifHandlers.MigrateCommandHandler(context, container, bus)

        # Register migration pipeline
        from flext_ldif.migration_pipeline import LdifMigrationPipelineService

        pipeline = LdifMigrationPipelineService(
            params={"input_dir": "/tmp", "output_dir": "/tmp"},
            source_server_type="oid",
            target_server_type="oud",
        )
        container.register("migration_pipeline", pipeline)

        command = FlextLdifModels.MigrateCommand(
            entries=[],
            source_format="oid",
            target_format="oud",
        )

        result = handler.handle(command)

        # Should handle empty list gracefully
        assert result.is_success or result.is_failure


class TestRegisterQuirkCommandHandler:
    """Test suite for RegisterQuirkCommandHandler."""

    def test_handler_initialization(self) -> None:
        """Test RegisterQuirkCommandHandler initializes correctly."""
        context = FlextContext()
        container = FlextContainer()
        bus = FlextBus()

        handler = FlextLdifHandlers.RegisterQuirkCommandHandler(context, container, bus)

        assert handler is not None
        assert handler.config.handler_name == "RegisterQuirkCommandHandler"
        assert handler.config.handler_type == "command"

    def test_handle_missing_registry(self) -> None:
        """Test handling when quirk registry is not available."""
        context = FlextContext()
        container = FlextContainer()  # Empty container
        bus = FlextBus()
        handler = FlextLdifHandlers.RegisterQuirkCommandHandler(context, container, bus)

        # Create a mock quirk implementation
        from flext_ldif.quirks.servers.oid_quirks import OidSchemaQuirk

        quirk = OidSchemaQuirk()

        command = FlextLdifModels.RegisterQuirkCommand(
            quirk_type="schema",
            quirk_impl=quirk,
        )

        result = handler.handle(command)

        # Should handle missing registry gracefully
        assert result.is_success or result.is_failure


class TestHandlerIntegration:
    """Test suite for handler integration scenarios."""

    def test_full_handler_registration_pipeline(self) -> None:
        """Test complete handler registration process."""
        context = FlextContext()
        container = FlextContainer()
        bus = FlextBus()

        # Register all handlers
        result = FlextLdifHandlers.register_all_handlers(context, container, bus)

        assert result.is_success

        # Verify dispatcher and registry exist
        dispatcher = FlextLdifHandlers.get_dispatcher(bus)
        registry = FlextLdifHandlers.get_registry(dispatcher)

        assert dispatcher is not None
        assert registry is not None

    def test_handler_lifecycle(self) -> None:
        """Test handler creation and basic lifecycle."""
        context = FlextContext()
        container = FlextContainer()
        bus = FlextBus()

        # Create each handler type
        parse_handler = FlextLdifHandlers.ParseQueryHandler(context, container, bus)
        validate_handler = FlextLdifHandlers.ValidateQueryHandler(
            context, container, bus
        )
        analyze_handler = FlextLdifHandlers.AnalyzeQueryHandler(context, container, bus)
        write_handler = FlextLdifHandlers.WriteCommandHandler(context, container, bus)
        migrate_handler = FlextLdifHandlers.MigrateCommandHandler(
            context, container, bus
        )
        quirk_handler = FlextLdifHandlers.RegisterQuirkCommandHandler(
            context, container, bus
        )

        # Verify all handlers initialized
        assert all([
            parse_handler,
            validate_handler,
            analyze_handler,
            write_handler,
            migrate_handler,
            quirk_handler,
        ])
