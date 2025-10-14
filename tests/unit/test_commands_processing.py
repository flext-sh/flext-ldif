"""Tests for commands_processing.py module.

Tests CQRS Query and Command models for LDIF processing.
"""

from __future__ import annotations

import pytest
from flext_core import FlextCore
from pydantic import ValidationError

from flext_ldif.models import FlextLdifModels


def test_parse_query_creation() -> None:
    """Test ParseQuery model instantiation."""
    from flext_ldif.commands_processing import ParseQuery

    query = ParseQuery(source="dn: cn=test,dc=example,dc=com")
    assert query.source == "dn: cn=test,dc=example,dc=com"
    assert query.format == "auto"  # default
    assert query.encoding == "utf-8"  # default
    assert query.strict is True  # default


def test_parse_query_with_all_fields() -> None:
    """Test ParseQuery with all fields specified."""
    from flext_ldif.commands_processing import ParseQuery

    query = ParseQuery(
        source="/path/to/file.ldif",
        format="rfc2849",
        encoding="latin-1",
        strict=False,
    )
    assert query.source == "/path/to/file.ldif"
    assert query.format == "rfc2849"
    assert query.encoding == "latin-1"
    assert query.strict is False


def test_parse_query_missing_required() -> None:
    """Test ParseQuery fails without required source field."""
    from flext_ldif.commands_processing import ParseQuery

    with pytest.raises(ValidationError) as exc_info:
        ParseQuery(source="")

    assert "source" in str(exc_info.value)


def test_validate_query_creation() -> None:
    """Test ValidateQuery model instantiation."""
    from flext_ldif.commands_processing import ValidateQuery
    from flext_ldif.models import FlextLdifModels

    entries = [FlextLdifModels.Entry.create("cn=test,dc=example,dc=com", {}).unwrap()]
    query = ValidateQuery(entries=entries)
    assert query.entries == entries
    assert query.schema_config is None  # default
    assert query.strict is True  # default


def test_validate_query_with_schema_config() -> None:
    """Test ValidateQuery with schema configuration."""
    from flext_ldif.commands_processing import ValidateQuery

    entries = [FlextLdifModels.Entry.create("cn=test", {}).unwrap()]
    schema_config: FlextCore.Types.Dict = {"validate_objectclasses": True}
    query = ValidateQuery(entries=entries, schema_config=schema_config, strict=False)
    assert query.entries == entries
    assert query.schema_config == schema_config
    assert query.strict is False


def test_analyze_query_creation() -> None:
    """Test AnalyzeQuery model instantiation."""
    from flext_ldif.commands_processing import AnalyzeQuery

    query = AnalyzeQuery(
        ldif_content="dn: cn=test,dc=example,dc=com",
        analysis_types=["structure", "attributes"],
    )
    assert query.ldif_content == "dn: cn=test,dc=example,dc=com"
    assert query.analysis_types == ["structure", "attributes"]
    assert query.metrics is None  # default
    assert query.include_patterns is True  # default


def test_analyze_query_with_metrics() -> None:
    """Test AnalyzeQuery with metrics configuration."""
    from flext_ldif.commands_processing import AnalyzeQuery

    metrics: FlextCore.Types.Dict = {"count_entries": True, "track_attributes": True}
    query = AnalyzeQuery(
        ldif_content="test content",
        analysis_types=["schema"],
        metrics=metrics,
        include_patterns=False,
    )
    assert query.metrics == metrics
    assert query.include_patterns is False


def test_write_command_creation() -> None:
    """Test WriteCommand model instantiation."""
    from flext_ldif.commands_processing import WriteCommand

    entries = [FlextLdifModels.Entry.create("cn=test", {}).unwrap()]
    command = WriteCommand(entries=entries)
    assert command.entries == entries
    assert command.format == "rfc"  # default
    assert command.output is None  # default
    assert command.line_width == 76  # default


def test_write_command_with_all_fields() -> None:
    """Test WriteCommand with all fields specified."""
    from flext_ldif.commands_processing import WriteCommand

    entries = [FlextLdifModels.Entry.create("cn=test", {}).unwrap()]
    command = WriteCommand(
        entries=entries,
        format="standard",
        output="/path/to/output.ldif",
        line_width=80,
    )
    assert command.format == "standard"
    assert command.output == "/path/to/output.ldif"
    assert command.line_width == 80


def test_write_command_line_width_validation() -> None:
    """Test WriteCommand line_width field validation."""
    from flext_ldif.commands_processing import WriteCommand

    # Valid range: 40-120
    entries = [FlextLdifModels.Entry.create("cn=test", {}).unwrap()]

    # Test minimum
    command = WriteCommand(entries=entries, line_width=40)
    assert command.line_width == 40

    # Test maximum
    command = WriteCommand(entries=entries, line_width=120)
    assert command.line_width == 120

    # Test below minimum
    with pytest.raises(ValidationError):
        WriteCommand(entries=entries, line_width=39)

    # Test above maximum
    with pytest.raises(ValidationError):
        WriteCommand(entries=entries, line_width=121)


def test_migrate_command_creation() -> None:
    """Test MigrateCommand model instantiation."""
    from flext_ldif.commands_processing import MigrateCommand

    entries = [FlextLdifModels.Entry.create("cn=test", {}).unwrap()]
    command = MigrateCommand(
        entries=entries,
        source_format="oid",
        target_format="oud",
    )
    assert command.entries == entries
    assert command.source_format == "oid"
    assert command.target_format == "oud"
    assert command.options is None  # default


def test_migrate_command_with_options() -> None:
    """Test MigrateCommand with migration options."""
    from flext_ldif.commands_processing import MigrateCommand

    entries = [FlextLdifModels.Entry.create("cn=test", {}).unwrap()]
    options: FlextCore.Types.Dict = {"preserve_timestamps": True, "convert_acls": True}
    command = MigrateCommand(
        entries=entries,
        source_format="openldap",
        target_format="ad",
        options=options,
    )
    assert command.options == options


def test_register_quirk_command_creation() -> None:
    """Test RegisterQuirkCommand model instantiation."""
    from flext_ldif.commands_processing import RegisterQuirkCommand

    quirk_impl = object()  # Mock quirk implementation
    command = RegisterQuirkCommand(
        quirk_type="custom_server",
        quirk_impl=quirk_impl,
    )
    assert command.quirk_type == "custom_server"
    assert command.quirk_impl is quirk_impl
    assert command.override is False  # default


def test_register_quirk_command_with_override() -> None:
    """Test RegisterQuirkCommand with override flag."""
    from flext_ldif.commands_processing import RegisterQuirkCommand

    quirk_impl = object()
    command = RegisterQuirkCommand(
        quirk_type="oid",
        quirk_impl=quirk_impl,
        override=True,
    )
    assert command.override is True


def test_commands_processing_module_imports() -> None:
    """Test all classes can be imported from module."""
    from flext_ldif import commands_processing

    assert hasattr(commands_processing, "ParseQuery")
    assert hasattr(commands_processing, "ValidateQuery")
    assert hasattr(commands_processing, "AnalyzeQuery")
    assert hasattr(commands_processing, "WriteCommand")
    assert hasattr(commands_processing, "MigrateCommand")
    assert hasattr(commands_processing, "RegisterQuirkCommand")
