"""Test suite for LDIF protocols module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.protocols import FlextLdifProtocols


class TestFlextLdifProtocols:
    """Test suite for FlextLdifProtocols namespace class."""

    def test_protocols_namespace_exists(self) -> None:
        """Test FlextLdifProtocols namespace class is accessible."""
        assert FlextLdifProtocols is not None
        assert hasattr(FlextLdifProtocols, "__name__")

    def test_ldif_entry_protocol_exists(self) -> None:
        """Test LdifEntryProtocol exists in FlextLdifProtocols."""
        assert hasattr(FlextLdifProtocols, "LdifEntryProtocol")
        protocol = FlextLdifProtocols.LdifEntryProtocol
        assert protocol is not None

    def test_ldif_processor_protocol_exists(self) -> None:
        """Test LdifProcessorProtocol exists in FlextLdifProtocols."""
        assert hasattr(FlextLdifProtocols, "LdifProcessorProtocol")
        protocol = FlextLdifProtocols.LdifProcessorProtocol
        assert protocol is not None

    def test_ldif_validator_protocol_exists(self) -> None:
        """Test LdifValidatorProtocol exists in FlextLdifProtocols."""
        assert hasattr(FlextLdifProtocols, "LdifValidatorProtocol")
        protocol = FlextLdifProtocols.LdifValidatorProtocol
        assert protocol is not None

    def test_ldif_writer_protocol_exists(self) -> None:
        """Test LdifWriterProtocol exists in FlextLdifProtocols."""
        assert hasattr(FlextLdifProtocols, "LdifWriterProtocol")
        protocol = FlextLdifProtocols.LdifWriterProtocol
        assert protocol is not None

    def test_ldif_analytics_protocol_exists(self) -> None:
        """Test LdifAnalyticsProtocol exists in FlextLdifProtocols."""
        assert hasattr(FlextLdifProtocols, "LdifAnalyticsProtocol")
        protocol = FlextLdifProtocols.LdifAnalyticsProtocol
        assert protocol is not None

    def test_parser_strategy_protocol_exists(self) -> None:
        """Test ParserStrategyProtocol exists in FlextLdifProtocols."""
        assert hasattr(FlextLdifProtocols, "ParserStrategyProtocol")
        protocol = FlextLdifProtocols.ParserStrategyProtocol
        assert protocol is not None

    def test_schema_builder_protocol_exists(self) -> None:
        """Test SchemaBuilderProtocol exists in FlextLdifProtocols."""
        assert hasattr(FlextLdifProtocols, "SchemaBuilderProtocol")
        protocol = FlextLdifProtocols.SchemaBuilderProtocol
        assert protocol is not None

    def test_acl_rule_protocol_exists(self) -> None:
        """Test AclRuleProtocol exists in FlextLdifProtocols."""
        assert hasattr(FlextLdifProtocols, "AclRuleProtocol")
        protocol = FlextLdifProtocols.AclRuleProtocol
        assert protocol is not None

    def test_server_adapter_protocol_exists(self) -> None:
        """Test ServerAdapterProtocol exists in FlextLdifProtocols."""
        assert hasattr(FlextLdifProtocols, "ServerAdapterProtocol")
        protocol = FlextLdifProtocols.ServerAdapterProtocol
        assert protocol is not None

    def test_validator_plugin_protocol_exists(self) -> None:
        """Test ValidatorPluginProtocol exists in FlextLdifProtocols."""
        assert hasattr(FlextLdifProtocols, "ValidatorPluginProtocol")
        protocol = FlextLdifProtocols.ValidatorPluginProtocol
        assert protocol is not None

    def test_migration_pipeline_protocol_exists(self) -> None:
        """Test MigrationPipelineProtocol exists in FlextLdifProtocols."""
        assert hasattr(FlextLdifProtocols, "MigrationPipelineProtocol")
        protocol = FlextLdifProtocols.MigrationPipelineProtocol
        assert protocol is not None

    def test_quirk_registry_protocol_exists(self) -> None:
        """Test QuirkRegistryProtocol exists in FlextLdifProtocols."""
        assert hasattr(FlextLdifProtocols, "QuirkRegistryProtocol")
        protocol = FlextLdifProtocols.QuirkRegistryProtocol
        assert protocol is not None
