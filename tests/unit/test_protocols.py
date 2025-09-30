"""Tests for flext_ldif.protocols module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.models import FlextLdifModels
from flext_ldif.processor import FlextLdifProcessor
from flext_ldif.protocols import FlextLdifProtocols


class TestFlextLdifProtocols:
    """Test FlextLdifProtocols definitions."""

    def test_ldif_entry_protocol(self) -> None:
        """Test LdifEntryProtocol with Entry model."""
        result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectClass": ["person"]},
        )
        assert result.is_success
        entry = result.unwrap()
        assert isinstance(entry, FlextLdifProtocols.LdifEntryProtocol)

    def test_ldif_processor_protocol(self) -> None:
        """Test LdifProcessorProtocol with FlextLdifProcessor."""
        processor = FlextLdifProcessor()
        assert isinstance(processor, FlextLdifProtocols.LdifProcessorProtocol)

    def test_ldif_validator_protocol(self) -> None:
        """Test LdifValidatorProtocol - no direct implementation, test protocol exists."""
        # Just test that the protocol is defined
        assert hasattr(FlextLdifProtocols, "LdifValidatorProtocol")

    def test_ldif_writer_protocol(self) -> None:
        """Test LdifWriterProtocol - no direct implementation, test protocol exists."""
        assert hasattr(FlextLdifProtocols, "LdifWriterProtocol")

    def test_ldif_analytics_protocol(self) -> None:
        """Test LdifAnalyticsProtocol - no direct implementation, test protocol exists."""
        assert hasattr(FlextLdifProtocols, "LdifAnalyticsProtocol")

    def test_parser_strategy_protocol(self) -> None:
        """Test ParserStrategyProtocol - no direct implementation, test protocol exists."""
        assert hasattr(FlextLdifProtocols, "ParserStrategyProtocol")

    def test_schema_builder_protocol(self) -> None:
        """Test SchemaBuilderProtocol - no direct implementation, test protocol exists."""
        assert hasattr(FlextLdifProtocols, "SchemaBuilderProtocol")

    def test_acl_rule_protocol(self) -> None:
        """Test AclRuleProtocol - no direct implementation, test protocol exists."""
        assert hasattr(FlextLdifProtocols, "AclRuleProtocol")

    def test_server_adapter_protocol(self) -> None:
        """Test ServerAdapterProtocol - no direct implementation, test protocol exists."""
        assert hasattr(FlextLdifProtocols, "ServerAdapterProtocol")

    def test_validator_plugin_protocol(self) -> None:
        """Test ValidatorPluginProtocol - no direct implementation, test protocol exists."""
        assert hasattr(FlextLdifProtocols, "ValidatorPluginProtocol")
