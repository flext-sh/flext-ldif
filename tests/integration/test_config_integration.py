"""Config Integration Tests - FlextLdifSettings Integration Verification.

Tests comprehensive config integration with ldif facade including:
- Configuration initialization with facade
- Server type selection and behavior
- Quirks mode handling
- Configuration impacts on parsing
- Config consistency across operations

Scope: Integration testing of FlextLdifSettings through ldif facade,
server type behavior, parsing consistency, and filtering operations.

Modules tested: flext_ldif, flext_ldif.settings

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_core import FlextLogger
from flext_ldif import FlextLdifSettings, ldif
from tests import c

logger = FlextLogger(__name__)


ConfigTestData = c.Ldif.ConfigIntegration


class TestFlextLdifSettingsIntegration:
    """Test FlextLdifSettings integration through ldif facade.

    All tests use real implementations without mocks.
    Uses parametrization and mappings for maximum DRY.
    """

    def test_default_config_initialization(self) -> None:
        """Test facade initializes with default config."""
        api = ldif()
        result = api.parse_ldif(ConfigTestData.BASIC_ENTRY)
        assert result.is_success

    def test_custom_config_with_server_type(self) -> None:
        """Test facade with custom config and server type."""
        config = FlextLdifSettings()
        api = ldif(config=config)
        result = api.parse_ldif(
            ConfigTestData.BASIC_ENTRY, server_type=c.Ldif.Fixtures.OPENLDAP
        )
        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_config_independence_between_instances(self) -> None:
        """Test that multiple ldif instances with different configs are independent."""
        config1 = FlextLdifSettings()
        config2 = FlextLdifSettings()
        ldif1 = ldif(config=config1)
        ldif2 = ldif(config=config2)
        result1 = ldif1.parse_ldif(
            ConfigTestData.BASIC_ENTRY, server_type=c.Ldif.Fixtures.OID
        )
        result2 = ldif2.parse_ldif(
            ConfigTestData.BASIC_ENTRY, server_type=c.Ldif.Fixtures.OPENLDAP
        )
        assert result1.is_success
        assert result2.is_success

    @pytest.mark.parametrize("server_type", ConfigTestData.SERVER_TYPES[:3])
    def test_config_affects_parsing_behavior(
        self,
        server_type: c.Ldif.ServerTypeLiteral,
    ) -> None:
        """Test that config settings affect parsing behavior."""
        config = FlextLdifSettings()
        api = ldif(config=config)
        result = api.parse_ldif(ConfigTestData.BASIC_ENTRY, server_type=server_type)
        assert result.is_success

    @pytest.mark.parametrize(
        ("server_type", "expected_content_key"),
        [
            (c.Ldif.Fixtures.RFC, c.Ldif.Fixtures.RFC),
            (c.Ldif.Fixtures.OID, c.Ldif.Fixtures.OID),
            (c.Ldif.Fixtures.OUD, c.Ldif.Fixtures.OUD),
            (c.Ldif.Fixtures.OPENLDAP, c.Ldif.Fixtures.OPENLDAP),
        ],
    )
    def test_config_with_server_type(
        self,
        server_type: c.Ldif.ServerTypeLiteral,
        expected_content_key: str,
    ) -> None:
        """Test config with specific server type using parametrization."""
        config = FlextLdifSettings()
        api = ldif(config=config)
        content = ConfigTestData.SERVER_CONTENT[expected_content_key]
        result = api.parse_ldif(content, server_type=server_type)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_config_consistency_across_operations(self) -> None:
        """Test that config remains consistent across operations."""
        config = FlextLdifSettings()
        api = ldif(config=config)
        content1 = "dn: cn=Test1,dc=example,dc=com\ncn: Test1\nobjectClass: person\n"
        content2 = "dn: cn=Test2,dc=example,dc=com\ncn: Test2\nobjectClass: person\n"
        result1 = api.parse_ldif(content1)
        result2 = api.parse_ldif(content2)
        assert result1.is_success
        assert result2.is_success

    def test_config_with_multiple_entries(self) -> None:
        """Test config handling with multiple entries."""
        config = FlextLdifSettings()
        api = ldif(config=config)
        result = api.parse_ldif(ConfigTestData.MULTIPLE_ENTRIES)
        assert result.is_success
        entries = result.value
        assert len(entries) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
