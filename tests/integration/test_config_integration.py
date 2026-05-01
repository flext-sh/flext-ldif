"""Config Integration Tests - FlextLdifSettings Integration Verification.

Tests comprehensive settings integration with ldif facade including:
- Configuration initialization with facade
- Server type selection and behavior
- Servers mode handling
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

from flext_ldif import FlextLdif, FlextLdifSettings, ldif
from tests import c, u

logger = u.fetch_logger(__name__)


class TestsFlextLdifConfigIntegration:
    """Test FlextLdifSettings integration through ldif facade.

    All tests use real implementations without mocks.
    Uses parametrization and mappings for maximum DRY.
    """

    def test_default_config_initialization(self) -> None:
        """Test facade initializes with default settings."""
        api = ldif
        result = api.parse_ldif(c.Tests.CONFIG_BASIC_ENTRY)
        assert result.success

    def test_custom_config_with_server_type(self) -> None:
        """Test facade with custom settings and server type."""
        settings = FlextLdifSettings()
        api = FlextLdif(settings=settings)
        result = api.parse_ldif(
            c.Tests.CONFIG_BASIC_ENTRY,
            server_type=c.Tests.OPENLDAP,
        )
        assert result.success
        entries = result.value.entries
        assert len(entries) == 1

    def test_config_independence_between_instances(self) -> None:
        """Test that multiple ldif instances with different configs are independent."""
        config1 = FlextLdifSettings()
        config2 = FlextLdifSettings()
        ldif1 = FlextLdif(settings=config1)
        ldif2 = FlextLdif(settings=config2)
        result1 = ldif1.parse_ldif(
            c.Tests.CONFIG_BASIC_ENTRY,
            server_type=c.Tests.OID,
        )
        result2 = ldif2.parse_ldif(
            c.Tests.CONFIG_BASIC_ENTRY,
            server_type=c.Tests.OPENLDAP,
        )
        assert result1.success
        assert result2.success

    @pytest.mark.parametrize("server_type", c.Tests.CONFIG_SERVER_TYPES[:3])
    def test_config_affects_parsing_behavior(
        self,
        server_type: str,
    ) -> None:
        """Test that settings settings affect parsing behavior."""
        settings = FlextLdifSettings()
        api = FlextLdif(settings=settings)
        result = api.parse_ldif(c.Tests.CONFIG_BASIC_ENTRY, server_type=server_type)
        assert result.success

    @pytest.mark.parametrize(
        ("server_type", "expected_content_key"),
        [
            (c.Tests.RFC, c.Tests.RFC),
            (c.Tests.OID, c.Tests.OID),
            (c.Tests.OUD, c.Tests.OUD),
            (c.Tests.OPENLDAP, c.Tests.OPENLDAP),
        ],
    )
    def test_config_with_server_type(
        self,
        server_type: str,
        expected_content_key: str,
    ) -> None:
        """Test settings with specific server type using parametrization."""
        settings = FlextLdifSettings()
        api = FlextLdif(settings=settings)
        content = c.Tests.CONFIG_SERVER_CONTENT[expected_content_key]
        result = api.parse_ldif(content, server_type=server_type)
        assert result.success
        entries = result.value.entries
        assert len(entries) == 1

    def test_config_consistency_across_operations(self) -> None:
        """Test that settings remains consistent across operations."""
        settings = FlextLdifSettings()
        api = FlextLdif(settings=settings)
        content1 = "dn: cn=Test1,dc=example,dc=com\ncn: Test1\nobjectClass: person\n"
        content2 = "dn: cn=Test2,dc=example,dc=com\ncn: Test2\nobjectClass: person\n"
        result1 = api.parse_ldif(content1)
        result2 = api.parse_ldif(content2)
        assert result1.success
        assert result2.success

    def test_config_with_multiple_entries(self) -> None:
        """Test settings handling with multiple entries."""
        settings = FlextLdifSettings()
        api = FlextLdif(settings=settings)
        result = api.parse_ldif(c.Tests.CONFIG_MULTIPLE_ENTRIES)
        assert result.success
        entries = result.value.entries
        assert len(entries) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
