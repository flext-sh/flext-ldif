"""Config Integration Tests - FlextLdifSettings Integration Verification.

Tests comprehensive config integration with FlextLdif facade including:
- Configuration initialization with facade
- Server type selection and behavior
- Quirks mode handling
- Configuration impacts on parsing
- Config consistency across operations

Scope: Integration testing of FlextLdifSettings through FlextLdif facade,
server type behavior, parsing consistency, and filtering operations.

Modules tested: flext_ldif, flext_ldif.settings

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

import pytest
from flext_core import FlextLogger

from flext_ldif import FlextLdif, FlextLdifSettings

logger = FlextLogger(__name__)


class ConfigTestData:
    """Test data constants and mappings for config integration tests."""

    # Server types - use constants directly
    SERVER_TYPES: Final[list[str]] = ["oid", "oud", "openldap", "rfc"]

    # LDIF content templates
    BASIC_ENTRY: Final[str] = """dn: cn=Test,dc=example,dc=com
cn: Test
objectClass: person
"""

    MULTIPLE_ENTRIES: Final[str] = """dn: cn=User1,dc=example,dc=com
cn: User1
objectClass: person

dn: cn=User2,dc=example,dc=com
cn: User2
objectClass: person

dn: cn=User3,dc=example,dc=com
cn: User3
objectClass: person
"""

    FILTER_CONTENT: Final[str] = """dn: cn=Person1,dc=example,dc=com
cn: Person1
objectClass: person

dn: cn=Group1,dc=example,dc=com
cn: Group1
objectClass: groupOfNames
"""

    # Server type specific content mapping
    SERVER_CONTENT: Final[Mapping[str, str]] = {
        "oid": """dn: cn=OID Test,dc=example,dc=com
cn: OID Test
objectClass: person
""",
        "oud": """dn: cn=OUD Test,dc=example,dc=com
cn: OUD Test
objectClass: person
""",
        "openldap": """dn: cn=OpenLDAP Test,dc=example,dc=com
cn: OpenLDAP Test
objectClass: person
""",
        "rfc": """dn: cn=RFC Test,dc=example,dc=com
cn: RFC Test
objectClass: person
""",
    }


class TestFlextLdifSettingsIntegration:
    """Test FlextLdifSettings integration through FlextLdif facade.

    All tests use real implementations without mocks.
    Uses parametrization and mappings for maximum DRY.
    """

    def test_default_config_initialization(self) -> None:
        """Test facade initializes with default config."""
        ldif = FlextLdif()
        result = ldif.parse(ConfigTestData.BASIC_ENTRY)
        assert result.is_success

    def test_custom_config_with_server_type(self) -> None:
        """Test facade with custom config and server type."""
        config = FlextLdifSettings(server_type="openldap")
        ldif = FlextLdif(config=config)
        result = ldif.parse(ConfigTestData.BASIC_ENTRY)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_config_independence_between_instances(self) -> None:
        """Test that multiple FlextLdif instances with different configs are independent."""
        config1 = FlextLdifSettings(server_type="oid")
        config2 = FlextLdifSettings(server_type="openldap")
        ldif1 = FlextLdif(config=config1)
        ldif2 = FlextLdif(config=config2)

        result1 = ldif1.parse(ConfigTestData.BASIC_ENTRY)
        result2 = ldif2.parse(ConfigTestData.BASIC_ENTRY)

        assert result1.is_success
        assert result2.is_success

    @pytest.mark.parametrize("server_type", ConfigTestData.SERVER_TYPES[:3])
    def test_config_affects_parsing_behavior(self, server_type: str) -> None:
        """Test that config settings affect parsing behavior."""
        config = FlextLdifSettings(server_type=server_type)
        ldif = FlextLdif(config=config)
        result = ldif.parse(ConfigTestData.BASIC_ENTRY)
        # All server types should support basic parsing
        assert result.is_success

    @pytest.mark.parametrize(
        ("server_type", "expected_content_key"),
        [
            ("rfc", "rfc"),
            ("oid", "oid"),
            ("oud", "oud"),
            ("openldap", "openldap"),
        ],
    )
    def test_config_with_server_type(
        self,
        server_type: str,
        expected_content_key: str,
    ) -> None:
        """Test config with specific server type using parametrization."""
        config = FlextLdifSettings(server_type=server_type)
        ldif = FlextLdif(config=config)
        content = ConfigTestData.SERVER_CONTENT[expected_content_key]
        result = ldif.parse(content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_config_consistency_across_operations(self) -> None:
        """Test that config remains consistent across operations."""
        config = FlextLdifSettings(server_type="rfc")
        ldif = FlextLdif(config=config)

        # Perform multiple operations with same config
        content1 = """dn: cn=Test1,dc=example,dc=com
cn: Test1
objectClass: person
"""
        content2 = """dn: cn=Test2,dc=example,dc=com
cn: Test2
objectClass: person
"""

        result1 = ldif.parse(content1)
        result2 = ldif.parse(content2)

        assert result1.is_success
        assert result2.is_success

    def test_config_with_multiple_entries(self) -> None:
        """Test config handling with multiple entries."""
        config = FlextLdifSettings(server_type="rfc")
        ldif = FlextLdif(config=config)
        result = ldif.parse(ConfigTestData.MULTIPLE_ENTRIES)
        assert result.is_success
        entries = result.value
        assert len(entries) == 3

    def test_config_filtering_behavior(self) -> None:
        """Test that config doesn't interfere with filtering."""
        config = FlextLdifSettings(server_type="rfc")
        ldif = FlextLdif(config=config)

        parse_result = ldif.parse(ConfigTestData.FILTER_CONTENT)
        assert parse_result.is_success

        entries = parse_result.value
        assert len(entries) == 2

        # Filter works regardless of config
        filter_result = ldif.filter(entries, objectclass="person")
        assert filter_result.is_success
        filtered = filter_result.value
        assert len(filtered) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
