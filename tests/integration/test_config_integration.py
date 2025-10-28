"""Config integration tests verifying FlextLdifConfig through facade.

Tests config integration with FlextLdif:
- Configuration initialization with facade
- Server type selection and behavior
- Quirks mode handling
- Configuration impacts on parsing

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextLogger

from flext_ldif import FlextLdif
from flext_ldif.config import FlextLdifConfig

logger = FlextLogger(__name__)


class TestFlextLdifConfigIntegration:
    """Test FlextLdifConfig integration through FlextLdif facade."""

    def test_default_config_initialization(self) -> None:
        """Test facade initializes with default config."""
        ldif = FlextLdif()

        content = """dn: cn=Test,dc=example,dc=com
cn: Test
objectClass: person
"""

        result = ldif.parse(content)
        assert result.is_success

    def test_custom_config_with_server_type(self) -> None:
        """Test facade with custom config and server type."""
        config = FlextLdifConfig(server_type="rfc")
        ldif = FlextLdif(config=config)

        content = """dn: cn=Test,dc=example,dc=com
cn: Test
objectClass: person
"""

        result = ldif.parse(content)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1

    def test_config_independence_between_instances(self) -> None:
        """Test that multiple FlextLdif instances with different configs are independent."""
        config1 = FlextLdifConfig(server_type="oid")
        config2 = FlextLdifConfig(server_type="rfc")

        ldif1 = FlextLdif(config=config1)
        ldif2 = FlextLdif(config=config2)

        content = """dn: cn=Test,dc=example,dc=com
cn: Test
objectClass: person
"""

        result1 = ldif1.parse(content)
        result2 = ldif2.parse(content)

        assert result1.is_success
        assert result2.is_success

    def test_config_affects_parsing_behavior(self) -> None:
        """Test that config settings affect parsing behavior."""
        # Different server types might have different quirks
        for server_type in ["rfc", "oid", "oud", "openldap"]:
            config = FlextLdifConfig(server_type=server_type)
            ldif = FlextLdif(config=config)

            content = """dn: cn=Test,dc=example,dc=com
cn: Test
objectClass: person
"""

            result = ldif.parse(content)
            # All server types should support basic parsing
            assert result.is_success

    def test_config_with_rfc_server_type(self) -> None:
        """Test config with RFC server type."""
        config = FlextLdifConfig(server_type="rfc")
        ldif = FlextLdif(config=config)

        content = """dn: cn=RFC Test,dc=example,dc=com
cn: RFC Test
objectClass: person
"""

        result = ldif.parse(content)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1

    def test_config_with_oid_server_type(self) -> None:
        """Test config with Oracle Internet Directory server type."""
        config = FlextLdifConfig(server_type="oid")
        ldif = FlextLdif(config=config)

        content = """dn: cn=OID Test,dc=example,dc=com
cn: OID Test
objectClass: person
"""

        result = ldif.parse(content)
        assert result.is_success

    def test_config_with_oud_server_type(self) -> None:
        """Test config with Oracle Unified Directory server type."""
        config = FlextLdifConfig(server_type="oud")
        ldif = FlextLdif(config=config)

        content = """dn: cn=OUD Test,dc=example,dc=com
cn: OUD Test
objectClass: person
"""

        result = ldif.parse(content)
        assert result.is_success

    def test_config_with_openldap_server_type(self) -> None:
        """Test config with OpenLDAP server type."""
        config = FlextLdifConfig(server_type="openldap")
        ldif = FlextLdif(config=config)

        content = """dn: cn=OpenLDAP Test,dc=example,dc=com
cn: OpenLDAP Test
objectClass: person
"""

        result = ldif.parse(content)
        assert result.is_success

    def test_config_consistency_across_operations(self) -> None:
        """Test that config remains consistent across operations."""
        config = FlextLdifConfig(server_type="rfc")
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
        config = FlextLdifConfig(server_type="rfc")
        ldif = FlextLdif(config=config)

        content = """dn: cn=User1,dc=example,dc=com
cn: User1
objectClass: person

dn: cn=User2,dc=example,dc=com
cn: User2
objectClass: person

dn: cn=User3,dc=example,dc=com
cn: User3
objectClass: person
"""

        result = ldif.parse(content)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 3

    def test_config_filtering_behavior(self) -> None:
        """Test that config doesn't interfere with filtering."""
        config = FlextLdifConfig(server_type="rfc")
        ldif = FlextLdif(config=config)

        content = """dn: cn=Person1,dc=example,dc=com
cn: Person1
objectClass: person

dn: cn=Group1,dc=example,dc=com
cn: Group1
objectClass: groupOfNames
"""

        parse_result = ldif.parse(content)
        assert parse_result.is_success

        entries = parse_result.unwrap()
        assert len(entries) == 2

        # Filter works regardless of config
        filter_result = ldif.filter(entries, objectclass="person")
        assert filter_result.is_success
        filtered = filter_result.unwrap()
        assert len(filtered) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
