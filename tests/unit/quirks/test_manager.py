"""Tests for FlextLdifRegistry - server-specific quirks management.

This module provides comprehensive testing for the quirks registry which
manages server-specific LDAP quirks and configurations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.services.registry import FlextLdifRegistry


class TestFlextLdifRegistry:
    """Tests for FlextLdifRegistry initialization and quirks management."""

    def test_initialization(self) -> None:
        """Test registry initialization."""
        registry = FlextLdifRegistry()
        assert registry is not None

    def test_get_global_instance(self) -> None:
        """Test getting global singleton registry instance."""
        registry1 = FlextLdifRegistry.get_global_instance()
        registry2 = FlextLdifRegistry.get_global_instance()

        assert registry1 is not None
        assert registry2 is not None
        assert isinstance(registry1, FlextLdifRegistry)
        assert isinstance(registry2, FlextLdifRegistry)
        # Both should be the same instance (singleton)
        assert registry1 is registry2

    def test_get_acl_quirks_oracle_oid(self) -> None:
        """Test getting ACL quirks for Oracle OID."""
        registry = FlextLdifRegistry()

        # Get the ACL quirks for Oracle OID
        quirks = registry.get_acl_quirks(FlextLdifConstants.LdapServers.ORACLE_OID)
        assert quirks is not None

    def test_get_acl_quirks_oracle_oud(self) -> None:
        """Test getting ACL quirks for Oracle OUD."""
        registry = FlextLdifRegistry()

        quirks = registry.get_acl_quirks(FlextLdifConstants.LdapServers.ORACLE_OUD)
        assert quirks is not None

    def test_get_acl_quirks_openldap(self) -> None:
        """Test getting ACL quirks for OpenLDAP."""
        registry = FlextLdifRegistry()

        quirks = registry.get_acl_quirks(FlextLdifConstants.LdapServers.OPENLDAP_2)
        assert quirks is not None

    def test_get_schema_quirks_oracle_oid(self) -> None:
        """Test getting schema quirks for Oracle OID."""
        registry = FlextLdifRegistry()

        quirks = registry.get_schema_quirks(FlextLdifConstants.LdapServers.ORACLE_OID)
        assert quirks is not None

    def test_get_schema_quirks_openldap(self) -> None:
        """Test getting schema quirks for OpenLDAP."""
        registry = FlextLdifRegistry()

        quirks = registry.get_schema_quirks(FlextLdifConstants.LdapServers.OPENLDAP_2)
        assert quirks is not None

    def test_find_acl_quirk_is_callable(self) -> None:
        """Test that find_acl_quirk method is available and callable."""
        registry = FlextLdifRegistry()

        # Test that the method exists and can be called without raising an exception
        # The result depends on the server type and line content
        try:
            registry.find_acl_quirk(
                FlextLdifConstants.LdapServers.OPENLDAP, "test line"
            )
            # If we got here, the method works
        except AttributeError as e:
            pytest.fail(f"find_acl_quirk method not found on FlextLdifRegistry: {e}")

    def test_get_entrys_oracle_oid(self) -> None:
        """Test getting entry quirks for Oracle OID."""
        registry = FlextLdifRegistry()

        quirks = registry.get_entrys(FlextLdifConstants.LdapServers.ORACLE_OID)
        assert quirks is not None

    def test_get_entrys_oracle_oud(self) -> None:
        """Test getting entry quirks for Oracle OUD."""
        registry = FlextLdifRegistry()

        quirks = registry.get_entrys(FlextLdifConstants.LdapServers.ORACLE_OUD)
        assert quirks is not None

    def test_registry_supports_all_server_types(self) -> None:
        """Test that registry has quirks for all supported server types."""
        registry = FlextLdifRegistry()

        supported_servers = [
            FlextLdifConstants.LdapServers.OPENLDAP_2,
            FlextLdifConstants.LdapServers.OPENLDAP_1,
            FlextLdifConstants.LdapServers.ORACLE_OID,
            FlextLdifConstants.LdapServers.ORACLE_OUD,
            FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY,
            FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
            FlextLdifConstants.LdapServers.DS_389,
            FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY,
            FlextLdifConstants.LdapServers.IBM_TIVOLI,
            FlextLdifConstants.LdapServers.GENERIC,
        ]

        for server_type in supported_servers:
            schema_quirks = registry.get_schema_quirks(server_type)
            assert schema_quirks is not None, (
                f"Schema quirks not found for {server_type}"
            )

            acl_quirks = registry.get_acl_quirks(server_type)
            assert acl_quirks is not None, f"ACL quirks not found for {server_type}"

            entrys = registry.get_entrys(server_type)
            assert entrys is not None, f"Entry quirks not found for {server_type}"


__all__ = ["TestFlextLdifRegistry"]
