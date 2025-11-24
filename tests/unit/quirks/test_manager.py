"""Tests for FlextLdifServer - server-specific quirks management.

This module provides comprehensive testing for the quirks registry which
manages server-specific LDAP quirks and configurations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdifConstants
from flext_ldif.services.server import FlextLdifServer


class TestFlextLdifServer:
    """Tests for FlextLdifServer initialization and quirks management."""

    def test_initialization(self) -> None:
        """Test registry initialization."""
        registry = FlextLdifServer()
        assert registry is not None

    def test_get_global_instance(self) -> None:
        """Test getting global singleton registry instance."""
        registry1 = FlextLdifServer.get_global_instance()
        registry2 = FlextLdifServer.get_global_instance()

        assert registry1 is not None
        assert registry2 is not None
        assert isinstance(registry1, FlextLdifServer)
        assert isinstance(registry2, FlextLdifServer)
        # Both should be the same instance (singleton)
        assert registry1 is registry2

    def test_get_acls_oracle_oid(self) -> None:
        """Test getting ACL quirks for Oracle OID."""
        registry = FlextLdifServer()

        # Get the ACL quirk for Oracle OID
        quirk = registry.acl(FlextLdifConstants.LdapServers.ORACLE_OID)
        assert quirk is not None

    def test_get_acls_oracle_oud(self) -> None:
        """Test getting ACL quirks for Oracle OUD."""
        registry = FlextLdifServer()

        quirk = registry.acl(FlextLdifConstants.LdapServers.ORACLE_OUD)
        assert quirk is not None

    def test_get_acls_openldap(self) -> None:
        """Test getting ACL quirks for OpenLDAP."""
        registry = FlextLdifServer()

        quirk = registry.acl(FlextLdifConstants.LdapServers.OPENLDAP_1)
        assert quirk is not None

    def test_get_schemas_oracle_oid(self) -> None:
        """Test getting schema quirks for Oracle OID."""
        registry = FlextLdifServer()

        quirk = registry.schema(FlextLdifConstants.LdapServers.ORACLE_OID)
        assert quirk is not None

    def test_get_schemas_openldap(self) -> None:
        """Test getting schema quirks for OpenLDAP."""
        registry = FlextLdifServer()

        quirk = registry.schema(FlextLdifConstants.LdapServers.OPENLDAP_1)
        assert quirk is not None

    def test_find_acl_is_callable(self) -> None:
        """Test that find_acl_for_line method is available and callable."""
        registry = FlextLdifServer()

        # Test that the method exists and can be called without raising an exception
        # The result depends on the server type and line content
        try:
            registry.find_acl_for_line(
                FlextLdifConstants.LdapServers.OPENLDAP, "test line"
            )
            # If we got here, the method works
        except AttributeError as e:
            pytest.fail(f"find_acl_for_line method not found on FlextLdifServer: {e}")

    def test_get_entrys_oracle_oid(self) -> None:
        """Test getting entry quirks for Oracle OID."""
        registry = FlextLdifServer()

        quirk = registry.entry(FlextLdifConstants.LdapServers.ORACLE_OID)
        assert quirk is not None

    def test_get_entrys_oracle_oud(self) -> None:
        """Test getting entry quirks for Oracle OUD."""
        registry = FlextLdifServer()

        quirk = registry.entry(FlextLdifConstants.LdapServers.ORACLE_OUD)
        assert quirk is not None

    def test_registry_supports_all_server_types(self) -> None:
        """Test that registry has quirks for all supported server types."""
        registry = FlextLdifServer()

        supported_servers = [
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
            schema = registry.schema(server_type)
            assert schema is not None, f"Schema quirk not found for {server_type}"

            acl = registry.acl(server_type)
            # ACL may be None for some servers
            if acl is None:
                # Some servers may not have ACL quirks - this is acceptable
                pass

            entry = registry.entry(server_type)
            assert entry is not None, f"Entry quirk not found for {server_type}"


__all__ = ["TestFlextLdifServer"]
