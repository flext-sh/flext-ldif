"""Comprehensive tests for LDAP server quirks manager.

This module provides complete test coverage for the quirks manager,
including:
- Initialization and configuration
- Server type detection for all supported LDAP servers
- Quirks retrieval (ACL attributes, formats, schema subentries)
- Error handling and edge cases
"""

from __future__ import annotations

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.manager import FlextLdifQuirksManager


class TestQuirksManagerInitialization:
    """Tests for FlextLdifQuirksManager initialization."""

    def test_initialization_default_server_type(self) -> None:
        """Test manager initialization with default (generic) server type."""
        manager = FlextLdifQuirksManager()
        assert manager is not None
        assert manager.server_type == FlextLdifConstants.LdapServers.GENERIC
        assert len(manager.quirks_registry) > 0

    def test_initialization_custom_server_type(self) -> None:
        """Test manager initialization with custom server type."""
        manager = FlextLdifQuirksManager(
            server_type=FlextLdifConstants.LdapServers.ORACLE_OID
        )
        assert manager.server_type == FlextLdifConstants.LdapServers.ORACLE_OID

    def test_initialization_sets_up_quirks_registry(self) -> None:
        """Test that initialization sets up quirks registry for all servers."""
        manager = FlextLdifQuirksManager()
        # Verify all major server types are in registry
        expected_servers = [
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
        for server in expected_servers:
            assert server in manager.quirks_registry

    def test_server_type_property(self) -> None:
        """Test server_type property returns correct value."""
        manager = FlextLdifQuirksManager(
            server_type=FlextLdifConstants.LdapServers.OPENLDAP_2
        )
        assert manager.server_type == FlextLdifConstants.LdapServers.OPENLDAP_2


class TestQuirksManagerExecute:
    """Tests for FlextLdifQuirksManager execute method."""

    def test_execute_returns_service_metadata(self) -> None:
        """Test execute returns service metadata."""
        manager = FlextLdifQuirksManager(
            server_type=FlextLdifConstants.LdapServers.ORACLE_OID
        )
        result = manager.execute()

        assert result.is_success
        metadata = result.unwrap()
        assert metadata["service"] == FlextLdifQuirksManager
        assert metadata["server_type"] == FlextLdifConstants.LdapServers.ORACLE_OID
        quirks_loaded = metadata["quirks_loaded"]
        assert isinstance(quirks_loaded, int) and quirks_loaded > 0


class TestQuirksManagerGetServerQuirks:
    """Tests for get_server_quirks method."""

    def test_get_server_quirks_with_default_server_type(self) -> None:
        """Test getting quirks using manager's default server type."""
        manager = FlextLdifQuirksManager(
            server_type=FlextLdifConstants.LdapServers.ORACLE_OID
        )
        result = manager.get_server_quirks()

        assert result.is_success
        quirks = result.unwrap()
        assert FlextLdifConstants.DictKeys.ACL_ATTRIBUTE in quirks
        assert (
            quirks[FlextLdifConstants.DictKeys.ACL_ATTRIBUTE]
            == FlextLdifConstants.DictKeys.ORCLACI
        )

    def test_get_server_quirks_with_custom_server_type(self) -> None:
        """Test getting quirks for specified server type."""
        manager = FlextLdifQuirksManager()
        result = manager.get_server_quirks(
            server_type=FlextLdifConstants.LdapServers.OPENLDAP_2
        )

        assert result.is_success
        quirks = result.unwrap()
        assert FlextLdifConstants.DictKeys.ACL_ATTRIBUTE in quirks
        assert (
            quirks[FlextLdifConstants.DictKeys.ACL_ATTRIBUTE]
            == FlextLdifConstants.DictKeys.OLCACCESS
        )

    def test_get_server_quirks_unknown_server_type_fails(self) -> None:
        """Test getting quirks for unknown server type fails."""
        manager = FlextLdifQuirksManager()
        result = manager.get_server_quirks(server_type="unknown-server")

        assert not result.is_success
        assert result.error is not None
        assert "Unknown server type" in result.error

    def test_get_server_quirks_all_supported_servers(self) -> None:
        """Test getting quirks for all supported server types."""
        manager = FlextLdifQuirksManager()
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
            result = manager.get_server_quirks(server_type=server_type)
            assert result.is_success
            quirks = result.unwrap()
            assert FlextLdifConstants.DictKeys.ACL_ATTRIBUTE in quirks
            assert FlextLdifConstants.DictKeys.ACL_FORMAT in quirks


class TestQuirksManagerGetAclAttributeName:
    """Tests for get_acl_attribute_name method."""

    def test_get_acl_attribute_name_default_server(self) -> None:
        """Test getting ACL attribute name for default server type."""
        manager = FlextLdifQuirksManager(
            server_type=FlextLdifConstants.LdapServers.ORACLE_OID
        )
        result = manager.get_acl_attribute_name()

        assert result.is_success
        assert result.unwrap() == FlextLdifConstants.DictKeys.ORCLACI

    def test_get_acl_attribute_name_custom_server(self) -> None:
        """Test getting ACL attribute name for specified server type."""
        manager = FlextLdifQuirksManager()
        result = manager.get_acl_attribute_name(
            server_type=FlextLdifConstants.LdapServers.OPENLDAP_2
        )

        assert result.is_success
        assert result.unwrap() == FlextLdifConstants.DictKeys.OLCACCESS

    def test_get_acl_attribute_name_unknown_server_fails(self) -> None:
        """Test getting ACL attribute name for unknown server type fails."""
        manager = FlextLdifQuirksManager()
        result = manager.get_acl_attribute_name(server_type="unknown-server")

        assert not result.is_success
        assert result.error is not None
        assert "Unknown server type" in result.error

    def test_get_acl_attribute_name_all_servers(self) -> None:
        """Test getting ACL attribute name for all supported servers."""
        manager = FlextLdifQuirksManager()
        servers = [
            (
                FlextLdifConstants.LdapServers.OPENLDAP_2,
                FlextLdifConstants.DictKeys.OLCACCESS,
            ),
            (
                FlextLdifConstants.LdapServers.OPENLDAP_1,
                FlextLdifConstants.DictKeys.ACCESS,
            ),
            (
                FlextLdifConstants.LdapServers.ORACLE_OID,
                FlextLdifConstants.DictKeys.ORCLACI,
            ),
            (
                FlextLdifConstants.LdapServers.ORACLE_OUD,
                FlextLdifConstants.DictKeys.DS_PRIVILEGE_NAME,
            ),
            (
                FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY,
                FlextLdifConstants.DictKeys.NTSECURITYDESCRIPTOR,
            ),
        ]

        for server_type, expected_attr in servers:
            result = manager.get_acl_attribute_name(server_type=server_type)
            assert result.is_success
            assert result.unwrap() == expected_attr


class TestQuirksManagerGetAclFormat:
    """Tests for get_acl_format method."""

    def test_get_acl_format_default_server(self) -> None:
        """Test getting ACL format for default server type."""
        manager = FlextLdifQuirksManager(
            server_type=FlextLdifConstants.LdapServers.ORACLE_OID
        )
        result = manager.get_acl_format()

        assert result.is_success
        assert result.unwrap() == FlextLdifConstants.AclFormats.OID_ACL

    def test_get_acl_format_custom_server(self) -> None:
        """Test getting ACL format for specified server type."""
        manager = FlextLdifQuirksManager()
        result = manager.get_acl_format(
            server_type=FlextLdifConstants.LdapServers.OPENLDAP_2
        )

        assert result.is_success
        assert result.unwrap() == FlextLdifConstants.AclFormats.OPENLDAP2_ACL

    def test_get_acl_format_unknown_server_fails(self) -> None:
        """Test getting ACL format for unknown server type fails."""
        manager = FlextLdifQuirksManager()
        result = manager.get_acl_format(server_type="unknown-server")

        assert not result.is_success
        assert result.error is not None
        assert "Unknown server type" in result.error

    def test_get_acl_format_all_servers(self) -> None:
        """Test getting ACL format for all supported servers."""
        manager = FlextLdifQuirksManager()
        servers = [
            (
                FlextLdifConstants.LdapServers.OPENLDAP_2,
                FlextLdifConstants.AclFormats.OPENLDAP2_ACL,
            ),
            (
                FlextLdifConstants.LdapServers.OPENLDAP_1,
                FlextLdifConstants.AclFormats.OPENLDAP1_ACL,
            ),
            (
                FlextLdifConstants.LdapServers.ORACLE_OID,
                FlextLdifConstants.AclFormats.OID_ACL,
            ),
            (
                FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY,
                FlextLdifConstants.AclFormats.AD_ACL,
            ),
            (
                FlextLdifConstants.LdapServers.DS_389,
                FlextLdifConstants.AclFormats.DS389_ACL,
            ),
        ]

        for server_type, expected_format in servers:
            result = manager.get_acl_format(server_type=server_type)
            assert result.is_success
            assert result.unwrap() == expected_format
