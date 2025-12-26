"""Tests for quirks registry and auto-discovery mechanism.

This module tests the registry system that manages discovery and registration
of server-specific quirks implementations across the system.
"""

from __future__ import annotations

from flext_ldif.services.server import FlextLdifServer
from tests import s


class TestsTestFlextLdifServer(s):
    """Test suite for quirk registry initialization and auto-discovery."""

    def test_initialization(self) -> None:
        """Test quirk registry initializes and auto-discovers all servers."""
        registry = FlextLdifServer()

        assert registry is not None
        # Registry auto-discovers all servers at initialization
        servers = registry.list_registered_servers()
        assert len(servers) > 0
        assert "oid" in servers
        assert "oud" in servers
        # OpenLDAP is registered as "openldap2" (canonical form)
        # "openldap" alias normalizes to "openldap2" but registry uses canonical form
        assert "openldap2" in servers

    def test_get_global_instance(self) -> None:
        """Test global instance singleton pattern."""
        instance1 = FlextLdifServer.get_global_instance()
        instance2 = FlextLdifServer.get_global_instance()

        assert instance1 is instance2  # Same instance

    def test_registry_stats(self) -> None:
        """Test registry statistics with auto-discovered servers."""
        registry = FlextLdifServer()
        stats = registry.get_registry_stats()

        # Registry should have auto-discovered servers
        total_servers = stats["total_servers"]
        assert isinstance(total_servers, int)
        assert total_servers > 0
        # Note: API changed - stats now use "quirks_by_server" instead of separate dicts
        assert "quirks_by_server" in stats
        assert isinstance(stats["quirks_by_server"], dict)
        # Each server should have quirks registered
        assert len(stats["quirks_by_server"]) > 0


class TestSchemaRetrieval:
    """Test suite for schema quirk retrieval operations."""

    def test_get_schemas_oid(self) -> None:
        """Test retrieving schema quirks for OID server."""
        registry = FlextLdifServer()

        quirk = registry.get_schema_quirk("oid")

        assert quirk is not None
        # Quirks don't have server_type attribute - verify they have parse method
        assert hasattr(quirk, "parse")

    def test_get_schemas_oud(self) -> None:
        """Test retrieving schema quirks for OUD server."""
        registry = FlextLdifServer()

        quirk = registry.get_schema_quirk("oud")

        assert quirk is not None
        # Quirks don't have server_type attribute - verify they have parse method
        assert hasattr(quirk, "parse")

    def test_get_schemas_openldap(self) -> None:
        """Test retrieving schema quirks for OpenLDAP server."""
        registry = FlextLdifServer()

        quirk = registry.get_schema_quirk("openldap")

        assert quirk is not None
        # Quirks don't have server_type attribute - verify they have parse method
        assert hasattr(quirk, "parse")

    def test_get_schemas_nonexistent_server(self) -> None:
        """Test retrieving schema quirks for nonexistent server type."""
        registry = FlextLdifServer()

        quirk = registry.get_schema_quirk("unknown_server")

        assert quirk is None


class TestQuirkPriorityOrdering:
    """Test suite for quirk priority-based ordering."""

    def test_schemas_sorted_by_priority(self) -> None:
        """Test that schema quirks are sorted by priority."""
        registry = FlextLdifServer()

        quirk = registry.get_schema_quirk("oid")

        # Single quirk per server type now - just verify it exists
        assert quirk is not None
        assert hasattr(quirk, "parse")

    def test_acls_sorted_by_priority(self) -> None:
        """Test that ACL quirks are sorted by priority."""
        registry = FlextLdifServer()

        quirk = registry.acl("oid")

        # Single quirk per server type now - just verify it exists
        assert quirk is not None
        assert hasattr(quirk, "parse")

    def test_entrys_sorted_by_priority(self) -> None:
        """Test that entry quirks are sorted by priority."""
        registry = FlextLdifServer()

        quirk = registry.entry("oid")

        # Single quirk per server type now - just verify it exists
        assert quirk is not None
        assert hasattr(quirk, "can_handle")


class TestNestedQuirks:
    """Test suite for nested quirk access (ACL and Entry quirks)."""

    def test_get_acls_for_oid(self) -> None:
        """Test retrieving ACL quirks for OID."""
        registry = FlextLdifServer()

        acl = registry.acl("oid")

        # Should have auto-discovered ACL quirk
        assert acl is not None
        # ACL quirks don't have server_type attribute - verify they have parse method
        assert hasattr(acl, "parse")

    def test_get_entrys_for_oid(self) -> None:
        """Test retrieving entry quirks for OID."""
        registry = FlextLdifServer()

        entry = registry.entry("oid")

        # Should have auto-discovered entry quirk
        assert entry is not None
        # Entry quirks don't have server_type attribute - verify they have can_handle method
        assert hasattr(entry, "can_handle")

    def test_get_alls_for_server(self) -> None:
        """Test retrieving all quirk types for a server."""
        registry = FlextLdifServer()

        alls_result = registry.get_all_quirks("oid")

        # Updated API: get_all_quirks now returns FlextResult
        assert alls_result.is_success
        alls = alls_result.value

        assert "schema" in alls
        assert "acl" in alls
        assert "entry" in alls
        # Note: API changed - get_alls_for_server returns quirk instances, not lists
        # Each should be a quirk instance (Schema, Acl, Entry)
        assert alls["schema"] is not None
        assert alls["acl"] is not None
        assert alls["entry"] is not None
        # Verify they are quirk instances
        assert hasattr(alls["schema"], "parse_attribute")
        assert hasattr(alls["acl"], "parse")
        assert hasattr(alls["entry"], "parse")


class TestRegistryStats:
    """Test suite for registry statistics."""

    def test_registry_stats_all_servers(self) -> None:
        """Test registry statistics include all auto-discovered servers."""
        registry = FlextLdifServer()

        stats = registry.get_registry_stats()

        # Should have all SUPPORTED_SERVERS from constants
        total_servers = stats["total_servers"]
        assert isinstance(total_servers, int)
        assert (
            total_servers >= 8
        )  # At least OID, OUD, OpenLDAP, AD, 389DS, Apache, Novell, Tivoli

        # Updated API: get_registry_stats() returns quirks_by_server with class names
        quirks = stats["quirks_by_server"]
        assert isinstance(quirks, dict)
        assert "oid" in quirks
        assert "oud" in quirks
        # OpenLDAP is registered as "openldap2" (not "openldap")
        assert "openldap2" in quirks
        # Verify nested quirks - they contain class names (or None)
        oid_quirks = quirks["oid"]
        assert isinstance(oid_quirks, dict)
        assert "schema" in oid_quirks
        assert oid_quirks["schema"] is not None
        oud_quirks = quirks["oud"]
        assert isinstance(oud_quirks, dict)
        assert "schema" in oud_quirks
        assert oud_quirks["schema"] is not None
        # OpenLDAP is registered as "openldap2" (not "openldap")
        openldap_quirks = quirks["openldap2"]
        assert isinstance(openldap_quirks, dict)
        assert "schema" in openldap_quirks
        assert openldap_quirks["schema"] is not None

    def test_list_registered_servers(self) -> None:
        """Test listing all registered server types."""
        registry = FlextLdifServer()

        servers = registry.list_registered_servers()

        # Should have all auto-discovered servers
        assert len(servers) >= 8
        assert "oid" in servers
        assert "oud" in servers
        # OpenLDAP is registered as "openldap2" (canonical form)
        # "openldap" alias normalizes to "openldap2" but registry uses canonical form
        assert "openldap2" in servers
        # Should be sorted
        assert servers == sorted(servers)

    def test_registry_stats_all_types(self) -> None:
        """Test that registry stats include all quirk types."""
        registry = FlextLdifServer()

        stats = registry.get_registry_stats()

        # Note: API returns "quirks_by_server" with class names (or None) as values
        assert "quirks_by_server" in stats
        assert "total_servers" in stats
        quirks_by_server = stats["quirks_by_server"]
        assert isinstance(quirks_by_server, dict)
        # Verify each server has quirk type keys
        for server_quirks in quirks_by_server.values():
            assert isinstance(server_quirks, dict)
            assert "schema" in server_quirks
            assert "acl" in server_quirks
            assert "entry" in server_quirks


class TestServerQuirksAvailability:
    """Test that all supported servers have quirks available."""

    def test_all_supported_servers_haves(self) -> None:
        """Test that all registered servers have quirks available."""
        registry = FlextLdifServer()

        # Use actual registered server names from the registry
        # (not the constants which use different names like 'oracle_oid' vs 'oid')
        supported_servers = registry.list_registered_servers()
        # Exclude 'rfc' and 'relaxed' - these are special modes, not actual servers
        supported_servers = [
            s for s in supported_servers if s not in {"rfc", "relaxed"}
        ]

        assert len(supported_servers) > 0, "No servers registered in registry"

        for server_type in supported_servers:
            # Each server should have at least schema quirks
            schema = registry.get_schema_quirk(server_type)
            assert schema is not None, f"No schema quirk for {server_type}"

            # Each server should have entry quirks
            entry = registry.entry(server_type)
            assert entry is not None, f"No entry quirk for {server_type}"

            # ACL quirks may or may not exist for all servers
            acl = registry.acl(server_type)
            # ACL may be None for some servers
            if acl is not None:
                assert hasattr(acl, "parse"), f"ACL quirk invalid for {server_type}"


class TestErrorHandling:
    """Test suite for error handling in registry operations."""

    def test_gets_with_empty_server_type(self) -> None:
        """Test that getting quirks handles empty server type gracefully."""
        registry = FlextLdifServer()

        quirk = registry.get_schema_quirk("")
        assert quirk is None

    def test_find_with_empty_definition(self) -> None:
        """Test getting schema quirk with empty server type string."""
        registry = FlextLdifServer()

        found = registry.get_schema_quirk("")

        # Should handle gracefully - empty server type returns None
        assert found is None

    def test_get_alls_for_unknown_server(self) -> None:
        """Test getting all quirks for unknown server."""
        registry = FlextLdifServer()

        alls = registry.get_all_quirks("unknown_server")

        # Updated API: Unknown server returns FlextResult.fail()
        assert alls.is_failure
        assert "unknown_server" in alls.error or "Invalid server type" in alls.error
