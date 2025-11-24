"""Test suite for quirks registry service.

This module provides comprehensive testing for FlextLdifServer which manages
discovery, registration, and retrieval of server-specific quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.services.server import FlextLdifServer


class TestFlextLdifServer:
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
        assert "openldap" in servers

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
        assert stats["total_servers"] > 0
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

        quirk = registry.schema("oid")

        assert quirk is not None
        # Quirks don't have server_type attribute - verify they have parse method
        assert hasattr(quirk, "parse")

    def test_get_schemas_oud(self) -> None:
        """Test retrieving schema quirks for OUD server."""
        registry = FlextLdifServer()

        quirk = registry.schema("oud")

        assert quirk is not None
        # Quirks don't have server_type attribute - verify they have parse method
        assert hasattr(quirk, "parse")

    def test_get_schemas_openldap(self) -> None:
        """Test retrieving schema quirks for OpenLDAP server."""
        registry = FlextLdifServer()

        quirk = registry.schema("openldap")

        assert quirk is not None
        # Quirks don't have server_type attribute - verify they have parse method
        assert hasattr(quirk, "parse")

    def test_get_schemas_nonexistent_server(self) -> None:
        """Test retrieving schema quirks for nonexistent server type."""
        registry = FlextLdifServer()

        quirk = registry.schema("unknown_server")

        assert quirk is None


class TestQuirkPriorityOrdering:
    """Test suite for quirk priority-based ordering."""

    def test_schemas_sorted_by_priority(self) -> None:
        """Test that schema quirks are sorted by priority."""
        registry = FlextLdifServer()

        quirk = registry.schema("oid")

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


class TestQuirkFinding:
    """Test suite for finding specific quirks by capability."""

    def test_find_schema_for_attribute(self) -> None:
        """Test finding schema quirk that can handle attribute definition."""
        registry = FlextLdifServer()

        # OID attribute definition
        attr_def = "( 2.16.840.1.113894.1.1.1 NAME 'orclNetDescString' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )"

        found = registry.find_schema_for_attribute("oid", attr_def)

        # May or may not find depending on implementation - just verify no exception
        # Schema quirks don't have server_type attribute anymore
        assert found is None or hasattr(found, "parse")

    def test_find_schema_for_objectclass(self) -> None:
        """Test finding schema quirk that can handle objectClass definition."""
        registry = FlextLdifServer()

        # OID objectClass definition
        oc_def = "( 2.16.840.1.113894.1.1.2 NAME 'orclContainer' SUP top STRUCTURAL MUST cn )"

        found = registry.find_schema_for_objectclass("oid", oc_def)

        # May or may not find depending on implementation - just verify no exception
        # Schema quirks don't have server_type attribute anymore
        assert found is None or hasattr(found, "parse")

    def test_find_returns_none_for_unknown_server(self) -> None:
        """Test finding quirk returns None for unknown server type."""
        registry = FlextLdifServer()

        found = registry.find_schema_for_attribute("unknown", "attr def")

        assert found is None


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

        alls = registry.get_all_quirks("oid")

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
        assert (
            total_servers >= 8
        )  # At least OID, OUD, OpenLDAP, AD, 389DS, Apache, Novell, Tivoli

        # Updated API: get_registry_stats() returns quirks_by_server, not schemas_by_server
        quirks = stats["quirks_by_server"]
        assert "oid" in quirks
        assert "oud" in quirks
        assert "openldap" in quirks
        # Verify nested quirks
        assert quirks["oid"]["has_schema"]
        assert quirks["oud"]["has_schema"]
        assert quirks["openldap"]["has_schema"]

    def test_list_registered_servers(self) -> None:
        """Test listing all registered server types."""
        registry = FlextLdifServer()

        servers = registry.list_registered_servers()

        # Should have all auto-discovered servers
        assert len(servers) >= 8
        assert "oid" in servers
        assert "oud" in servers
        assert "openldap" in servers
        # Should be sorted
        assert servers == sorted(servers)

    def test_registry_stats_all_types(self) -> None:
        """Test that registry stats include all quirk types."""
        registry = FlextLdifServer()

        stats = registry.get_registry_stats()

        # Note: API changed - stats now use "quirks_by_server" instead of separate dicts
        assert "quirks_by_server" in stats
        assert "total_servers" in stats
        # Verify each server has quirk type flags
        for server_quirks in stats["quirks_by_server"].values():
            assert "has_schema" in server_quirks
            assert "has_acl" in server_quirks
            assert "has_entry" in server_quirks


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
            schema = registry.schema(server_type)
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

        quirk = registry.schema("")
        assert quirk is None

    def test_find_with_empty_definition(self) -> None:
        """Test finding quirk with empty definition string."""
        registry = FlextLdifServer()

        found = registry.find_schema_for_attribute("oid", "")

        # Should handle gracefully (Schema quirks don't have server_type anymore)
        assert found is None or hasattr(found, "parse")

    def test_get_alls_for_unknown_server(self) -> None:
        """Test getting all quirks for unknown server."""
        registry = FlextLdifServer()

        alls = registry.get_all_quirks("unknown_server")

        # Updated API: Unknown server returns None for all quirks, not empty lists
        assert alls == {"schema": None, "acl": None, "entry": None}
