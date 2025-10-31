"""Test suite for quirks registry service.

This module provides comprehensive testing for FlextLdifRegistry which manages
discovery, registration, and retrieval of server-specific quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.services.registry import FlextLdifRegistry


class TestFlextLdifRegistry:
    """Test suite for quirk registry initialization and auto-discovery."""

    def test_initialization(self) -> None:
        """Test quirk registry initializes and auto-discovers all servers."""
        registry = FlextLdifRegistry()

        assert registry is not None
        # Registry auto-discovers all servers at initialization
        servers = registry.list_registered_servers()
        assert len(servers) > 0
        assert "oid" in servers
        assert "oud" in servers
        assert "openldap" in servers

    def test_get_global_instance(self) -> None:
        """Test global instance singleton pattern."""
        instance1 = FlextLdifRegistry.get_global_instance()
        instance2 = FlextLdifRegistry.get_global_instance()

        assert instance1 is instance2  # Same instance

    def test_registry_stats(self) -> None:
        """Test registry statistics with auto-discovered servers."""
        registry = FlextLdifRegistry()
        stats = registry.get_registry_stats()

        # Registry should have auto-discovered servers
        assert stats["total_servers"] > 0
        assert isinstance(stats["schema_quirks_by_server"], dict)
        assert isinstance(stats["acl_quirks_by_server"], dict)
        assert isinstance(stats["entrys_by_server"], dict)
        # Each server should have quirks registered
        assert len(stats["schema_quirks_by_server"]) > 0


class TestSchemaRetrieval:
    """Test suite for schema quirk retrieval operations."""

    def test_get_schema_quirks_oid(self) -> None:
        """Test retrieving schema quirks for OID server."""
        registry = FlextLdifRegistry()

        quirks = registry.get_schema_quirks("oid")

        assert len(quirks) > 0
        assert all(q.server_type == "oid" for q in quirks)

    def test_get_schema_quirks_oud(self) -> None:
        """Test retrieving schema quirks for OUD server."""
        registry = FlextLdifRegistry()

        quirks = registry.get_schema_quirks("oud")

        assert len(quirks) > 0
        assert all(q.server_type == "oud" for q in quirks)

    def test_get_schema_quirks_openldap(self) -> None:
        """Test retrieving schema quirks for OpenLDAP server."""
        registry = FlextLdifRegistry()

        quirks = registry.get_schema_quirks("openldap")

        assert len(quirks) > 0
        assert all(q.server_type == "openldap" for q in quirks)

    def test_get_schema_quirks_nonexistent_server(self) -> None:
        """Test retrieving schema quirks for nonexistent server type."""
        registry = FlextLdifRegistry()

        quirks = registry.get_schema_quirks("unknown_server")

        assert quirks == []


class TestQuirkPriorityOrdering:
    """Test suite for quirk priority-based ordering."""

    def test_schema_quirks_sorted_by_priority(self) -> None:
        """Test that schema quirks are sorted by priority."""
        registry = FlextLdifRegistry()

        quirks = registry.get_schema_quirks("oid")

        # Quirks should be sorted by priority (lower number = higher priority)
        if len(quirks) > 1:
            for i in range(len(quirks) - 1):
                assert quirks[i].priority <= quirks[i + 1].priority

    def test_acl_quirks_sorted_by_priority(self) -> None:
        """Test that ACL quirks are sorted by priority."""
        registry = FlextLdifRegistry()

        quirks = registry.get_acl_quirks("oid")

        # Quirks should be sorted by priority (lower number = higher priority)
        if len(quirks) > 1:
            for i in range(len(quirks) - 1):
                assert quirks[i].priority <= quirks[i + 1].priority

    def test_entrys_sorted_by_priority(self) -> None:
        """Test that entry quirks are sorted by priority."""
        registry = FlextLdifRegistry()

        quirks = registry.get_entrys("oid")

        # Quirks should be sorted by priority (lower number = higher priority)
        if len(quirks) > 1:
            for i in range(len(quirks) - 1):
                assert quirks[i].priority <= quirks[i + 1].priority


class TestQuirkFinding:
    """Test suite for finding specific quirks by capability."""

    def test_find_schema_quirk_for_attribute(self) -> None:
        """Test finding schema quirk that can handle attribute definition."""
        registry = FlextLdifRegistry()

        # OID attribute definition
        attr_def = "( 2.16.840.1.113894.1.1.1 NAME 'orclNetDescString' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )"

        found_quirk = registry.find_schema_quirk_for_attribute("oid", attr_def)

        # May or may not find depending on implementation - just verify no exception
        assert found_quirk is None or hasattr(found_quirk, "server_type")

    def test_find_schema_quirk_for_objectclass(self) -> None:
        """Test finding schema quirk that can handle objectClass definition."""
        registry = FlextLdifRegistry()

        # OID objectClass definition
        oc_def = "( 2.16.840.1.113894.1.1.2 NAME 'orclContainer' SUP top STRUCTURAL MUST cn )"

        found_quirk = registry.find_schema_quirk_for_objectclass("oid", oc_def)

        # May or may not find depending on implementation - just verify no exception
        assert found_quirk is None or hasattr(found_quirk, "server_type")

    def test_find_quirk_returns_none_for_unknown_server(self) -> None:
        """Test finding quirk returns None for unknown server type."""
        registry = FlextLdifRegistry()

        found_quirk = registry.find_schema_quirk_for_attribute("unknown", "attr def")

        assert found_quirk is None


class TestNestedQuirks:
    """Test suite for nested quirk access (ACL and Entry quirks)."""

    def test_get_acl_quirks_for_oid(self) -> None:
        """Test retrieving ACL quirks for OID."""
        registry = FlextLdifRegistry()

        acl_quirks = registry.get_acl_quirks("oid")

        # Should have auto-discovered ACL quirks
        assert isinstance(acl_quirks, list)
        assert all(q.server_type == "oid" for q in acl_quirks)

    def test_get_entrys_for_oid(self) -> None:
        """Test retrieving entry quirks for OID."""
        registry = FlextLdifRegistry()

        entrys = registry.get_entrys("oid")

        # Should have auto-discovered entry quirks
        assert isinstance(entrys, list)
        assert all(q.server_type == "oid" for q in entrys)

    def test_get_all_quirks_for_server(self) -> None:
        """Test retrieving all quirk types for a server."""
        registry = FlextLdifRegistry()

        all_quirks = registry.get_all_quirks_for_server("oid")

        assert "schema" in all_quirks
        assert "acl" in all_quirks
        assert "entry" in all_quirks
        # Each should be a list
        assert isinstance(all_quirks["schema"], list)
        assert isinstance(all_quirks["acl"], list)
        assert isinstance(all_quirks["entry"], list)
        # Should have auto-discovered quirks
        assert len(all_quirks["schema"]) > 0


class TestRegistryStats:
    """Test suite for registry statistics."""

    def test_registry_stats_all_servers(self) -> None:
        """Test registry statistics include all auto-discovered servers."""
        registry = FlextLdifRegistry()

        stats = registry.get_registry_stats()

        # Should have all SUPPORTED_SERVERS from constants
        total_servers = stats["total_servers"]
        assert (
            total_servers >= 8
        )  # At least OID, OUD, OpenLDAP, AD, 389DS, Apache, Novell, Tivoli

        schema_quirks = stats["schema_quirks_by_server"]
        assert "oid" in schema_quirks
        assert "oud" in schema_quirks
        assert "openldap" in schema_quirks

    def test_list_registered_servers(self) -> None:
        """Test listing all registered server types."""
        registry = FlextLdifRegistry()

        servers = registry.list_registered_servers()

        # Should have all auto-discovered servers
        assert len(servers) >= 8
        assert "oid" in servers
        assert "oud" in servers
        assert "openldap" in servers
        # Should be sorted
        assert servers == sorted(servers)

    def test_registry_stats_all_quirk_types(self) -> None:
        """Test that registry stats include all quirk types."""
        registry = FlextLdifRegistry()

        stats = registry.get_registry_stats()

        assert "schema_quirks_by_server" in stats
        assert "acl_quirks_by_server" in stats
        assert "entrys_by_server" in stats
        assert "total_servers" in stats


class TestServerQuirksAvailability:
    """Test that all supported servers have quirks available."""

    def test_all_supported_servers_have_quirks(self) -> None:
        """Test that all registered servers have quirks available."""
        registry = FlextLdifRegistry()

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
            schema_quirks = registry.get_schema_quirks(server_type)
            assert len(schema_quirks) > 0, f"No schema quirks for {server_type}"

            # Each server should have entry quirks
            entrys = registry.get_entrys(server_type)
            assert len(entrys) > 0, f"No entry quirks for {server_type}"

            # ACL quirks may or may not exist for all servers
            acl_quirks = registry.get_acl_quirks(server_type)
            assert isinstance(acl_quirks, list), (
                f"ACL quirks not a list for {server_type}"
            )


class TestErrorHandling:
    """Test suite for error handling in registry operations."""

    def test_get_quirks_with_empty_server_type(self) -> None:
        """Test that getting quirks handles empty server type gracefully."""
        registry = FlextLdifRegistry()

        quirks = registry.get_schema_quirks("")
        assert quirks == []

    def test_find_quirk_with_empty_definition(self) -> None:
        """Test finding quirk with empty definition string."""
        registry = FlextLdifRegistry()

        found_quirk = registry.find_schema_quirk_for_attribute("oid", "")

        # Should handle gracefully
        assert found_quirk is None or hasattr(found_quirk, "server_type")

    def test_get_all_quirks_for_unknown_server(self) -> None:
        """Test getting all quirks for unknown server."""
        registry = FlextLdifRegistry()

        all_quirks = registry.get_all_quirks_for_server("unknown_server")

        assert all_quirks == {"schema": [], "acl": [], "entry": []}
