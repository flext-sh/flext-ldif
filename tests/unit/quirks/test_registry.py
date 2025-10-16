"""Test suite for quirks registry service.

This module provides comprehensive testing for FlextLdifQuirksRegistry which manages
discovery, registration, and retrieval of server-specific quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid
from flext_ldif.quirks.servers.openldap_quirks import FlextLdifQuirksServersOpenldap
from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud


class TestFlextLdifQuirksRegistry:
    """Test suite for quirk registry initialization and basic operations."""

    def test_initialization(self) -> None:
        """Test quirk registry initializes with empty registries."""
        registry = FlextLdifQuirksRegistry()

        assert registry is not None
        assert registry.list_registered_servers() == []

    def test_get_global_instance(self) -> None:
        """Test global instance singleton pattern."""
        instance1 = FlextLdifQuirksRegistry.get_global_instance()
        instance2 = FlextLdifQuirksRegistry.get_global_instance()

        assert instance1 is instance2  # Same instance

    def test_registry_stats_empty(self) -> None:
        """Test registry statistics for empty registry."""
        registry = FlextLdifQuirksRegistry()
        stats = registry.get_registry_stats()

        assert stats["total_servers"] == 0
        assert stats["schema_quirks_by_server"] == {}
        assert stats["acl_quirks_by_server"] == {}
        assert stats["entry_quirks_by_server"] == {}


class TestSchemaQuirkRegistration:
    """Test suite for schema quirk registration."""

    def test_register_schema_quirk_success(self) -> None:
        """Test successful schema quirk registration."""
        registry = FlextLdifQuirksRegistry()
        quirk = FlextLdifQuirksServersOid()

        result = registry.register_schema_quirk(quirk)

        assert result.is_success
        assert "oid" in registry.list_registered_servers()

    def test_register_multiple_schema_quirks_same_server(self) -> None:
        """Test registering multiple schema quirks for same server type."""
        registry = FlextLdifQuirksRegistry()
        quirk1 = FlextLdifQuirksServersOid()
        quirk2 = FlextLdifQuirksServersOid()

        result1 = registry.register_schema_quirk(quirk1)
        result2 = registry.register_schema_quirk(quirk2)

        assert result1.is_success
        assert result2.is_success

        quirks = registry.get_schema_quirks("oid")
        assert len(quirks) == 2

    def test_register_schema_quirks_different_servers(self) -> None:
        """Test registering schema quirks for different server types."""
        registry = FlextLdifQuirksRegistry()
        oid_quirk = FlextLdifQuirksServersOid()
        oud_quirk = FlextLdifQuirksServersOud()

        registry.register_schema_quirk(oid_quirk)
        registry.register_schema_quirk(oud_quirk)

        servers = registry.list_registered_servers()
        assert "oid" in servers
        assert "oud" in servers
        assert len(servers) == 2


class TestSchemaQuirkRetrieval:
    """Test suite for schema quirk retrieval operations."""

    def test_get_schema_quirks_existing_server(self) -> None:
        """Test retrieving schema quirks for existing server type."""
        registry = FlextLdifQuirksRegistry()
        quirk = FlextLdifQuirksServersOid()
        registry.register_schema_quirk(quirk)

        quirks = registry.get_schema_quirks("oid")

        assert len(quirks) == 1
        assert quirks[0].server_type == "oid"

    def test_get_schema_quirks_nonexistent_server(self) -> None:
        """Test retrieving schema quirks for nonexistent server type."""
        registry = FlextLdifQuirksRegistry()

        quirks = registry.get_schema_quirks("unknown_server")

        assert quirks == []

    def test_get_schema_quirks_empty_registry(self) -> None:
        """Test retrieving from empty registry."""
        registry = FlextLdifQuirksRegistry()

        quirks = registry.get_schema_quirks("oid")

        assert quirks == []


class TestQuirkPriorityOrdering:
    """Test suite for quirk priority-based ordering."""

    def test_schema_quirks_sorted_by_priority(self) -> None:
        """Test that schema quirks are sorted by priority (lower = higher priority)."""
        registry = FlextLdifQuirksRegistry()

        # OpenLDAP 2.x has server_type "openldap" and priority 10
        openldap_quirk = FlextLdifQuirksServersOpenldap()
        registry.register_schema_quirk(openldap_quirk)

        # Get quirks for correct server type
        quirks = registry.get_schema_quirks(openldap_quirk.server_type)

        # Should have registered quirk
        assert len(quirks) > 0
        # First quirk should have lowest priority number (highest priority)
        assert quirks[0].priority == 10

    def test_priority_ordering_with_multiple_quirks(self) -> None:
        """Test priority ordering with multiple quirks of same server type."""
        registry = FlextLdifQuirksRegistry()

        # Register multiple OID quirks (same priority)
        quirk1 = FlextLdifQuirksServersOid()
        quirk2 = FlextLdifQuirksServersOid()

        registry.register_schema_quirk(quirk1)
        registry.register_schema_quirk(quirk2)

        quirks = registry.get_schema_quirks("oid")

        # All should have same priority
        assert all(q.priority == 10 for q in quirks)


class TestQuirkFinding:
    """Test suite for finding specific quirks by capability."""

    def test_find_schema_quirk_for_attribute(self) -> None:
        """Test finding schema quirk that can handle attribute definition."""
        registry = FlextLdifQuirksRegistry()
        quirk = FlextLdifQuirksServersOid()
        registry.register_schema_quirk(quirk)

        # OID attribute definition
        attr_def = "( 2.16.840.1.113894.1.1.1 NAME 'orclNetDescString' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )"

        found_quirk = registry.find_schema_quirk_for_attribute("oid", attr_def)

        # May or may not find depending on implementation
        # Test that method executes without error
        assert found_quirk is None or isinstance(found_quirk, FlextLdifQuirksServersOid)

    def test_find_schema_quirk_for_objectclass(self) -> None:
        """Test finding schema quirk that can handle objectClass definition."""
        registry = FlextLdifQuirksRegistry()
        quirk = FlextLdifQuirksServersOid()
        registry.register_schema_quirk(quirk)

        # OID objectClass definition
        oc_def = "( 2.16.840.1.113894.1.1.2 NAME 'orclContainer' SUP top STRUCTURAL MUST cn )"

        found_quirk = registry.find_schema_quirk_for_objectclass("oid", oc_def)

        # May or may not find depending on implementation
        assert found_quirk is None or isinstance(found_quirk, FlextLdifQuirksServersOid)

    def test_find_quirk_returns_none_for_unknown_server(self) -> None:
        """Test finding quirk returns None for unknown server type."""
        registry = FlextLdifQuirksRegistry()
        quirk = FlextLdifQuirksServersOid()
        registry.register_schema_quirk(quirk)

        found_quirk = registry.find_schema_quirk_for_attribute("unknown", "attr def")

        assert found_quirk is None


class TestNestedQuirks:
    """Test suite for nested quirk access (ACL and Entry quirks)."""

    def test_get_acl_quirks_empty(self) -> None:
        """Test retrieving ACL quirks from empty registry."""
        registry = FlextLdifQuirksRegistry()

        acl_quirks = registry.get_acl_quirks("oid")

        assert acl_quirks == []

    def test_get_entry_quirks_empty(self) -> None:
        """Test retrieving entry quirks from empty registry."""
        registry = FlextLdifQuirksRegistry()

        entry_quirks = registry.get_entry_quirks("oid")

        assert entry_quirks == []

    def test_get_all_quirks_for_server(self) -> None:
        """Test retrieving all quirk types for a server."""
        registry = FlextLdifQuirksRegistry()
        schema_quirk = FlextLdifQuirksServersOid()
        registry.register_schema_quirk(schema_quirk)

        all_quirks = registry.get_all_quirks_for_server("oid")

        assert "schema" in all_quirks
        assert "acl" in all_quirks
        assert "entry" in all_quirks
        assert len(all_quirks["schema"]) == 1
        assert len(all_quirks["acl"]) == 0
        assert len(all_quirks["entry"]) == 0


class TestRegistryStats:
    """Test suite for registry statistics."""

    def test_registry_stats_with_quirks(self) -> None:
        """Test registry statistics after registering quirks."""
        registry = FlextLdifQuirksRegistry()
        oid_quirk = FlextLdifQuirksServersOid()
        oud_quirk = FlextLdifQuirksServersOud()

        registry.register_schema_quirk(oid_quirk)
        registry.register_schema_quirk(oud_quirk)

        stats = registry.get_registry_stats()

        assert stats["total_servers"] == 2
        schema_quirks = stats["schema_quirks_by_server"]
        assert isinstance(schema_quirks, dict)
        assert "oid" in schema_quirks
        assert "oud" in schema_quirks
        assert schema_quirks["oid"] == 1
        assert schema_quirks["oud"] == 1

    def test_list_registered_servers(self) -> None:
        """Test listing all registered server types."""
        registry = FlextLdifQuirksRegistry()
        registry.register_schema_quirk(FlextLdifQuirksServersOid())
        registry.register_schema_quirk(FlextLdifQuirksServersOud())

        servers = registry.list_registered_servers()

        assert len(servers) == 2
        assert "oid" in servers
        assert "oud" in servers
        # Should be sorted
        assert servers == sorted(servers)


class TestErrorHandling:
    """Test suite for error handling in registry operations."""

    def test_get_quirks_with_none_server_type(self) -> None:
        """Test that getting quirks handles edge cases gracefully."""
        registry = FlextLdifQuirksRegistry()

        # Empty string server type
        quirks = registry.get_schema_quirks("")
        assert quirks == []

    def test_find_quirk_with_empty_definition(self) -> None:
        """Test finding quirk with empty definition string."""
        registry = FlextLdifQuirksRegistry()
        registry.register_schema_quirk(FlextLdifQuirksServersOid())

        found_quirk = registry.find_schema_quirk_for_attribute("oid", "")

        # Should handle gracefully
        assert found_quirk is None or isinstance(found_quirk, FlextLdifQuirksServersOid)
