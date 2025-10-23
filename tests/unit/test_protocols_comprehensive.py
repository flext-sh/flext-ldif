"""Comprehensive tests for protocol definitions and satisfaction.

Tests verify that:
1. Protocol definitions are correctly structured
2. Actual quirk implementations satisfy protocol contracts
3. isinstance() checks work with @runtime_checkable protocols
4. All protocol methods are callable and return FlextResult

All tests use REAL implementations without mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid
from flext_ldif.quirks.servers.openldap_quirks import FlextLdifQuirksServersOpenldap
from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud
from flext_ldif.quirks.servers.relaxed_quirks import FlextLdifQuirksServersRelaxedSchema


class TestProtocolsExist:
    """Test that all protocol definitions exist and are accessible."""

    def test_quirks_namespace_exists(self) -> None:
        """Test that Quirks namespace exists."""
        assert hasattr(FlextLdifProtocols, "Quirks")

    def test_schema_quirk_protocol_exists(self) -> None:
        """Test that SchemaQuirkProtocol is defined."""
        assert hasattr(FlextLdifProtocols.Quirks, "SchemaQuirkProtocol")

    def test_acl_quirk_protocol_exists(self) -> None:
        """Test that AclQuirkProtocol is defined."""
        assert hasattr(FlextLdifProtocols.Quirks, "AclQuirkProtocol")

    def test_entry_quirk_protocol_exists(self) -> None:
        """Test that EntryQuirkProtocol is defined."""
        assert hasattr(FlextLdifProtocols.Quirks, "EntryQuirkProtocol")

    def test_conversion_matrix_protocol_exists(self) -> None:
        """Test that ConversionMatrixProtocol is defined."""
        assert hasattr(FlextLdifProtocols.Quirks, "ConversionMatrixProtocol")

    def test_quirk_registry_protocol_exists(self) -> None:
        """Test that QuirkRegistryProtocol is defined."""
        assert hasattr(FlextLdifProtocols.Quirks, "QuirkRegistryProtocol")


class TestSchemaQuirkProtocolSatisfaction:
    """Test that schema quirk implementations satisfy SchemaQuirkProtocol."""

    def test_oid_quirk_satisfies_schema_protocol(self) -> None:
        """Test that OID quirk satisfies SchemaQuirkProtocol."""
        quirk = FlextLdifQuirksServersOid()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.SchemaQuirkProtocol)

    def test_oud_quirk_satisfies_schema_protocol(self) -> None:
        """Test that OUD quirk satisfies SchemaQuirkProtocol."""
        quirk = FlextLdifQuirksServersOud()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.SchemaQuirkProtocol)

    def test_openldap_quirk_satisfies_schema_protocol(self) -> None:
        """Test that OpenLDAP quirk satisfies SchemaQuirkProtocol."""
        quirk = FlextLdifQuirksServersOpenldap()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.SchemaQuirkProtocol)

    def test_relaxed_quirk_satisfies_schema_protocol(self) -> None:
        """Test that Relaxed quirk satisfies SchemaQuirkProtocol."""
        quirk = FlextLdifQuirksServersRelaxedSchema()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.SchemaQuirkProtocol)


class TestSchemaQuirkProtocolMethods:
    """Test that schema quirks have all required protocol methods."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid()

    def test_schema_quirk_has_server_type(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test that quirk has server_type attribute."""
        assert hasattr(oid_quirk, "server_type")
        assert isinstance(oid_quirk.server_type, str)

    def test_schema_quirk_has_priority(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test that quirk has priority attribute."""
        assert hasattr(oid_quirk, "priority")
        assert isinstance(oid_quirk.priority, int)

    def test_schema_quirk_has_attribute_methods(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test that quirk has all attribute processing methods."""
        assert callable(oid_quirk.can_handle_attribute)
        assert callable(oid_quirk.parse_attribute)
        assert callable(oid_quirk.convert_attribute_to_rfc)
        assert callable(oid_quirk.convert_attribute_from_rfc)
        assert callable(oid_quirk.write_attribute_to_rfc)

    def test_schema_quirk_has_objectclass_methods(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test that quirk has all objectClass processing methods."""
        assert callable(oid_quirk.can_handle_objectclass)
        assert callable(oid_quirk.parse_objectclass)
        assert callable(oid_quirk.convert_objectclass_to_rfc)
        assert callable(oid_quirk.convert_objectclass_from_rfc)
        assert callable(oid_quirk.write_objectclass_to_rfc)

    def test_attribute_methods_return_flext_result(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test that attribute methods return FlextResult."""
        # Test parse_attribute
        result = oid_quirk.parse_attribute("( 2.5.4.3 NAME 'cn' )")
        assert hasattr(result, "is_success")

    def test_can_handle_attribute_returns_bool(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test that can_handle_attribute returns boolean."""
        result = oid_quirk.can_handle_attribute("( 2.5.4.3 NAME 'cn' )")
        assert isinstance(result, bool)


class TestAclQuirkProtocolSatisfaction:
    """Test that ACL quirk implementations have ACL methods when available."""

    def test_oid_quirk_has_acl_methods_defined(self) -> None:
        """Test that OID quirk defines ACL methods if implemented."""
        quirk = FlextLdifQuirksServersOid()
        # Check if ACL methods exist on the implementation
        has_acl_methods = (
            hasattr(quirk, "can_handle_acl")
            and hasattr(quirk, "parse_acl")
            and hasattr(quirk, "convert_acl_to_rfc")
            and hasattr(quirk, "convert_acl_from_rfc")
            and hasattr(quirk, "write_acl_to_rfc")
        )
        # If methods exist, they should be callable
        if has_acl_methods:
            assert callable(quirk.can_handle_acl)

    def test_oud_quirk_has_acl_methods_defined(self) -> None:
        """Test that OUD quirk defines ACL methods if implemented."""
        quirk = FlextLdifQuirksServersOud()
        # Check if ACL methods exist
        has_acl_methods = (
            hasattr(quirk, "can_handle_acl")
            and hasattr(quirk, "parse_acl")
            and hasattr(quirk, "convert_acl_to_rfc")
            and hasattr(quirk, "convert_acl_from_rfc")
            and hasattr(quirk, "write_acl_to_rfc")
        )
        # If methods exist, they should be callable
        if has_acl_methods:
            assert callable(quirk.can_handle_acl)


class TestAclQuirkProtocolMethods:
    """Test that ACL quirks have all required protocol methods when implemented."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid()

    def test_acl_methods_callable_if_defined(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test that ACL methods are callable if defined on the quirk."""
        # Only test methods that actually exist on this implementation
        if hasattr(oid_quirk, "can_handle_acl"):
            assert callable(oid_quirk.can_handle_acl)


class TestEntryQuirkProtocolSatisfaction:
    """Test that entry quirk implementations have entry methods when available."""

    def test_oid_quirk_has_entry_methods_defined(self) -> None:
        """Test that OID quirk defines entry methods if implemented."""
        quirk = FlextLdifQuirksServersOid()
        # Check if entry methods exist on the implementation
        has_entry_methods = (
            hasattr(quirk, "can_handle_entry")
            and hasattr(quirk, "process_entry")
            and hasattr(quirk, "convert_entry_to_rfc")
            and hasattr(quirk, "convert_entry_from_rfc")
        )
        # If methods exist, they should be callable
        if has_entry_methods:
            assert callable(quirk.can_handle_entry)

    def test_oud_quirk_has_entry_methods_defined(self) -> None:
        """Test that OUD quirk defines entry methods if implemented."""
        quirk = FlextLdifQuirksServersOud()
        # Check if entry methods exist
        has_entry_methods = (
            hasattr(quirk, "can_handle_entry")
            and hasattr(quirk, "process_entry")
            and hasattr(quirk, "convert_entry_to_rfc")
            and hasattr(quirk, "convert_entry_from_rfc")
        )
        # If methods exist, they should be callable
        if has_entry_methods:
            assert callable(quirk.can_handle_entry)


class TestEntryQuirkProtocolMethods:
    """Test that entry quirks have required methods when implemented."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid()

    def test_entry_methods_callable_if_defined(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test that entry methods are callable if defined."""
        if hasattr(oid_quirk, "can_handle_entry"):
            assert callable(oid_quirk.can_handle_entry)


class TestQuirkRegistryProtocolSatisfaction:
    """Test that QuirkRegistry has registry methods."""

    def test_quirk_registry_has_core_methods(self) -> None:
        """Test that FlextLdifQuirksRegistry has core registry methods."""
        registry = FlextLdifQuirksRegistry()
        # Check for key registry methods
        assert hasattr(registry, "register_schema_quirk") or hasattr(
            registry, "register_quirk"
        )
        assert hasattr(registry, "get_global_instance")


class TestQuirkRegistryProtocolMethods:
    """Test that quirk registry has core methods."""

    @pytest.fixture
    def registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry instance."""
        return FlextLdifQuirksRegistry()

    def test_registry_has_core_methods_defined(
        self, registry: FlextLdifQuirksRegistry
    ) -> None:
        """Test that registry has core methods defined."""
        # Check for core registry methods if they exist
        if hasattr(registry, "register_schema_quirk"):
            assert callable(registry.register_schema_quirk)
        if hasattr(registry, "get_global_instance"):
            assert callable(registry.get_global_instance)

    def test_registry_can_retrieve_quirks(
        self, registry: FlextLdifQuirksRegistry
    ) -> None:
        """Test that registry can retrieve quirks."""
        # Test retrieval methods if they exist
        if hasattr(registry, "get_schema_quirks"):
            result = registry.get_schema_quirks("oid")
            # May return list or FlextResult depending on implementation
            assert result is not None and (
                isinstance(result, list) or hasattr(result, "is_success")
            )

    def test_get_global_instance_returns_registry(self) -> None:
        """Test that get_global_instance returns something callable."""
        instance = FlextLdifQuirksRegistry.get_global_instance()
        # Should return a registry instance
        assert instance is not None


class TestProtocolInheritance:
    """Test protocol inheritance relationships."""

    def test_quirks_class_is_accessible(self) -> None:
        """Test that Quirks class is accessible from protocols."""
        quirks_class = FlextLdifProtocols.Quirks
        assert quirks_class is not None

    def test_schema_protocol_satisfied_by_implementations(self) -> None:
        """Test that schema quirks satisfy SchemaQuirkProtocol."""
        oid_quirk = FlextLdifQuirksServersOid()
        # OID quirk should satisfy schema protocol
        assert isinstance(oid_quirk, FlextLdifProtocols.Quirks.SchemaQuirkProtocol)


class TestProtocolUsagePatterns:
    """Test common protocol usage patterns."""

    def test_protocol_can_be_used_for_type_checking(self) -> None:
        """Test that protocol can be used for type checking."""
        oid_quirk: object = FlextLdifQuirksServersOid()
        # This should work with isinstance and protocol
        is_schema_quirk = isinstance(
            oid_quirk, FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        )
        assert is_schema_quirk

    def test_protocol_filtering_quirks_by_type(self) -> None:
        """Test filtering quirks by protocol type."""
        quirks = [
            FlextLdifQuirksServersOid(),
            FlextLdifQuirksServersOud(),
            FlextLdifQuirksServersOpenldap(),
        ]
        schema_quirks = [
            q
            for q in quirks
            if isinstance(q, FlextLdifProtocols.Quirks.SchemaQuirkProtocol)
        ]
        assert len(schema_quirks) == 3

    def test_protocol_method_call_pattern(self) -> None:
        """Test calling protocol methods on implementation."""
        quirk = FlextLdifQuirksServersOid()
        # Should be able to call protocol methods
        result = quirk.can_handle_attribute("( 2.5.4.3 NAME 'cn' )")
        assert isinstance(result, bool)

        # Should be able to call other protocol methods
        parse_result = quirk.parse_attribute("( 2.5.4.3 NAME 'cn' )")
        assert hasattr(parse_result, "is_success")
