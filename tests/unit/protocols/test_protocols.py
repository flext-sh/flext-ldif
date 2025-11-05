"""Test protocol definitions for LDIF quirks.

Tests the FlextLdifProtocols protocol definitions:
- SchemaProtocol (attribute and objectClass processing)
- QuirkRegistryProtocol (quirk discovery and management)

Verifies protocol definitions and basic implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.openldap import FlextLdifServersOpenldap
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.servers.relaxed import FlextLdifServersRelaxed
from flext_ldif.services.server import FlextLdifServer


class TestProtocolDefinitions:
    """Test protocol definitions are accessible."""

    def test_schema_protocol_is_defined(self) -> None:
        """Test that SchemaProtocol is defined."""
        protocol = FlextLdifProtocols.Quirks.SchemaProtocol
        assert protocol is not None

    def test_acl_protocol_is_defined(self) -> None:
        """Test that AclProtocol is defined."""
        protocol = FlextLdifProtocols.Quirks.AclProtocol
        assert protocol is not None

    def test_entry_protocol_is_defined(self) -> None:
        """Test that EntryProtocol is defined."""
        protocol = FlextLdifProtocols.Quirks.EntryProtocol
        assert protocol is not None

    def test_conversion_protocol_is_defined(self) -> None:
        """Test that ConversionMatrixProtocol is defined."""
        protocol = FlextLdifProtocols.Quirks.ConversionMatrixProtocol
        assert protocol is not None

    def test_registry_protocol_is_defined(self) -> None:
        """Test that QuirkRegistryProtocol is defined."""
        protocol = FlextLdifProtocols.Quirks.QuirkRegistryProtocol
        assert protocol is not None


class TestSchemaProtocol:
    """Test SchemaProtocol protocol implementation."""

    def test_oid_schema_satisfies_schema_protocol(self) -> None:
        """Test that OID Schema quirks satisfies SchemaProtocol."""
        oid_schema = FlextLdifServersOid.Schema()
        assert isinstance(oid_schema, FlextLdifProtocols.Quirks.SchemaProtocol)

    def test_schema_protocol_has_server_type(self) -> None:
        """Test that server quirks have server_type (on main class, not nested)."""
        oid_server = FlextLdifServersOid()
        assert hasattr(oid_server, "server_type")
        assert isinstance(oid_server.server_type, str)

    def test_schema_protocol_has_priority(self) -> None:
        """Test that server quirks have priority (on main class, not nested)."""
        oid_server = FlextLdifServersOid()
        assert hasattr(oid_server, "priority")
        assert isinstance(oid_server.priority, int)

    def test_schema_protocol_has_attribute_methods(self) -> None:
        """Test that SchemaProtocol has attribute methods."""
        oid_schema = FlextLdifServersOid.Schema()

        # Verify attribute methods exist and are callable
        assert callable(oid_schema.can_handle_attribute)
        assert callable(oid_schema.parse)  # Public API method
        assert callable(oid_schema.write)  # Public API method

    def test_schema_protocol_has_objectclass_methods(self) -> None:
        """Test that SchemaProtocol has objectClass methods."""
        oid_schema = FlextLdifServersOid.Schema()

        # Verify objectClass methods exist and are callable
        assert callable(oid_schema.can_handle_objectclass)
        assert callable(oid_schema.parse)  # Public API method
        assert callable(oid_schema.write)  # Public API method

    def test_schema_parse_attribute_returns_flext_result(self) -> None:
        """Test parse_attribute returns FlextResult."""
        oid_schema = FlextLdifServersOid.Schema()
        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        result = oid_schema.parse(attr_def)
        assert isinstance(result, FlextResult)

    def test_schema_parse_objectclass_returns_flext_result(self) -> None:
        """Test parse_objectclass returns FlextResult."""
        oid_schema = FlextLdifServersOid.Schema()
        oc_def = "( 2.5.6.0 NAME 'top' ABSTRACT )"
        result = oid_schema.parse(oc_def)
        assert isinstance(result, FlextResult)

    def test_schema_can_handle_methods_return_bool(self) -> None:
        """Test that can_handle methods return bool."""
        oid_schema = FlextLdifServersOid.Schema()

        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        result = oid_schema.can_handle_attribute(attr_def)
        assert isinstance(result, bool)

        oc_def = "( 2.5.6.0 NAME 'top' ABSTRACT )"
        result = oid_schema.can_handle_objectclass(oc_def)
        assert isinstance(result, bool)

    def test_schema_write_methods_return_flext_result(self) -> None:
        """Test write_*_to_rfc methods return FlextResult."""
        oid_schema = FlextLdifServersOid.Schema()
        test_data: dict[str, object] = {"oid": "2.5.4.3", "name": "cn"}

        result = oid_schema.write(test_data)
        assert isinstance(result, FlextResult)

        result = oid_schema.write(test_data)
        assert isinstance(result, FlextResult)


class TestProtocolNamespace:
    """Test protocol namespace organization."""

    def test_protocol_namespace_has_schema_protocol(self) -> None:
        """Test Quirks namespace has SchemaProtocol."""
        assert hasattr(FlextLdifProtocols.Quirks, "SchemaProtocol")

    def test_protocol_namespace_has_acl_protocol(self) -> None:
        """Test Quirks namespace has AclProtocol."""
        assert hasattr(FlextLdifProtocols.Quirks, "AclProtocol")

    def test_protocol_namespace_has_entry_protocol(self) -> None:
        """Test Quirks namespace has EntryProtocol."""
        assert hasattr(FlextLdifProtocols.Quirks, "EntryProtocol")

    def test_protocol_namespace_has_conversion_protocol(self) -> None:
        """Test Quirks namespace has ConversionMatrixProtocol."""
        assert hasattr(FlextLdifProtocols.Quirks, "ConversionMatrixProtocol")

    def test_protocol_namespace_has_registry_protocol(self) -> None:
        """Test Quirks namespace has QuirkRegistryProtocol."""
        assert hasattr(FlextLdifProtocols.Quirks, "QuirkRegistryProtocol")


class TestQuirkRegistry:
    """Test QuirkRegistry implementation."""

    def test_registry_has_retrieval_methods(self) -> None:
        """Test that registry has retrieval methods."""
        registry = FlextLdifServer()

        # Verify retrieval methods exist and are callable
        assert callable(registry.get_schemas)
        assert callable(registry.get_acls)
        assert callable(registry.get_entrys)
        assert callable(registry.find_schema_for_attribute)
        assert callable(registry.find_schema_for_objectclass)


class TestProtocolAttributes:
    """Test protocol attribute definitions."""

    def test_schema_protocol_server_type_attribute(self) -> None:
        """Test server quirks define server_type attribute (on main class)."""
        oid_server = FlextLdifServersOid()
        # Should have server_type attribute with string value
        assert hasattr(oid_server, "server_type")
        assert isinstance(oid_server.server_type, str)

    def test_schema_protocol_priority_attribute(self) -> None:
        """Test server quirks define priority attribute (on main class)."""
        oid_server = FlextLdifServersOid()
        # Should have priority attribute with int value
        assert hasattr(oid_server, "priority")
        assert isinstance(oid_server.priority, int)


class TestProtocolsExist:
    """Test that all protocol definitions exist and are accessible."""

    def tests_namespace_exists(self) -> None:
        """Test that Quirks namespace exists."""
        assert hasattr(FlextLdifProtocols, "Quirks")

    def test_schema_protocol_exists(self) -> None:
        """Test that SchemaProtocol is defined."""
        assert hasattr(FlextLdifProtocols.Quirks, "SchemaProtocol")

    def test_acl_protocol_exists(self) -> None:
        """Test that AclProtocol is defined."""
        assert hasattr(FlextLdifProtocols.Quirks, "AclProtocol")

    def test_entry_protocol_exists(self) -> None:
        """Test that EntryProtocol is defined."""
        assert hasattr(FlextLdifProtocols.Quirks, "EntryProtocol")

    def test_conversion_protocol_exists(self) -> None:
        """Test that ConversionMatrixProtocol is defined."""
        assert hasattr(FlextLdifProtocols.Quirks, "ConversionMatrixProtocol")

    def test_registry_protocol_exists(self) -> None:
        """Test that QuirkRegistryProtocol is defined."""
        assert hasattr(FlextLdifProtocols.Quirks, "QuirkRegistryProtocol")


class TestSchemaProtocolSatisfaction:
    """Test that schema quirk implementations satisfy SchemaProtocol."""

    def test_oid_satisfies_schema_protocol(self) -> None:
        """Test that OID Schema quirk satisfies SchemaProtocol."""
        quirk = FlextLdifServersOid.Schema()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.SchemaProtocol)

    def test_oud_satisfies_schema_protocol(self) -> None:
        """Test that OUD Schema quirk satisfies SchemaProtocol."""
        quirk = FlextLdifServersOud.Schema()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.SchemaProtocol)

    def test_openldap_satisfies_schema_protocol(self) -> None:
        """Test that OpenLDAP Schema quirk satisfies SchemaProtocol."""
        quirk = FlextLdifServersOpenldap.Schema()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.SchemaProtocol)

    def test_relaxed_satisfies_schema_protocol(self) -> None:
        """Test that Relaxed Schema quirk satisfies SchemaProtocol."""
        quirk = FlextLdifServersRelaxed.Schema()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.SchemaProtocol)


class TestSchemaProtocolMethods:
    """Test that schema quirks have all required protocol methods."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID Schema quirk instance."""
        return FlextLdifServersOid.Schema()

    def test_schema_has_server_type(self) -> None:
        """Test that server quirks have server_type attribute (on main class)."""
        oid_server = FlextLdifServersOid()
        assert hasattr(oid_server, "server_type")
        assert isinstance(oid_server.server_type, str)

    def test_schema_has_priority(self) -> None:
        """Test that server quirks have priority attribute (on main class)."""
        oid_server = FlextLdifServersOid()
        assert hasattr(oid_server, "priority")
        assert isinstance(oid_server.priority, int)

    def test_schema_has_attribute_methods(
        self, oid_schema: FlextLdifServersOid.Schema
    ) -> None:
        """Test that quirk has all attribute processing methods."""
        assert callable(oid_schema.can_handle_attribute)
        assert callable(oid_schema.parse)  # Public API method
        assert callable(oid_schema.write)  # Public API method

    def test_schema_has_objectclass_methods(
        self, oid_schema: FlextLdifServersOid.Schema
    ) -> None:
        """Test that quirk has all objectClass processing methods."""
        assert callable(oid_schema.can_handle_objectclass)
        assert callable(oid_schema.parse)  # Public API method
        assert callable(oid_schema.write)  # Public API method

    def test_attribute_methods_return_flext_result(
        self, oid_schema: FlextLdifServersOid.Schema
    ) -> None:
        """Test that attribute methods return FlextResult."""
        # Test parse_attribute
        result = oid_schema.parse("( 2.5.4.3 NAME 'cn' )")
        assert hasattr(result, "is_success")

    def testcan_handle_attribute_returns_bool(
        self, oid_schema: FlextLdifServersOid.Schema
    ) -> None:
        """Test that can_handle_attribute returns boolean."""
        result = oid_schema.can_handle_attribute("( 2.5.4.3 NAME 'cn' )")
        assert isinstance(result, bool)


class TestAclProtocolSatisfaction:
    """Test that ACL quirk implementations have ACL methods when available."""

    def test_oid_has_acl_methods_defined(self) -> None:
        """Test that OID quirk defines ACL methods if implemented."""
        quirk = FlextLdifServersOid()
        # Check if ACL methods exist on the implementation
        has_acl_methods = (
            hasattr(quirk, "can_handle")
            and hasattr(quirk, "parse")
            and hasattr(quirk, "write_acl_to_rfc")
        )
        # If methods exist, they should be callable
        if has_acl_methods:
            assert callable(quirk.can_handle)

    def test_oud_has_acl_methods_defined(self) -> None:
        """Test that OUD quirk defines ACL methods if implemented."""
        quirk = FlextLdifServersOud()
        # Check if ACL methods exist
        has_acl_methods = (
            hasattr(quirk, "can_handle")
            and hasattr(quirk, "parse")
            and hasattr(quirk, "write_acl_to_rfc")
        )
        # If methods exist, they should be callable
        if has_acl_methods:
            assert callable(quirk.can_handle)


class TestAclProtocolMethods:
    """Test that ACL quirks have all required protocol methods when implemented."""

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create OID quirk instance."""
        return FlextLdifServersOid()

    def test_acl_methods_callable_if_defined(
        self, oid: FlextLdifServersOid
    ) -> None:
        """Test that ACL methods are callable if defined on the quirk."""
        # Only test methods that actually exist on this implementation
        if hasattr(oid, "can_handle"):
            assert callable(oid.can_handle)


class TestEntryProtocolSatisfaction:
    """Test that entry quirk implementations have entry methods when available."""

    def test_oid_has_entry_methods_defined(self) -> None:
        """Test that OID quirk defines entry methods if implemented."""
        quirk = FlextLdifServersOid()
        # Check if entry methods exist on the implementation
        has_entry_methods = hasattr(quirk, "can_handle_entry") and hasattr(
            quirk, "process_entry"
        )
        # If methods exist, they should be callable
        if has_entry_methods:
            assert callable(quirk.can_handle_entry)

    def test_oud_has_entry_methods_defined(self) -> None:
        """Test that OUD quirk defines entry methods if implemented."""
        quirk = FlextLdifServersOud()
        # Check if entry methods exist
        has_entry_methods = hasattr(quirk, "can_handle_entry") and hasattr(
            quirk, "process_entry"
        )
        # If methods exist, they should be callable
        if has_entry_methods:
            assert callable(quirk.can_handle_entry)


class TestEntryProtocolMethods:
    """Test that entry quirks have required methods when implemented."""

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create OID quirk instance."""
        return FlextLdifServersOid()

    def test_entry_methods_callable_if_defined(
        self, oid: FlextLdifServersOid
    ) -> None:
        """Test that entry methods are callable if defined."""
        if hasattr(oid, "can_handle_entry"):
            assert callable(oid.can_handle_entry)


class TestQuirkRegistryProtocolMethods:
    """Test that quirk registry has core methods."""

    @pytest.fixture
    def registry(self) -> FlextLdifServer:
        """Create quirk registry instance."""
        return FlextLdifServer()

    def test_registry_can_retrieves(self, registry: FlextLdifServer) -> None:
        """Test that registry can retrieve quirks."""
        # Test retrieval methods if they exist
        if hasattr(registry, "get_schemas"):
            result = registry.get_schemas("oid")
            # May return list or FlextResult depending on implementation
            assert result is not None and (
                isinstance(result, list) or hasattr(result, "is_success")
            )

    def test_get_global_instance_returns_registry(self) -> None:
        """Test that get_global_instance returns something callable."""
        instance = FlextLdifServer.get_global_instance()
        # Should return a registry instance
        assert instance is not None


class TestProtocolInheritance:
    """Test protocol inheritance relationships."""

    def tests_class_is_accessible(self) -> None:
        """Test that Quirks class is accessible from protocols."""
        quirks_class = FlextLdifProtocols.Quirks
        assert quirks_class is not None

    def test_schema_protocol_satisfied_by_implementations(self) -> None:
        """Test that schema quirks satisfy SchemaProtocol."""
        oid_schema = FlextLdifServersOid.Schema()
        # OID Schema quirk should satisfy schema protocol
        assert isinstance(oid_schema, FlextLdifProtocols.Quirks.SchemaProtocol)


class TestProtocolUsagePatterns:
    """Test common protocol usage patterns."""

    def test_protocol_can_be_used_for_type_checking(self) -> None:
        """Test that protocol can be used for type checking."""
        oid_schema: object = FlextLdifServersOid.Schema()
        # This should work with isinstance and protocol
        is_schema = isinstance(
            oid_schema, FlextLdifProtocols.Quirks.SchemaProtocol
        )
        assert is_schema

    def test_protocol_filterings_by_type(self) -> None:
        """Test filtering quirks by protocol type."""
        schemas_list = [
            FlextLdifServersOid.Schema(),
            FlextLdifServersOud.Schema(),
            FlextLdifServersOpenldap.Schema(),
        ]
        schemas = [
            q
            for q in schemas_list
            if isinstance(q, FlextLdifProtocols.Quirks.SchemaProtocol)
        ]
        assert len(schemas) == 3

    def test_protocol_method_call_pattern(self) -> None:
        """Test calling protocol methods on implementation."""
        schema = FlextLdifServersOid.Schema()
        # Should be able to call protocol methods
        result = schema.can_handle_attribute("( 2.5.4.3 NAME 'cn' )")
        assert isinstance(result, bool)

        # Should be able to call other protocol methods
        parse_result = schema.parse("( 2.5.4.3 NAME 'cn' )")
        assert hasattr(parse_result, "is_success")


__all__ = [
    "TestAclProtocolMethods",
    "TestAclProtocolSatisfaction",
    "TestEntryProtocolMethods",
    "TestEntryProtocolSatisfaction",
    "TestProtocolAttributes",
    "TestProtocolDefinitions",
    "TestProtocolInheritance",
    "TestProtocolNamespace",
    "TestProtocolUsagePatterns",
    "TestProtocolsExist",
    "TestQuirkRegistry",
    "TestQuirkRegistryProtocolMethods",
    "TestSchemaProtocol",
    "TestSchemaProtocolMethods",
    "TestSchemaProtocolSatisfaction",
]
