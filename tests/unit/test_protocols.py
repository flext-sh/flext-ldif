"""Test protocol definitions for LDIF quirks.

Tests the FlextLdifProtocols protocol definitions:
- SchemaQuirkProtocol (attribute and objectClass processing)
- QuirkRegistryProtocol (quirk discovery and management)

Verifies protocol definitions and basic implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid


class TestProtocolDefinitions:
    """Test protocol definitions are accessible."""

    def test_schema_quirk_protocol_is_defined(self) -> None:
        """Test that SchemaQuirkProtocol is defined."""
        protocol = FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        assert protocol is not None

    def test_acl_quirk_protocol_is_defined(self) -> None:
        """Test that AclQuirkProtocol is defined."""
        protocol = FlextLdifProtocols.Quirks.AclQuirkProtocol
        assert protocol is not None

    def test_entry_quirk_protocol_is_defined(self) -> None:
        """Test that EntryQuirkProtocol is defined."""
        protocol = FlextLdifProtocols.Quirks.EntryQuirkProtocol
        assert protocol is not None

    def test_conversion_matrix_protocol_is_defined(self) -> None:
        """Test that ConversionMatrixProtocol is defined."""
        protocol = FlextLdifProtocols.Quirks.ConversionMatrixProtocol
        assert protocol is not None

    def test_quirk_registry_protocol_is_defined(self) -> None:
        """Test that QuirkRegistryProtocol is defined."""
        protocol = FlextLdifProtocols.Quirks.QuirkRegistryProtocol
        assert protocol is not None


class TestSchemaQuirkProtocol:
    """Test SchemaQuirkProtocol protocol implementation."""

    def test_oid_quirks_satisfies_schema_quirk_protocol(self) -> None:
        """Test that OID quirks satisfies SchemaQuirkProtocol."""
        oid_quirk = FlextLdifQuirksServersOid()
        assert isinstance(oid_quirk, FlextLdifProtocols.Quirks.SchemaQuirkProtocol)

    def test_schema_quirk_protocol_has_server_type(self) -> None:
        """Test that SchemaQuirkProtocol instances have server_type."""
        oid_quirk = FlextLdifQuirksServersOid()
        assert hasattr(oid_quirk, "server_type")
        assert isinstance(oid_quirk.server_type, str)

    def test_schema_quirk_protocol_has_priority(self) -> None:
        """Test that SchemaQuirkProtocol instances have priority."""
        oid_quirk = FlextLdifQuirksServersOid()
        assert hasattr(oid_quirk, "priority")
        assert isinstance(oid_quirk.priority, int)

    def test_schema_quirk_protocol_has_attribute_methods(self) -> None:
        """Test that SchemaQuirkProtocol has attribute methods."""
        oid_quirk = FlextLdifQuirksServersOid()

        # Verify attribute methods exist and are callable
        assert callable(oid_quirk.can_handle_attribute)
        assert callable(oid_quirk.parse_attribute)
        assert callable(oid_quirk.convert_attribute_to_rfc)
        assert callable(oid_quirk.convert_attribute_from_rfc)
        assert callable(oid_quirk.write_attribute_to_rfc)

    def test_schema_quirk_protocol_has_objectclass_methods(self) -> None:
        """Test that SchemaQuirkProtocol has objectClass methods."""
        oid_quirk = FlextLdifQuirksServersOid()

        # Verify objectClass methods exist and are callable
        assert callable(oid_quirk.can_handle_objectclass)
        assert callable(oid_quirk.parse_objectclass)
        assert callable(oid_quirk.convert_objectclass_to_rfc)
        assert callable(oid_quirk.convert_objectclass_from_rfc)
        assert callable(oid_quirk.write_objectclass_to_rfc)

    def test_schema_quirk_parse_attribute_returns_flext_result(self) -> None:
        """Test parse_attribute returns FlextResult."""
        oid_quirk = FlextLdifQuirksServersOid()
        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        result = oid_quirk.parse_attribute(attr_def)
        assert isinstance(result, FlextResult)

    def test_schema_quirk_parse_objectclass_returns_flext_result(self) -> None:
        """Test parse_objectclass returns FlextResult."""
        oid_quirk = FlextLdifQuirksServersOid()
        oc_def = "( 2.5.6.0 NAME 'top' ABSTRACT )"
        result = oid_quirk.parse_objectclass(oc_def)
        assert isinstance(result, FlextResult)

    def test_schema_quirk_can_handle_methods_return_bool(self) -> None:
        """Test that can_handle methods return bool."""
        oid_quirk = FlextLdifQuirksServersOid()

        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        result = oid_quirk.can_handle_attribute(attr_def)
        assert isinstance(result, bool)

        oc_def = "( 2.5.6.0 NAME 'top' ABSTRACT )"
        result = oid_quirk.can_handle_objectclass(oc_def)
        assert isinstance(result, bool)

    def test_schema_quirk_write_methods_return_flext_result(self) -> None:
        """Test write_*_to_rfc methods return FlextResult."""
        oid_quirk = FlextLdifQuirksServersOid()
        test_data: dict[str, object] = {"oid": "2.5.4.3", "name": "cn"}

        result = oid_quirk.write_attribute_to_rfc(test_data)
        assert isinstance(result, FlextResult)

        result = oid_quirk.write_objectclass_to_rfc(test_data)
        assert isinstance(result, FlextResult)

    def test_schema_quirk_convert_methods_return_flext_result(self) -> None:
        """Test convert_* methods return FlextResult."""
        oid_quirk = FlextLdifQuirksServersOid()
        test_data: dict[str, object] = {"oid": "2.5.4.3", "name": "cn"}

        result = oid_quirk.convert_attribute_to_rfc(test_data)
        assert isinstance(result, FlextResult)

        result = oid_quirk.convert_objectclass_to_rfc(test_data)
        assert isinstance(result, FlextResult)


class TestProtocolNamespace:
    """Test protocol namespace organization."""

    def test_protocol_namespace_has_schema_quirk_protocol(self) -> None:
        """Test Quirks namespace has SchemaQuirkProtocol."""
        assert hasattr(FlextLdifProtocols.Quirks, "SchemaQuirkProtocol")

    def test_protocol_namespace_has_acl_quirk_protocol(self) -> None:
        """Test Quirks namespace has AclQuirkProtocol."""
        assert hasattr(FlextLdifProtocols.Quirks, "AclQuirkProtocol")

    def test_protocol_namespace_has_entry_quirk_protocol(self) -> None:
        """Test Quirks namespace has EntryQuirkProtocol."""
        assert hasattr(FlextLdifProtocols.Quirks, "EntryQuirkProtocol")

    def test_protocol_namespace_has_conversion_matrix_protocol(self) -> None:
        """Test Quirks namespace has ConversionMatrixProtocol."""
        assert hasattr(FlextLdifProtocols.Quirks, "ConversionMatrixProtocol")

    def test_protocol_namespace_has_quirk_registry_protocol(self) -> None:
        """Test Quirks namespace has QuirkRegistryProtocol."""
        assert hasattr(FlextLdifProtocols.Quirks, "QuirkRegistryProtocol")


class TestQuirkRegistry:
    """Test QuirkRegistry implementation."""

    def test_quirk_registry_has_register_methods(self) -> None:
        """Test that registry has registration methods."""
        registry = FlextLdifQuirksRegistry()

        assert callable(registry.register_schema_quirk)
        assert callable(registry.register_acl_quirk)
        assert callable(registry.register_entry_quirk)

    def test_quirk_registry_has_retrieval_methods(self) -> None:
        """Test that registry has retrieval methods."""
        registry = FlextLdifQuirksRegistry()

        # Verify retrieval methods exist and are callable
        assert callable(registry.get_schema_quirks)
        assert callable(registry.get_acl_quirks)
        assert callable(registry.get_entry_quirks)
        assert callable(registry.find_schema_quirk_for_attribute)
        assert callable(registry.find_schema_quirk_for_objectclass)


class TestProtocolAttributes:
    """Test protocol attribute definitions."""

    def test_schema_quirk_protocol_server_type_attribute(self) -> None:
        """Test SchemaQuirkProtocol defines server_type attribute."""
        oid_quirk = FlextLdifQuirksServersOid()
        # Should have server_type attribute with string value
        assert hasattr(oid_quirk, "server_type")
        assert isinstance(oid_quirk.server_type, str)

    def test_schema_quirk_protocol_priority_attribute(self) -> None:
        """Test SchemaQuirkProtocol defines priority attribute."""
        oid_quirk = FlextLdifQuirksServersOid()
        # Should have priority attribute with int value
        assert hasattr(oid_quirk, "priority")
        assert isinstance(oid_quirk.priority, int)


__all__ = [
    "TestProtocolAttributes",
    "TestProtocolDefinitions",
    "TestProtocolNamespace",
    "TestQuirkRegistry",
    "TestSchemaQuirkProtocol",
]
