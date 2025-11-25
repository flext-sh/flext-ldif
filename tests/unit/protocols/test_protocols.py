"""Test suite for FlextLdifProtocols protocol definitions.

Tests protocol definitions and implementations:
- Protocol accessibility and namespace organization
- SchemaProtocol implementation across servers (OID, OUD, OpenLDAP, Relaxed)
- Protocol satisfaction via structural typing (duck typing)
- QuirkRegistryProtocol implementation
- Protocol attribute definitions and method contracts

Test Structure:
- ProtocolAccess: Protocol definition existence and accessibility
- ProtocolImplementation: Server implementations satisfying protocols
- ProtocolMethods: Method contracts and return types
- ProtocolUsage: Common usage patterns and filtering

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import dataclasses
from enum import StrEnum

import pytest
from flext_core import FlextResult

from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.openldap import FlextLdifServersOpenldap
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.servers.relaxed import FlextLdifServersRelaxed
from flext_ldif.services.server import FlextLdifServer


class ProtocolNames(StrEnum):
    """Protocol names in FlextLdifProtocols.Quirks namespace."""

    SCHEMA = "SchemaProtocol"
    ACL = "AclProtocol"
    ENTRY = "EntryProtocol"
    CONVERSION = "ConversionMatrixProtocol"
    REGISTRY = "QuirkRegistryProtocol"


class ServerTypes(StrEnum):
    """Server types implementing schema protocol."""

    OID = "oid"
    OUD = "oud"
    OPENLDAP = "openldap"
    RELAXED = "relaxed"


@dataclasses.dataclass(frozen=True)
class ProtocolServer:
    """Server implementation for schema protocol testing."""

    name: str
    server_class: type  # type: ignore[type-arg]
    schema_class: type  # type: ignore[type-arg]


# Test data for parametrized server tests
SERVER_IMPLEMENTATIONS = (
    ProtocolServer(
        name="OID",
        server_class=FlextLdifServersOid,  # type: ignore[arg-type]
        schema_class=FlextLdifServersOid.Schema,  # type: ignore[arg-type]
    ),
    ProtocolServer(
        name="OUD",
        server_class=FlextLdifServersOud,  # type: ignore[arg-type]
        schema_class=FlextLdifServersOud.Schema,  # type: ignore[arg-type]
    ),
    ProtocolServer(
        name="OpenLDAP",
        server_class=FlextLdifServersOpenldap,  # type: ignore[arg-type]
        schema_class=FlextLdifServersOpenldap.Schema,  # type: ignore[arg-type]
    ),
    ProtocolServer(
        name="Relaxed",
        server_class=FlextLdifServersRelaxed,  # type: ignore[arg-type]
        schema_class=FlextLdifServersRelaxed.Schema,  # type: ignore[arg-type]
    ),
)


class TestFlextLdifProtocols:
    """Test suite for FlextLdifProtocols protocol definitions."""

    class ProtocolAccess:
        """Test protocol definition accessibility."""

        @pytest.mark.parametrize(
            "protocol_name",
            [p.value for p in ProtocolNames],
        )
        def test_protocol_is_defined(self, protocol_name: str) -> None:
            """Test that protocol is defined and accessible."""
            assert hasattr(FlextLdifProtocols.Quirks, protocol_name)
            protocol = getattr(FlextLdifProtocols.Quirks, protocol_name)
            assert protocol is not None

    class ProtocolNamespace:
        """Test protocol namespace organization."""

        def test_quirks_namespace_exists(self) -> None:
            """Test that Quirks namespace exists."""
            assert hasattr(FlextLdifProtocols, "Quirks")

        @pytest.mark.parametrize(
            "protocol_name",
            [p.value for p in ProtocolNames],
        )
        def test_protocol_in_namespace(self, protocol_name: str) -> None:
            """Test that protocol exists in Quirks namespace."""
            assert hasattr(FlextLdifProtocols.Quirks, protocol_name)

    class ProtocolImplementation:
        """Test server implementations satisfy schema protocol."""

        @pytest.mark.parametrize(
            "protocol_server",
            SERVER_IMPLEMENTATIONS,
        )
        def test_schema_satisfies_protocol(
            self,
            protocol_server: ProtocolServer,
        ) -> None:
            """Test that schema implementation satisfies SchemaProtocol."""
            schema: object = protocol_server.schema_class()
            # Protocol satisfied via structural typing (duck typing)
            assert hasattr(schema, "parse")
            assert callable(schema.parse)  # pyright: ignore[reportAttributeAccessIssue]
            assert hasattr(schema, "write")
            assert callable(schema.write)  # pyright: ignore[reportAttributeAccessIssue]

        @pytest.mark.parametrize(
            "protocol_server",
            SERVER_IMPLEMENTATIONS,
        )
        def test_server_has_protocol_attributes(
            self,
            protocol_server: ProtocolServer,
        ) -> None:
            """Test that server implements protocol attributes."""
            server: object = protocol_server.server_class()
            assert hasattr(server, "server_type")
            assert isinstance(server.server_type, str)  # pyright: ignore[reportAttributeAccessIssue]
            assert hasattr(server, "priority")
            assert isinstance(server.priority, int)  # pyright: ignore[reportAttributeAccessIssue]

    class SchemaProtocol:
        """Test SchemaProtocol implementation details."""

        @pytest.fixture
        def oid_schema(self) -> FlextLdifServersOid.Schema:
            """Create OID Schema instance."""
            return FlextLdifServersOid.Schema()

        def test_schema_has_required_methods(
            self,
            oid_schema: FlextLdifServersOid.Schema,
        ) -> None:
            """Test schema has all required protocol methods."""
            # Attribute methods
            assert callable(oid_schema.can_handle_attribute)
            assert callable(oid_schema.parse)
            assert callable(oid_schema.write)
            # ObjectClass methods
            assert callable(oid_schema.can_handle_objectclass)

        def test_parse_returns_flext_result(
            self,
            oid_schema: FlextLdifServersOid.Schema,
        ) -> None:
            """Test parse method returns FlextResult."""
            result = oid_schema.parse(
                "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
            )
            assert isinstance(result, FlextResult)

        def test_can_handle_returns_bool(
            self,
            oid_schema: FlextLdifServersOid.Schema,
        ) -> None:
            """Test can_handle methods return bool."""
            attr_result = oid_schema.can_handle_attribute("( 2.5.4.3 NAME 'cn' )")
            assert isinstance(attr_result, bool)

            oc_result = oid_schema.can_handle_objectclass(
                "( 2.5.6.0 NAME 'top' ABSTRACT )"
            )
            assert isinstance(oc_result, bool)

    class QuirkRegistry:
        """Test QuirkRegistry protocol implementation."""

        @pytest.fixture
        def registry(self) -> FlextLdifServer:
            """Create quirk registry instance."""
            return FlextLdifServer()

        def test_registry_has_retrieval_methods(
            self,
            registry: FlextLdifServer,
        ) -> None:
            """Test registry has required retrieval methods."""
            assert callable(registry.schema)
            assert callable(registry.acl)
            assert callable(registry.entry)
            assert callable(registry.find_schema_for_attribute)
            assert callable(registry.find_schema_for_objectclass)

        def test_registry_schema_retrieval(
            self,
            registry: FlextLdifServer,
        ) -> None:
            """Test registry can retrieve schema quirks."""
            result = registry.schema("oid")
            # Returns quirk instance or None
            assert result is None or hasattr(result, "parse")

        def test_registry_global_instance(self) -> None:
            """Test registry global instance is accessible."""
            instance = FlextLdifServer.get_global_instance()
            assert instance is not None

    class ProtocolUsage:
        """Test common protocol usage patterns."""

        def test_protocol_type_checking(self) -> None:
            """Test protocol can be used for type checking."""
            oid_schema: object = FlextLdifServersOid.Schema()
            # Protocol satisfied via structural typing
            is_schema = hasattr(oid_schema, "parse") and hasattr(oid_schema, "write")
            assert is_schema

        def test_protocol_filtering(self) -> None:
            """Test filtering implementations by protocol."""
            schemas_list: list[object] = [
                FlextLdifServersOid.Schema(),
                FlextLdifServersOud.Schema(),
                FlextLdifServersOpenldap.Schema(),
            ]
            schemas = [
                s for s in schemas_list if hasattr(s, "parse") and hasattr(s, "write")
            ]
            assert len(schemas) == 3

        def test_protocol_method_calls(self) -> None:
            """Test calling protocol methods on implementations."""
            schema = FlextLdifServersOid.Schema()

            # Test can_handle_attribute
            result = schema.can_handle_attribute("( 2.5.4.3 NAME 'cn' )")
            assert isinstance(result, bool)

            # Test parse
            parse_result = schema.parse("( 2.5.4.3 NAME 'cn' )")
            assert hasattr(parse_result, "is_success")


__all__ = [
    "ProtocolNames",
    "ProtocolServer",
    "ServerTypes",
    "TestFlextLdifProtocols",
]
