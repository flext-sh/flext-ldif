from __future__ import annotations

import dataclasses
from enum import StrEnum
from typing import ClassVar

import pytest
from flext_core import FlextResult
from tests import s

from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.openldap import FlextLdifServersOpenldap
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.servers.relaxed import FlextLdifServersRelaxed
from flext_ldif.services.server import FlextLdifServer


def _create_server_implementations() -> list[tuple[str, type, type]]:
    """Create server implementations for testing."""
    return [
        ("OID", FlextLdifServersOid, FlextLdifServersOid.Schema),
        ("OUD", FlextLdifServersOud, FlextLdifServersOud.Schema),
        ("OpenLDAP", FlextLdifServersOpenldap, FlextLdifServersOpenldap.Schema),
        ("Relaxed", FlextLdifServersRelaxed, FlextLdifServersRelaxed.Schema),
    ]


class TestsTestFlextLdifProtocols(s):
    """Test suite for FlextLdifProtocols protocol definitions.

    Uses nested classes for organization: ProtocolNames, ServerTypes, TestCase,
    Constants, Helpers, and test method groups.
    """

    class ProtocolNames(StrEnum):
        """Protocol names in FlextLdifProtocols.Quirks namespace organized as nested enum."""

        __test__ = False

        SCHEMA = "SchemaProtocol"
        ACL = "AclProtocol"
        ENTRY = "EntryProtocol"
        QUIRKS_PORT = "QuirksPort"

    # Protocol names list for parametrization (defined after enum)
    # Use list() to iterate over enum members
    _PROTOCOL_NAMES: ClassVar[list[str]] = [
        ProtocolNames.SCHEMA.value,
        ProtocolNames.ACL.value,
        ProtocolNames.ENTRY.value,
        ProtocolNames.QUIRKS_PORT.value,
    ]

    class ServerTypes(StrEnum):
        """Server types implementing schema protocol organized as nested enum."""

        __test__ = False

        OID = "oid"
        OUD = "oud"
        OPENLDAP = "openldap"
        RELAXED = "relaxed"

    @dataclasses.dataclass(frozen=True)
    class ProtocolServer:
        """Server implementation for schema protocol testing organized as nested dataclass."""

        __test__ = False

        name: str
        server_class: type
        schema_class: type

    class Constants:
        """Test constants organized as nested class."""

        NAMESPACE_QUIRKS: str = "Quirks"
        ATTR_PARSE: str = "parse"
        ATTR_WRITE: str = "write"
        ATTR_SERVER_TYPE: str = "server_type"
        ATTR_PRIORITY: str = "priority"
        ATTR_CAN_HANDLE_ATTRIBUTE: str = "can_handle_attribute"
        ATTR_CAN_HANDLE_OBJECTCLASS: str = "can_handle_objectclass"
        ATTR_SCHEMA: str = "schema"
        ATTR_ACL: str = "acl"
        ATTR_ENTRY: str = "entry"
        ATTR_IS_SUCCESS: str = "is_success"
        SAMPLE_ATTR_DEF: str = (
            "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        SAMPLE_ATTR_DEF_SIMPLE: str = "( 2.5.4.3 NAME 'cn' )"
        SAMPLE_OC_DEF: str = "( 2.5.6.0 NAME 'top' ABSTRACT )"

    class Helpers:
        """Helper methods organized as nested class."""

        @staticmethod
        def verify_protocol_methods(schema: object) -> None:
            """Verify schema has all required protocol methods."""
            assert hasattr(schema, TestFlextLdifProtocols.Constants.ATTR_PARSE)
            assert callable(
                getattr(schema, TestFlextLdifProtocols.Constants.ATTR_PARSE),
            )
            assert hasattr(schema, TestFlextLdifProtocols.Constants.ATTR_WRITE)
            assert callable(
                getattr(schema, TestFlextLdifProtocols.Constants.ATTR_WRITE),
            )
            assert hasattr(
                schema,
                TestFlextLdifProtocols.Constants.ATTR_CAN_HANDLE_ATTRIBUTE,
            )
            assert callable(
                getattr(
                    schema,
                    TestFlextLdifProtocols.Constants.ATTR_CAN_HANDLE_ATTRIBUTE,
                ),
            )
            assert hasattr(
                schema,
                TestFlextLdifProtocols.Constants.ATTR_CAN_HANDLE_OBJECTCLASS,
            )
            assert callable(
                getattr(
                    schema,
                    TestFlextLdifProtocols.Constants.ATTR_CAN_HANDLE_OBJECTCLASS,
                ),
            )

        @staticmethod
        def verify_server_attributes(server: object) -> None:
            """Verify server has protocol attributes via Constants class.

            Server implementations store SERVER_TYPE and PRIORITY in nested Constants class,
            not as direct instance attributes.
            """
            # Check for Constants class
            assert hasattr(server, "Constants")
            # Type narrowing: server has Constants attribute
            # Use getattr for type safety
            constants_cls = server.Constants

            # SERVER_TYPE in Constants
            assert hasattr(constants_cls, "SERVER_TYPE")
            server_type = constants_cls.SERVER_TYPE
            assert isinstance(server_type, str) or hasattr(server_type, "value")

            # PRIORITY in Constants
            assert hasattr(constants_cls, "PRIORITY")
            priority = constants_cls.PRIORITY
            assert isinstance(priority, int)

        @staticmethod
        def verify_registry_methods(registry: object) -> None:
            """Verify registry has required retrieval methods."""
            methods = [
                TestFlextLdifProtocols.Constants.ATTR_SCHEMA,
                TestFlextLdifProtocols.Constants.ATTR_ACL,
                TestFlextLdifProtocols.Constants.ATTR_ENTRY,
            ]
            for method in methods:
                assert hasattr(registry, method)
                assert callable(getattr(registry, method))

    @classmethod
    def get_server_implementations(cls) -> list[ProtocolServer]:
        """Get all server implementations for testing."""
        return [
            cls.ProtocolServer(
                name=name,
                server_class=server_class,
                schema_class=schema_class,
            )
            for name, server_class, schema_class in _create_server_implementations()
        ]

    @pytest.mark.parametrize(
        "protocol_name",
        _PROTOCOL_NAMES,
    )
    def test_protocol_is_defined(self, protocol_name: str) -> None:
        """Test that protocol is defined and accessible."""
        assert hasattr(FlextLdifProtocols.Quirks, protocol_name)
        protocol = getattr(FlextLdifProtocols.Quirks, protocol_name)
        assert protocol is not None

    def test_quirks_namespace_exists(self) -> None:
        """Test that Quirks namespace exists."""
        assert hasattr(FlextLdifProtocols, self.Constants.NAMESPACE_QUIRKS)

    @pytest.mark.parametrize(
        "protocol_name",
        _PROTOCOL_NAMES,
    )
    def test_protocol_in_namespace(self, protocol_name: str) -> None:
        """Test that protocol exists in Quirks namespace."""
        assert hasattr(FlextLdifProtocols.Quirks, protocol_name)

    def test_schema_satisfies_protocol_oid(self) -> None:
        """Test that OID schema satisfies SchemaProtocol."""
        schema: object = FlextLdifServersOid.Schema()
        self.Helpers.verify_protocol_methods(schema)

    def test_schema_satisfies_protocol_oud(self) -> None:
        """Test that OUD schema satisfies SchemaProtocol."""
        schema: object = FlextLdifServersOud.Schema()
        self.Helpers.verify_protocol_methods(schema)

    def test_schema_satisfies_protocol_openldap(self) -> None:
        """Test that OpenLDAP schema satisfies SchemaProtocol."""
        schema: object = FlextLdifServersOpenldap.Schema()
        self.Helpers.verify_protocol_methods(schema)

    def test_schema_satisfies_protocol_relaxed(self) -> None:
        """Test that Relaxed schema satisfies SchemaProtocol."""
        schema: object = FlextLdifServersRelaxed.Schema()
        self.Helpers.verify_protocol_methods(schema)

    def test_server_has_protocol_attributes_oid(self) -> None:
        """Test that OID server class has protocol attributes in Constants."""
        self.Helpers.verify_server_attributes(FlextLdifServersOid)

    def test_server_has_protocol_attributes_oud(self) -> None:
        """Test that OUD server class has protocol attributes in Constants."""
        self.Helpers.verify_server_attributes(FlextLdifServersOud)

    def test_server_has_protocol_attributes_openldap(self) -> None:
        """Test that OpenLDAP server class has protocol attributes in Constants."""
        self.Helpers.verify_server_attributes(FlextLdifServersOpenldap)

    def test_server_has_protocol_attributes_relaxed(self) -> None:
        """Test that Relaxed server class has protocol attributes in Constants."""
        self.Helpers.verify_server_attributes(FlextLdifServersRelaxed)

    oid_schema: ClassVar[FlextLdifServersOid.Schema]  # pytest fixture

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID Schema instance."""
        return FlextLdifServersOid.Schema()

    def test_schema_has_required_methods(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test schema has all required protocol methods."""
        self.Helpers.verify_protocol_methods(oid_schema)

    def test_parse_returns_flext_result(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test parse method returns FlextResult."""
        result = oid_schema.parse(self.Constants.SAMPLE_ATTR_DEF)
        assert isinstance(result, FlextResult)

    def test_can_handle_returns_bool(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test can_handle methods return bool."""
        attr_result = oid_schema.can_handle_attribute(
            self.Constants.SAMPLE_ATTR_DEF_SIMPLE,
        )
        assert isinstance(attr_result, bool)

        oc_result = oid_schema.can_handle_objectclass(self.Constants.SAMPLE_OC_DEF)
        assert isinstance(oc_result, bool)

    @pytest.fixture
    def registry(self) -> FlextLdifServer:
        """Create quirk registry instance."""
        return FlextLdifServer()

    def test_registry_has_retrieval_methods(
        self,
        registry: FlextLdifServer,
    ) -> None:
        """Test registry has required retrieval methods."""
        self.Helpers.verify_registry_methods(registry)

    def test_registry_schema_retrieval(
        self,
        registry: FlextLdifServer,
    ) -> None:
        """Test registry can retrieve schema quirks."""
        result = registry.schema(self.ServerTypes.OID)
        # Returns quirk instance or None
        assert result is None or hasattr(result, self.Constants.ATTR_PARSE)

    def test_registry_global_instance(self) -> None:
        """Test registry global instance is accessible."""
        instance = FlextLdifServer.get_global_instance()
        assert instance is not None

    def test_protocol_type_checking(self) -> None:
        """Test protocol can be used for type checking."""
        oid_schema: object = FlextLdifServersOid.Schema()
        # Protocol satisfied via structural typing
        is_schema = hasattr(oid_schema, self.Constants.ATTR_PARSE) and hasattr(
            oid_schema,
            self.Constants.ATTR_WRITE,
        )
        assert is_schema

    def test_protocol_filtering(self) -> None:
        """Test filtering implementations by protocol."""
        schemas_list: list[object] = [
            FlextLdifServersOid.Schema(),
            FlextLdifServersOud.Schema(),
            FlextLdifServersOpenldap.Schema(),
        ]
        schemas = [
            s
            for s in schemas_list
            if hasattr(s, self.Constants.ATTR_PARSE)
            and hasattr(s, self.Constants.ATTR_WRITE)
        ]
        assert len(schemas) == 3

    def test_protocol_method_calls(self) -> None:
        """Test calling protocol methods on implementations."""
        schema = FlextLdifServersOid.Schema()

        # Test can_handle_attribute
        result = schema.can_handle_attribute(self.Constants.SAMPLE_ATTR_DEF_SIMPLE)
        assert isinstance(result, bool)

        # Test parse
        parse_result = schema.parse(self.Constants.SAMPLE_ATTR_DEF_SIMPLE)
        assert hasattr(parse_result, self.Constants.ATTR_IS_SUCCESS)
