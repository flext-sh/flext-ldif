"""Tests for FlextLdif protocol definitions and implementations.

This module tests the core protocols used across FlextLdif including
server implementations, ACL handling, and service contracts.
"""

from __future__ import annotations

from enum import StrEnum, unique
from typing import ClassVar

import pytest
from flext_core import r
from pydantic import BaseModel, ConfigDict, Field

from flext_ldif import FlextLdifProtocols, FlextLdifServer, p
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.openldap import FlextLdifServersOpenldap
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.servers.relaxed import FlextLdifServersRelaxed
from tests import s, u


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

    @unique
    class ProtocolNames(StrEnum):
        """Protocol names in FlextLdifProtocols.Ldif namespace organized as nested enum."""

        __test__ = False
        SCHEMA = "SchemaQuirk"
        ACL = "AclQuirk"
        ENTRY = "EntryQuirk"

    _PROTOCOL_NAMES: ClassVar[list[str]] = [
        ProtocolNames.SCHEMA.value,
        ProtocolNames.ACL.value,
        ProtocolNames.ENTRY.value,
    ]

    @unique
    class ServerTypes(StrEnum):
        """Server types implementing schema protocol organized as nested enum."""

        __test__ = False
        OID = "oid"
        OUD = "oud"
        OPENLDAP = "openldap"
        RELAXED = "relaxed"

    class ProtocolServer(BaseModel):
        """Server implementation for schema protocol testing."""

        __test__ = False
        model_config = ConfigDict(frozen=True)

        name: str = Field(description="Protocol server implementation name")
        server_class: type = Field(description="Server implementation class")
        schema_class: type = Field(description="Schema implementation class")

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
        def verify_protocol_methods(schema: p.Ldif.SchemaQuirk) -> None:
            """Verify schema has all required protocol methods."""
            u.Tests.Matchers.that(
                hasattr(schema, TestsTestFlextLdifProtocols.Constants.ATTR_PARSE),
                eq=True,
            )
            u.Tests.Matchers.that(
                callable(
                    getattr(schema, TestsTestFlextLdifProtocols.Constants.ATTR_PARSE)
                ),
                eq=True,
            )
            u.Tests.Matchers.that(
                hasattr(schema, TestsTestFlextLdifProtocols.Constants.ATTR_WRITE),
                eq=True,
            )
            u.Tests.Matchers.that(
                callable(
                    getattr(schema, TestsTestFlextLdifProtocols.Constants.ATTR_WRITE)
                ),
                eq=True,
            )
            u.Tests.Matchers.that(
                hasattr(
                    schema,
                    TestsTestFlextLdifProtocols.Constants.ATTR_CAN_HANDLE_ATTRIBUTE,
                ),
                eq=True,
            )
            u.Tests.Matchers.that(
                callable(
                    getattr(
                        schema,
                        TestsTestFlextLdifProtocols.Constants.ATTR_CAN_HANDLE_ATTRIBUTE,
                    )
                ),
                eq=True,
            )
            u.Tests.Matchers.that(
                hasattr(
                    schema,
                    TestsTestFlextLdifProtocols.Constants.ATTR_CAN_HANDLE_OBJECTCLASS,
                ),
                eq=True,
            )
            u.Tests.Matchers.that(
                callable(
                    getattr(
                        schema,
                        TestsTestFlextLdifProtocols.Constants.ATTR_CAN_HANDLE_OBJECTCLASS,
                    )
                ),
                eq=True,
            )

        @staticmethod
        def verify_server_attributes(server: type) -> None:
            """Verify server has protocol attributes via Constants class.

            Server implementations store SERVER_TYPE and PRIORITY in nested Constants class,
            not as direct instance attributes.
            """
            u.Tests.Matchers.that(hasattr(server, "Constants"), eq=True)
            constants_cls = server.Constants
            u.Tests.Matchers.that(hasattr(constants_cls, "SERVER_TYPE"), eq=True)
            server_type = constants_cls.SERVER_TYPE
            u.Tests.Matchers.that(
                isinstance(server_type, str) or hasattr(server_type, "value"), eq=True
            )
            u.Tests.Matchers.that(hasattr(constants_cls, "PRIORITY"), eq=True)
            priority = constants_cls.PRIORITY
            u.Tests.Matchers.that(isinstance(priority, int), eq=True)

        @staticmethod
        def verify_registry_methods(registry: p.Ldif.QuirkRegistry) -> None:
            """Verify registry has required retrieval methods."""
            methods = [
                TestsTestFlextLdifProtocols.Constants.ATTR_SCHEMA,
                TestsTestFlextLdifProtocols.Constants.ATTR_ACL,
                TestsTestFlextLdifProtocols.Constants.ATTR_ENTRY,
            ]
            for method in methods:
                u.Tests.Matchers.that(hasattr(registry, method), eq=True)
                u.Tests.Matchers.that(callable(getattr(registry, method)), eq=True)

    @classmethod
    def get_server_implementations(cls) -> list[ProtocolServer]:
        """Get all server implementations for testing."""
        return [
            cls.ProtocolServer(
                name=name, server_class=server_class, schema_class=schema_class
            )
            for name, server_class, schema_class in _create_server_implementations()
        ]

    @pytest.mark.parametrize("protocol_name", _PROTOCOL_NAMES)
    def test_protocol_is_defined(self, protocol_name: str) -> None:
        """Test that protocol is defined and accessible."""
        u.Tests.Matchers.that(hasattr(FlextLdifProtocols.Ldif, protocol_name), eq=True)
        protocol = getattr(FlextLdifProtocols.Ldif, protocol_name)
        u.Tests.Matchers.that(protocol is not None, eq=True)

    def test_quirks_namespace_exists(self) -> None:
        """Test that Quirks namespace exists in Ldif namespace."""
        u.Tests.Matchers.that(
            hasattr(FlextLdifProtocols.Ldif, self.Constants.NAMESPACE_QUIRKS), eq=True
        )

    def test_schema_satisfies_protocol_oid(self) -> None:
        """Test that OID schema satisfies Schema."""
        schema: p.Ldif.SchemaQuirk = FlextLdifServersOid.Schema()
        self.Helpers.verify_protocol_methods(schema)

    def test_schema_satisfies_protocol_oud(self) -> None:
        """Test that OUD schema satisfies Schema."""
        schema: p.Ldif.SchemaQuirk = FlextLdifServersOud.Schema()
        self.Helpers.verify_protocol_methods(schema)

    def test_schema_satisfies_protocol_openldap(self) -> None:
        """Test that OpenLDAP schema satisfies Schema."""
        schema: p.Ldif.SchemaQuirk = FlextLdifServersOpenldap.Schema()
        self.Helpers.verify_protocol_methods(schema)

    def test_schema_satisfies_protocol_relaxed(self) -> None:
        """Test that Relaxed schema satisfies Schema."""
        schema: p.Ldif.SchemaQuirk = FlextLdifServersRelaxed.Schema()
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

    oid_schema: ClassVar[FlextLdifServersOid.Schema]

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID Schema instance."""
        return FlextLdifServersOid.Schema()

    def test_schema_has_required_methods(
        self, oid_schema: FlextLdifServersOid.Schema
    ) -> None:
        """Test schema has all required protocol methods."""
        self.Helpers.verify_protocol_methods(oid_schema)

    def test_parse_returns_flext_result(
        self, oid_schema: FlextLdifServersOid.Schema
    ) -> None:
        """Test parse method returns r."""
        result = oid_schema.parse(self.Constants.SAMPLE_ATTR_DEF)
        u.Tests.Matchers.that(isinstance(result, r), eq=True)

    def test_can_handle_returns_bool(
        self, oid_schema: FlextLdifServersOid.Schema
    ) -> None:
        """Test can_handle methods return bool."""
        attr_result = oid_schema.can_handle_attribute(
            self.Constants.SAMPLE_ATTR_DEF_SIMPLE
        )
        u.Tests.Matchers.that(isinstance(attr_result, bool), eq=True)
        oc_result = oid_schema.can_handle_objectclass(self.Constants.SAMPLE_OC_DEF)
        u.Tests.Matchers.that(isinstance(oc_result, bool), eq=True)

    registry: ClassVar[FlextLdifServer]

    @pytest.fixture
    def registry(self) -> FlextLdifServer:
        """Create quirk registry instance."""
        return FlextLdifServer()

    def test_registry_has_retrieval_methods(self, registry: FlextLdifServer) -> None:
        """Test registry has required retrieval methods."""
        self.Helpers.verify_registry_methods(registry)

    def test_registry_schema_retrieval(self, registry: FlextLdifServer) -> None:
        """Test registry can retrieve schema quirks."""
        result = registry.get_schema_quirk(self.ServerTypes.OID)
        u.Tests.Matchers.that(
            result is None or hasattr(result, self.Constants.ATTR_PARSE), eq=True
        )

    def test_registry_global_instance(self) -> None:
        """Test registry global instance is accessible."""
        instance = FlextLdifServer.get_global_instance()
        u.Tests.Matchers.that(instance is not None, eq=True)

    def test_protocol_type_checking(self) -> None:
        """Test protocol can be used for type checking."""
        oid_schema: p.Ldif.SchemaQuirk = FlextLdifServersOid.Schema()
        is_schema = hasattr(oid_schema, self.Constants.ATTR_PARSE) and hasattr(
            oid_schema, self.Constants.ATTR_WRITE
        )
        u.Tests.Matchers.that(is_schema, eq=True)

    def test_protocol_filtering(self) -> None:
        """Test filtering implementations by protocol."""
        schemas_list: list[p.Ldif.SchemaQuirk] = [
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
        u.Tests.Matchers.that(len(schemas) == 3, eq=True)

    def test_protocol_method_calls(self) -> None:
        """Test calling protocol methods on implementations."""
        schema = FlextLdifServersOid.Schema()
        result = schema.can_handle_attribute(self.Constants.SAMPLE_ATTR_DEF_SIMPLE)
        u.Tests.Matchers.that(isinstance(result, bool), eq=True)
        parse_result = schema.parse(self.Constants.SAMPLE_ATTR_DEF_SIMPLE)
        u.Tests.Matchers.that(
            hasattr(parse_result, self.Constants.ATTR_IS_SUCCESS), eq=True
        )
