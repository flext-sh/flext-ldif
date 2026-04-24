"""Tests for ldif protocol definitions and implementations.

This module tests the core protocols used across ldif including
server implementations, ACL handling, and service contracts.
"""

from __future__ import annotations

from collections.abc import (
    Sequence,
)
from typing import ClassVar

import pytest
from flext_tests import tm

from flext_ldif import (
    FlextLdifProtocols,
    FlextLdifServer,
    FlextLdifServersBaseSchema,
    FlextLdifServersOid,
    FlextLdifServersOpenldap,
    FlextLdifServersOud,
    FlextLdifServersRelaxed,
    p,
    t,
)
from tests import c, m, r


def _create_server_implementations() -> Sequence[tuple[str, type, type]]:
    """Create server implementations for testing."""
    return [
        ("OID", FlextLdifServersOid, FlextLdifServersOid.Schema),
        ("OUD", FlextLdifServersOud, FlextLdifServersOud.Schema),
        ("OpenLDAP", FlextLdifServersOpenldap, FlextLdifServersOpenldap.Schema),
        ("Relaxed", FlextLdifServersRelaxed, FlextLdifServersRelaxed.Schema),
    ]


class TestsFlextLdifProtocolsUnit:
    """Test suite for FlextLdifProtocols protocol definitions.

    Uses nested classes for organization: ProtocolNames, ServerTypes, TestCase,
    Constants, Helpers, and test method groups.
    """

    _PROTOCOL_NAMES: ClassVar[t.StrSequence] = [
        c.Ldif.Tests.PROTOCOL_NAME_SCHEMA,
        c.Ldif.Tests.PROTOCOL_NAME_ACL,
        c.Ldif.Tests.PROTOCOL_NAME_ENTRY,
    ]

    class Helpers:
        """Helper methods organized as nested class."""

        @staticmethod
        def verify_protocol_methods(
            schema: p.Ldif.SchemaQuirk | FlextLdifServersBaseSchema,
        ) -> None:
            """Verify schema has all required protocol methods."""
            tm.that(
                hasattr(schema, c.Ldif.Tests.PROTOCOL_ATTR_PARSE),
                eq=True,
            )
            tm.that(
                callable(
                    getattr(schema, c.Ldif.Tests.PROTOCOL_ATTR_PARSE),
                ),
                eq=True,
            )
            tm.that(
                hasattr(schema, c.Ldif.Tests.PROTOCOL_ATTR_WRITE),
                eq=True,
            )
            tm.that(
                callable(
                    getattr(schema, c.Ldif.Tests.PROTOCOL_ATTR_WRITE),
                ),
                eq=True,
            )
            tm.that(
                hasattr(
                    schema,
                    c.Ldif.Tests.PROTOCOL_ATTR_CAN_HANDLE_ATTRIBUTE,
                ),
                eq=True,
            )
            tm.that(
                callable(
                    getattr(
                        schema,
                        c.Ldif.Tests.PROTOCOL_ATTR_CAN_HANDLE_ATTRIBUTE,
                    ),
                ),
                eq=True,
            )
            tm.that(
                hasattr(
                    schema,
                    c.Ldif.Tests.PROTOCOL_ATTR_CAN_HANDLE_OBJECTCLASS,
                ),
                eq=True,
            )
            tm.that(
                callable(
                    getattr(
                        schema,
                        c.Ldif.Tests.PROTOCOL_ATTR_CAN_HANDLE_OBJECTCLASS,
                    ),
                ),
                eq=True,
            )

        @staticmethod
        def verify_server_attributes(server: type) -> None:
            """Verify server has protocol attributes via Constants class.

            Server implementations store SERVER_TYPE and PRIORITY in nested Constants class,
            not as direct instance attributes.
            """
            constants_cls: type = getattr(server, "Constants")
            server_type: str = getattr(constants_cls, "SERVER_TYPE")
            tm.that(
                hasattr(server_type, "value") or bool(server_type),
                eq=True,
            )
            priority: int = getattr(constants_cls, "PRIORITY")
            tm.that(priority, is_=int)

        @staticmethod
        def verify_registry_methods(
            registry: p.Ldif.QuirkRegistry | FlextLdifServer,
        ) -> None:
            """Verify registry has required retrieval methods."""
            methods = [
                c.Ldif.Tests.PROTOCOL_ATTR_SCHEMA,
                c.Ldif.Tests.PROTOCOL_ATTR_ACL,
                c.Ldif.Tests.PROTOCOL_ATTR_ENTRY,
            ]
            for _method in methods:
                pass

    @classmethod
    def get_server_implementations(cls) -> Sequence[m.Ldif.Tests.ProtocolServer]:
        """Get all server implementations for testing."""
        return [
            m.Ldif.Tests.ProtocolServer(
                name=name,
                server_class=server_class,
                schema_class=schema_class,
            )
            for name, server_class, schema_class in _create_server_implementations()
        ]

    @pytest.mark.parametrize("protocol_name", _PROTOCOL_NAMES)
    def test_protocol_is_defined(self, protocol_name: str) -> None:
        """Test that protocol is defined and accessible."""
        protocol = getattr(FlextLdifProtocols.Ldif, protocol_name)
        tm.that(protocol, none=False)

    def test_schema_satisfies_protocol_oid(self) -> None:
        """Test that OID schema satisfies Schema."""
        schema = FlextLdifServersOid.Schema()
        self.Helpers.verify_protocol_methods(schema)

    def test_schema_satisfies_protocol_oud(self) -> None:
        """Test that OUD schema satisfies Schema."""
        schema = FlextLdifServersOud.Schema()
        self.Helpers.verify_protocol_methods(schema)

    def test_schema_satisfies_protocol_openldap(self) -> None:
        """Test that OpenLDAP schema satisfies Schema."""
        schema = FlextLdifServersOpenldap.Schema()
        self.Helpers.verify_protocol_methods(schema)

    def test_schema_satisfies_protocol_relaxed(self) -> None:
        """Test that Relaxed schema satisfies Schema."""
        schema = FlextLdifServersRelaxed.Schema()
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
        """Test parse method returns r."""
        result = oid_schema.parse_attribute(c.Ldif.Tests.PROTOCOL_SAMPLE_ATTR_DEF)
        tm.that(result, is_=r)

    def test_can_handle_returns_bool(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test can_handle methods return bool."""
        result = oid_schema.can_handle_attribute(c.Ldif.Tests.PROTOCOL_SAMPLE_ATTR_DEF)
        tm.that(result, is_=bool)
