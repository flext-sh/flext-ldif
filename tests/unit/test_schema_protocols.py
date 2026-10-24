"""Public schema contracts preserve parsed requirements and railway failures.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif import c, ldif, m, p


class TestsFlextLdifSchemaProtocols:
    """Exercise schema payloads through the public facade and protocol types."""

    @staticmethod
    @pytest.mark.parametrize(
        "server_type",
        [c.Ldif.ServerTypes.RFC, c.Ldif.ServerTypes.OID, c.Ldif.ServerTypes.OUD],
    )
    def test_schema_server_exposes_requirements(
        server_type: c.Ldif.ServerTypes,
    ) -> None:
        """The public parser exposes required and optional attributes directly."""
        server: p.Ldif.SchemaServer = ldif.schema_server(server_type).unwrap()
        tm.ok(isinstance(server, p.Ldif.SchemaServer))
        attribute: p.Ldif.SchemaAttribute = server.parse_attribute(
            "( 2.5.4.3 NAME 'cn' SUP name )"
        ).unwrap()
        tm.that(attribute.oid, eq="2.5.4.3")
        tm.that(attribute.name, eq="cn")
        definition = (
            "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL "
            "MUST ( sn $ cn ) MAY description )"
        )
        parsed = server.parse_objectclass(definition).unwrap()
        tm.ok(isinstance(parsed, p.Ldif.SchemaObjectClass))
        tm.that(parsed.sup, eq="top")
        tm.that(set(parsed.must or ()), eq={"sn", "cn"})
        tm.that(list(parsed.may or ()), eq=["description"])
        written = server.write_objectclass(parsed).unwrap()
        roundtrip: p.Ldif.SchemaObjectClass = server.parse_objectclass(written).unwrap()
        tm.that(roundtrip.oid, eq=parsed.oid)
        tm.that(roundtrip.sup, eq=parsed.sup)
        tm.that(roundtrip.must, eq=parsed.must)
        tm.that(roundtrip.may, eq=parsed.may)
        routed = server.parse_input(server.write(parsed).unwrap()).unwrap()
        tm.ok(isinstance(routed, p.Ldif.SchemaObjectClass))
        tm.that(routed.oid, eq=parsed.oid)
        tm.that(routed.name, eq=parsed.name)

    @staticmethod
    @pytest.mark.parametrize(
        "superiors",
        [None, "top", ["top", "person"]],
    )
    def test_objectclass_model_satisfies_readonly_contract(
        superiors: str | list[str] | None,
    ) -> None:
        """All model-supported superior shapes satisfy the same upstream contract."""
        payload: p.Ldif.SchemaObjectClass = m.Ldif.SchemaObjectClass(
            oid="1.3.6.1.4.1.55555.1",
            name="contractPerson",
            sup=superiors,
            must=None,
            may=None,
        )
        tm.ok(isinstance(payload, p.Ldif.SchemaObjectClass))
        tm.that(payload.sup, eq=superiors)
        tm.that(payload.must, none=True)
        tm.that(payload.may, none=True)

    @staticmethod
    @pytest.mark.parametrize("definition", ["", "NAME 'missingOid'"])
    def test_parse_routes_preserve_failure_details(definition: str) -> None:
        """Routing to a union result preserves the parser's error metadata."""
        server: p.Ldif.SchemaServer = ldif.schema_server(
            c.Ldif.ServerTypes.RFC
        ).unwrap()
        direct = server.parse_attribute(definition)
        routed = server.parse_server(definition)
        tm.ok(direct.failure)
        tm.ok(routed.failure)
        tm.that(routed.error, eq=direct.error)
        tm.that(routed.error_code, eq=direct.error_code)
        tm.that(routed.error_data, eq=direct.error_data)
        tm.that(type(routed.exception), eq=type(direct.exception))
