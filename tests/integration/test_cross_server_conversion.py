"""Cross-server conversion integration tests.

Behavioral contract for translating LDAP schema and ACL models between server
dialects (OID <-> RFC <-> OUD). Every assertion targets observable public
behavior: the ``r[T]`` outcome of a fallible operation, the public field state
of the returned Pydantic models, and the rendered LDIF text — never private
attributes, internal collaborators, or line-coverage pokes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flext_tests import tm
from tests import c, m

if TYPE_CHECKING:
    from flext_ldif.servers.base import FlextLdifServersBase
    from flext_ldif.services.conversion import FlextLdifConversion
    from tests import p, t


class TestsFlextLdifCrossServerConversion:
    """Behavioral tests for cross-server schema/ACL conversion.

    Fixtures (from tests/unit/fixtures.py):
    - oid_server / oud_server: full server facades
    - oid_schema_server / oud_schema_server: schema sub-servers
    - oid_acl_server / oud_acl_server: ACL sub-servers
    - conversion_matrix: FlextLdifConversion facade
    - oid_schema_fixture: raw OID schema LDIF text
    """

    def test_oid_attribute_roundtrips_through_rfc_to_oud_preserving_identity(
        self,
        oid_schema_server: p.Ldif.SchemaServer,
        oud_schema_server: p.Ldif.SchemaServer,
    ) -> None:
        """Parsing an OID attribute, rendering it, then parsing with OUD keeps oid/name/syntax."""
        parse_result = oid_schema_server.parse_server(
            c.Tests.CROSS_SERVER_OID_ATTRIBUTE_ORCLGUID
        )
        tm.ok(parse_result)
        source = parse_result.value
        assert isinstance(source, m.Ldif.SchemaAttribute)
        tm.that(source.oid, eq="2.16.840.1.113894.1.1.1")
        tm.that(source.name, eq="orclguid")

        rfc_result = oid_schema_server.write(source)
        tm.ok(rfc_result)

        oud_parse_result = oud_schema_server.parse_server(rfc_result.value)
        tm.ok(oud_parse_result)
        target = oud_parse_result.value
        assert isinstance(target, m.Ldif.SchemaAttribute)
        tm.that(target.oid, eq=source.oid)
        tm.that(target.name, eq=source.name)
        tm.that(target.syntax, eq=source.syntax)

    def test_oid_objectclass_roundtrips_through_rfc_to_oud_preserving_identity(
        self,
        oid_schema_server: p.Ldif.SchemaServer,
        oud_schema_server: p.Ldif.SchemaServer,
    ) -> None:
        """Parsing an OID objectClass, rendering it, then parsing with OUD keeps oid/name/kind/sup."""
        parse_result = oid_schema_server.parse_server(
            c.Tests.CROSS_SERVER_OID_OBJECTCLASS_ORCLCONTAINER
        )
        tm.ok(parse_result)
        source = parse_result.value
        assert isinstance(source, m.Ldif.SchemaObjectClass)
        tm.that(source.oid, eq="2.16.840.1.113894.2.1.1")
        tm.that(source.name, eq="orclContainer")
        tm.that(source.kind, eq="STRUCTURAL")

        rfc_result = oid_schema_server.write(source)
        tm.ok(rfc_result)

        oud_parse_result = oud_schema_server.parse_server(rfc_result.value)
        tm.ok(oud_parse_result)
        target = oud_parse_result.value
        assert isinstance(target, m.Ldif.SchemaObjectClass)
        tm.that(target.oid, eq=source.oid)
        tm.that(target.name, eq=source.name)
        tm.that(target.kind, eq=source.kind)
        tm.that(target.sup, eq=source.sup)

    def test_oid_acl_parses_into_acl_model_with_oid_server_type(
        self, oid_acl_server: p.Ldif.AclServer
    ) -> None:
        """An OID orclaci string parses into an Acl model tagged as an OID dialect."""
        parse_result = oid_acl_server.parse_server(
            c.Tests.CROSS_SERVER_OID_ACL_ANONYMOUS
        )
        tm.ok(parse_result)
        parsed = parse_result.value
        assert isinstance(parsed, m.Ldif.Acl)
        tm.that({"oid", "oracle_oid"}, has=parsed.server_type)

    def test_oud_acl_parses_and_rewrites_to_text(
        self, oud_acl_server: p.Ldif.AclServer
    ) -> None:
        """An OUD aci string parses into an Acl model and re-renders to LDIF text."""
        parse_result = oud_acl_server.parse_server(
            c.Tests.CROSS_SERVER_OUD_ACI_ANONYMOUS
        )
        tm.ok(parse_result)
        parsed = parse_result.value
        assert isinstance(parsed, m.Ldif.Acl)
        tm.that({"oud", "rfc", "generic"}, has=parsed.server_type)

        write_result = oud_acl_server.write(parsed)
        tm.ok(write_result)
        tm.that(write_result.value, is_=str)
        assert write_result.value

    def test_convert_model_translates_oid_acl_to_rfc_dialect(
        self, conversion_matrix: FlextLdifConversion, oid_acl_server: p.Ldif.AclServer
    ) -> None:
        """convert_model(OID->RFC) yields an Acl retagged to RFC with a rendered raw_acl."""
        parse_result = oid_acl_server.parse_server(
            c.Tests.CROSS_SERVER_OID_ACL_ANONYMOUS
        )
        tm.ok(parse_result)
        assert isinstance(parse_result.value, m.Ldif.Acl)

        result = conversion_matrix.convert_model(
            c.Tests.OID, c.Tests.RFC, parse_result.value
        )
        tm.ok(result)
        converted = result.value
        assert isinstance(converted, m.Ldif.Acl)
        tm.that(converted.server_type, eq=c.Tests.RFC)
        tm.that(converted.raw_acl, none=False)

    # Iterates every Oracle attribute in the OID fixture through a full
    # parse->write->parse schema round-trip: ~18s of real CPU work (profiled),
    # exceeding the global --timeout=10 under load. Per-test ceiling, not a
    # suppression of a hang (proven to complete in 18s with timeout raised).
    @pytest.mark.timeout(60)
    def test_oid_schema_fixture_oracle_attributes_convert_to_oud_preserving_identity(
        self,
        oid_schema_server: p.Ldif.SchemaServer,
        oud_schema_server: p.Ldif.SchemaServer,
        oid_schema_fixture: str,
    ) -> None:
        """Every parseable Oracle attribute in the OID fixture round-trips to OUD with oid/name intact."""
        oracle_attr_defs = [
            line.split(":", 1)[1].strip()
            for line in oid_schema_fixture.split("\n")
            if "attributetypes:" in line.lower() and "2.16.840.1.113894" in line
        ]
        assert oracle_attr_defs, "No Oracle attributes found in OID fixture"

        converted_any = False
        for attr_def in oracle_attr_defs:
            parse_result = oid_schema_server.parse_server(attr_def)
            if parse_result.failure:
                continue
            source = parse_result.value
            rfc_result = oid_schema_server.write(source)
            tm.ok(rfc_result)
            oud_result = oud_schema_server.parse_server(rfc_result.value)
            tm.ok(oud_result)
            target = oud_result.value
            tm.that(target.oid, eq=source.oid)
            tm.that(target.name, eq=source.name)
            converted_any = True
        assert converted_any, (
            "No Oracle attribute survived the OID->RFC->OUD round-trip"
        )

    def test_conversion_matrix_is_available(
        self, conversion_matrix: FlextLdifConversion
    ) -> None:
        """The conversion facade fixture resolves to a usable instance."""
        tm.that(conversion_matrix, none=False)

    def test_resolve_supported_conversions_reports_all_model_kinds(
        self, conversion_matrix: FlextLdifConversion, oud_server: FlextLdifServersBase
    ) -> None:
        """A full-featured server advertises support for every convertible model kind."""
        supported = conversion_matrix.resolve_supported_conversions(oud_server)
        tm.that(supported["attribute"], eq=True)
        tm.that(supported["objectClass"], eq=True)
        tm.that(supported["acl"], eq=True)
        tm.that(supported["entry"], eq=True)

    def test_attribute_converts_oud_to_oid_rendering_oracle_identity(
        self, oud_server: FlextLdifServersBase, oid_server: FlextLdifServersBase
    ) -> None:
        """OUD attribute -> RFC -> OID renders back to OID text carrying the Oracle oid and name."""
        parsed = oud_server.schema_server.parse_attribute(
            c.Tests.CROSS_SERVER_OUD_ATTRIBUTE_ORCLGUID
        )
        tm.ok(parsed)
        rfc_text = oud_server.schema_server.write(parsed.value)
        tm.ok(rfc_text)

        oid_parsed = oid_server.schema_server.parse_attribute(rfc_text.value)
        tm.ok(oid_parsed)
        oid_text = oid_server.schema_server.write(oid_parsed.value)
        tm.ok(oid_text)
        tm.that(oid_text.value, has="2.16.840.1.113894.1.1.1")
        tm.that(oid_text.value, has="orclGUID")

    def test_objectclass_converts_oid_to_oud_rendering_oracle_identity(
        self, oud_server: FlextLdifServersBase, oid_server: FlextLdifServersBase
    ) -> None:
        """OID objectClass -> RFC -> OUD renders back to OUD text carrying the Oracle oid and name."""
        parsed = oid_server.schema_server.parse_objectclass(
            c.Tests.CROSS_SERVER_OID_OBJECTCLASS_ORCLCONTEXT
        )
        tm.ok(parsed)
        rfc_text = oid_server.schema_server.write(parsed.value)
        tm.ok(rfc_text)

        oud_parsed = oud_server.schema_server.parse_objectclass(rfc_text.value)
        tm.ok(oud_parsed)
        oud_text = oud_server.schema_server.write(oud_parsed.value)
        tm.ok(oud_text)
        tm.that(oud_text.value, has="2.16.840.1.113894.1.2.1")
        tm.that(oud_text.value, has="orclContext")

    def test_batch_attribute_conversion_preserves_each_attribute_name(
        self, oud_server: FlextLdifServersBase, oid_server: FlextLdifServersBase
    ) -> None:
        """Converting a batch of OUD attributes to OID preserves each distinct attribute name."""
        oud_attr_strings: t.SequenceOf[str] = [
            c.Tests.CROSS_SERVER_OUD_ATTRIBUTE_ORCLGUID,
            (
                "( 2.16.840.1.113894.1.1.2 NAME 'orclDBName' "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
            ),
        ]
        oid_rendered: t.MutableSequenceOf[str] = []
        for attr_string in oud_attr_strings:
            oud_parsed = oud_server.schema_server.parse_attribute(attr_string)
            tm.ok(oud_parsed)
            rfc_text = oud_server.schema_server.write(oud_parsed.value)
            tm.ok(rfc_text)
            oid_parsed = oid_server.schema_server.parse_attribute(rfc_text.value)
            tm.ok(oid_parsed)
            oid_text = oid_server.schema_server.write(oid_parsed.value)
            tm.ok(oid_text)
            oid_rendered.append(oid_text.value)

        tm.that(len(oid_rendered), eq=2)
        tm.that(oid_rendered[0], has="orclGUID")
        tm.that(oid_rendered[1], has="orclDBName")

    def test_attribute_survives_full_bidirectional_roundtrip(
        self, oud_server: FlextLdifServersBase, oid_server: FlextLdifServersBase
    ) -> None:
        """OUD->RFC->OID->RFC->OUD keeps the Oracle oid and name in the final rendered text."""
        rendered = c.Tests.CROSS_SERVER_OUD_ATTRIBUTE_ORCLGUID
        servers = (
            oud_server.schema_server,
            oid_server.schema_server,
            oud_server.schema_server,
        )
        for schema_server in servers:
            parsed = schema_server.parse_attribute(rendered)
            tm.ok(parsed)
            written = schema_server.write(parsed.value)
            tm.ok(written)
            rendered = written.value

        tm.that(rendered, has="2.16.840.1.113894.1.1.1")
        tm.that(rendered, has="orclGUID")

    def test_convert_model_fails_for_structurally_invalid_entry(
        self,
        conversion_matrix: FlextLdifConversion,
        oud_server: FlextLdifServersBase,
        oid_server: FlextLdifServersBase,
    ) -> None:
        """Converting an entry with null dn/attributes yields a failure result with an error message."""
        invalid_model = m.Ldif.Entry(dn=None, attributes=None)
        result = conversion_matrix.convert_model(oud_server, oid_server, invalid_model)
        tm.fail(result)
        tm.that(result.error, none=False)
        tm.that(result.error, ne="")


__all__: list[str] = ["TestsFlextLdifCrossServerConversion"]
