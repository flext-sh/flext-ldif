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

from tests.constants import c
from tests.models import m

if TYPE_CHECKING:
    from flext_ldif.servers.base import FlextLdifServersBase
    from flext_ldif.services.conversion import FlextLdifConversion
    from tests.protocols import p
    from tests.typings import t


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
            c.Tests.CROSS_SERVER_OID_ATTRIBUTE_ORCLGUID,
        )
        assert parse_result.success, f"OID parse failed: {parse_result.error}"
        source = parse_result.value
        assert isinstance(source, m.Ldif.SchemaAttribute)
        assert source.oid == "2.16.840.1.113894.1.1.1"
        assert source.name == "orclguid"

        rfc_result = oid_schema_server.write(source)
        assert rfc_result.success, f"OID write failed: {rfc_result.error}"

        oud_parse_result = oud_schema_server.parse_server(rfc_result.value)
        assert oud_parse_result.success, f"OUD parse failed: {oud_parse_result.error}"
        target = oud_parse_result.value
        assert isinstance(target, m.Ldif.SchemaAttribute)
        assert target.oid == source.oid
        assert target.name == source.name
        assert target.syntax == source.syntax

    def test_oid_objectclass_roundtrips_through_rfc_to_oud_preserving_identity(
        self,
        oid_schema_server: p.Ldif.SchemaServer,
        oud_schema_server: p.Ldif.SchemaServer,
    ) -> None:
        """Parsing an OID objectClass, rendering it, then parsing with OUD keeps oid/name/kind/sup."""
        parse_result = oid_schema_server.parse_server(
            c.Tests.CROSS_SERVER_OID_OBJECTCLASS_ORCLCONTAINER,
        )
        assert parse_result.success, f"OID parse failed: {parse_result.error}"
        source = parse_result.value
        assert isinstance(source, m.Ldif.SchemaObjectClass)
        assert source.oid == "2.16.840.1.113894.2.1.1"
        assert source.name == "orclContainer"
        assert source.kind == "STRUCTURAL"

        rfc_result = oid_schema_server.write(source)
        assert rfc_result.success, f"OID write failed: {rfc_result.error}"

        oud_parse_result = oud_schema_server.parse_server(rfc_result.value)
        assert oud_parse_result.success, f"OUD parse failed: {oud_parse_result.error}"
        target = oud_parse_result.value
        assert isinstance(target, m.Ldif.SchemaObjectClass)
        assert target.oid == source.oid
        assert target.name == source.name
        assert target.kind == source.kind
        assert target.sup == source.sup

    def test_oid_acl_parses_into_acl_model_with_oid_server_type(
        self,
        oid_acl_server: p.Ldif.AclServer,
    ) -> None:
        """An OID orclaci string parses into an Acl model tagged as an OID dialect."""
        parse_result = oid_acl_server.parse_server(
            c.Tests.CROSS_SERVER_OID_ACL_ANONYMOUS,
        )
        assert parse_result.success, f"OID ACL parse failed: {parse_result.error}"
        parsed = parse_result.value
        assert isinstance(parsed, m.Ldif.Acl)
        assert parsed.server_type in {"oid", "oracle_oid"}

    def test_oud_acl_parses_and_rewrites_to_text(
        self,
        oud_acl_server: p.Ldif.AclServer,
    ) -> None:
        """An OUD aci string parses into an Acl model and re-renders to LDIF text."""
        parse_result = oud_acl_server.parse_server(
            c.Tests.CROSS_SERVER_OUD_ACI_ANONYMOUS,
        )
        assert parse_result.success, f"OUD ACL parse failed: {parse_result.error}"
        parsed = parse_result.value
        assert isinstance(parsed, m.Ldif.Acl)
        assert parsed.server_type in {"oud", "rfc", "generic"}

        write_result = oud_acl_server.write(parsed)
        assert write_result.success, f"OUD ACL write failed: {write_result.error}"
        assert isinstance(write_result.value, str)
        assert write_result.value

    def test_convert_model_translates_oid_acl_to_rfc_dialect(
        self,
        conversion_matrix: FlextLdifConversion,
        oid_acl_server: p.Ldif.AclServer,
    ) -> None:
        """convert_model(OID->RFC) yields an Acl retagged to RFC with a rendered raw_acl."""
        parse_result = oid_acl_server.parse_server(
            c.Tests.CROSS_SERVER_OID_ACL_ANONYMOUS,
        )
        assert parse_result.success, f"OID ACL parse failed: {parse_result.error}"
        assert isinstance(parse_result.value, m.Ldif.Acl)

        result = conversion_matrix.convert_model(
            c.Tests.OID,
            c.Tests.RFC,
            parse_result.value,
        )
        assert result.success, f"OID->RFC ACL conversion failed: {result.error}"
        converted = result.value
        assert isinstance(converted, m.Ldif.Acl)
        assert converted.server_type == c.Tests.RFC
        assert converted.raw_acl is not None

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
            assert rfc_result.success, f"OID write failed: {rfc_result.error}"
            oud_result = oud_schema_server.parse_server(rfc_result.value)
            assert oud_result.success, f"OUD parse failed: {oud_result.error}"
            target = oud_result.value
            assert target.oid == source.oid
            assert target.name == source.name
            converted_any = True
        assert converted_any, "No Oracle attribute survived the OID->RFC->OUD round-trip"

    def test_conversion_matrix_is_available(
        self,
        conversion_matrix: FlextLdifConversion,
    ) -> None:
        """The conversion facade fixture resolves to a usable instance."""
        assert conversion_matrix is not None

    def test_resolve_supported_conversions_reports_all_model_kinds(
        self,
        conversion_matrix: FlextLdifConversion,
        oud_server: FlextLdifServersBase,
    ) -> None:
        """A full-featured server advertises support for every convertible model kind."""
        supported = conversion_matrix.resolve_supported_conversions(oud_server)
        assert supported["attribute"] is True
        assert supported["objectClass"] is True
        assert supported["acl"] is True
        assert supported["entry"] is True

    def test_attribute_converts_oud_to_oid_rendering_oracle_identity(
        self,
        oud_server: FlextLdifServersBase,
        oid_server: FlextLdifServersBase,
    ) -> None:
        """OUD attribute -> RFC -> OID renders back to OID text carrying the Oracle oid and name."""
        parsed = oud_server.schema_server.parse_attribute(
            c.Tests.CROSS_SERVER_OUD_ATTRIBUTE_ORCLGUID,
        )
        assert parsed.success, f"Parse failed: {parsed.error}"
        rfc_text = oud_server.schema_server.write(parsed.value)
        assert rfc_text.success, f"Write failed: {rfc_text.error}"

        oid_parsed = oid_server.schema_server.parse_attribute(rfc_text.value)
        assert oid_parsed.success, f"Parse failed: {oid_parsed.error}"
        oid_text = oid_server.schema_server.write(oid_parsed.value)
        assert oid_text.success, f"Write failed: {oid_text.error}"
        assert "2.16.840.1.113894.1.1.1" in oid_text.value
        assert "orclGUID" in oid_text.value

    def test_objectclass_converts_oid_to_oud_rendering_oracle_identity(
        self,
        oud_server: FlextLdifServersBase,
        oid_server: FlextLdifServersBase,
    ) -> None:
        """OID objectClass -> RFC -> OUD renders back to OUD text carrying the Oracle oid and name."""
        parsed = oid_server.schema_server.parse_objectclass(
            c.Tests.CROSS_SERVER_OID_OBJECTCLASS_ORCLCONTEXT,
        )
        assert parsed.success, f"Parse failed: {parsed.error}"
        rfc_text = oid_server.schema_server.write(parsed.value)
        assert rfc_text.success, f"Write failed: {rfc_text.error}"

        oud_parsed = oud_server.schema_server.parse_objectclass(rfc_text.value)
        assert oud_parsed.success, f"Parse failed: {oud_parsed.error}"
        oud_text = oud_server.schema_server.write(oud_parsed.value)
        assert oud_text.success, f"Write failed: {oud_text.error}"
        assert "2.16.840.1.113894.1.2.1" in oud_text.value
        assert "orclContext" in oud_text.value

    def test_batch_attribute_conversion_preserves_each_attribute_name(
        self,
        oud_server: FlextLdifServersBase,
        oid_server: FlextLdifServersBase,
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
            assert oud_parsed.success, f"Parse failed: {oud_parsed.error}"
            rfc_text = oud_server.schema_server.write(oud_parsed.value)
            assert rfc_text.success, f"Write failed: {rfc_text.error}"
            oid_parsed = oid_server.schema_server.parse_attribute(rfc_text.value)
            assert oid_parsed.success, f"Parse failed: {oid_parsed.error}"
            oid_text = oid_server.schema_server.write(oid_parsed.value)
            assert oid_text.success, f"Write failed: {oid_text.error}"
            oid_rendered.append(oid_text.value)

        assert len(oid_rendered) == 2
        assert "orclGUID" in oid_rendered[0]
        assert "orclDBName" in oid_rendered[1]

    def test_attribute_survives_full_bidirectional_roundtrip(
        self,
        oud_server: FlextLdifServersBase,
        oid_server: FlextLdifServersBase,
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
            assert parsed.success, f"Parse failed: {parsed.error}"
            written = schema_server.write(parsed.value)
            assert written.success, f"Write failed: {written.error}"
            rendered = written.value

        assert "2.16.840.1.113894.1.1.1" in rendered
        assert "orclGUID" in rendered

    def test_convert_model_fails_for_structurally_invalid_entry(
        self,
        conversion_matrix: FlextLdifConversion,
        oud_server: FlextLdifServersBase,
        oid_server: FlextLdifServersBase,
    ) -> None:
        """Converting an entry with null dn/attributes yields a failure result with an error message."""
        invalid_model = m.Ldif.Entry(dn=None, attributes=None)
        result = conversion_matrix.convert_model(oud_server, oid_server, invalid_model)
        assert result.failure
        assert result.error is not None
        assert result.error != ""


__all__: list[str] = ["TestsFlextLdifCrossServerConversion"]
