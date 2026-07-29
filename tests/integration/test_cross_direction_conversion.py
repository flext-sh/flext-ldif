"""Behavioral tests for cross-direction schema conversion (OID<->RFC<->OUD).

Every assertion targets observable public contract only:
- server ``parse_*`` / ``write_*`` returning ``r[T]`` outcomes and their values,
- ``FlextLdifConversion.convert_model`` returning ``r[m.Ldif.Entry]``,
- public model fields (``.syntax``, ``.equality``) and written schema text.

No private attribute/method access, no internal-collaborator spying, no
monkeypatching of the units under test.
"""

from __future__ import annotations

import pytest

from flext_ldif.services.conversion import FlextLdifConversion
from flext_ldif.services.server import FlextLdifServer
from flext_tests import tm
from tests import m

pytestmark = [pytest.mark.integration]


class TestsFlextLdifCrossDirectionConversion:
    """Cross-direction schema conversion observable behavior."""

    @pytest.fixture
    def server_registry(self) -> FlextLdifServer:
        """Real server registry (unit under test, no mocks)."""
        return FlextLdifServer()

    @pytest.fixture
    def conversion(self) -> FlextLdifConversion:
        """Real entry-level conversion service (unit under test)."""
        return FlextLdifConversion()

    # ------------------------------------------------------------------
    # Attribute definition conversion (server parse in source, write target)
    # ------------------------------------------------------------------
    @pytest.mark.parametrize(
        ("source", "target", "attr_def", "must_contain", "must_not_contain"),
        [
            pytest.param(
                "oid",
                "oud",
                "( 2.16.840.1.113894.1.1.327 NAME 'orclDASUIType' "
                "EQUALITY caseIgnoreSubstringsMatch "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
                ("SUBSTR caseIgnoreSubstringsMatch",),
                ("EQUALITY caseIgnoreSubstringsMatch",),
                id="oid-to-oud-substrings-rule-moves-to-substr",
            ),
            pytest.param(
                "oid",
                "oud",
                "( 2.16.840.1.113894.1.1.1 NAME 'orclIsEnabled' "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 SINGLE-VALUE )",
                ("1.3.6.1.4.1.1466.115.121.1.15",),
                ("SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 SINGLE-VALUE",),
                id="oid-to-oud-syntax-rfc-normalized",
            ),
            pytest.param(
                "oud",
                "oid",
                "( 1.3.6.1.4.1.26027.1.1.1 NAME 'ds-sync-hist' "
                "EQUALITY caseIgnoreMatch "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                ("caseIgnoreMatch",),
                ("accessDirectiveMatch",),
                id="oud-to-oid-generic-rule-not-rewritten",
            ),
            pytest.param(
                "oud",
                "oud",
                "( 1.3.6.1.4.1.26027.1.1.1 NAME 'ds-sync-hist' "
                "EQUALITY caseIgnoreMatch "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                ("ds-sync-hist",),
                (),
                id="oud-roundtrip-attribute-stable",
            ),
        ],
    )
    def test_attribute_definition_conversion_normalizes_output(
        self,
        server_registry: FlextLdifServer,
        source: str,
        target: str,
        attr_def: str,
        must_contain: tuple[str, ...],
        must_not_contain: tuple[str, ...],
    ) -> None:
        """Parsing in the source server and writing in the target normalizes text."""
        source_schema = server_registry.resolve_schema_server(source)
        target_schema = server_registry.resolve_schema_server(target)
        assert source_schema is not None
        assert target_schema is not None

        parse_result = source_schema.parse_attribute(attr_def)
        tm.ok(parse_result)

        write_result = target_schema.write_attribute(parse_result.value)
        tm.ok(write_result)

        written = write_result.value
        for token in must_contain:
            tm.that(written, has=token)
        for token in must_not_contain:
            tm.that(written, lacks=token)

    # ------------------------------------------------------------------
    # ObjectClass definition conversion
    # ------------------------------------------------------------------
    @pytest.mark.parametrize(
        ("source", "target", "oc_def", "must_contain", "must_not_contain"),
        [
            pytest.param(
                "oid",
                "oud",
                "( 2.16.840.1.113894.1.2.64 NAME 'orclReferenceObject' "
                "SUP 'top' STRUCTURAL MAY ( orclOwnerGUID $ seeAlso ) )",
                ("SUP top",),
                ("SUP 'top'",),
                id="oid-to-oud-quoted-sup-normalized",
            ),
            pytest.param(
                "oid",
                "oid",
                "( 2.16.840.1.113894.1.2.50 NAME 'orclTestOC' "
                "SUP top STRUCTURAL MUST cn MAY ( sn $ description ) )",
                ("orclTestOC", "SUP top", "STRUCTURAL"),
                (),
                id="oid-roundtrip-objectclass-semantics-preserved",
            ),
            pytest.param(
                "oud",
                "oud",
                "( 1.3.6.1.4.1.26027.1.2.1 NAME 'ds-root-dse' "
                "SUP top STRUCTURAL MAY cn )",
                ("ds-root-dse", "STRUCTURAL"),
                (),
                id="oud-roundtrip-objectclass-stable",
            ),
        ],
    )
    def test_objectclass_definition_conversion_normalizes_output(
        self,
        server_registry: FlextLdifServer,
        source: str,
        target: str,
        oc_def: str,
        must_contain: tuple[str, ...],
        must_not_contain: tuple[str, ...],
    ) -> None:
        """Parsing in source and writing in target preserves/normalizes semantics."""
        source_schema = server_registry.resolve_schema_server(source)
        target_schema = server_registry.resolve_schema_server(target)
        assert source_schema is not None
        assert target_schema is not None

        parse_result = source_schema.parse_objectclass(oc_def)
        tm.ok(parse_result)

        write_result = target_schema.write_objectclass(parse_result.value)
        tm.ok(write_result)

        written = write_result.value
        for token in must_contain:
            tm.that(written, has=token)
        for token in must_not_contain:
            tm.that(written, lacks=token)

    def test_oid_attribute_roundtrip_is_text_identical(
        self, server_registry: FlextLdifServer
    ) -> None:
        """OID->parse->OID->write is a byte-stable identity for OID-native text."""
        oid_schema = server_registry.resolve_schema_server("oid")
        assert oid_schema is not None
        attr_def = (
            "( 2.16.840.1.113894.1.1.327 NAME 'orclDASUIType' "
            "EQUALITY caseIgnoreSubstringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
        )
        parse_result = oid_schema.parse_attribute(attr_def)
        tm.ok(parse_result)
        write_result = oid_schema.write_attribute(parse_result.value)
        tm.ok(write_result)
        tm.that(write_result.value, eq=attr_def)

    # ------------------------------------------------------------------
    # Parsed-model field normalization (public model contract)
    # ------------------------------------------------------------------
    @pytest.mark.parametrize(
        ("server", "attr_def", "field", "expected"),
        [
            pytest.param(
                "oid",
                "( 2.16.840.1.113894.1.1.1 NAME 'orclIsEnabled' "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 SINGLE-VALUE )",
                "syntax",
                "1.3.6.1.4.1.1466.115.121.1.15",
                id="oid-syntax-normalized-to-rfc",
            ),
            pytest.param(
                "oid",
                "( 2.16.840.1.113894.1.1.600 NAME 'orclMemberRef' "
                "EQUALITY distinguishedNAMEMatch "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
                "equality",
                "distinguishedNameMatch",
                id="oid-matching-rule-case-canonicalized",
            ),
        ],
    )
    def test_parsed_attribute_field_is_canonicalized(
        self,
        server_registry: FlextLdifServer,
        server: str,
        attr_def: str,
        field: str,
        expected: str,
    ) -> None:
        """The parsed public model field carries the canonicalized value."""
        schema = server_registry.resolve_schema_server(server)
        assert schema is not None
        parse_result = schema.parse_attribute(attr_def)
        tm.ok(parse_result)
        tm.that(str(getattr(parse_result.value, field)), eq=expected)

    def test_oid_case_variant_matching_rule_normalizes_through_pipeline(
        self, server_registry: FlextLdifServer
    ) -> None:
        """OID case variant is canonicalized at parse and not re-emitted by OUD."""
        oid_schema = server_registry.resolve_schema_server("oid")
        oud_schema = server_registry.resolve_schema_server("oud")
        assert oid_schema is not None
        assert oud_schema is not None
        attr_def = (
            "( 2.16.840.1.113894.1.1.600 NAME 'orclMemberRef' "
            "EQUALITY distinguishedNAMEMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )"
        )
        parse_result = oid_schema.parse_attribute(attr_def)
        tm.ok(parse_result)
        tm.that(parse_result.value.equality, eq="distinguishedNameMatch")
        write_result = oud_schema.write_attribute(parse_result.value)
        tm.ok(write_result)
        tm.that(write_result.value, lacks="distinguishedNAMEMatch")

    # ------------------------------------------------------------------
    # Entry-level conversion (public convert_model contract)
    # ------------------------------------------------------------------
    def test_oid_to_oud_entry_rewrites_embedded_schema_values(
        self, conversion: FlextLdifConversion
    ) -> None:
        """convert_model('oid','oud', entry) normalizes embedded schema strings."""
        entry = m.Ldif.Entry.model_validate({
            "dn": {"value": "cn=subschemasubentry", "metadata": {}},
            "attributes": {
                "attributes": {
                    "attributeTypes": [
                        (
                            "( 2.16.840.1.113894.1.1.327 NAME 'orclDASUIType' "
                            "EQUALITY caseIgnoreSubStringsMatch "
                            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
                        )
                    ],
                    "objectClasses": [
                        (
                            "( 2.16.840.1.113894.1.2.64 NAME 'orclReferenceObject' "
                            "SUP 'top' STRUCTURAL MAY ( orclOwnerGUID $ seeAlso ) )"
                        )
                    ],
                },
                "attribute_metadata": {},
                "metadata": None,
            },
            "metadata": {"server_type": "oid"},
        })

        result = conversion.convert_model("oid", "oud", entry)
        tm.ok(result)
        assert isinstance(result.value, m.Ldif.Entry)

        converted = result.value
        assert converted.attributes is not None
        attribute = converted.attributes.attributes["attributeTypes"][0]
        objectclass = converted.attributes.attributes["objectClasses"][0]
        tm.that(attribute, has="SUBSTR caseIgnoreSubstringsMatch")
        tm.that(attribute, lacks="EQUALITY caseIgnoreSubStringsMatch")
        tm.that(objectclass, has="SUP top")
        tm.that(objectclass, lacks="SUP 'top'")

    def test_oud_to_oid_entry_preserves_generic_matching_rule(
        self, conversion: FlextLdifConversion
    ) -> None:
        """convert_model('oud','oid', entry) keeps generic caseIgnoreMatch intact."""
        entry = m.Ldif.Entry.model_validate({
            "dn": {"value": "cn=schema", "metadata": {}},
            "attributes": {
                "attributes": {
                    "attributeTypes": [
                        (
                            "( 1.3.6.1.4.1.26027.1.1.1 NAME 'ds-sync-hist' "
                            "EQUALITY caseIgnoreMatch "
                            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
                        )
                    ]
                },
                "attribute_metadata": {},
                "metadata": None,
            },
            "metadata": {"server_type": "oud"},
        })

        result = conversion.convert_model("oud", "oid", entry)
        tm.ok(result)
        assert isinstance(result.value, m.Ldif.Entry)

        converted = result.value
        assert converted.attributes is not None
        attribute = converted.attributes.attributes["attributeTypes"][0]
        tm.that(attribute, has="caseIgnoreMatch")
        tm.that(attribute, lacks="accessDirectiveMatch")


__all__: list[str] = ["TestsFlextLdifCrossDirectionConversion"]
