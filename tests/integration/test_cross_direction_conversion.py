"""Integration tests for cross-direction schema conversion (OID↔RFC↔OUD)."""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdifConversion, FlextLdifServer, m

pytestmark = [pytest.mark.integration]


class TestsTestFlextLdifCrossDirectionConversion:
    """Test all schema conversion directions with real quirks."""

    @pytest.fixture
    def server_registry(self) -> FlextLdifServer:
        """Create server registry."""
        return FlextLdifServer()

    def test_oid_to_oud_attribute_matching_rules(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """OID→RFC→OUD should move substrings rule from equality to substr."""
        oid_schema = server_registry.get_schema_quirk("oid")
        oud_schema = server_registry.get_schema_quirk("oud")
        assert oid_schema is not None
        assert oud_schema is not None
        attr_def = (
            "( 2.16.840.1.113894.1.1.327 NAME 'orclDASUIType' "
            "EQUALITY caseIgnoreSubstringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
        )
        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success, f"OID parse failed: {parse_result.error}"
        write_result = oud_schema.write_attribute(parse_result.value)
        assert write_result.is_success, f"OUD write failed: {write_result.error}"
        written = write_result.value
        assert "EQUALITY caseIgnoreSubstringsMatch" not in written
        assert "SUBSTR caseIgnoreSubstringsMatch" in written

    def test_oid_to_oud_objectclass_sup_normalization(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """OID→RFC→OUD should normalize quoted SUP to target form."""
        oid_schema = server_registry.get_schema_quirk("oid")
        oud_schema = server_registry.get_schema_quirk("oud")
        assert oid_schema is not None
        assert oud_schema is not None
        oc_def = (
            "( 2.16.840.1.113894.1.2.64 NAME 'orclReferenceObject' "
            "SUP 'top' STRUCTURAL MAY ( orclOwnerGUID $ seeAlso ) )"
        )
        parse_result = oid_schema.parse_objectclass(oc_def)
        assert parse_result.is_success, f"OID parse failed: {parse_result.error}"
        write_result = oud_schema.write_objectclass(parse_result.value)
        assert write_result.is_success, f"OUD write failed: {write_result.error}"
        written = write_result.value
        assert "SUP top" in written
        assert "SUP 'top'" not in written

    def test_oid_to_oud_syntax_normalization(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """OID→RFC→OUD should keep RFC-normalized syntax OID."""
        oid_schema = server_registry.get_schema_quirk("oid")
        oud_schema = server_registry.get_schema_quirk("oud")
        assert oid_schema is not None
        assert oud_schema is not None
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclIsEnabled' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 SINGLE-VALUE )"
        )
        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success, f"OID parse failed: {parse_result.error}"
        assert str(parse_result.value.syntax) == "1.3.6.1.4.1.1466.115.121.1.15"
        write_result = oud_schema.write_attribute(parse_result.value)
        assert write_result.is_success, f"OUD write failed: {write_result.error}"
        written = write_result.value
        assert "1.3.6.1.4.1.1466.115.121.1.15" in written
        assert "SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 " not in written

    def test_oid_roundtrip_attribute(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """OID→RFC→OID should preserve same-server original schema text."""
        oid_schema = server_registry.get_schema_quirk("oid")
        assert oid_schema is not None
        attr_def = (
            "( 2.16.840.1.113894.1.1.327 NAME 'orclDASUIType' "
            "EQUALITY caseIgnoreSubstringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
        )
        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success, f"OID parse failed: {parse_result.error}"
        write_result = oid_schema.write_attribute(parse_result.value)
        assert write_result.is_success, f"OID write failed: {write_result.error}"
        assert write_result.value == attr_def

    def test_oid_roundtrip_objectclass(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """OID→RFC→OID should preserve same-server objectClass semantics."""
        oid_schema = server_registry.get_schema_quirk("oid")
        assert oid_schema is not None
        oc_def = (
            "( 2.16.840.1.113894.1.2.50 NAME 'orclTestOC' "
            "SUP top STRUCTURAL MUST cn MAY ( sn $ description ) )"
        )
        parse_result = oid_schema.parse_objectclass(oc_def)
        assert parse_result.is_success, f"OID parse failed: {parse_result.error}"
        write_result = oid_schema.write_objectclass(parse_result.value)
        assert write_result.is_success, f"OID write failed: {write_result.error}"
        written = write_result.value
        assert "orclTestOC" in written
        assert "SUP top" in written
        assert "STRUCTURAL" in written

    def test_oud_roundtrip_attribute(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """OUD→RFC→OUD should be stable for regular schema attributes."""
        oud_schema = server_registry.get_schema_quirk("oud")
        assert oud_schema is not None
        attr_def = (
            "( 1.3.6.1.4.1.26027.1.1.1 NAME 'ds-sync-hist' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        parse_result = oud_schema.parse_attribute(attr_def)
        assert parse_result.is_success, f"OUD parse failed: {parse_result.error}"
        write_result = oud_schema.write_attribute(parse_result.value)
        assert write_result.is_success, f"OUD write failed: {write_result.error}"
        assert "ds-sync-hist" in write_result.value

    def test_oud_roundtrip_objectclass(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """OUD→RFC→OUD should be stable for regular objectClasses."""
        oud_schema = server_registry.get_schema_quirk("oud")
        assert oud_schema is not None
        oc_def = (
            "( 1.3.6.1.4.1.26027.1.2.1 NAME 'ds-root-dse' SUP top STRUCTURAL MAY cn )"
        )
        parse_result = oud_schema.parse_objectclass(oc_def)
        assert parse_result.is_success, f"OUD parse failed: {parse_result.error}"
        write_result = oud_schema.write_objectclass(parse_result.value)
        assert write_result.is_success, f"OUD write failed: {write_result.error}"
        written = write_result.value
        assert "ds-root-dse" in written
        assert "STRUCTURAL" in written

    def test_oud_to_oid_attribute(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """OUD→RFC→OID should not rewrite generic caseIgnoreMatch to accessDirectiveMatch."""
        oud_schema = server_registry.get_schema_quirk("oud")
        oid_schema = server_registry.get_schema_quirk("oid")
        assert oud_schema is not None
        assert oid_schema is not None
        attr_def = (
            "( 1.3.6.1.4.1.26027.1.1.1 NAME 'ds-sync-hist' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        parse_result = oud_schema.parse_attribute(attr_def)
        assert parse_result.is_success, f"OUD parse failed: {parse_result.error}"
        write_result = oid_schema.write_attribute(parse_result.value)
        assert write_result.is_success, f"OID write failed: {write_result.error}"
        written = write_result.value
        assert "caseIgnoreMatch" in written
        assert "accessDirectiveMatch" not in written

    def test_oid_case_variant_matching_rule_through_pipeline(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """OID case variants should normalize through the OID→OUD pipeline."""
        oid_schema = server_registry.get_schema_quirk("oid")
        oud_schema = server_registry.get_schema_quirk("oud")
        assert oid_schema is not None
        assert oud_schema is not None
        attr_def = (
            "( 2.16.840.1.113894.1.1.600 NAME 'orclMemberRef' "
            "EQUALITY distinguishedNAMEMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )"
        )
        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success, f"OID parse failed: {parse_result.error}"
        assert parse_result.value.equality == "distinguishedNameMatch"
        write_result = oud_schema.write_attribute(parse_result.value)
        assert write_result.is_success, f"OUD write failed: {write_result.error}"
        assert "distinguishedNAMEMatch" not in write_result.value

    def test_oid_to_oud_schema_entry_is_target_normalized(self) -> None:
        """OID schema entries should rewrite embedded schema values for OUD."""
        conversion = FlextLdifConversion()
        entry = m.Ldif.Entry.model_validate({
            "dn": {
                "value": "cn=subschemasubentry",
                "metadata": {},
            },
            "attributes": {
                "attributes": {
                    "attributeTypes": [
                        (
                            "( 2.16.840.1.113894.1.1.327 NAME 'orclDASUIType' "
                            "EQUALITY caseIgnoreSubStringsMatch "
                            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
                        ),
                    ],
                    "objectClasses": [
                        (
                            "( 2.16.840.1.113894.1.2.64 NAME 'orclReferenceObject' "
                            "SUP 'top' STRUCTURAL MAY ( orclOwnerGUID $ seeAlso ) )"
                        ),
                    ],
                },
                "attribute_metadata": {},
                "metadata": None,
            },
            "metadata": {
                "quirk_type": "oid",
            },
        })
        result = conversion.convert_entry("oid", "oud", entry)
        assert result.is_success, f"Entry conversion failed: {result.error}"
        assert isinstance(result.value, m.Ldif.Entry)
        converted_entry = result.value
        assert converted_entry.attributes is not None
        converted_attribute = converted_entry.attributes.attributes["attributeTypes"][0]
        converted_objectclass = converted_entry.attributes.attributes["objectClasses"][
            0
        ]
        assert "SUBSTR caseIgnoreSubstringsMatch" in converted_attribute
        assert "EQUALITY caseIgnoreSubStringsMatch" not in converted_attribute
        assert "SUP top" in converted_objectclass
        assert "SUP 'top'" not in converted_objectclass

    def test_oud_to_oid_schema_entry_preserves_generic_matching_rule(self) -> None:
        """OUD schema entries should not rewrite generic caseIgnoreMatch to OID-only rules."""
        conversion = FlextLdifConversion()
        entry = m.Ldif.Entry.model_validate({
            "dn": {
                "value": "cn=schema",
                "metadata": {},
            },
            "attributes": {
                "attributes": {
                    "attributeTypes": [
                        (
                            "( 1.3.6.1.4.1.26027.1.1.1 NAME 'ds-sync-hist' "
                            "EQUALITY caseIgnoreMatch "
                            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
                        ),
                    ],
                },
                "attribute_metadata": {},
                "metadata": None,
            },
            "metadata": {
                "quirk_type": "oud",
            },
        })
        result = conversion.convert_entry("oud", "oid", entry)
        assert result.is_success, f"Entry conversion failed: {result.error}"
        assert isinstance(result.value, m.Ldif.Entry)
        converted_entry = result.value
        assert converted_entry.attributes is not None
        converted_attribute = converted_entry.attributes.attributes["attributeTypes"][0]
        assert "caseIgnoreMatch" in converted_attribute
        assert "accessDirectiveMatch" not in converted_attribute


__all__ = ["TestsTestFlextLdifCrossDirectionConversion"]
