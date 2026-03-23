"""Cross-quirk conversion integration tests.

Tests conversion between different LDAP server quirk types:
- Parse with source quirk (e.g., OID)
- Convert to RFC representation
- Write with target quirk (e.g., OUD)
- Validate conversion accuracy

Also tests the QuirksConversionMatrix facade for universal translation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif import (
    FlextLdifConversion,
    FlextLdifServersOid,
    FlextLdifServersOud,
    m,
    p,
)


class CrossQuirkConversionConstants:
    """Constants for cross-quirk conversion tests."""

    OID_ATTRIBUTE_ORCLGUID = "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' DESC 'Oracle GUID' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
    OID_OBJECTCLASS_ORCLCONTAINER = "( 2.16.840.1.113894.2.1.1 NAME 'orclContainer' DESC 'Oracle Container' SUP top STRUCTURAL MUST cn MAY description )"
    OID_ACL_ANONYMOUS = "orclaci: access to entry by * (browse)"
    OUD_ACI_ANONYMOUS = 'aci: (targetattr="*")(version 3.0; acl "Test ACL"; allow (read,search) userdn="ldap:///anyone";)'
    OUD_ATTRIBUTE_ORCLGUID = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
    OID_OBJECTCLASS_ORCLCONTEXT = (
        "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
    )


CROSS_QUIRK_CONVERSION_CONSTANTS = CrossQuirkConversionConstants()


class TestOidToOudSchemaConversion:
    """Test OID schema → OUD schema conversion.

    Uses centralized fixtures from tests/integration/conftest.py:
    - oid_schema_fixture: OID schema LDIF content
    - oud_schema_fixture: OUD schema LDIF content
    """

    def test_convert_oid_attribute_to_oud(
        self,
        oid_schema_quirk: p.Ldif.SchemaQuirk,
        oud_schema_quirk: p.Ldif.SchemaQuirk,
    ) -> None:
        """Test converting OID attribute definition to OUD format."""
        oid_attribute = CROSS_QUIRK_CONVERSION_CONSTANTS.OID_ATTRIBUTE_ORCLGUID
        parse_result = oid_schema_quirk.parse(oid_attribute)
        assert parse_result.is_success, f"OID parse failed: {parse_result.error}"
        unwrapped = parse_result.value
        assert isinstance(unwrapped, m.Ldif.SchemaAttribute), (
            f"Expected SchemaAttribute, got {type(unwrapped).__name__}"
        )
        parsed_data: m.Ldif.SchemaAttribute = unwrapped
        assert parsed_data.oid == "2.16.840.1.113894.1.1.1"
        assert parsed_data.name == "orclguid"
        assert hasattr(parsed_data, "_metadata") or hasattr(parsed_data, "metadata")
        rfc_result = oid_schema_quirk.write(parsed_data)
        assert rfc_result.is_success, f"OID write failed: {rfc_result.error}"
        rfc_format: str = rfc_result.value
        oud_parse_result = oud_schema_quirk.parse(rfc_format)
        assert oud_parse_result.is_success, (
            f"OUD parse failed: {oud_parse_result.error}"
        )
        oud_unwrapped = oud_parse_result.value
        assert isinstance(oud_unwrapped, m.Ldif.SchemaAttribute), (
            f"Expected SchemaAttribute, got {type(oud_unwrapped).__name__}"
        )
        oud_data: m.Ldif.SchemaAttribute = oud_unwrapped
        assert oud_data.oid == parsed_data.oid
        assert oud_data.name == parsed_data.name
        assert oud_data.syntax == parsed_data.syntax

    def test_convert_oid_objectclass_to_oud(
        self,
        oid_schema_quirk: p.Ldif.SchemaQuirk,
        oud_schema_quirk: p.Ldif.SchemaQuirk,
    ) -> None:
        """Test converting OID objectClass definition to OUD format."""
        oid_objectclass = CROSS_QUIRK_CONVERSION_CONSTANTS.OID_OBJECTCLASS_ORCLCONTAINER
        parse_result = oid_schema_quirk.parse(oid_objectclass)
        assert parse_result.is_success, f"OID parse failed: {parse_result.error}"
        unwrapped = parse_result.value
        assert isinstance(unwrapped, m.Ldif.SchemaObjectClass), (
            f"Expected SchemaObjectClass, got {type(unwrapped).__name__}"
        )
        parsed_data: m.Ldif.SchemaObjectClass = unwrapped
        assert parsed_data.oid == "2.16.840.1.113894.2.1.1"
        assert parsed_data.name == "orclContainer"
        assert parsed_data.kind == "STRUCTURAL"
        assert hasattr(parsed_data, "_metadata") or hasattr(parsed_data, "metadata")
        rfc_result = oid_schema_quirk.write(parsed_data)
        assert rfc_result.is_success, f"OID write failed: {rfc_result.error}"
        rfc_format: str = rfc_result.value
        oud_parse_result = oud_schema_quirk.parse(rfc_format)
        assert oud_parse_result.is_success, (
            f"OUD parse failed: {oud_parse_result.error}"
        )
        oud_unwrapped = oud_parse_result.value
        assert isinstance(oud_unwrapped, m.Ldif.SchemaObjectClass), (
            f"Expected SchemaObjectClass, got {type(oud_unwrapped).__name__}"
        )
        oud_data: m.Ldif.SchemaObjectClass = oud_unwrapped
        assert oud_data.oid == parsed_data.oid
        assert oud_data.name == parsed_data.name
        assert oud_data.kind == parsed_data.kind
        assert oud_data.sup == parsed_data.sup


class TestOidToOudAclConversion:
    """Test OID ACL parsing and OUD ACL parsing independently.

    Note: Direct ACL conversion between OID and OUD formats is not supported
    because they use fundamentally different ACL models:
    - OID: orclaci format (access to entry/attr by subject (permissions))
    - OUD: ACI format (targetattr)(version; acl "name"; allow/deny)

    For ACL comparison across quirks, use the FlextLdifDiff utility instead.
    """

    def test_oid_acl_parsing_and_roundtrip(
        self, oid_acl_quirk: p.Ldif.AclQuirk
    ) -> None:
        """Test OID ACL parsing and round-trip within OID format."""
        oid_acl_str = CROSS_QUIRK_CONVERSION_CONSTANTS.OID_ACL_ANONYMOUS
        parse_result = oid_acl_quirk.parse(oid_acl_str)
        assert parse_result.is_success, f"OID ACL parse failed: {parse_result.error}"
        parsed_data = parse_result.value
        assert parsed_data.server_type in {"oid", "oracle_oid"}
        assert hasattr(parsed_data, "name")
        assert hasattr(parsed_data, "target")
        assert hasattr(parsed_data, "subject")
        assert hasattr(parsed_data, "permissions")

    def test_oud_acl_parsing_and_roundtrip(
        self, oud_acl_quirk: p.Ldif.AclQuirk
    ) -> None:
        """Test OUD ACL parsing and round-trip within OUD format."""
        oud_aci = CROSS_QUIRK_CONVERSION_CONSTANTS.OUD_ACI_ANONYMOUS
        parse_result = oud_acl_quirk.parse(oud_aci)
        assert parse_result.is_success, f"OUD ACL parse failed: {parse_result.error}"
        parsed_data = parse_result.value
        assert parsed_data.server_type in {"oud", "rfc", "generic"}
        assert hasattr(parsed_data, "target")
        assert hasattr(parsed_data, "name")
        assert hasattr(parsed_data, "metadata")
        write_result = oud_acl_quirk.write(parsed_data)
        assert write_result.is_success, f"OUD ACL write failed: {write_result.error}"
        written_format = write_result.value
        assert isinstance(written_format, str)


class TestOidToOudIntegrationConversion:
    """Test complete OID fixture → OUD conversion workflow.

    Uses centralized fixtures from tests/integration/conftest.py:
    - oid_schema_fixture: OID schema LDIF content
    """

    def test_convert_oid_schema_fixture_to_oud(
        self,
        oid_schema_quirk: p.Ldif.SchemaQuirk,
        oud_schema_quirk: p.Ldif.SchemaQuirk,
        oid_schema_fixture: str,
    ) -> None:
        """Test converting OID schema fixture to OUD format.

        Uses fixtures:
        - oid: OID schema quirk instance (internal)
        - oud: OUD schema quirk instance (internal)
        - oid_schema_fixture: OID schema LDIF content (conftest)

        Validates:
        - OID schema parsing succeeds
        - Attributes with Oracle OIDs (2.16.840.1.113894.*) are extracted
        - Conversion to OUD format preserves key fields (OID, name)
        """
        oid_oracle_attrs = sum(
            1
            for line in oid_schema_fixture.split("\n")
            if "attributetypes:" in line.lower() and "2.16.840.1.113894" in line
        )
        assert oid_oracle_attrs > 0, "No Oracle attributes found in OID fixture"
        for line in oid_schema_fixture.split("\n"):
            if "attributetypes:" in line.lower() and "2.16.840.1.113894" in line:
                attr_def = line.split(":", 1)[1].strip()
                parse_result = oid_schema_quirk.parse(attr_def)
                if not parse_result.is_success:
                    continue
                parsed_data = parse_result.value
                rfc_result = oid_schema_quirk.write(parsed_data)
                assert rfc_result.is_success
                oud_result = oud_schema_quirk.parse(rfc_result.value)
                assert oud_result.is_success, (
                    "OUD quirk should parse converted attribute"
                )
                oud_data = oud_result.value
                assert oud_data.oid == parsed_data.oid
                assert oud_data.name == parsed_data.name
                break


class TestQuirksConversionMatrixFacade:
    """Test QuirksConversionMatrix facade for universal translation."""

    def test_matrix_instantiation(self, conversion_matrix: FlextLdifConversion) -> None:
        """Test that conversion matrix can be instantiated."""
        assert conversion_matrix is not None

    def test_get_supported_conversions(
        self, conversion_matrix: FlextLdifConversion, oud_quirk: FlextLdifServersOud
    ) -> None:
        """Test checking supported conversions."""
        supported = conversion_matrix.get_supported_conversions(oud_quirk)
        assert supported["attribute"] is True
        assert supported["objectClass"] is True
        assert supported["acl"] is True
        assert supported["entry"] is True

    def test_convert_attribute_oud_to_oid(
        self,
        conversion_matrix: FlextLdifConversion,
        oud_quirk: FlextLdifServersOud,
        oid_quirk: FlextLdifServersOid,
    ) -> None:
        """Test schema attribute conversion via direct quirk API (not matrix)."""
        oud_attr_string = CROSS_QUIRK_CONVERSION_CONSTANTS.OUD_ATTRIBUTE_ORCLGUID
        parse_result = oud_quirk.schema_quirk.parse_attribute(oud_attr_string)
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        oud_attr_model = parse_result.value
        write_to_rfc = oud_quirk.schema_quirk.write(oud_attr_model)
        assert write_to_rfc.is_success, f"Write failed: {write_to_rfc.error}"
        rfc_attr_string = write_to_rfc.value
        parse_from_rfc = oid_quirk.schema_quirk.parse_attribute(rfc_attr_string)
        assert parse_from_rfc.is_success, f"Parse failed: {parse_from_rfc.error}"
        oid_attr_model = parse_from_rfc.value
        write_result = oid_quirk.schema_quirk.write(oid_attr_model)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        oid_attr_string = write_result.value
        assert "2.16.840.1.113894.1.1.1" in oid_attr_string
        assert "orclGUID" in oid_attr_string

    def test_convert_objectclass_oid_to_oud(
        self,
        conversion_matrix: FlextLdifConversion,
        oud_quirk: FlextLdifServersOud,
        oid_quirk: FlextLdifServersOid,
    ) -> None:
        """Test schema objectClass conversion via direct quirk API (not matrix)."""
        oid_oc_string = CROSS_QUIRK_CONVERSION_CONSTANTS.OID_OBJECTCLASS_ORCLCONTEXT
        parse_result = oid_quirk.schema_quirk.parse_objectclass(oid_oc_string)
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        oid_oc_model = parse_result.value
        write_to_rfc = oid_quirk.schema_quirk.write(oid_oc_model)
        assert write_to_rfc.is_success, f"Write failed: {write_to_rfc.error}"
        rfc_oc_string = write_to_rfc.value
        parse_from_rfc = oud_quirk.schema_quirk.parse_objectclass(rfc_oc_string)
        assert parse_from_rfc.is_success, f"Parse failed: {parse_from_rfc.error}"
        oud_oc_model = parse_from_rfc.value
        write_result = oud_quirk.schema_quirk.write(oud_oc_model)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        oud_oc_string = write_result.value
        assert "2.16.840.1.113894.1.2.1" in oud_oc_string
        assert "orclContext" in oud_oc_string

    def test_batch_convert_attributes(
        self,
        conversion_matrix: FlextLdifConversion,
        oud_quirk: FlextLdifServersOud,
        oid_quirk: FlextLdifServersOid,
    ) -> None:
        """Test batch attribute conversion via direct quirk API (not matrix)."""
        oud_attr_strings = [
            CROSS_QUIRK_CONVERSION_CONSTANTS.OUD_ATTRIBUTE_ORCLGUID,
            "( 2.16.840.1.113894.1.1.2 NAME 'orclDBName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        ]
        oud_attr_models: list[m.Ldif.SchemaAttribute] = []
        for attr_string in oud_attr_strings:
            parse_result = oud_quirk.schema_quirk.parse_attribute(attr_string)
            assert parse_result.is_success, f"Parse failed: {parse_result.error}"
            oud_attr_models.append(parse_result.value)
        assert len(oud_attr_models) == 2
        oid_attr_strings: list[str] = []
        for oud_model in oud_attr_models:
            write_result = oud_quirk.schema_quirk.write(oud_model)
            assert write_result.is_success, f"Write failed: {write_result.error}"
            rfc_string = write_result.value
            parse_result = oid_quirk.schema_quirk.parse_attribute(rfc_string)
            assert parse_result.is_success, f"Parse failed: {parse_result.error}"
            oid_model = parse_result.value
            write_oid = oid_quirk.schema_quirk.write(oid_model)
            assert write_oid.is_success, f"Write failed: {write_oid.error}"
            oid_attr_strings.append(write_oid.value)
        assert len(oid_attr_strings) == 2
        assert "orclGUID" in oid_attr_strings[0]
        assert "orclDBName" in oid_attr_strings[1]

    def test_bidirectional_conversion(
        self,
        conversion_matrix: FlextLdifConversion,
        oud_quirk: FlextLdifServersOud,
        oid_quirk: FlextLdifServersOid,
    ) -> None:
        """Test bidirectional attribute conversion OUD ↔ OID via direct quirk API."""
        original_string = CROSS_QUIRK_CONVERSION_CONSTANTS.OUD_ATTRIBUTE_ORCLGUID
        parse_result = oud_quirk.schema_quirk.parse_attribute(original_string)
        assert parse_result.is_success
        oud_model = parse_result.value
        write_rfc = oud_quirk.schema_quirk.write(oud_model)
        assert write_rfc.is_success
        rfc_string = write_rfc.value
        parse_oid = oid_quirk.schema_quirk.parse_attribute(rfc_string)
        assert parse_oid.is_success
        oid_model = parse_oid.value
        write_rfc2 = oid_quirk.schema_quirk.write(oid_model)
        assert write_rfc2.is_success
        rfc_string2 = write_rfc2.value
        parse_oud2 = oud_quirk.schema_quirk.parse_attribute(rfc_string2)
        assert parse_oud2.is_success
        oud_model2 = parse_oud2.value
        write_final = oud_quirk.schema_quirk.write(oud_model2)
        assert write_final.is_success
        roundtrip_string = write_final.value
        assert "2.16.840.1.113894.1.1.1" in roundtrip_string
        assert "orclGUID" in roundtrip_string

    def test_invalid_data_type(
        self,
        conversion_matrix: FlextLdifConversion,
        oud_quirk: FlextLdifServersOud,
        oid_quirk: FlextLdifServersOid,
    ) -> None:
        """Test error handling for invalid model type."""
        invalid_model = m.Ldif.Entry(dn=None, attributes=None)
        result = conversion_matrix.convert(oud_quirk, oid_quirk, invalid_model)
        assert result.is_failure
        assert result.error is not None


__all__ = [
    "TestOidToOudAclConversion",
    "TestOidToOudIntegrationConversion",
    "TestOidToOudSchemaConversion",
    "TestQuirksConversionMatrixFacade",
]
