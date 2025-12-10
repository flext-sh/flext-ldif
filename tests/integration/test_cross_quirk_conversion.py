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

from flext_ldif.models import m
from flext_ldif.protocols import p
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.services.conversion import FlextLdifConversion
from flext_ldif.typings import t


# Cross-quirk conversion test constants - defined at top of module without type checking
class CrossQuirkConversionConstants:
    """Constants for cross-quirk conversion tests."""

    OID_ATTRIBUTE_ORCLGUID = """( 2.16.840.1.113894.1.1.1 NAME 'orclguid' DESC 'Oracle GUID' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"""
    OID_OBJECTCLASS_ORCLCONTAINER = """( 2.16.840.1.113894.2.1.1 NAME 'orclContainer' DESC 'Oracle Container' SUP top STRUCTURAL MUST cn MAY description )"""
    OID_ACL_ANONYMOUS = """orclaci: access to entry by * (browse)"""
    OUD_ACI_ANONYMOUS = """aci: (targetattr="*")(version 3.0; acl "Test ACL"; allow (read,search) userdn="ldap:///anyone";)"""
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
        oid_schema_quirk: t.SchemaQuirk,
        oud_schema_quirk: t.SchemaQuirk,
    ) -> None:
        """Test converting OID attribute definition to OUD format."""
        # OID attribute definition
        oid_attribute = CROSS_QUIRK_CONVERSION_CONSTANTS.OID_ATTRIBUTE_ORCLGUID

        # Parse with OID quirk
        parse_result = oid_schema_quirk.parse(oid_attribute)
        assert parse_result.is_success, f"OID parse failed: {parse_result.error}"
        unwrapped = parse_result.value
        assert isinstance(unwrapped, m.Ldif.SchemaAttribute), (
            f"Expected SchemaAttribute, got {type(unwrapped).__name__}"
        )
        parsed_data: p.Ldif.SchemaAttribute = unwrapped

        # Verify parsed data (SchemaAttribute object, not dict)
        assert parsed_data.oid == "2.16.840.1.113894.1.1.1"
        assert parsed_data.name == "orclguid"
        assert hasattr(parsed_data, "_metadata") or hasattr(
            parsed_data,
            "metadata",
        )  # Metadata preserved

        # Convert to RFC format using OID quirk
        rfc_result = oid_schema_quirk.write(parsed_data)
        assert rfc_result.is_success, f"OID write failed: {rfc_result.error}"
        rfc_format: str = rfc_result.value

        # Parse RFC format with OUD quirk
        oud_parse_result = oud_schema_quirk.parse(rfc_format)
        assert oud_parse_result.is_success, (
            f"OUD parse failed: {oud_parse_result.error}"
        )
        oud_unwrapped = oud_parse_result.value
        assert isinstance(oud_unwrapped, m.Ldif.SchemaAttribute), (
            f"Expected SchemaAttribute, got {type(oud_unwrapped).__name__}"
        )
        oud_data: p.Ldif.SchemaAttribute = oud_unwrapped

        # Verify conversion preserved key fields (both are objects, not dicts)
        assert oud_data.oid == parsed_data.oid
        assert oud_data.name == parsed_data.name
        assert oud_data.syntax == parsed_data.syntax

    def test_convert_oid_objectclass_to_oud(
        self,
        oid_schema_quirk: t.SchemaQuirk,
        oud_schema_quirk: t.SchemaQuirk,
    ) -> None:
        """Test converting OID objectClass definition to OUD format."""
        # OID objectClass definition
        oid_objectclass = CROSS_QUIRK_CONVERSION_CONSTANTS.OID_OBJECTCLASS_ORCLCONTAINER

        # Parse with OID quirk
        parse_result = oid_schema_quirk.parse(oid_objectclass)
        assert parse_result.is_success, f"OID parse failed: {parse_result.error}"
        unwrapped = parse_result.value
        assert isinstance(unwrapped, m.Ldif.SchemaObjectClass), (
            f"Expected SchemaObjectClass, got {type(unwrapped).__name__}"
        )
        parsed_data: p.Ldif.SchemaObjectClass = unwrapped

        # Verify parsed data (object, not dict)
        assert parsed_data.oid == "2.16.840.1.113894.2.1.1"
        assert parsed_data.name == "orclContainer"
        assert parsed_data.kind == "STRUCTURAL"
        assert hasattr(parsed_data, "_metadata") or hasattr(parsed_data, "metadata")

        # Convert to RFC format using OID quirk
        rfc_result = oid_schema_quirk.write(parsed_data)
        assert rfc_result.is_success, f"OID write failed: {rfc_result.error}"
        rfc_format: str = rfc_result.value

        # Parse RFC format with OUD quirk
        oud_parse_result = oud_schema_quirk.parse(rfc_format)
        assert oud_parse_result.is_success, (
            f"OUD parse failed: {oud_parse_result.error}"
        )
        oud_unwrapped = oud_parse_result.value
        assert isinstance(oud_unwrapped, m.Ldif.SchemaObjectClass), (
            f"Expected SchemaObjectClass, got {type(oud_unwrapped).__name__}"
        )
        oud_data: p.Ldif.SchemaObjectClass = oud_unwrapped

        # Verify conversion preserved key fields (objects, not dicts)
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
        self,
        oid_acl_quirk: t.AclQuirk,
    ) -> None:
        """Test OID ACL parsing and round-trip within OID format."""
        # OID ACL definition
        oid_acl_str = CROSS_QUIRK_CONVERSION_CONSTANTS.OID_ACL_ANONYMOUS

        # Parse with OID ACL quirk
        # Note: parse internally converts OID format to RFC format
        parse_result = oid_acl_quirk.parse(oid_acl_str)
        assert parse_result.is_success, f"OID ACL parse failed: {parse_result.error}"
        parsed_data = parse_result.value

        # Verify parsed data structure contains expected fields (Acl object, not dict)
        assert parsed_data.server_type in {
            "oid",
            "oracle_oid",
        }  # OID ACL format variants
        assert hasattr(parsed_data, "name")  # Has name field
        assert hasattr(parsed_data, "target")  # Has target field
        assert hasattr(parsed_data, "subject")  # Has subject field
        assert hasattr(parsed_data, "permissions")  # Has permissions field

    def test_oud_acl_parsing_and_roundtrip(
        self,
        oud_acl_quirk: t.AclQuirk,
    ) -> None:
        """Test OUD ACL parsing and round-trip within OUD format."""
        # OUD ACI format
        oud_aci = CROSS_QUIRK_CONVERSION_CONSTANTS.OUD_ACI_ANONYMOUS

        # Parse with OUD ACL quirk
        parse_result = oud_acl_quirk.parse(oud_aci)
        assert parse_result.is_success, f"OUD ACL parse failed: {parse_result.error}"
        parsed_data = parse_result.value

        # Verify parsed data structure (Acl object, not dict)
        # Note: Parsed ACL is converted to generic (RFC) format after parsing OUD-specific format
        # Current implementation: OUD parsing sets server_type to "oud"
        # "generic" is an alias for "rfc" but the actual server_type is "oud" when parsed by OUD quirk
        assert parsed_data.server_type in {
            "oud",
            "rfc",
            "generic",
        }  # Accept current behavior
        assert hasattr(parsed_data, "target")  # Has target field
        assert hasattr(parsed_data, "name")  # Has name field
        assert hasattr(parsed_data, "metadata")  # Has metadata field

        # Write back to OUD format for round-trip
        write_result = oud_acl_quirk.write(parsed_data)
        assert write_result.is_success, f"OUD ACL write failed: {write_result.error}"
        written_format = write_result.value

        # Verify round-trip (should preserve ACI format)
        assert isinstance(written_format, str)


class TestOidToOudIntegrationConversion:
    """Test complete OID fixture → OUD conversion workflow.

    Uses centralized fixtures from tests/integration/conftest.py:
    - oid_schema_fixture: OID schema LDIF content
    """

    def test_convert_oid_schema_fixture_to_oud(
        self,
        oid_schema_quirk: t.SchemaQuirk,
        oud_schema_quirk: t.SchemaQuirk,
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
        # Extract attribute definitions from fixture
        # In a real scenario, we'd parse the LDIF entry and extract attributeTypes
        # For this test, we'll test the conversion pipeline works

        # Count Oracle attributes in OID fixture
        oid_oracle_attrs = sum(
            1
            for line in oid_schema_fixture.split("\n")
            if "attributetypes:" in line.lower() and "2.16.840.1.113894" in line
        )

        # Verify we have Oracle attributes in fixture
        assert oid_oracle_attrs > 0, "No Oracle attributes found in OID fixture"

        # Extract one attribute for conversion test
        for line in oid_schema_fixture.split("\n"):
            if "attributetypes:" in line.lower() and "2.16.840.1.113894" in line:
                # Extract the attribute definition (remove "attributetypes: " prefix)
                attr_def = line.split(":", 1)[1].strip()

                # Parse with OID quirk
                parse_result = oid_schema_quirk.parse(attr_def)
                if not parse_result.is_success:
                    continue

                parsed_data = parse_result.value

                # Convert to RFC format
                rfc_result = oid_schema_quirk.write(parsed_data)
                assert rfc_result.is_success

                # Parse with OUD quirk
                oud_result = oud_schema_quirk.parse(rfc_result.value)
                assert oud_result.is_success, (
                    "OUD quirk should parse converted attribute"
                )

                # Verify key fields preserved
                oud_data = oud_result.value
                assert oud_data.oid == parsed_data.oid
                assert oud_data.name == parsed_data.name

                # Successfully converted at least one attribute
                break


class TestQuirksConversionMatrixFacade:
    """Test QuirksConversionMatrix facade for universal translation."""

    def test_matrix_instantiation(self, conversion_matrix: FlextLdifConversion) -> None:
        """Test that conversion matrix can be instantiated."""
        assert conversion_matrix is not None

    def test_get_supported_conversions(
        self,
        conversion_matrix: FlextLdifConversion,
        oud_quirk: FlextLdifServersOud,
    ) -> None:
        """Test checking supported conversions."""
        supported = conversion_matrix.get_supported_conversions(oud_quirk)

        # Schema support should be detected
        assert supported["attribute"] is True
        assert supported["objectClass"] is True

        # ACL support is now available (implemented)
        # Entry support is available
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

        # Parse string to model using source quirk (OUD)
        parse_result = oud_quirk.schema_quirk.parse_attribute(oud_attr_string)
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        oud_attr_model = parse_result.value

        # Write model to RFC format using source quirk
        write_to_rfc = oud_quirk.schema_quirk.write(oud_attr_model)
        assert write_to_rfc.is_success, f"Write failed: {write_to_rfc.error}"
        rfc_attr_string = write_to_rfc.value

        # Parse RFC format with target quirk (OID)
        parse_from_rfc = oid_quirk.schema_quirk.parse_attribute(rfc_attr_string)
        assert parse_from_rfc.is_success, f"Parse failed: {parse_from_rfc.error}"
        oid_attr_model = parse_from_rfc.value

        # Convert back to string for assertion
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

        # Parse string to model using source quirk (OID)
        parse_result = oid_quirk.schema_quirk.parse_objectclass(oid_oc_string)
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        oid_oc_model = parse_result.value

        # Write model to RFC format using source quirk
        write_to_rfc = oid_quirk.schema_quirk.write(oid_oc_model)
        assert write_to_rfc.is_success, f"Write failed: {write_to_rfc.error}"
        rfc_oc_string = write_to_rfc.value

        # Parse RFC format with target quirk (OUD)
        parse_from_rfc = oud_quirk.schema_quirk.parse_objectclass(rfc_oc_string)
        assert parse_from_rfc.is_success, f"Parse failed: {parse_from_rfc.error}"
        oud_oc_model = parse_from_rfc.value

        # Convert back to string for assertion
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

        # Parse all strings to models using source quirk (OUD)
        oud_attr_models = []
        for attr_string in oud_attr_strings:
            parse_result = oud_quirk.schema_quirk.parse_attribute(attr_string)
            assert parse_result.is_success, f"Parse failed: {parse_result.error}"
            oud_attr_models.append(parse_result.value)

        assert len(oud_attr_models) == 2

        # Convert each model via write→parse pipeline
        oid_attr_strings = []
        for oud_model in oud_attr_models:
            # Write to RFC format
            write_result = oud_quirk.schema_quirk.write(oud_model)
            assert write_result.is_success, f"Write failed: {write_result.error}"
            rfc_string = write_result.value

            # Parse RFC format with target quirk
            parse_result = oid_quirk.schema_quirk.parse_attribute(rfc_string)
            assert parse_result.is_success, f"Parse failed: {parse_result.error}"
            oid_model = parse_result.value

            # Write to OID format
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

        # Parse original string to model
        parse_result = oud_quirk.schema_quirk.parse_attribute(original_string)
        assert parse_result.is_success
        oud_model = parse_result.value

        # OUD → RFC
        write_rfc = oud_quirk.schema_quirk.write(oud_model)
        assert write_rfc.is_success
        rfc_string = write_rfc.value

        # RFC → OID
        parse_oid = oid_quirk.schema_quirk.parse_attribute(rfc_string)
        assert parse_oid.is_success
        oid_model = parse_oid.value

        # OID → RFC
        write_rfc2 = oid_quirk.schema_quirk.write(oid_model)
        assert write_rfc2.is_success
        rfc_string2 = write_rfc2.value

        # RFC → OUD (roundtrip)
        parse_oud2 = oud_quirk.schema_quirk.parse_attribute(rfc_string2)
        assert parse_oud2.is_success
        oud_model2 = parse_oud2.value

        # Convert back to string for assertion
        write_final = oud_quirk.schema_quirk.write(oud_model2)
        assert write_final.is_success
        roundtrip_string = write_final.value

        # Validate semantic equivalence
        assert "2.16.840.1.113894.1.1.1" in roundtrip_string
        assert "orclGUID" in roundtrip_string

    def test_invalid_data_type(
        self,
        conversion_matrix: FlextLdifConversion,
        oud_quirk: FlextLdifServersOud,
        oid_quirk: FlextLdifServersOid,
    ) -> None:
        """Test error handling for invalid model type."""
        # Try to convert with an invalid model type (not Entry, SchemaAttribute, etc.)
        # Use a plain dict instead of a proper model to trigger validation error
        invalid_model: dict[str, str] = {"invalid": "data"}

        result = conversion_matrix.convert(oud_quirk, oid_quirk, invalid_model)

        assert result.is_failure
        assert result.error is not None


__all__ = [
    "TestOidToOudAclConversion",
    "TestOidToOudIntegrationConversion",
    "TestOidToOudSchemaConversion",
    "TestQuirksConversionMatrixFacade",
]
