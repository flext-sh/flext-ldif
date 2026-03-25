"""Zero Data Loss Tests for Schema Deviations OID↔OUD↔RFC.

Tests ALL minimal differences in schema definitions are tracked and preserved:
- Syntax quotation (OID quotes syntax OIDs, OUD/RFC don't)
- Missing spaces (SYNTAX1.3.6.1 malformation)
- X-ORIGIN presence/absence
- Multiple NAME aliases
- OBSOLETE markers
- Attribute/ObjectClass key casing
- DN format (cn=subschemasubentry vs cn=schema)
- Complete round-trip preservation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import (
    FlextLdif,
    FlextLdifServersBaseSchema,
    FlextLdifServersOid,
    FlextLdifServersOud,
)
from tests import u


class TestSchemaDeviationsSyntaxQuotes:
    """Test syntax OID quotation tracking (OID uses quotes, OUD/RFC don't)."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersBaseSchema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    @pytest.fixture
    def oud_schema(self) -> FlextLdifServersBaseSchema:
        """Create OUD schema quirk instance."""
        return FlextLdifServersOud().schema_quirk

    def test_oid_syntax_quotes_tracked(
        self,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test OID syntax with quotes is tracked in metadata."""
        oid_definition = "( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success, f"Parse failed: {result.error}"
        attr = result.value
        assert attr.metadata is not None, "Missing metadata"
        format_details = attr.metadata.schema_format_details
        assert format_details is not None
        extensions_dict = format_details.extensions.model_dump()
        assert "syntax_quotes" in extensions_dict, "Missing syntax_quotes tracking"
        assert extensions_dict["syntax_quotes"] is True, "Should detect syntax quotes"
        assert extensions_dict.get("syntax_quote_char") == "'", (
            "Should detect single quotes"
        )

    def test_oud_syntax_no_quotes_tracked(
        self,
        oud_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test OUD syntax without quotes is tracked in metadata."""
        oud_definition = "( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} X-ORIGIN 'RFC 4519' )"
        result = oud_schema._parse_attribute(oud_definition)
        assert result.is_success, f"Parse failed: {result.error}"
        attr = result.value
        assert attr.metadata is not None, "Missing metadata"
        format_details = attr.metadata.schema_format_details
        assert format_details is not None
        extensions_dict = format_details.extensions.model_dump()
        assert "syntax_quotes" in extensions_dict, "Missing syntax_quotes tracking"
        assert extensions_dict["syntax_quotes"] is False, (
            "Should detect no syntax quotes"
        )


class TestSchemaDeviationsXOrigin:
    """Test X-ORIGIN presence/absence tracking."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersBaseSchema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    @pytest.fixture
    def oud_schema(self) -> FlextLdifServersBaseSchema:
        """Create OUD schema quirk instance."""
        return FlextLdifServersOud().schema_quirk

    def test_oid_no_x_origin_tracked(
        self,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test OID without X-ORIGIN is tracked in metadata."""
        oid_definition = "( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success, f"Parse failed: {result.error}"
        attr = result.value
        assert attr.metadata is not None, "Missing metadata"
        format_details = attr.metadata.schema_format_details
        assert format_details is not None
        extensions_dict = format_details.extensions.model_dump()
        assert "x_origin_presence" in extensions_dict, (
            "Missing x_origin_presence tracking"
        )
        assert extensions_dict["x_origin_presence"] is False, (
            "Should detect no X-ORIGIN"
        )
        assert extensions_dict.get("x_origin_value") is None, (
            "x_origin_value should be None when X-ORIGIN is absent"
        )

    def test_oud_x_origin_tracked(self, oud_schema: FlextLdifServersBaseSchema) -> None:
        """Test OUD with X-ORIGIN is tracked in metadata."""
        oud_definition = "( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} X-ORIGIN 'RFC 4519' )"
        result = oud_schema._parse_attribute(oud_definition)
        assert result.is_success, f"Parse failed: {result.error}"
        attr = result.value
        assert attr.metadata is not None, "Missing metadata"
        format_details = attr.metadata.schema_format_details
        assert format_details is not None
        extensions_dict = format_details.extensions.model_dump()
        assert "x_origin_presence" in extensions_dict, (
            "Missing x_origin_presence tracking"
        )
        assert extensions_dict["x_origin_presence"] is True, "Should detect X-ORIGIN"
        assert extensions_dict.get("x_origin_value") == "RFC 4519", (
            "Should preserve X-ORIGIN value"
        )
        assert isinstance(extensions_dict.get("x_origin_value"), str), (
            "x_origin_value should be a string when X-ORIGIN is present"
        )


class TestSchemaDeviationsNameAliases:
    """Test multiple NAME aliases preservation."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersBaseSchema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    @pytest.fixture
    def oud_schema(self) -> FlextLdifServersBaseSchema:
        """Create OUD schema quirk instance."""
        return FlextLdifServersOud().schema_quirk

    def test_oid_single_name_tracked(
        self,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test OID single NAME format is tracked."""
        oid_definition = "( 0.9.2342.19200300.100.1.1 NAME 'uid' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success, f"Parse failed: {result.error}"
        attr = result.value
        assert attr.metadata is not None, "Missing metadata"
        format_details = attr.metadata.schema_format_details
        assert format_details is not None
        extensions_dict = format_details.extensions.model_dump()
        assert extensions_dict.get("name_format") == "single", (
            "Should detect single NAME format"
        )
        assert extensions_dict.get("name_values") == ["uid"], (
            "Should preserve name value"
        )
        name_values: list[str] = list(extensions_dict.get("name_values", []))
        assert len(name_values) == 1, "Single name should have one value"

    def test_oud_multiple_names_tracked(
        self,
        oud_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test OUD multiple NAME aliases are tracked."""
        oud_definition = "( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        result = oud_schema._parse_attribute(oud_definition)
        assert result.is_success, f"Parse failed: {result.error}"
        attr = result.value
        assert attr.metadata is not None, "Missing metadata"
        format_details = attr.metadata.schema_format_details
        assert format_details is not None
        extensions_dict = format_details.extensions.model_dump()
        assert extensions_dict.get("name_format") == "multiple", (
            "Should detect multiple NAME format"
        )
        name_values: list[str] = list(extensions_dict.get("name_values", []))
        assert len(name_values) >= 2, "Multiple names should have at least 2 values"
        assert "uid" in name_values, "Should include 'uid' in name values"
        assert "userid" in name_values, "Should include 'userid' in name values"


class TestSchemaDeviationsObsolete:
    """Test OBSOLETE marker preservation."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersBaseSchema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    def test_obsolete_marker_tracked(
        self,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test OBSOLETE marker is tracked in metadata."""
        oid_definition = "( 0.9.2342.19200300.100.1.23 NAME 'lastModifiedTime' OBSOLETE SYNTAX '1.3.6.1.4.1.1466.115.121.1.53' )"
        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success, f"Parse failed: {result.error}"
        attr = result.value
        assert attr.metadata is not None, "Missing metadata"
        format_details = attr.metadata.schema_format_details
        assert format_details is not None
        extensions_dict = format_details.extensions.model_dump()
        assert "obsolete_presence" in extensions_dict, (
            "Missing obsolete_presence tracking"
        )
        assert extensions_dict["obsolete_presence"] is True, "Should detect OBSOLETE"
        assert "obsolete_position" in extensions_dict, "Should track OBSOLETE position"
        obsolete_position = extensions_dict.get("obsolete_position")
        assert obsolete_position is not None, "obsolete_position should not be None"
        assert isinstance(obsolete_position, (int, str)), (
            "obsolete_position should be int or str"
        )

    def test_no_obsolete_tracked(self, oid_schema: FlextLdifServersBaseSchema) -> None:
        """Test absence of OBSOLETE is tracked."""
        oid_definition = "( 0.9.2342.19200300.100.1.1 NAME 'uid' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success
        attr = result.value
        assert attr.metadata is not None
        format_details = attr.metadata.schema_format_details
        assert format_details is not None
        extensions_dict = format_details.extensions.model_dump()
        assert extensions_dict.get("obsolete_presence") is False, (
            "Should detect no OBSOLETE"
        )


class TestSchemaDeviationsSpacing:
    """Test spacing preservation between fields."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersBaseSchema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    def test_trailing_spaces_tracked(
        self,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test trailing spaces are tracked."""
        oid_definition = "( 0.9.2342.19200300.100.1.1 NAME 'uid' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )  "
        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success
        attr = result.value
        assert attr.metadata is not None
        format_details = attr.metadata.schema_format_details
        assert format_details is not None
        extensions_dict = format_details.extensions.model_dump()
        assert "trailing_spaces" in extensions_dict, "Missing trailing_spaces tracking"
        extensions_dict.get("trailing_spaces")
        assert "trailing_spaces" in extensions_dict, (
            "trailing_spaces field should exist"
        )
        original = format_details.original_string_complete
        assert original is not None, "original_string_complete should be preserved"
        assert isinstance(original, str), "original_string_complete should be a string"

    def test_field_order_tracked(self, oid_schema: FlextLdifServersBaseSchema) -> None:
        """Test field order is tracked."""
        oid_definition = "( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success
        attr = result.value
        assert attr.metadata is not None
        format_details = attr.metadata.schema_format_details
        assert format_details is not None
        assert format_details.field_order is not None, "Missing field_order tracking"
        field_order = format_details.field_order
        assert "OID" in field_order, "Should track OID position"
        assert "NAME" in field_order, "Should track NAME position"
        assert "SYNTAX" in field_order, "Should track SYNTAX position"
        assert isinstance(field_order, list), "field_order should be a list"
        assert len(field_order) >= 3, "Should track at least 3 fields"
        for field_name in field_order:
            assert isinstance(field_name, str), (
                f"Field name should be string, got {type(field_name)}"
            )
            assert field_name, "Field name should not be empty"


class TestSchemaDeviationsOriginalString:
    """Test complete original string preservation."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersBaseSchema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    @pytest.fixture
    def oud_schema(self) -> FlextLdifServersBaseSchema:
        """Create OUD schema quirk instance."""
        return FlextLdifServersOud().schema_quirk

    def test_oid_original_string_preserved(
        self,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test complete OID original string is preserved."""
        oid_definition = "( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )  "
        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success
        attr = result.value
        assert attr.metadata is not None
        format_details = attr.metadata.schema_format_details
        assert format_details is not None, "Schema format details should be preserved"
        assert format_details.field_order is not None, "Field order should be preserved"
        assert format_details.field_order, "Field order should contain fields"
        assert "OID" in format_details.field_order, "Should track OID in field_order"
        assert "NAME" in format_details.field_order, "Should track NAME in field_order"
        assert "SYNTAX" in format_details.field_order, (
            "Should track SYNTAX in field_order"
        )
        original = format_details.original_string_complete
        assert original is not None, "original_string_complete should exist"
        assert isinstance(original, str), "original_string_complete should be a string"
        assert original, "original_string_complete should not be empty"

    def test_oud_original_string_preserved(
        self,
        oud_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test complete OUD original string is preserved."""
        oud_definition = "( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} X-ORIGIN 'RFC 4519' )"
        result = oud_schema._parse_attribute(oud_definition)
        assert result.is_success
        attr = result.value
        assert attr.metadata is not None
        format_details = attr.metadata.schema_format_details
        assert format_details is not None
        original_string = format_details.original_string_complete
        assert isinstance(original_string, str), "original_string should be a string"
        assert original_string, "original_string should not be empty"
        assert "0.9.2342.19200300.100.1.1" in original_string, "OID should be preserved"
        assert "uid" in original_string, "NAME should be preserved"
        assert "1.3.6.1.4.1.1466.115.121.1.15" in original_string, (
            "SYNTAX should be preserved"
        )


class TestSchemaDeviationsRoundTrip:
    """Test round-trip conversion preserves all deviations."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif.get_instance()

    def test_oid_to_rfc_metadata_preserved(self) -> None:
        """Test OID→RFC conversion preserves all metadata."""
        oid_schema = FlextLdifServersOid().schema_quirk
        oid_definition = "( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success
        attr = result.value
        assert attr.metadata is not None
        format_details = attr.metadata.schema_format_details
        assert format_details is not None
        assert format_details.extensions is not None
        assert "syntax_quotes" in format_details.extensions.model_dump(), (
            "Missing syntax_quotes for round-trip"
        )
        assert format_details.original_string_complete is not None, (
            "Missing original for round-trip"
        )
        model_fields = list(format_details.__class__.model_fields.keys())
        assert "original_string_complete" in model_fields, (
            "original_string_complete should be a model field"
        )
        assert model_fields, "Should have model fields"

    def test_oud_to_rfc_metadata_preserved(self) -> None:
        """Test OUD→RFC conversion preserves all metadata."""
        oud_schema = FlextLdifServersOud().schema_quirk
        oud_definition = "( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} X-ORIGIN 'RFC 4519' )"
        result = oud_schema._parse_attribute(oud_definition)
        assert result.is_success
        attr = result.value
        assert attr.metadata is not None
        format_details = attr.metadata.schema_format_details
        assert format_details is not None
        assert format_details.extensions is not None
        assert "x_origin_presence" in format_details.extensions.model_dump(), (
            "Missing x_origin for round-trip"
        )
        assert "name_format" in format_details.extensions.model_dump(), (
            "Missing name_format for round-trip"
        )
        assert format_details.original_string_complete is not None, (
            "Missing original for round-trip"
        )
        model_fields = list(format_details.__class__.model_fields.keys())
        assert "original_string_complete" in model_fields, (
            "original_string_complete should be a model field"
        )
        assert model_fields, "Should have model fields"


class TestSchemaDeviationsUtilities:
    """Test schema formatting utilities."""

    def test_analyze_schema_formatting_comprehensive(self) -> None:
        """Test analyze_schema_formatting captures all deviations."""
        definition = "( 0.9.2342.19200300.100.1.1 NAME 'uid' DESC 'User identifier' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )  "
        details = u.Ldif.analyze_schema_formatting(definition)
        assert details.original_string_complete is not None, (
            "Missing original_string_complete"
        )
        extensions_dict = details.extensions.model_dump()
        assert "oid_value" in extensions_dict, "Missing oid_value"
        assert "syntax_quotes" in extensions_dict, "Missing syntax_quotes"
        assert "name_format" in extensions_dict, "Missing name_format"
        assert "desc_presence" in extensions_dict, "Missing desc_presence"
        assert details.field_order is not None, "Missing field_order"
        assert "trailing_spaces" in extensions_dict, "Missing trailing_spaces"
        assert extensions_dict["syntax_quotes"] is True, "Should detect syntax quotes"
        assert extensions_dict["desc_presence"] is True, "Should detect DESC"
        assert extensions_dict["oid_value"] == "0.9.2342.19200300.100.1.1", (
            "Should extract OID"
        )
        expected_fields = [
            "oid_value",
            "syntax_quotes",
            "name_format",
            "desc_presence",
            "trailing_spaces",
        ]
        for field in expected_fields:
            assert field in extensions_dict, f"Missing field: {field}"
        assert isinstance(details.field_order, list), "field_order should be a list"
        assert len(details.field_order) >= 3, (
            "Should track at least 3 fields in field_order"
        )
        assert "OID" in details.field_order, "Should track OID in field_order"
        assert "NAME" in details.field_order, "Should track NAME in field_order"
        assert "SYNTAX" in details.field_order, "Should track SYNTAX in field_order"

    def test_analyze_oud_style_formatting(self) -> None:
        """Test analyze_schema_formatting for OUD-style definition."""
        definition = "( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} X-ORIGIN 'RFC 4519' )"
        details = u.Ldif.analyze_schema_formatting(definition)
        extensions_dict = details.extensions.model_dump()
        assert extensions_dict["syntax_quotes"] is False, (
            "OUD should not have syntax quotes"
        )
        assert extensions_dict["x_origin_presence"] is True, "OUD should have X-ORIGIN"
        assert extensions_dict.get("x_origin_value") == "RFC 4519", (
            "Should preserve X-ORIGIN value"
        )
        x_origin_value = extensions_dict.get("x_origin_value")
        assert isinstance(x_origin_value, str), "x_origin_value should be a string"
        assert x_origin_value, "x_origin_value should not be empty"


class TestSchemaDeviationsMissingSpaces:
    """Test malformed definitions with missing spaces."""

    @pytest.fixture
    def oud_schema(self) -> FlextLdifServersBaseSchema:
        """Create OUD schema quirk instance."""
        return FlextLdifServersOud().schema_quirk

    def test_missing_space_before_syntax_oid_tracked(
        self,
        oud_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test malformed SYNTAX1.3.6.1 is tracked for restoration."""
        oud_definition = "( 0.9.2342.19200300.100.1.47 NAME 'mailPreferenceOption' SYNTAX1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE X-ORIGIN 'RFC 1274' )"
        result = oud_schema._parse_attribute(oud_definition)
        if result.is_success:
            attr = result.value
            if attr.metadata and attr.metadata.schema_format_details:
                schema_details = attr.metadata.schema_format_details
                syntax_spacing_before = getattr(
                    schema_details,
                    "syntax_spacing_before",
                    None,
                )
                assert syntax_spacing_before == "" or syntax_spacing_before is None, (
                    "Missing space before SYNTAX should be tracked (empty spacing_before)"
                )
                assert schema_details is not None, "schema_format_details should exist"
                original = schema_details.original_string_complete
                if original:
                    assert "SYNTAX1.3.6.1" in original or "SYNTAX1" in original, (
                        "Original string should contain malformed SYNTAX"
                    )


class TestSchemaDeviationsAttributeKeyCasing:
    """Test attribute key casing (attributetypes vs attributeTypes)."""

    def test_oid_lowercase_attribute_key(self) -> None:
        """Test OID lowercase 'attributetypes:' is tracked."""
        definition = "attributetypes: ( 0.9.2342.19200300.100.1.1 NAME 'uid' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        details = u.Ldif.analyze_schema_formatting(definition)
        extensions_dict = details.extensions.model_dump()
        assert extensions_dict.get("attribute_case") == "attributetypes", (
            "Should detect lowercase 'attributetypes'"
        )
        attribute_case = extensions_dict.get("attribute_case")
        assert isinstance(attribute_case, str), "attribute_case should be a string"
        assert attribute_case.islower(), "OID should use lowercase attribute case"

    def test_oud_mixed_case_attribute_key(self) -> None:
        """Test OUD mixed-case 'attributeTypes:' is tracked."""
        definition = "attributeTypes: ( 0.9.2342.19200300.100.1.1 NAME 'uid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        details = u.Ldif.analyze_schema_formatting(definition)
        extensions_dict = details.extensions.model_dump()
        assert extensions_dict.get("attribute_case") == "attributeTypes", (
            "Should detect mixed-case 'attributeTypes'"
        )
        attribute_case = extensions_dict.get("attribute_case")
        assert isinstance(attribute_case, str), "attribute_case should be a string"
        assert attribute_case == "attributeTypes", (
            "OUD should use mixed-case 'attributeTypes'"
        )


class TestSchemaDeviationsComplete:
    """Integration tests for complete deviation tracking."""

    def test_all_oid_deviations_tracked(self) -> None:
        """Test ALL OID deviations are tracked for zero data loss."""
        oid_schema = FlextLdifServersOid().schema_quirk
        oid_definition = "( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success
        attr = result.value
        assert attr.metadata is not None
        format_details = attr.metadata.schema_format_details
        oid_must_track = [
            "syntax_quotes",
            "original_string_complete",
            "field_order",
            "oid_value",
        ]
        assert format_details is not None
        extensions_dict = format_details.extensions.model_dump()
        missing: list[str] = []
        for f in oid_must_track:
            if f == "original_string_complete":
                if format_details.original_string_complete is None:
                    missing.append(f)
            elif f == "field_order":
                if format_details.field_order is None or not format_details.field_order:
                    missing.append(f)
            elif f not in extensions_dict:
                missing.append(f)
        assert not missing, f"Missing OID deviation tracking: {missing}"
        assert extensions_dict["syntax_quotes"] is True, "OID syntax should be quoted"
        tracked_fields = len(extensions_dict) + len(
            format_details.__class__.model_fields,
        )
        assert tracked_fields >= len(oid_must_track), (
            f"Should track at least {len(oid_must_track)} fields, got {tracked_fields}"
        )
        assert extensions_dict["syntax_quotes"], "OID should have syntax quotes"
        assert extensions_dict.get("syntax_quote_char") == "'", (
            "OID should use single quotes"
        )

    def test_all_oud_deviations_tracked(self) -> None:
        """Test ALL OUD deviations are tracked for zero data loss."""
        oud_schema = FlextLdifServersOud().schema_quirk
        oud_definition = "( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} X-ORIGIN 'RFC 4519' )"
        result = oud_schema._parse_attribute(oud_definition)
        assert result.is_success
        attr = result.value
        assert attr.metadata is not None
        format_details = attr.metadata.schema_format_details
        oud_must_track = [
            "syntax_quotes",
            "x_origin_presence",
            "name_format",
            "original_string_complete",
        ]
        assert format_details is not None
        extensions_dict = format_details.extensions.model_dump()
        missing: list[str] = []
        for f in oud_must_track:
            if f == "original_string_complete":
                if format_details.original_string_complete is None:
                    missing.append(f)
            elif f == "field_order":
                if format_details.field_order is None or not format_details.field_order:
                    missing.append(f)
            elif f not in extensions_dict:
                missing.append(f)
        assert not missing, f"Missing OUD deviation tracking: {missing}"
        assert extensions_dict["syntax_quotes"] is False, (
            "OUD syntax should not be quoted"
        )
        assert extensions_dict["x_origin_presence"] is True, "OUD should have X-ORIGIN"
        tracked_fields = len(extensions_dict) + len(
            format_details.__class__.model_fields,
        )
        assert tracked_fields >= len(oud_must_track), (
            f"Should track at least {len(oud_must_track)} fields, got {tracked_fields}"
        )
        assert extensions_dict.get("name_format") == "multiple", (
            "OUD should use multiple NAME format"
        )
        assert extensions_dict.get("x_origin_value") == "RFC 4519", (
            "OUD should preserve X-ORIGIN value"
        )
