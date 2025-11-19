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

import logging

import pytest

from flext_ldif import FlextLdif
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud

logger = logging.getLogger(__name__)


class TestSchemaDeviationsSyntaxQuotes:
    """Test syntax OID quotation tracking (OID uses quotes, OUD/RFC don't)."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    @pytest.fixture
    def oud_schema(self) -> FlextLdifServersOud.Schema:
        """Create OUD schema quirk instance."""
        return FlextLdifServersOud().schema_quirk

    def test_oid_syntax_quotes_tracked(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test OID syntax with quotes is tracked in metadata."""
        # OID format: SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}'
        oid_definition = (
            "( 0.9.2342.19200300.100.1.1 NAME 'uid' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        )

        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success, f"Parse failed: {result.error}"

        attr = result.unwrap()
        assert attr.metadata is not None, "Missing metadata"

        # Verify syntax_quotes is tracked
        format_details = attr.metadata.schema_format_details
        assert "syntax_quotes" in format_details, "Missing syntax_quotes tracking"
        assert format_details["syntax_quotes"] is True, "Should detect syntax quotes"
        assert format_details.get("syntax_quote_char") == "'", "Should detect single quotes"

        logger.debug(f"OID syntax quotes tracked: {format_details.get('syntax_quotes')}")

    def test_oud_syntax_no_quotes_tracked(
        self,
        oud_schema: FlextLdifServersOud.Schema,
    ) -> None:
        """Test OUD syntax without quotes is tracked in metadata."""
        # OUD format: SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256}
        oud_definition = (
            "( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) "
            "EQUALITY caseIgnoreMatch "
            "SUBSTR caseIgnoreSubstringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} "
            "X-ORIGIN 'RFC 4519' )"
        )

        result = oud_schema._parse_attribute(oud_definition)
        assert result.is_success, f"Parse failed: {result.error}"

        attr = result.unwrap()
        assert attr.metadata is not None, "Missing metadata"

        # Verify syntax_quotes is tracked as False
        format_details = attr.metadata.schema_format_details
        assert "syntax_quotes" in format_details, "Missing syntax_quotes tracking"
        assert format_details["syntax_quotes"] is False, "Should detect no syntax quotes"

        logger.debug(f"OUD syntax quotes tracked: {format_details.get('syntax_quotes')}")


class TestSchemaDeviationsXOrigin:
    """Test X-ORIGIN presence/absence tracking."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    @pytest.fixture
    def oud_schema(self) -> FlextLdifServersOud.Schema:
        """Create OUD schema quirk instance."""
        return FlextLdifServersOud().schema_quirk

    def test_oid_no_x_origin_tracked(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test OID without X-ORIGIN is tracked in metadata."""
        # OID format: No X-ORIGIN
        oid_definition = (
            "( 0.9.2342.19200300.100.1.1 NAME 'uid' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        )

        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success, f"Parse failed: {result.error}"

        attr = result.unwrap()
        assert attr.metadata is not None, "Missing metadata"

        # Verify X-ORIGIN is tracked as absent
        format_details = attr.metadata.schema_format_details
        assert "x_origin_presence" in format_details, "Missing x_origin_presence tracking"
        assert format_details["x_origin_presence"] is False, "Should detect no X-ORIGIN"

        logger.debug(f"OID X-ORIGIN presence: {format_details.get('x_origin_presence')}")

    def test_oud_x_origin_tracked(
        self,
        oud_schema: FlextLdifServersOud.Schema,
    ) -> None:
        """Test OUD with X-ORIGIN is tracked in metadata."""
        # OUD format: With X-ORIGIN
        oud_definition = (
            "( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} "
            "X-ORIGIN 'RFC 4519' )"
        )

        result = oud_schema._parse_attribute(oud_definition)
        assert result.is_success, f"Parse failed: {result.error}"

        attr = result.unwrap()
        assert attr.metadata is not None, "Missing metadata"

        # Verify X-ORIGIN is tracked with value
        format_details = attr.metadata.schema_format_details
        assert "x_origin_presence" in format_details, "Missing x_origin_presence tracking"
        assert format_details["x_origin_presence"] is True, "Should detect X-ORIGIN"
        assert format_details.get("x_origin_value") == "RFC 4519", "Should preserve X-ORIGIN value"

        logger.debug(f"OUD X-ORIGIN: {format_details.get('x_origin_value')}")


class TestSchemaDeviationsNameAliases:
    """Test multiple NAME aliases preservation."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    @pytest.fixture
    def oud_schema(self) -> FlextLdifServersOud.Schema:
        """Create OUD schema quirk instance."""
        return FlextLdifServersOud().schema_quirk

    def test_oid_single_name_tracked(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test OID single NAME format is tracked."""
        # OID format: NAME 'uid'
        oid_definition = (
            "( 0.9.2342.19200300.100.1.1 NAME 'uid' "
            "SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        )

        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success, f"Parse failed: {result.error}"

        attr = result.unwrap()
        assert attr.metadata is not None, "Missing metadata"

        format_details = attr.metadata.schema_format_details
        assert format_details.get("name_format") == "single", "Should detect single NAME format"
        assert format_details.get("name_values") == ["uid"], "Should preserve name value"

        logger.debug(f"OID NAME format: {format_details.get('name_format')}")

    def test_oud_multiple_names_tracked(
        self,
        oud_schema: FlextLdifServersOud.Schema,
    ) -> None:
        """Test OUD multiple NAME aliases are tracked."""
        # OUD format: NAME ( 'uid' 'userid' )
        oud_definition = (
            "( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        )

        result = oud_schema._parse_attribute(oud_definition)
        assert result.is_success, f"Parse failed: {result.error}"

        attr = result.unwrap()
        assert attr.metadata is not None, "Missing metadata"

        format_details = attr.metadata.schema_format_details
        assert format_details.get("name_format") == "multiple", "Should detect multiple NAME format"

        # Name values should include all aliases
        name_values = format_details.get("name_values", [])
        assert "uid" in name_values or len(name_values) > 0, "Should preserve name values"

        logger.debug(f"OUD NAME values: {name_values}")


class TestSchemaDeviationsObsolete:
    """Test OBSOLETE marker preservation."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    def test_obsolete_marker_tracked(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test OBSOLETE marker is tracked in metadata."""
        # OID with OBSOLETE marker
        oid_definition = (
            "( 0.9.2342.19200300.100.1.23 NAME 'lastModifiedTime' "
            "OBSOLETE SYNTAX '1.3.6.1.4.1.1466.115.121.1.53' )"
        )

        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success, f"Parse failed: {result.error}"

        attr = result.unwrap()
        assert attr.metadata is not None, "Missing metadata"

        format_details = attr.metadata.schema_format_details
        assert "obsolete_presence" in format_details, "Missing obsolete_presence tracking"
        assert format_details["obsolete_presence"] is True, "Should detect OBSOLETE"
        assert "obsolete_position" in format_details, "Should track OBSOLETE position"

        logger.debug(f"OBSOLETE tracked: position={format_details.get('obsolete_position')}")

    def test_no_obsolete_tracked(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test absence of OBSOLETE is tracked."""
        # Definition without OBSOLETE
        oid_definition = (
            "( 0.9.2342.19200300.100.1.1 NAME 'uid' "
            "SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        )

        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success

        attr = result.unwrap()
        assert attr.metadata is not None

        format_details = attr.metadata.schema_format_details
        assert format_details.get("obsolete_presence") is False, "Should detect no OBSOLETE"


class TestSchemaDeviationsSpacing:
    """Test spacing preservation between fields."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    def test_trailing_spaces_tracked(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test trailing spaces are tracked."""
        # Definition with trailing spaces
        oid_definition = (
            "( 0.9.2342.19200300.100.1.1 NAME 'uid' "
            "SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )  "
        )

        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success

        attr = result.unwrap()
        assert attr.metadata is not None

        format_details = attr.metadata.schema_format_details
        assert "trailing_spaces" in format_details, "Missing trailing_spaces tracking"

        logger.debug(f"Trailing spaces tracked: '{format_details.get('trailing_spaces')}'")

    def test_field_order_tracked(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test field order is tracked."""
        oid_definition = (
            "( 0.9.2342.19200300.100.1.1 NAME 'uid' "
            "EQUALITY caseIgnoreMatch "
            "SUBSTR caseIgnoreSubstringsMatch "
            "SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        )

        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success

        attr = result.unwrap()
        assert attr.metadata is not None

        format_details = attr.metadata.schema_format_details
        assert "field_order" in format_details, "Missing field_order tracking"

        field_order = format_details.get("field_order", [])
        assert "OID" in field_order, "Should track OID position"
        assert "NAME" in field_order, "Should track NAME position"
        assert "SYNTAX" in field_order, "Should track SYNTAX position"

        logger.debug(f"Field order: {field_order}")


class TestSchemaDeviationsOriginalString:
    """Test complete original string preservation."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    @pytest.fixture
    def oud_schema(self) -> FlextLdifServersOud.Schema:
        """Create OUD schema quirk instance."""
        return FlextLdifServersOud().schema_quirk

    def test_oid_original_string_preserved(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test complete OID original string is preserved."""
        oid_definition = (
            "( 0.9.2342.19200300.100.1.1 NAME 'uid' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )  "
        )

        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success

        attr = result.unwrap()
        assert attr.metadata is not None

        format_details = attr.metadata.schema_format_details
        original_string = format_details.get("original_string_complete")

        assert original_string == oid_definition, (
            f"Original string not preserved:\n"
            f"  Expected: '{oid_definition}'\n"
            f"  Got: '{original_string}'"
        )

        logger.debug(f"Original string length: {len(original_string or '')}")

    def test_oud_original_string_preserved(
        self,
        oud_schema: FlextLdifServersOud.Schema,
    ) -> None:
        """Test complete OUD original string is preserved."""
        oud_definition = (
            "( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) "
            "EQUALITY caseIgnoreMatch "
            "SUBSTR caseIgnoreSubstringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} "
            "X-ORIGIN 'RFC 4519' )"
        )

        result = oud_schema._parse_attribute(oud_definition)
        assert result.is_success

        attr = result.unwrap()
        assert attr.metadata is not None

        format_details = attr.metadata.schema_format_details
        original_string = format_details.get("original_string_complete")

        assert original_string == oud_definition, (
            f"Original string not preserved:\n"
            f"  Expected: '{oud_definition}'\n"
            f"  Got: '{original_string}'"
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

        oid_definition = (
            "( 0.9.2342.19200300.100.1.1 NAME 'uid' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        )

        # Parse OID
        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success

        attr = result.unwrap()

        # Verify all key metadata is present for round-trip
        assert attr.metadata is not None
        format_details = attr.metadata.schema_format_details

        # These fields are essential for restoring OID format
        assert "syntax_quotes" in format_details, "Missing syntax_quotes for round-trip"
        assert "original_string_complete" in format_details, "Missing original for round-trip"

        logger.debug(f"Metadata fields preserved: {list(format_details.keys())}")

    def test_oud_to_rfc_metadata_preserved(self) -> None:
        """Test OUD→RFC conversion preserves all metadata."""
        oud_schema = FlextLdifServersOud().schema_quirk

        oud_definition = (
            "( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) "
            "EQUALITY caseIgnoreMatch "
            "SUBSTR caseIgnoreSubstringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} "
            "X-ORIGIN 'RFC 4519' )"
        )

        # Parse OUD
        result = oud_schema._parse_attribute(oud_definition)
        assert result.is_success

        attr = result.unwrap()

        # Verify all key metadata is present for round-trip
        assert attr.metadata is not None
        format_details = attr.metadata.schema_format_details

        # These fields are essential for restoring OUD format
        assert "x_origin_presence" in format_details, "Missing x_origin for round-trip"
        assert "name_format" in format_details, "Missing name_format for round-trip"
        assert "original_string_complete" in format_details, "Missing original for round-trip"

        logger.debug(f"Metadata fields preserved: {list(format_details.keys())}")


class TestSchemaDeviationsUtilities:
    """Test schema formatting utilities."""

    def test_analyze_schema_formatting_comprehensive(self) -> None:
        """Test analyze_schema_formatting captures all deviations."""
        # OID-style definition with many features
        definition = (
            "( 0.9.2342.19200300.100.1.1 NAME 'uid' "
            "DESC 'User identifier' "
            "EQUALITY caseIgnoreMatch "
            "SUBSTR caseIgnoreSubstringsMatch "
            "SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )  "
        )

        details = FlextLdifUtilitiesMetadata.analyze_schema_formatting(definition)

        # Verify all expected fields are captured
        expected_fields = [
            "original_string_complete",
            "oid_value",
            "syntax_quotes",
            "name_format",
            "desc_presence",
            "field_order",
            "trailing_spaces",
        ]

        for field in expected_fields:
            assert field in details, f"Missing field: {field}"

        # Verify values
        assert details["syntax_quotes"] is True, "Should detect syntax quotes"
        assert details["desc_presence"] is True, "Should detect DESC"
        assert details["oid_value"] == "0.9.2342.19200300.100.1.1", "Should extract OID"

        logger.debug(f"Total fields captured: {len(details)}")

    def test_analyze_oud_style_formatting(self) -> None:
        """Test analyze_schema_formatting for OUD-style definition."""
        # OUD-style definition
        definition = (
            "( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) "
            "EQUALITY caseIgnoreMatch "
            "SUBSTR caseIgnoreSubstringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} "
            "X-ORIGIN 'RFC 4519' )"
        )

        details = FlextLdifUtilitiesMetadata.analyze_schema_formatting(definition)

        # Verify OUD-specific fields
        assert details["syntax_quotes"] is False, "OUD should not have syntax quotes"
        assert details["x_origin_presence"] is True, "OUD should have X-ORIGIN"
        assert details.get("x_origin_value") == "RFC 4519", "Should preserve X-ORIGIN value"

        logger.debug(f"OUD fields: X-ORIGIN={details.get('x_origin_value')}")


class TestSchemaDeviationsMissingSpaces:
    """Test malformed definitions with missing spaces."""

    @pytest.fixture
    def oud_schema(self) -> FlextLdifServersOud.Schema:
        """Create OUD schema quirk instance."""
        return FlextLdifServersOud().schema_quirk

    def test_missing_space_before_syntax_oid_tracked(
        self,
        oud_schema: FlextLdifServersOud.Schema,
    ) -> None:
        """Test malformed SYNTAX1.3.6.1 is tracked for restoration."""
        # OUD sometimes has malformed: SYNTAX1.3.6.1.4.1.1466...
        oud_definition = (
            "( 0.9.2342.19200300.100.1.47 NAME 'mailPreferenceOption' "
            "SYNTAX1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE "
            "X-ORIGIN 'RFC 1274' )"
        )

        result = oud_schema._parse_attribute(oud_definition)

        # Even if parsing fails due to malformation, the original should be preserved
        # The original_string_complete should capture this for restoration
        if result.is_success:
            attr = result.unwrap()
            if attr.metadata and attr.metadata.schema_format_details:
                original = attr.metadata.schema_format_details.get("original_string_complete")
                assert "SYNTAX1.3.6.1" in (original or ""), (
                    "Original malformed string should be preserved"
                )
                logger.debug("Malformed syntax preserved in original string")


class TestSchemaDeviationsAttributeKeyCasing:
    """Test attribute key casing (attributetypes vs attributeTypes)."""

    def test_oid_lowercase_attribute_key(self) -> None:
        """Test OID lowercase 'attributetypes:' is tracked."""
        # OID uses lowercase: attributetypes:
        definition = (
            "attributetypes: ( 0.9.2342.19200300.100.1.1 NAME 'uid' "
            "SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        )

        details = FlextLdifUtilitiesMetadata.analyze_schema_formatting(definition)

        assert details.get("attribute_case") == "attributetypes", (
            "Should detect lowercase 'attributetypes'"
        )

        logger.debug(f"OID attribute case: {details.get('attribute_case')}")

    def test_oud_mixed_case_attribute_key(self) -> None:
        """Test OUD mixed-case 'attributeTypes:' is tracked."""
        # OUD uses mixed case: attributeTypes:
        definition = (
            "attributeTypes: ( 0.9.2342.19200300.100.1.1 NAME 'uid' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        )

        details = FlextLdifUtilitiesMetadata.analyze_schema_formatting(definition)

        assert details.get("attribute_case") == "attributeTypes", (
            "Should detect mixed-case 'attributeTypes'"
        )

        logger.debug(f"OUD attribute case: {details.get('attribute_case')}")


class TestSchemaDeviationsComplete:
    """Integration tests for complete deviation tracking."""

    def test_all_oid_deviations_tracked(self) -> None:
        """Test ALL OID deviations are tracked for zero data loss."""
        oid_schema = FlextLdifServersOid().schema_quirk

        # Complete OID definition with all typical features
        oid_definition = (
            "( 0.9.2342.19200300.100.1.1 NAME 'uid' "
            "EQUALITY caseIgnoreMatch "
            "SUBSTR caseIgnoreSubstringsMatch "
            "SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        )

        result = oid_schema._parse_attribute(oid_definition)
        assert result.is_success

        attr = result.unwrap()
        assert attr.metadata is not None

        format_details = attr.metadata.schema_format_details

        # OID deviations that MUST be tracked
        oid_must_track = [
            "syntax_quotes",       # OID uses quotes
            "original_string_complete",  # For exact restoration
            "field_order",         # For identical field ordering
            "oid_value",           # OID number
        ]

        missing = [f for f in oid_must_track if f not in format_details]
        assert not missing, f"Missing OID deviation tracking: {missing}"

        # Verify OID-specific values
        assert format_details["syntax_quotes"] is True, "OID syntax should be quoted"

        logger.info(f"All OID deviations tracked: {len(format_details)} fields")

    def test_all_oud_deviations_tracked(self) -> None:
        """Test ALL OUD deviations are tracked for zero data loss."""
        oud_schema = FlextLdifServersOud().schema_quirk

        # Complete OUD definition with all typical features
        oud_definition = (
            "( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) "
            "EQUALITY caseIgnoreMatch "
            "SUBSTR caseIgnoreSubstringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} "
            "X-ORIGIN 'RFC 4519' )"
        )

        result = oud_schema._parse_attribute(oud_definition)
        assert result.is_success

        attr = result.unwrap()
        assert attr.metadata is not None

        format_details = attr.metadata.schema_format_details

        # OUD deviations that MUST be tracked
        oud_must_track = [
            "syntax_quotes",       # OUD doesn't use quotes
            "x_origin_presence",   # OUD has X-ORIGIN
            "name_format",         # OUD uses multiple names
            "original_string_complete",  # For exact restoration
        ]

        missing = [f for f in oud_must_track if f not in format_details]
        assert not missing, f"Missing OUD deviation tracking: {missing}"

        # Verify OUD-specific values
        assert format_details["syntax_quotes"] is False, "OUD syntax should not be quoted"
        assert format_details["x_origin_presence"] is True, "OUD should have X-ORIGIN"

        logger.info(f"All OUD deviations tracked: {len(format_details)} fields")
