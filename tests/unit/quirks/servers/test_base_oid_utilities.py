"""Test suite for FlextLdifUtilities OID extraction utilities.

Tests for extract_from_schema_object and matches_pattern utilities
in FlextLdifUtilities.OID.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


class TestExtractOidFromSchemaObject:
    """Test extract_from_schema_object utility method."""

    def test_extract_oid_from_original_format(self) -> None:
        """Test extracting OID from original_format metadata."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            metadata=FlextLdifModels.QuirkMetadata(
                original_format="( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' ... )"
            ),
        )

        result = FlextLdifUtilities.OID.extract_from_schema_object(attr)
        assert result == "2.16.840.1.113894.1.1.1"

    def test_fallback_to_model_oid(self) -> None:
        """Test fallback to model OID field when original_format not available."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn",
        )

        result = FlextLdifUtilities.OID.extract_from_schema_object(attr)
        assert result == "2.5.4.3"

    def test_extract_oid_from_objectclass(self) -> None:
        """Test extracting OID from objectClass metadata."""
        oc = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113894.1.1.5",
            name="orcldASObject",
            metadata=FlextLdifModels.QuirkMetadata(
                original_format="( 2.16.840.1.113894.1.1.5 NAME 'orcldASObject' ... )"
            ),
        )

        result = FlextLdifUtilities.OID.extract_from_schema_object(oc)
        assert result == "2.16.840.1.113894.1.1.5"

    def test_handle_missing_oid(self) -> None:
        """Test that the model OID is used when no metadata is available."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.6.0",
            name="test",
        )

        result = FlextLdifUtilities.OID.extract_from_schema_object(attr)
        assert result == "2.5.6.0"

    def test_extract_oid_with_whitespace_in_original_format(self) -> None:
        """Test OID extraction with various whitespace patterns."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.6.0",
            name="top",
            metadata=FlextLdifModels.QuirkMetadata(
                original_format="(   2.5.6.0   NAME 'top' ... )"
            ),
        )

        result = FlextLdifUtilities.OID.extract_from_schema_object(attr)
        assert result == "2.5.6.0"


class TestMatchesPattern:
    """Test matches_pattern utility method."""

    def test_handle_oid_pattern_match(self) -> None:
        """Test that OID matching the pattern returns True."""
        oid_pattern = re.compile(r"2\.16\.840\.1\.113894\.")
        # matches_pattern expects a definition string, not a SchemaAttribute
        attr_definition = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' ... )"

        result = FlextLdifUtilities.OID.matches_pattern(attr_definition, oid_pattern)
        assert result is True

    def test_handle_oid_pattern_no_match(self) -> None:
        """Test that OID not matching the pattern returns False."""
        oid_pattern = re.compile(r"2\.16\.840\.1\.113894\.")
        # matches_pattern expects a definition string, not a SchemaAttribute
        attr_definition = "( 2.5.4.3 NAME 'cn' ... )"

        result = FlextLdifUtilities.OID.matches_pattern(attr_definition, oid_pattern)
        assert result is False

    def test_handle_openldap_pattern(self) -> None:
        """Test OpenLDAP configuration OID pattern."""
        openldap_pattern = re.compile(r"1\.3\.6\.1\.4\.1\.4203\.")
        # matches_pattern expects a definition string, not a SchemaAttribute
        attr_definition = "( 1.3.6.1.4.1.4203.1.1.1 NAME 'olcBackend' ... )"

        result = FlextLdifUtilities.OID.matches_pattern(
            attr_definition, openldap_pattern
        )
        assert result is True

    def test_handle_non_matching_oid_returns_false(self) -> None:
        """Test that non-matching OID returns False."""
        oid_pattern = re.compile(r"2\.16\.840\.1\.113894\.")
        # matches_pattern expects a definition string, not a SchemaAttribute
        attr_definition = "( 2.5.4.3 NAME 'cn' ... )"

        result = FlextLdifUtilities.OID.matches_pattern(attr_definition, oid_pattern)
        assert result is False

    def test_handle_objectclass_with_pattern(self) -> None:
        """Test pattern matching on objectClass."""
        oid_pattern = re.compile(r"2\.5\.6\.")
        # matches_pattern expects a definition string, not a SchemaObjectClass
        oc_definition = "( 2.5.6.0 NAME 'top' ... )"

        result = FlextLdifUtilities.OID.matches_pattern(oc_definition, oid_pattern)
        assert result is True

    def test_handle_invalid_input_type(self) -> None:
        """Test that invalid input types return False."""
        oid_pattern = re.compile(r"2\.16\.840\.1\.113894\.")

        result = FlextLdifUtilities.OID.matches_pattern(
            "not a schema object", oid_pattern
        )
        assert result is False

    def test_handle_complex_oid_pattern(self) -> None:
        """Test matching with complex OID patterns."""
        # Pattern to match Oracle (2.16.840.1.113894) OR Novell (2.16.840.1.113719)
        oracle_or_novell = re.compile(r"2\.16\.840\.1\.11(3894|3719)\.")

        # matches_pattern expects definition strings, not SchemaAttribute objects
        oracle_attr_definition = "( 2.16.840.1.113894.1.1.1 NAME 'orclAttr' ... )"
        assert (
            FlextLdifUtilities.OID.matches_pattern(
                oracle_attr_definition, oracle_or_novell
            )
            is True
        )

        novell_attr_definition = "( 2.16.840.1.113719.1.1.1 NAME 'ndsAttr' ... )"
        assert (
            FlextLdifUtilities.OID.matches_pattern(
                novell_attr_definition, oracle_or_novell
            )
            is True
        )

        rfc_attr_definition = "( 2.5.4.3 NAME 'cn' ... )"
        assert (
            FlextLdifUtilities.OID.matches_pattern(
                rfc_attr_definition, oracle_or_novell
            )
            is False
        )
