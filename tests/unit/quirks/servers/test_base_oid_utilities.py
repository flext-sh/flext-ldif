"""Test suite for FlextLdifServersBase OID extraction utilities.

Tests for extract_oid_from_schema_object and can_handle_by_oid_pattern
utilities added to the base class.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.base import FlextLdifServersBase


class TestExtractOidFromSchemaObject:
    """Test extract_oid_from_schema_object utility method."""

    def test_extract_oid_from_original_format(self) -> None:
        """Test extracting OID from original_format metadata."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            metadata=FlextLdifModels.QuirkMetadata(
                original_format="( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' ... )"
            ),
        )

        result = FlextLdifServersBase.extract_oid_from_schema_object(attr)
        assert result == "2.16.840.1.113894.1.1.1"

    def test_fallback_to_model_oid(self) -> None:
        """Test fallback to model OID field when original_format not available."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn",
        )

        result = FlextLdifServersBase.extract_oid_from_schema_object(attr)
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

        result = FlextLdifServersBase.extract_oid_from_schema_object(oc)
        assert result == "2.16.840.1.113894.1.1.5"

    def test_handle_missing_oid(self) -> None:
        """Test that the model OID is used when no metadata is available."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.6.0",
            name="test",
        )

        result = FlextLdifServersBase.extract_oid_from_schema_object(attr)
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

        result = FlextLdifServersBase.extract_oid_from_schema_object(attr)
        assert result == "2.5.6.0"


class TestCanHandleByOidPattern:
    """Test can_handle_by_oid_pattern utility method."""

    def test_handle_oid_pattern_match(self) -> None:
        """Test that OID matching the pattern returns True."""
        oid_pattern = re.compile(r"2\.16\.840\.1\.113894\.")
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
        )

        result = FlextLdifServersBase.can_handle_by_oid_pattern(attr, oid_pattern)
        assert result is True

    def test_handle_oid_pattern_no_match(self) -> None:
        """Test that OID not matching the pattern returns False."""
        oid_pattern = re.compile(r"2\.16\.840\.1\.113894\.")
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn",
        )

        result = FlextLdifServersBase.can_handle_by_oid_pattern(attr, oid_pattern)
        assert result is False

    def test_handle_openldap_pattern(self) -> None:
        """Test OpenLDAP configuration OID pattern."""
        openldap_pattern = re.compile(r"1\.3\.6\.1\.4\.1\.4203\.")
        attr = FlextLdifModels.SchemaAttribute(
            oid="1.3.6.1.4.1.4203.1.1.1",
            name="olcBackend",
        )

        result = FlextLdifServersBase.can_handle_by_oid_pattern(attr, openldap_pattern)
        assert result is True

    def test_handle_non_matching_oid_returns_false(self) -> None:
        """Test that non-matching OID returns False."""
        oid_pattern = re.compile(r"2\.16\.840\.1\.113894\.")
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn",
        )

        result = FlextLdifServersBase.can_handle_by_oid_pattern(attr, oid_pattern)
        assert result is False

    def test_handle_objectclass_with_pattern(self) -> None:
        """Test pattern matching on objectClass."""
        oid_pattern = re.compile(r"2\.5\.6\.")
        oc = FlextLdifModels.SchemaObjectClass(
            oid="2.5.6.0",
            name="top",
        )

        result = FlextLdifServersBase.can_handle_by_oid_pattern(oc, oid_pattern)
        assert result is True

    def test_handle_invalid_input_type(self) -> None:
        """Test that invalid input types return False."""
        oid_pattern = re.compile(r"2\.16\.840\.1\.113894\.")

        result = FlextLdifServersBase.can_handle_by_oid_pattern(
            "not a schema object", oid_pattern
        )
        assert result is False

    def test_handle_complex_oid_pattern(self) -> None:
        """Test matching with complex OID patterns."""
        # Pattern to match Oracle (2.16.840.1.113894) OR Novell (2.16.840.1.113719)
        oracle_or_novell = re.compile(r"2\.16\.840\.1\.11(3894|3719)\.")

        oracle_attr = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclAttr",
        )
        assert FlextLdifServersBase.can_handle_by_oid_pattern(
            oracle_attr, oracle_or_novell
        ) is True

        novell_attr = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113719.1.1.1",
            name="ndsAttr",
        )
        assert FlextLdifServersBase.can_handle_by_oid_pattern(
            novell_attr, oracle_or_novell
        ) is True

        rfc_attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn",
        )
        assert FlextLdifServersBase.can_handle_by_oid_pattern(
            rfc_attr, oracle_or_novell
        ) is False
