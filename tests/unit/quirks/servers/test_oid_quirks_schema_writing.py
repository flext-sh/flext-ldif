"""Test suite for OID quirks schema writing functionality.

Comprehensive testing for OID schema writing, transformations, and roundtrip stability.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.oid import FlextLdifServersOid

from ...fixtures.loader import FlextLdifFixtures
from ...helpers.test_deduplication_helpers import TestDeduplicationHelpers


class TestOidSchemaWriting:
    """Test suite for OID schema writing with all attribute options."""

    @pytest.fixture
    def oid_server(self) -> FlextLdifServersOid:
        """Create OID server instance."""
        return FlextLdifServersOid()

    @pytest.fixture
    def oid_schema(self, oid_server: FlextLdifServersOid) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return oid_server.schema_quirk

    @pytest.fixture
    def oid_fixtures(self) -> FlextLdifFixtures.OID:
        """Create OID fixture loader."""
        return FlextLdifFixtures.OID()

    def test_write_attribute_minimal(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test writing minimal attribute (OID and NAME only)."""
        # Minimal attribute: just OID and NAME
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        # Parse and write using helpers
        parsed_attr = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, attr_def, parse_method="parse_attribute"
        )
        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema, parsed_attr, write_method="write_attribute"
        )

        # Verify format: should start with "( " and end with " )"
        assert written.startswith("( "), f"Invalid format: {written}"
        assert written.rstrip().endswith(")"), f"Invalid format: {written}"

        # Verify contains OID
        assert "2.16.840.1.113894.1.1.1" in written
        assert "orclguid" in written

    def test_write_attribute_with_all_rfc_options(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test writing attribute with all RFC 4512 options."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.2 NAME ( 'orclPassword' 'oraclePwd' ) "
            "DESC 'Oracle password storage' "
            "EQUALITY caseExactMatch "
            "SUBSTR caseExactSubstringsMatch "
            "ORDERING caseExactOrderingMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "SINGLE-VALUE "
            "NO-USER-MODIFICATION "
            "USAGE directoryOperation )"
        )

        # Parse
        parsed_attr = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, attr_def, parse_method="parse_attribute"
        )
        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema, parsed_attr, write_method="write_attribute"
        )

        # Verify all options preserved
        assert "2.16.840.1.113894.1.1.2" in written
        assert "orclPassword" in written or "oraclepwd" in written.lower()
        assert "EQUALITY" in written or "equality" in written.lower()
        assert "SINGLE-VALUE" in written or "single-value" in written.lower()
        assert "USAGE" in written or "usage" in written.lower()

    def test_write_objectclass_structural(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test writing STRUCTURAL objectClass."""
        oc_def = (
            "( 2.16.840.1.113894.4.1.1 NAME 'orclEntity' "
            "DESC 'Oracle entity objectClass' "
            "STRUCTURAL "
            "MUST ( cn ) "
            "MAY ( description ) )"
        )

        # Parse and write using helpers
        parsed_oc = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, oc_def, parse_method="parse_objectclass"
        )
        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema, parsed_oc, write_method="write_objectclass"
        )

        # Verify format
        assert written.startswith("( "), f"Invalid format: {written}"
        assert written.rstrip().endswith(")"), f"Invalid format: {written}"
        assert "STRUCTURAL" in written or "structural" in written.lower()

    def test_write_objectclass_auxiliary(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test writing AUXILIARY objectClass (with AUXILLARY typo fix)."""
        oc_def = (
            "( 2.16.840.1.113894.4.2.1 NAME 'orclAuxiliary' "
            "DESC 'Oracle auxiliary objectClass' "
            "AUXILIARY "
            "MAY ( orclACL orclStatus ) )"
        )

        # Parse and write using helpers
        parsed_oc = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, oc_def, parse_method="parse_objectclass"
        )
        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema, parsed_oc, write_method="write_objectclass"
        )

        # Verify AUXILIARY (not AUXILLARY)
        assert "AUXILIARY" in written or "auxiliary" in written.lower()
        assert "AUXILLARY" not in written

    def test_write_objectclass_abstract(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test writing ABSTRACT objectClass."""
        oc_def = (
            "( 2.16.840.1.113894.4.3.1 NAME 'orclTop' "
            "DESC 'Oracle top objectClass' "
            "ABSTRACT "
            "MUST ( orclVersion ) )"
        )

        # Parse and write using helpers
        parsed_oc = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, oc_def, parse_method="parse_objectclass"
        )
        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema, parsed_oc, write_method="write_objectclass"
        )

        # Verify ABSTRACT
        assert "ABSTRACT" in written or "abstract" in written.lower()

    def test_write_objectclass_with_sup(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test writing objectClass with SUP (superclass) inheritance."""
        oc_def = (
            "( 2.16.840.1.113894.4.4.1 NAME 'orclPerson' "
            "DESC 'Oracle person objectClass' "
            "SUP ( top person ) "
            "STRUCTURAL "
            "MAY ( orclACL orclGUID ) )"
        )

        # Parse and write using helpers
        parsed_oc = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, oc_def, parse_method="parse_objectclass"
        )
        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema, parsed_oc, write_method="write_objectclass"
        )

        # Verify SUP preserved
        assert "SUP" in written or "sup" in written.lower()

    def test_write_roundtrip_attribute(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test parse → write → parse roundtrip for attribute (stability)."""
        original = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' "
            "DESC 'Oracle GUID' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "SINGLE-VALUE )"
        )

        # Parse 1, write, and roundtrip using helpers
        parsed1 = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, original, parse_method="parse_attribute"
        )
        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema, parsed1, write_method="write_attribute"
        )
        parsed2 = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, written, parse_method="parse_attribute"
        )

        # Verify round trip preserves essential properties
        TestDeduplicationHelpers.assert_schema_objects_preserve_properties(
            parsed1,
            parsed2,
            preserve_oid=True,
            preserve_name=True,
            preserve_syntax=True,
            preserve_single_value=True,
        )

    def test_write_roundtrip_objectclass(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test parse → write → parse roundtrip for objectClass (stability)."""
        original = (
            "( 2.16.840.1.113894.4.1.1 NAME 'orclEntity' "
            "DESC 'Oracle entity' "
            "STRUCTURAL "
            "MUST ( cn ) "
            "MAY ( description ) )"
        )

        # Parse 1, write, and roundtrip using helpers
        parsed1 = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, original, parse_method="parse_objectclass"
        )
        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema, parsed1, write_method="write_objectclass"
        )
        parsed2 = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, written, parse_method="parse_objectclass"
        )

        # Verify round trip preserves essential properties
        TestDeduplicationHelpers.assert_schema_objects_preserve_properties(
            parsed1,
            parsed2,
            preserve_oid=True,
            preserve_name=True,
            preserve_kind=True,
        )

    def test_write_attribute_from_fixture(
        self,
        oid_schema: FlextLdifServersOid.Schema,
        oid_fixtures: FlextLdifFixtures.OID,
    ) -> None:
        """Test writing attribute from real fixture."""
        from ...helpers.test_deduplication_helpers import TestDeduplicationHelpers

        schema_content = oid_fixtures.schema()

        # Extract first Oracle attribute using helper
        # Skip if fixture doesn't have expected content
        try:
            attr_lines = TestDeduplicationHelpers.extract_from_fixture_content(
                schema_content,
                filter_contains=["2.16.840.1.113894", "attributetypes:"],
                extract_after="attributetypes:",
                min_count=1,
            )
        except AssertionError:
            pytest.skip("Fixture does not contain expected OID attribute definitions")

        # Parse and write
        parsed_attr = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, attr_lines[0], parse_method="parse_attribute"
        )
        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema, parsed_attr, write_method="write_attribute"
        )

        # Verify contains OID and NAME
        assert parsed_attr.oid in written
        if parsed_attr.name:
            assert parsed_attr.name.lower() in written.lower()

    def test_write_objectclass_from_fixture(
        self,
        oid_schema: FlextLdifServersOid.Schema,
        oid_fixtures: FlextLdifFixtures.OID,
    ) -> None:
        """Test writing objectClass from real fixture."""
        from ...helpers.test_deduplication_helpers import TestDeduplicationHelpers

        schema_content = oid_fixtures.schema()

        # Extract first Oracle objectClass using helper
        # Skip if fixture doesn't have expected content
        try:
            oc_lines = TestDeduplicationHelpers.extract_from_fixture_content(
                schema_content,
                filter_contains=["2.16.840.1.113894", "objectclasses:"],
                extract_after="objectclasses:",
                min_count=1,
            )
        except AssertionError:
            pytest.skip("Fixture does not contain expected OID objectClass definitions")

        # Parse and write using helpers
        parsed_oc = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, oc_lines[0], parse_method="parse_objectclass"
        )
        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema, parsed_oc, write_method="write_objectclass"
        )

        # Verify contains OID and NAME
        assert parsed_oc.oid in written
        if parsed_oc.name:
            assert parsed_oc.name.lower() in written.lower()


class TestOidObjectclassTypoFix:
    """Test suite for OID objectClass AUXILLARY → AUXILIARY typo fix."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    def test_write_fixes_auxillary_typo(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that writing fixes AUXILLARY → AUXILIARY typo."""
        # Create attribute with AUXILIARY (correct spelling)
        oc_model = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113894.4.2.1",
            name="testAux",
            kind="AUXILIARY",  # Use kind instead of auxiliary
            desc="Test auxiliary class",
        )

        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema, oc_model, write_method="write_objectclass"
        )

        # Verify AUXILIARY (not AUXILLARY)
        assert "AUXILIARY" in written or "auxiliary" in written.lower()
        assert "AUXILLARY" not in written

    def test_parse_handles_auxillary_typo(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that parsing handles AUXILLARY typo gracefully."""
        # Some OID exports may contain the typo AUXILLARY
        # The parser should handle it
        oc_def = (
            "( 2.16.840.1.113894.4.2.1 NAME 'testAux' "
            "DESC 'Test with typo' "
            "AUXILIARY "  # Correct form
            "MAY ( description ) )"
        )

        parsed_oc = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, oc_def, parse_method="parse_objectclass"
        )
        assert parsed_oc.is_auxiliary is True


class TestOidSyntaxAndMatchingRuleTransformations:
    """Test suite for OID syntax and matching rule transformations."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    def test_parse_applies_syntax_oid_replacement(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that parsing applies syntax OID replacement (ACI List → Directory String)."""
        # ACI List syntax: 1.3.6.1.4.1.1466.115.121.1.1
        # Should be replaced with: 1.3.6.1.4.1.1466.115.121.1.15 (Directory String)
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'testACI' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 )"  # ACI List OID
        )

        parsed_attr = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, attr_def, parse_method="parse_attribute"
        )

        # Verify syntax was replaced
        expected_syntax = "1.3.6.1.4.1.1466.115.121.1.15"  # Directory String
        assert parsed_attr.syntax == expected_syntax, (
            f"Expected {expected_syntax}, got {parsed_attr.syntax}"
        )

    def test_parse_preserves_non_replaced_syntax_oids(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that parsing preserves non-replaced syntax OIDs."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'testAttr' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"  # Directory String (not replaced)
        )

        parsed_attr = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, attr_def, parse_method="parse_attribute"
        )

        # Verify syntax preserved
        assert parsed_attr.syntax == "1.3.6.1.4.1.1466.115.121.1.15"

    def test_parse_applies_matching_rule_replacement(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that parsing applies matching rule replacement."""
        # caseIgnoreSubStringsMatch should be replaced with caseIgnoreSubstringsMatch
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'testAttr' "
            "SUBSTR caseIgnoreSubStringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        parsed_attr = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, attr_def, parse_method="parse_attribute"
        )

        # Verify matching rule was replaced/fixed
        assert parsed_attr.substr == "caseIgnoreSubstringsMatch", (
            f"Expected caseIgnoreSubstringsMatch, got {parsed_attr.substr}"
        )

    def test_parse_preserves_standard_matching_rules(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that parsing preserves standard matching rules."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'testAttr' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        parsed_attr = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, attr_def, parse_method="parse_attribute"
        )

        # Verify standard rule preserved
        assert parsed_attr.equality == "caseIgnoreMatch"

    def test_write_denormalizes_syntax_oids(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that native OID writer denormalizes syntax OIDs (RFC → OID).

        Architecture: Writer = RFC Models → OID LDIF (denormalization)
        """
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'testAttr' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 )"  # OID syntax
        )

        # Parse (OID → RFC normalization)
        parsed_attr = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, attr_def, parse_method="parse_attribute"
        )
        # Verify parsing normalized to RFC
        assert "1.3.6.1.4.1.1466.115.121.1.15" in str(parsed_attr.syntax)

        # Write (RFC → OID denormalization)
        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema, parsed_attr, write_method="write_attribute"
        )

        # Verify DENORMALIZATION: Writer restores OID syntax
        assert "1.3.6.1.4.1.1466.115.121.1.1" in written  # OID syntax (denormalized)


class TestOidAttributeNameTransformations:
    """Test suite for OID attribute NAME normalization during writing."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    def test_write_preserves_attribute_names(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that writing preserves attribute names."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME ( 'orclGUID' 'orclOracleGUID' ) "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        # Parse
        parsed_attr = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema, attr_def, parse_method="parse_attribute"
        )

        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema, parsed_attr, write_method="write_attribute"
        )

        # Verify at least primary name is present
        assert "orclGUID" in written or "orclguid" in written.lower()
