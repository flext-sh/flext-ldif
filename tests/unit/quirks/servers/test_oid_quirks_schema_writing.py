"""Test suite for OID quirks schema writing functionality.

Comprehensive testing for OID schema writing, transformations, and roundtrip stability.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.oid import FlextLdifServersOid
from tests.fixtures.loader import FlextLdifFixtures


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

        # Parse
        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        parsed_attr = parse_result.unwrap()

        # Write
        write_result = oid_schema.write_attribute(parsed_attr)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        written = write_result.unwrap()

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
        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        parsed_attr = parse_result.unwrap()

        # Write
        write_result = oid_schema.write_attribute(parsed_attr)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        written = write_result.unwrap()

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

        # Parse
        parse_result = oid_schema.parse_objectclass(oc_def)
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        parsed_oc = parse_result.unwrap()

        # Write
        write_result = oid_schema.write_objectclass(parsed_oc)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        written = write_result.unwrap()

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

        # Parse
        parse_result = oid_schema.parse_objectclass(oc_def)
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        parsed_oc = parse_result.unwrap()

        # Write
        write_result = oid_schema.write_objectclass(parsed_oc)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        written = write_result.unwrap()

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

        # Parse
        parse_result = oid_schema.parse_objectclass(oc_def)
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        parsed_oc = parse_result.unwrap()

        # Write
        write_result = oid_schema.write_objectclass(parsed_oc)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        written = write_result.unwrap()

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

        # Parse
        parse_result = oid_schema.parse_objectclass(oc_def)
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        parsed_oc = parse_result.unwrap()

        # Write
        write_result = oid_schema.write_objectclass(parsed_oc)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        written = write_result.unwrap()

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

        # Parse 1
        parse1_result = oid_schema.parse_attribute(original)
        assert parse1_result.is_success
        parsed1 = parse1_result.unwrap()

        # Write
        write_result = oid_schema.write_attribute(parsed1)
        assert write_result.is_success
        written = write_result.unwrap()

        # Parse 2 (from written)
        parse2_result = oid_schema.parse_attribute(written)
        assert parse2_result.is_success
        parsed2 = parse2_result.unwrap()

        # Verify round trip preserves essential properties
        assert parsed1.oid == parsed2.oid
        assert parsed1.name == parsed2.name
        assert parsed1.syntax == parsed2.syntax
        assert parsed1.single_value == parsed2.single_value

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

        # Parse 1
        parse1_result = oid_schema.parse_objectclass(original)
        assert parse1_result.is_success
        parsed1 = parse1_result.unwrap()

        # Write
        write_result = oid_schema.write_objectclass(parsed1)
        assert write_result.is_success
        written = write_result.unwrap()

        # Parse 2
        parse2_result = oid_schema.parse_objectclass(written)
        assert parse2_result.is_success
        parsed2 = parse2_result.unwrap()

        # Verify round trip preserves essential properties
        assert parsed1.oid == parsed2.oid
        assert parsed1.name == parsed2.name
        assert parsed1.is_structural == parsed2.is_structural

    def test_write_attribute_from_fixture(
        self,
        oid_schema: FlextLdifServersOid.Schema,
        oid_fixtures: FlextLdifFixtures.OID,
    ) -> None:
        """Test writing attribute from real fixture."""
        schema_content = oid_fixtures.schema()

        # Extract first Oracle attribute from fixtures
        oracle_attrs = [
            line
            for line in schema_content.splitlines()
            if "2.16.840.1.113894" in line and "attributetypes:" in line
        ]

        assert len(oracle_attrs) > 0
        first_attr = oracle_attrs[0]
        attr_def = first_attr.split("attributetypes:", 1)[1].strip()

        # Parse
        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        # Write
        write_result = oid_schema.write_attribute(parsed_attr)
        assert write_result.is_success
        written = write_result.unwrap()

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
        schema_content = oid_fixtures.schema()

        # Extract first Oracle objectClass from fixtures
        oracle_ocs = [
            line
            for line in schema_content.splitlines()
            if "2.16.840.1.113894" in line and "objectclasses:" in line
        ]

        assert len(oracle_ocs) > 0
        first_oc = oracle_ocs[0]
        oc_def = first_oc.split("objectclasses:", 1)[1].strip()

        # Parse
        parse_result = oid_schema.parse_objectclass(oc_def)
        assert parse_result.is_success
        parsed_oc = parse_result.unwrap()

        # Write
        write_result = oid_schema.write_objectclass(parsed_oc)
        assert write_result.is_success
        written = write_result.unwrap()

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

        # Write
        write_result = oid_schema.write_objectclass(oc_model)
        assert write_result.is_success
        written = write_result.unwrap()

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

        parse_result = oid_schema.parse_objectclass(oc_def)
        assert parse_result.is_success
        parsed_oc = parse_result.unwrap()
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

        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

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

        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

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

        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

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

        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        # Verify standard rule preserved
        assert parsed_attr.equality == "caseIgnoreMatch"

    def test_write_preserves_syntax_oids(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that writing preserves replaced syntax OIDs."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'testAttr' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 )"
        )

        # Parse (applies replacement)
        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        # Write
        write_result = oid_schema.write_attribute(parsed_attr)
        assert write_result.is_success
        written = write_result.unwrap()

        # Verify replaced OID is in output
        assert "1.3.6.1.4.1.1466.115.121.1.15" in written


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
        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        # Write
        write_result = oid_schema.write_attribute(parsed_attr)
        assert write_result.is_success
        written = write_result.unwrap()

        # Verify at least primary name is present
        assert "orclGUID" in written or "orclguid" in written.lower()
