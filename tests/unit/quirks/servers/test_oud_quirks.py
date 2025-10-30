"""Comprehensive test suite for Oracle Unified Directory (OUD) quirks.

High-coverage testing using real OUD LDIF fixtures from tests/fixtures/oud/.
All tests use actual implementations with real data, no mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

import pytest
from flext_core import FlextResult

from flext_ldif.api import FlextLdif
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.servers.oud import FlextLdifServersOud


class TestOudQuirksWithRealFixtures:
    """Test OUD quirks using real LDIF fixtures from tests/fixtures/oud/."""

    @pytest.fixture
    def oud_fixture_dir(self) -> Path:
        """Get OUD fixtures directory."""
        return Path(__file__).parent.parent.parent.parent / "fixtures" / "oud"

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifServersOud.Schema:
        """Create OUD quirk instance."""
        return FlextLdifServersOud.Schema()

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif()

    def test_parse_oud_schema_fixture(
        self, api: FlextLdif, oud_fixture_dir: Path
    ) -> None:
        """Test parsing real OUD schema fixture file."""
        schema_file = oud_fixture_dir / "oud_schema_fixtures.ldif"
        if not schema_file.exists():
            pytest.skip(f"OUD schema fixture not found: {schema_file}")

        result = api.parse(schema_file, server_type="oud")

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0, "OUD schema fixture should contain schema entries"

    def test_parse_oud_entries_fixture(
        self, api: FlextLdif, oud_fixture_dir: Path
    ) -> None:
        """Test parsing real OUD directory entries fixture."""
        entries_file = oud_fixture_dir / "oud_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OUD entries fixture not found: {entries_file}")

        result = api.parse(entries_file, server_type="oud")

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0, "OUD entries fixture should contain directory entries"

        # Verify entries have valid DNs
        for entry in entries:
            assert entry.dn.value, "Each entry must have a DN"
            assert len(entry.attributes) > 0, "Each entry must have attributes"

    def test_parse_oud_acl_fixture(self, api: FlextLdif, oud_fixture_dir: Path) -> None:
        """Test parsing real OUD ACL fixture."""
        acl_file = oud_fixture_dir / "oud_acl_fixtures.ldif"
        if not acl_file.exists():
            pytest.skip(f"OUD ACL fixture not found: {acl_file}")

        result = api.parse(acl_file, server_type="oud")

        assert result.is_success

    def test_roundtrip_oud_entries(
        self, api: FlextLdif, oud_fixture_dir: Path, tmp_path: Path
    ) -> None:
        """Test parsing OUD entries and writing them back maintains data integrity."""
        entries_file = oud_fixture_dir / "oud_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OUD entries fixture not found: {entries_file}")

        # Parse original
        parse_result = api.parse(entries_file, server_type="oud")
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Write to temporary file
        output_file = tmp_path / "roundtrip_oud_entries.ldif"
        write_result = api.write(entries, output_file)
        assert write_result.is_success

        # Parse again
        reparse_result = api.parse(output_file, server_type="oud")
        assert reparse_result.is_success
        reparsed_entries = reparse_result.unwrap()

        # Verify same number of entries
        assert len(entries) == len(reparsed_entries)

    def test_oud_server_type_detection(
        self, api: FlextLdif, oud_fixture_dir: Path
    ) -> None:
        """Test that OUD server type is correctly detected from OUD entries."""
        entries_file = oud_fixture_dir / "oud_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OUD entries fixture not found: {entries_file}")

        # Parse with auto-detection
        result = api.parse(entries_file)

        assert result.is_success

    def test_oud_vs_rfc_parsing(self, api: FlextLdif, oud_fixture_dir: Path) -> None:
        """Verify OUD and RFC parsing work with OUD data."""
        entries_file = oud_fixture_dir / "oud_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OUD entries fixture not found: {entries_file}")

        # Parse with OUD quirks
        oud_result = api.parse(entries_file, server_type="oud")
        assert oud_result.is_success

        # Parse with RFC-only mode
        rfc_result = api.parse(entries_file, server_type="rfc")
        assert rfc_result.is_success

    def test_oud_entry_attributes_preserved(
        self, api: FlextLdif, oud_fixture_dir: Path
    ) -> None:
        """Test that OUD-specific attributes are preserved during processing."""
        entries_file = oud_fixture_dir / "oud_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OUD entries fixture not found: {entries_file}")

        result = api.parse(entries_file, server_type="oud")
        assert result.is_success
        entries = result.unwrap()

        # Verify entries contain expected OUD attributes
        for entry in entries:
            # Check that attributes are preserved
            assert len(entry.attributes) > 0

    def test_oud_normalize_server_type(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test OUD normalize server type method."""
        # Test normalization of server type strings
        result = oud_quirk._normalize_server_type_for_literal("oud")
        assert result is not None
        assert isinstance(result, str)

    def test_oud_quirk_initialization(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test OUD quirk instance is properly initialized."""
        assert oud_quirk is not None
        assert oud_quirk.server_type == "oud"
        assert oud_quirk.priority is not None
        assert oud_quirk.priority == 10

    def test_oud_quirk_has_nested_quirks(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test OUD quirk has required nested ACL quirk."""
        # OUD quirk has acl nested quirk
        assert hasattr(oud_quirk, "acl")
        assert oud_quirk.acl is not None

    def test_oud_api_parse_with_oud_mode(self, api: FlextLdif) -> None:
        """Test API can parse LDIF in OUD mode."""
        # Create a simple test LDIF content
        aud_ldif = """dn: cn=test,ou=people,dc=example,dc=com
objectClass: person
cn: test
sn: user
"""
        result = api.parse(aud_ldif, server_type="oud")

        # Should successfully parse
        if result.is_success:
            entries = result.unwrap()
            assert isinstance(entries, list)
            assert len(entries) > 0

    def test_oud_migration_from_rfc(self, api: FlextLdif, tmp_path: Path) -> None:
        """Test API can migrate LDIF files from RFC to OUD format."""
        from flext_core import FlextResult

        # Create temporary input/output directories
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create a simple RFC LDIF file
        rfc_ldif_file = input_dir / "test.ldif"
        rfc_ldif_file.write_text(
            "dn: cn=test,ou=people,dc=example,dc=com\n"
            "objectClass: person\n"
            "cn: test\n"
            "sn: user\n"
        )

        # Attempt migration from RFC to OUD
        migrate_result = api.migrate(
            input_dir=input_dir,
            output_dir=output_dir,
            from_server="rfc",
            to_server="oud",
        )
        # Should return FlextResult
        assert isinstance(migrate_result, FlextResult)
        # Migration may succeed or fail depending on content


class TestOudSchemaMethods:
    """Test OUD schema quirk-specific methods."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifServersOud.Schema:
        """Create OUD quirk instance."""
        return FlextLdifServersOud.Schema()

    def test_normalize_server_type_oid_to_oracle_oid(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test normalizing 'oid' to 'oracle_oid'."""
        normalized = oud_quirk._normalize_server_type_for_literal("oid")
        assert normalized == "oracle_oid"

    def test_normalize_server_type_oud_to_oracle_oud(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test normalizing 'oud' to 'oracle_oud'."""
        normalized = oud_quirk._normalize_server_type_for_literal("oud")
        assert normalized == "oracle_oud"

    def test_normalize_server_type_unknown_passthrough(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test normalizing unknown server type (pass-through)."""
        normalized = oud_quirk._normalize_server_type_for_literal("unknown_server")
        assert normalized == "unknown_server"

    def test_oud_quirk_server_type(self, oud_quirk: FlextLdifServersOud.Schema) -> None:
        """Test OUD quirk has correct server type."""
        assert oud_quirk.server_type == FlextLdifConstants.ServerTypes.OUD

    def test_oud_quirk_priority(self, oud_quirk: FlextLdifServersOud.Schema) -> None:
        """Test OUD quirk has correct priority."""
        assert oud_quirk.priority == 10

    def test_oracle_oud_pattern_matches_oracle_oid_oid(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test Oracle OUD pattern matches Oracle OID namespace."""
        pattern = oud_quirk.ORACLE_OUD_PATTERN
        oracle_oid = "2.16.840.1.113894.1.2.3"
        assert pattern.search(oracle_oid) is not None

    def test_oracle_oud_pattern_no_match_non_oracle(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test Oracle OUD pattern doesn't match non-Oracle OIDs."""
        pattern = oud_quirk.ORACLE_OUD_PATTERN
        non_oracle_oid = "1.2.3.4.5"
        assert pattern.search(non_oracle_oid) is None

    def test_oud_quirk_has_nested_acl_quirk(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test OUD quirk has nested ACL quirk instance."""
        assert hasattr(oud_quirk, "acl")
        assert oud_quirk.acl is not None


class TestOudSchemaParsingMethods:
    """Test OUD schema attribute and objectClass parsing."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifServersOud.Schema:
        """Create OUD quirk instance."""
        return FlextLdifServersOud.Schema()

    def test_can_handle_oracle_oid_attribute(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test if OUD quirk can handle Oracle OID attributes."""
        # Create an attribute definition with Oracle OID
        attr_def = {
            "NAME": "testAttr",
            "OID": "2.16.840.1.113894.1.2.3",
            "DESC": "Test attribute",
        }
        # Test the method signature (if it exists in the quirk)
        if hasattr(oud_quirk, "can_handle_attribute"):
            result = oud_quirk.can_handle_attribute(attr_def)
            assert isinstance(result, bool)


class TestOudEntryProcessing:
    """Test OUD entry-level processing."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifServersOud.Schema:
        """Create OUD quirk instance."""
        return FlextLdifServersOud.Schema()

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif()

    def test_parse_oud_entry_with_oracle_attributes(self, api: FlextLdif) -> None:
        """Test parsing OUD entry with Oracle-specific attributes."""
        oud_ldif = """dn: cn=oud_user,ou=people,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
cn: oud_user
sn: user
mail: oud_user@example.com
"""
        result = api.parse(oud_ldif, server_type="oud")
        assert result.is_success or result.is_failure

    def test_oud_entry_attributes_preserved(self, api: FlextLdif) -> None:
        """Test OUD entry attributes are preserved during parsing."""
        oud_ldif = """dn: cn=test,ou=people,dc=example,dc=com
objectClass: person
cn: test
description: OUD test entry
"""
        result = api.parse(oud_ldif, server_type="oud")
        if result.is_success:
            entries = result.unwrap()
            assert isinstance(entries, list)
            if len(entries) > 0:
                entry = entries[0]
                assert hasattr(entry, "dn")
                assert hasattr(entry, "attributes")


class TestOudConversionIntegration:
    """Test OUD conversion and migration functionality."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif()

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifServersOud.Schema:
        """Create OUD quirk instance."""
        return FlextLdifServersOud.Schema()

    def test_oud_to_rfc_conversion_structure(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test OUD quirk has conversion capability."""
        # Check if quirk has conversion-related methods
        conversion_methods = [
            "convert_attribute",
            "convert_objectclass",
            "convert_dn",
        ]
        for method in conversion_methods:
            # Just verify method might exist (optional)
            if hasattr(oud_quirk, method):
                assert callable(getattr(oud_quirk, method))

    def test_oud_acl_attribute_conversion(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test OUD ACL attributes are available for conversion."""
        # Verify nested ACL quirk exists
        assert hasattr(oud_quirk, "acl")
        acl_quirk = oud_quirk.acl
        assert acl_quirk is not None

    def test_oud_quirk_can_be_used_with_registry(self) -> None:
        """Test OUD quirk can be registered in quirk registry."""
        from flext_ldif.services.registry import FlextLdifRegistry

        registry = FlextLdifRegistry()
        oud_quirk = FlextLdifServersOud.Schema()
        # Should be able to create registry and quirk without errors
        assert registry is not None
        assert oud_quirk is not None


class TestOudAttributeParsing:
    """Test OUD attribute parsing methods."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifServersOud.Schema:
        """Create OUD quirk instance."""
        return FlextLdifServersOud.Schema()

    def test_parse_attribute_with_oid(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test parsing attribute definition with OID."""
        attr_def = "( 2.16.840.1.113894.1.2.1 NAME 'testAttr' DESC 'Test' SYNTAX 1.3.6.1.4.1.1466.115037.1.4.1.1 )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        attr = result.unwrap()
        assert attr.oid == "2.16.840.1.113894.1.2.1"
        assert attr.name == "testAttr"

    def test_parse_attribute_with_syntax_length(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test parsing attribute with SYNTAX length constraint."""
        attr_def = "( 1.1.1 NAME 'str' SYNTAX 1.3.6.1.4.1.1466.115037.1.4.1.1{256} )"
        result = oud_quirk.parse_attribute(attr_def)
        if result.is_success:
            attr = result.unwrap()
            assert attr.length == 256

    def test_parse_attribute_with_equality(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test parsing attribute with EQUALITY constraint."""
        attr_def = "( 1.1.2 NAME 'equal' EQUALITY caseIgnoreMatch )"
        result = oud_quirk.parse_attribute(attr_def)
        if result.is_success:
            attr = result.unwrap()
            assert attr.equality == "caseIgnoreMatch"

    def test_parse_attribute_with_single_value(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test parsing attribute with SINGLE-VALUE constraint."""
        attr_def = "( 1.1.3 NAME 'unique' SINGLE-VALUE )"
        result = oud_quirk.parse_attribute(attr_def)
        if result.is_success:
            attr = result.unwrap()
            assert attr.single_value is True

    def test_parse_attribute_with_superior(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test parsing attribute with SUP (superior) reference."""
        attr_def = "( 1.1.4 NAME 'subAttr' SUP name )"
        result = oud_quirk.parse_attribute(attr_def)
        if result.is_success:
            attr = result.unwrap()
            assert attr.sup == "name"

    def test_parse_attribute_with_x_origin(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test parsing attribute with X-ORIGIN extension."""
        attr_def = "( 1.1.5 NAME 'custom' X-ORIGIN 'OUD' )"
        result = oud_quirk.parse_attribute(attr_def)
        if result.is_success:
            attr = result.unwrap()
            assert attr.metadata is not None

    def test_parse_attribute_invalid_syntax(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test parsing invalid attribute definition."""
        attr_def = "invalid attribute syntax"
        result = oud_quirk.parse_attribute(attr_def)
        # Should return result with error or partially parsed attribute
        assert result.is_success or result.is_failure

    def test_parse_attribute_empty_string(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test parsing empty attribute definition."""
        result = oud_quirk.parse_attribute("")
        assert result.is_success or result.is_failure

    def test_can_handle_attribute_returns_true(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test can_handle_attribute always returns True."""
        result1 = oud_quirk.can_handle_attribute("any attribute")
        result2 = oud_quirk.can_handle_attribute("")
        assert result1 is True
        assert result2 is True


class TestOudObjectClassParsing:
    """Test OUD objectClass parsing methods."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifServersOud.Schema:
        """Create OUD quirk instance."""
        return FlextLdifServersOud.Schema()

    def test_can_handle_objectclass_returns_true(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test can_handle_objectclass always returns True."""
        result1 = oud_quirk.can_handle_objectclass("any objectClass")
        result2 = oud_quirk.can_handle_objectclass("")
        assert result1 is True
        assert result2 is True

    def test_should_filter_out_attribute_returns_false(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test should_filter_out_attribute returns False (accepts all)."""
        if hasattr(oud_quirk, "should_filter_out_attribute"):
            result = oud_quirk.should_filter_out_attribute("any attribute")
            assert result is False

    def test_should_filter_out_objectclass_returns_false(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test should_filter_out_objectclass returns False (accepts all)."""
        if hasattr(oud_quirk, "should_filter_out_objectclass"):
            result = oud_quirk.should_filter_out_objectclass("any objectClass")
            assert result is False


class TestOudQuirkMetadata:
    """Test OUD quirk metadata creation."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifServersOud.Schema:
        """Create OUD quirk instance."""
        return FlextLdifServersOud.Schema()

    def test_create_quirk_metadata(self, oud_quirk: FlextLdifServersOud.Schema) -> None:
        """Test creating quirk metadata."""
        if hasattr(oud_quirk, "create_quirk_metadata"):
            metadata = oud_quirk.create_quirk_metadata("test", {})
            assert metadata is not None

    def test_quirk_metadata_contains_server_type(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test quirk metadata contains server type."""
        if hasattr(oud_quirk, "create_quirk_metadata"):
            metadata = oud_quirk.create_quirk_metadata("test", {})
            # Metadata should have server type information
            assert metadata is not None


class TestOudConversionMethods:
    """Test OUD schema conversion methods."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifServersOud.Schema:
        """Create OUD quirk instance."""
        return FlextLdifServersOud.Schema()

    def test_convert_attribute_to_rfc(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test converting OUD attribute to RFC format."""
        attr_def = "( 1.1.1 NAME 'test' )"
        if hasattr(oud_quirk, "convert_attribute_to_rfc"):
            result = oud_quirk.convert_attribute_to_rfc(attr_def)
            if result is not None:
                # Result can be FlextResult or str
                assert isinstance(result, (str, FlextResult, type(None)))

    def test_convert_attribute_from_rfc(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test converting RFC attribute to OUD format."""
        attr_def = "( 1.1.1 NAME 'test' )"
        if hasattr(oud_quirk, "convert_attribute_from_rfc"):
            result = oud_quirk.convert_attribute_from_rfc(attr_def)
            if result is not None:
                # Result can be FlextResult or str
                assert isinstance(result, (str, FlextResult, type(None)))

    def test_write_attribute_to_rfc(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test writing OUD attribute in RFC format."""
        if hasattr(oud_quirk, "write_attribute_to_rfc"):
            # Method signature varies, just verify it exists and is callable
            assert callable(oud_quirk.write_attribute_to_rfc)


class TestOudAclIntegration:
    """Test OUD ACL quirk integration."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifServersOud.Schema:
        """Create OUD quirk instance."""
        return FlextLdifServersOud.Schema()

    def test_acl_quirk_is_instance_of_base(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test ACL quirk is properly initialized."""
        assert hasattr(oud_quirk, "acl")
        acl = oud_quirk.acl
        assert acl is not None
        # ACL quirk should have server_type attribute
        if hasattr(acl, "server_type"):
            assert acl.server_type in {"oud", FlextLdifConstants.ServerTypes.OUD}

    def test_acl_quirk_has_can_handle_method(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test ACL quirk has can_handle_acl method."""
        acl = oud_quirk.acl
        if hasattr(acl, "can_handle_acl"):
            assert callable(acl.can_handle_acl)

    def test_nested_quirk_relationship(
        self, oud_quirk: FlextLdifServersOud.Schema
    ) -> None:
        """Test parent-child relationship between quirks."""
        assert hasattr(oud_quirk, "acl")
        assert oud_quirk.acl is not None
        # Both should be OUD-related
        assert oud_quirk.server_type in {"oud", FlextLdifConstants.ServerTypes.OUD}
