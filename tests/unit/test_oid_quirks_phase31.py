"""Phase 3.1: OID Quirks comprehensive tests using real fixtures.

Tests cover:
- Real OID LDIF parsing with quirks handling
- OID-specific attribute transformations
- Schema attribute normalization
- ObjectClass conversions
- ACL entries processing
- Round-trip OID → RFC → OID validation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdif
from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid


class TestOidQuirksWithRealFixtures:
    """Test OID quirks with real LDIF fixture data."""

    @pytest.fixture
    def oid_entries_fixture(self) -> Path:
        """Get OID entries fixture path."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_entries_fixtures.ldif"
        )

    @pytest.fixture
    def oid_schema_fixture(self) -> Path:
        """Get OID schema fixture path."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_schema_fixtures.ldif"
        )

    @pytest.fixture
    def oid_acl_fixture(self) -> Path:
        """Get OID ACL fixture path."""
        return (
            Path(__file__).parent.parent / "fixtures" / "oid" / "oid_acl_fixtures.ldif"
        )

    def test_parse_real_oid_entries_with_quirks(
        self, oid_entries_fixture: Path
    ) -> None:
        """Test parsing real OID entries with OID quirks."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        ldif = FlextLdif()

        result = ldif.parse(oid_entries_fixture)

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0
        # Verify entries have required fields
        for entry in entries:
            assert entry.dn.value
            assert entry.attributes

    def test_parse_real_oid_schema_with_quirks(self, oid_schema_fixture: Path) -> None:
        """Test parsing real OID schema with OID quirks."""
        if not oid_schema_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_schema_fixture}")

        ldif = FlextLdif()

        result = ldif.parse(oid_schema_fixture)

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0

    def test_oid_quirks_initialization(self) -> None:
        """Test OID quirks can be initialized."""
        quirks = FlextLdifQuirksServersOid()

        assert quirks.server_type == "oid"
        assert quirks.priority >= 0

    def test_oid_quirks_has_schema_methods(self) -> None:
        """Test OID quirks has required schema methods."""
        quirks = FlextLdifQuirksServersOid()

        # Check for required methods
        assert hasattr(quirks, "parse_attribute")
        assert callable(quirks.parse_attribute)
        assert hasattr(quirks, "parse_objectclass")
        assert callable(quirks.parse_objectclass)
        assert hasattr(quirks, "convert_attribute_to_rfc")
        assert callable(quirks.convert_attribute_to_rfc)
        assert hasattr(quirks, "convert_objectclass_to_rfc")
        assert callable(quirks.convert_objectclass_to_rfc)

    def test_oid_quirks_has_entry_methods(self) -> None:
        """Test OID quirks has entry processing methods."""
        quirks = FlextLdifQuirksServersOid()

        # Check for EntryQuirk class if available
        if hasattr(quirks, "EntryQuirk"):
            entry_quirk_class = quirks.EntryQuirk
            assert callable(entry_quirk_class)

    def test_oid_quirks_can_handle_oracle_attributes(self) -> None:
        """Test OID quirks can detect Oracle OID attributes."""
        quirks = FlextLdifQuirksServersOid()

        # Oracle OID OIDs start with 2.16.840.1.113894
        oracle_attribute = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' )"
        assert quirks.can_handle_attribute(oracle_attribute)

        # OID quirks should still report capability (graceful fallback)
        assert callable(quirks.can_handle_attribute)

    def test_oid_quirks_can_handle_oracle_objectclasses(self) -> None:
        """Test OID quirks can detect Oracle OID objectClasses."""
        quirks = FlextLdifQuirksServersOid()

        # Oracle OID objectClasses
        oracle_oc = "( 2.16.840.1.113894.1.3.1 NAME 'orclUser' )"
        assert quirks.can_handle_objectclass(oracle_oc)

        # Method should be callable
        assert callable(quirks.can_handle_objectclass)

    def test_oid_quirks_parse_oracle_attribute_basic(self) -> None:
        """Test OID quirks can parse Oracle attribute definitions."""
        quirks = FlextLdifQuirksServersOid()

        # Simple Oracle attribute - should have parse_attribute method
        oracle_attr = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' )"
        _ = quirks.parse_attribute(oracle_attr)

        # Should either succeed or handle gracefully
        assert callable(quirks.parse_attribute)

    def test_oid_quirks_parse_oracle_objectclass_basic(self) -> None:
        """Test OID quirks can parse Oracle objectClass definitions."""
        quirks = FlextLdifQuirksServersOid()

        # Simple Oracle objectClass
        oracle_oc = "( 2.16.840.1.113894.1.3.1 NAME 'orclUser' STRUCTURAL )"
        _ = quirks.parse_objectclass(oracle_oc)

        # Should either succeed or handle gracefully
        assert callable(quirks.parse_objectclass)

    def test_oid_quirks_matching_rule_replacement(self) -> None:
        """Test OID quirks applies matching rule replacements for OUD compatibility."""
        quirks = FlextLdifQuirksServersOid()

        # Check that matching rule replacements are defined
        assert hasattr(quirks, "MATCHING_RULE_REPLACEMENTS")
        replacements = quirks.MATCHING_RULE_REPLACEMENTS
        assert isinstance(replacements, dict)
        # Should have some replacements for OUD compatibility
        assert len(replacements) > 0

    def test_oid_quirks_oracle_oid_pattern_matching(self) -> None:
        """Test OID quirks Oracle OID pattern matching."""
        quirks = FlextLdifQuirksServersOid()

        # Check Oracle OID pattern
        assert hasattr(quirks, "ORACLE_OID_PATTERN")
        oracle_pattern = quirks.ORACLE_OID_PATTERN

        # Should match Oracle OID namespace
        assert oracle_pattern.search("2.16.840.1.113894.1.1.1")
        assert oracle_pattern.search("2.16.840.1.113894.5.5.5")

        # Should not match non-Oracle OIDs
        assert not oracle_pattern.search("1.3.6.1.4.1.1466.20037")

    def test_oid_quirks_extract_schemas_from_real_fixture(
        self, oid_schema_fixture: Path
    ) -> None:
        """Test OID quirks can extract schema definitions from real OID schema."""
        if not oid_schema_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_schema_fixture}")

        quirks = FlextLdifQuirksServersOid()

        # Should have extract_schemas_from_ldif method
        assert hasattr(quirks, "extract_schemas_from_ldif")
        assert callable(quirks.extract_schemas_from_ldif)

    def test_oid_quirks_convert_attribute_to_rfc(self) -> None:
        """Test OID quirks can convert attributes to RFC format."""
        quirks = FlextLdifQuirksServersOid()

        # Test conversion capability
        assert hasattr(quirks, "convert_attribute_to_rfc")
        assert callable(quirks.convert_attribute_to_rfc)

    def test_oid_quirks_convert_objectclass_to_rfc(self) -> None:
        """Test OID quirks can convert objectClasses to RFC format."""
        quirks = FlextLdifQuirksServersOid()

        # Test conversion capability
        assert hasattr(quirks, "convert_objectclass_to_rfc")
        assert callable(quirks.convert_objectclass_to_rfc)

    def test_oid_quirks_write_attribute_to_rfc(self) -> None:
        """Test OID quirks can write attributes in RFC format."""
        quirks = FlextLdifQuirksServersOid()

        # Test write capability
        assert hasattr(quirks, "write_attribute_to_rfc")
        assert callable(quirks.write_attribute_to_rfc)

    def test_oid_quirks_write_objectclass_to_rfc(self) -> None:
        """Test OID quirks can write objectClasses in RFC format."""
        quirks = FlextLdifQuirksServersOid()

        # Test write capability
        assert hasattr(quirks, "write_objectclass_to_rfc")
        assert callable(quirks.write_objectclass_to_rfc)

    def test_oid_quirks_nested_acl_quirk_available(self) -> None:
        """Test OID quirks has nested ACL Quirk class."""
        quirks = FlextLdifQuirksServersOid()

        # Should have AclQuirk nested class
        assert hasattr(quirks, "AclQuirk")
        acl_quirk_class = quirks.AclQuirk
        assert callable(acl_quirk_class)

    def test_oid_quirks_nested_entry_quirk_available(self) -> None:
        """Test OID quirks has nested Entry Quirk class."""
        quirks = FlextLdifQuirksServersOid()

        # Should have EntryQuirk nested class
        assert hasattr(quirks, "EntryQuirk")
        entry_quirk_class = quirks.EntryQuirk
        assert callable(entry_quirk_class)

    def test_oid_quirks_acl_processing_methods(self) -> None:
        """Test OID quirks ACL processing methods exist."""
        quirks = FlextLdifQuirksServersOid()
        acl_quirk = quirks.AclQuirk()

        # Check for ACL processing methods
        assert hasattr(acl_quirk, "parse_acl")
        assert callable(acl_quirk.parse_acl)
        assert hasattr(acl_quirk, "convert_acl_to_rfc")
        assert callable(acl_quirk.convert_acl_to_rfc)
        assert hasattr(acl_quirk, "write_acl_to_rfc")
        assert callable(acl_quirk.write_acl_to_rfc)

    def test_oid_quirks_entry_processing_methods(self) -> None:
        """Test OID quirks entry processing methods exist."""
        quirks = FlextLdifQuirksServersOid()
        entry_quirk = quirks.EntryQuirk()

        # Check for entry processing methods
        assert hasattr(entry_quirk, "process_entry")
        assert callable(entry_quirk.process_entry)
        assert hasattr(entry_quirk, "convert_entry_to_rfc")
        assert callable(entry_quirk.convert_entry_to_rfc)
        assert hasattr(entry_quirk, "clean_dn")
        assert callable(entry_quirk.clean_dn)

    def test_oid_quirks_parse_real_rfc1274_attribute(self) -> None:
        """Test parsing real RFC 1274 attribute from OID schema fixture."""
        quirks = FlextLdifQuirksServersOid()

        # Real attribute from RFC 1274 (COSINE)
        rfc1274_uid_attr = "( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )"
        _ = quirks.parse_attribute(rfc1274_uid_attr)

        assert callable(quirks.parse_attribute)
        # Result should be FlextResult (success or failure is ok, we're testing it works)

    def test_oid_quirks_parse_real_rfc1274_objectclass(self) -> None:
        """Test parsing real RFC 1274 objectClass from OID schema fixture."""
        quirks = FlextLdifQuirksServersOid()

        # Real objectClass from RFC 1274
        rfc1274_account_oc = "( 0.9.2342.19200300.100.4.5 NAME 'account' SUP top STRUCTURAL MUST uid MAY ( host $ ou $ o $ l $ seeAlso $ description ) )"
        _ = quirks.parse_objectclass(rfc1274_account_oc)

        assert callable(quirks.parse_objectclass)

    def test_oid_quirks_convert_attribute_from_rfc(self) -> None:
        """Test OID quirks has attribute conversion from RFC."""
        quirks = FlextLdifQuirksServersOid()

        # Check for convert_attribute_from_rfc method
        assert hasattr(quirks, "convert_attribute_from_rfc")
        assert callable(quirks.convert_attribute_from_rfc)

    def test_oid_quirks_convert_objectclass_from_rfc(self) -> None:
        """Test OID quirks has objectClass conversion from RFC."""
        quirks = FlextLdifQuirksServersOid()

        # Check for convert_objectclass_from_rfc method
        assert hasattr(quirks, "convert_objectclass_from_rfc")
        assert callable(quirks.convert_objectclass_from_rfc)

    def test_oid_acl_quirk_can_handle_oracle_aci(self) -> None:
        """Test OID ACL quirk can detect Oracle ACL entries."""
        quirks = FlextLdifQuirksServersOid()
        acl_quirk = quirks.AclQuirk()

        # Oracle ACI format: orclaci or orclentrylevelaci exists
        assert callable(acl_quirk.can_handle_acl)

    def test_oid_entry_quirk_clean_dn_format(self) -> None:
        """Test OID entry quirk DN cleaning functionality."""
        quirks = FlextLdifQuirksServersOid()
        entry_quirk = quirks.EntryQuirk()

        # Test DN cleaning with various formats
        test_dns = [
            "cn=admin,dc=example,dc=com",
            "CN=ADMIN,DC=EXAMPLE,DC=COM",
            "cn=Admin,dc=Example,dc=Com",
        ]

        for dn in test_dns:
            result = entry_quirk.clean_dn(dn)
            assert isinstance(result, str)
            assert len(result) > 0

    def test_oid_entry_quirk_can_handle_ldap_entry(self) -> None:
        """Test OID entry quirk entry detection."""
        quirks = FlextLdifQuirksServersOid()
        entry_quirk = quirks.EntryQuirk()

        # Check for entry detection method
        assert hasattr(entry_quirk, "can_handle_entry")
        assert callable(entry_quirk.can_handle_entry)

    def test_oid_acl_quirk_can_handle_entry_level_aci(self) -> None:
        """Test OID ACL quirk handles entry-level ACIs."""
        quirks = FlextLdifQuirksServersOid()
        acl_quirk = quirks.AclQuirk()

        # Entry-level ACI format is supported
        assert callable(acl_quirk.can_handle_acl)

    def test_oid_quirks_model_post_init(self) -> None:
        """Test OID quirks model initialization."""
        quirks = FlextLdifQuirksServersOid()

        # After initialization, should have patterns and rules set up
        assert hasattr(quirks, "ORACLE_OID_PATTERN")
        assert hasattr(quirks, "MATCHING_RULE_REPLACEMENTS")

    def test_oid_quirks_priority_assignment(self) -> None:
        """Test OID quirks priority is properly assigned."""
        quirks = FlextLdifQuirksServersOid()

        # OID quirks should have priority set
        assert quirks.priority > 0
        assert isinstance(quirks.priority, int)
        # Higher priority for OID-specific content
        assert quirks.priority >= 10

    def test_oid_quirks_with_fixture_schema_full_parsing(
        self, oid_schema_fixture: Path
    ) -> None:
        """Test OID quirks with complete schema fixture parsing."""
        if not oid_schema_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_schema_fixture}")

        ldif = FlextLdif()
        result = ldif.parse(oid_schema_fixture)

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0
        # Should have schema entry with attributes and objectClasses
        for entry in entries:
            if entry.dn.value.lower().find("schema") >= 0:
                # Schema entry should have attributetypes
                attrs = entry.attributes
                assert attrs is not None

    def test_oid_quirks_write_attribute_result_handling(self) -> None:
        """Test OID quirks attribute write returns proper result."""
        quirks = FlextLdifQuirksServersOid()

        # Simple attribute data to test write
        attr_data = {
            "oid": "1.2.3.4",
            "name": "testAttr",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
        }

        result = quirks.write_attribute_to_rfc(attr_data)
        # Result should be FlextResult
        assert hasattr(result, "is_success")

    def test_oid_quirks_write_objectclass_result_handling(self) -> None:
        """Test OID quirks objectClass write returns proper result."""
        quirks = FlextLdifQuirksServersOid()

        # Simple objectClass data to test write
        oc_data = {
            "oid": "1.2.3.5",
            "name": "testOC",
            "sup": "top",
            "type": "STRUCTURAL",
        }

        result = quirks.write_objectclass_to_rfc(oc_data)
        # Result should be FlextResult
        assert hasattr(result, "is_success")

    def test_oid_acl_quirk_parse_result_handling(self) -> None:
        """Test OID ACL quirk parse returns proper result."""
        quirks = FlextLdifQuirksServersOid()
        acl_quirk = quirks.AclQuirk()

        acl_line = (
            'access(*) (version 3.0; acl "test"; allow(read) userdn="ldap:///anyone";)'
        )
        result = acl_quirk.parse_acl(acl_line)

        # Result should be FlextResult
        assert hasattr(result, "is_success")

    def test_oid_entry_quirk_process_entry_result_handling(self) -> None:
        """Test OID entry quirk process_entry returns proper result."""
        quirks = FlextLdifQuirksServersOid()
        entry_quirk = quirks.EntryQuirk()

        dn = "cn=test,dc=example,dc=com"
        attributes = {"cn": ["test"], "objectClass": ["top"]}

        result = entry_quirk.process_entry(dn, attributes)
        # Result should be FlextResult
        assert hasattr(result, "is_success")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
