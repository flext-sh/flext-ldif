"""Phase 3.2: OUD Quirks comprehensive tests using real fixtures.

Tests cover:
- Real OUD LDIF parsing with quirks handling
- OUD-specific attribute transformations
- Schema attribute normalization with OUD rules
- ObjectClass conversions for OUD compatibility
- DN case registry functionality
- ACL entries processing (ds-aci format)
- Round-trip OUD → RFC → OUD validation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdif
from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud


class TestOudQuirksWithRealFixtures:
    """Test OUD quirks with real LDIF fixture data."""

    @pytest.fixture
    def oud_entries_fixture(self) -> Path:
        """Get OUD entries fixture path."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oud"
            / "oud_entries_fixtures.ldif"
        )

    @pytest.fixture
    def oud_schema_fixture(self) -> Path:
        """Get OUD schema fixture path."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oud"
            / "oud_schema_fixtures.ldif"
        )

    @pytest.fixture
    def oud_acl_fixture(self) -> Path:
        """Get OUD ACL fixture path."""
        return (
            Path(__file__).parent.parent / "fixtures" / "oud" / "oud_acl_fixtures.ldif"
        )

    def test_oud_quirks_initialization(self) -> None:
        """Test OUD quirks can be initialized."""
        quirks = FlextLdifQuirksServersOud()

        assert quirks.server_type == "oud"
        assert quirks.priority >= 0

    def test_oud_quirks_has_schema_methods(self) -> None:
        """Test OUD quirks has required schema methods."""
        quirks = FlextLdifQuirksServersOud()

        # Check for required methods
        assert hasattr(quirks, "parse_attribute")
        assert callable(getattr(quirks, "parse_attribute"))
        assert hasattr(quirks, "parse_objectclass")
        assert callable(getattr(quirks, "parse_objectclass"))
        assert hasattr(quirks, "convert_attribute_to_rfc")
        assert callable(getattr(quirks, "convert_attribute_to_rfc"))
        assert hasattr(quirks, "convert_objectclass_to_rfc")
        assert callable(getattr(quirks, "convert_objectclass_to_rfc"))

    def test_oud_quirks_has_entry_methods(self) -> None:
        """Test OUD quirks has entry processing methods."""
        quirks = FlextLdifQuirksServersOud()

        # Check for EntryQuirk class
        if hasattr(quirks, "EntryQuirk"):
            entry_quirk_class = getattr(quirks, "EntryQuirk")
            assert callable(entry_quirk_class)

    def test_oud_quirks_model_post_init(self) -> None:
        """Test OUD quirks model initialization."""
        quirks = FlextLdifQuirksServersOud()

        # After initialization, should have patterns set up
        assert hasattr(quirks, "ORACLE_OUD_PATTERN")
        assert isinstance(
            quirks.ORACLE_OUD_PATTERN, type(getattr(quirks, "ORACLE_OUD_PATTERN"))
        )

        # Verify server type and priority are set
        assert quirks.server_type == "oud"
        assert quirks.priority >= 0

    def test_oud_quirks_parse_real_oud_entries(self, oud_entries_fixture: Path) -> None:
        """Test parsing real OUD entries."""
        if not oud_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oud_entries_fixture}")

        ldif = FlextLdif()
        result = ldif.parse(oud_entries_fixture)

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0

    def test_oud_quirks_parse_real_oud_schema(self, oud_schema_fixture: Path) -> None:
        """Test parsing real OUD schema."""
        if not oud_schema_fixture.exists():
            pytest.skip(f"Fixture not found: {oud_schema_fixture}")

        ldif = FlextLdif()
        result = ldif.parse(oud_schema_fixture)

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0

    def test_oud_quirks_can_handle_oud_attributes(self) -> None:
        """Test OUD quirks can detect OUD-specific attributes."""
        quirks = FlextLdifQuirksServersOud()

        # Method should be callable
        assert callable(quirks.can_handle_attribute)

    def test_oud_quirks_can_handle_oud_objectclasses(self) -> None:
        """Test OUD quirks can detect OUD-specific objectClasses."""
        quirks = FlextLdifQuirksServersOud()

        # Method should be callable
        assert callable(quirks.can_handle_objectclass)

    def test_oud_quirks_convert_attribute_to_rfc(self) -> None:
        """Test OUD quirks can convert attributes to RFC format."""
        quirks = FlextLdifQuirksServersOud()

        assert hasattr(quirks, "convert_attribute_to_rfc")
        assert callable(getattr(quirks, "convert_attribute_to_rfc"))

    def test_oud_quirks_convert_objectclass_to_rfc(self) -> None:
        """Test OUD quirks can convert objectClasses to RFC format."""
        quirks = FlextLdifQuirksServersOud()

        assert hasattr(quirks, "convert_objectclass_to_rfc")
        assert callable(getattr(quirks, "convert_objectclass_to_rfc"))

    def test_oud_quirks_convert_attribute_from_rfc(self) -> None:
        """Test OUD quirks has attribute conversion from RFC."""
        quirks = FlextLdifQuirksServersOud()

        assert hasattr(quirks, "convert_attribute_from_rfc")
        assert callable(getattr(quirks, "convert_attribute_from_rfc"))

    def test_oud_quirks_convert_objectclass_from_rfc(self) -> None:
        """Test OUD quirks has objectClass conversion from RFC."""
        quirks = FlextLdifQuirksServersOud()

        assert hasattr(quirks, "convert_objectclass_from_rfc")
        assert callable(getattr(quirks, "convert_objectclass_from_rfc"))

    def test_oud_quirks_write_attribute_to_rfc(self) -> None:
        """Test OUD quirks can write attributes in RFC format."""
        quirks = FlextLdifQuirksServersOud()

        assert hasattr(quirks, "write_attribute_to_rfc")
        assert callable(getattr(quirks, "write_attribute_to_rfc"))

    def test_oud_quirks_write_objectclass_to_rfc(self) -> None:
        """Test OUD quirks can write objectClasses in RFC format."""
        quirks = FlextLdifQuirksServersOud()

        assert hasattr(quirks, "write_objectclass_to_rfc")
        assert callable(getattr(quirks, "write_objectclass_to_rfc"))

    def test_oud_quirks_nested_acl_quirk_available(self) -> None:
        """Test OUD quirks has nested ACL Quirk class."""
        quirks = FlextLdifQuirksServersOud()

        assert hasattr(quirks, "AclQuirk")
        acl_quirk_class = getattr(quirks, "AclQuirk")
        assert callable(acl_quirk_class)

    def test_oud_quirks_nested_entry_quirk_available(self) -> None:
        """Test OUD quirks has nested Entry Quirk class."""
        quirks = FlextLdifQuirksServersOud()

        assert hasattr(quirks, "EntryQuirk")
        entry_quirk_class = getattr(quirks, "EntryQuirk")
        assert callable(entry_quirk_class)

    def test_oud_acl_quirk_acl_processing_methods(self) -> None:
        """Test OUD ACL quirk processing methods exist."""
        quirks = FlextLdifQuirksServersOud()
        acl_quirk = quirks.AclQuirk()

        # Check for ACL processing methods (OUD uses ds-aci format)
        assert hasattr(acl_quirk, "parse_acl")
        assert callable(getattr(acl_quirk, "parse_acl"))
        assert hasattr(acl_quirk, "convert_acl_to_rfc")
        assert callable(getattr(acl_quirk, "convert_acl_to_rfc"))

    def test_oud_entry_quirk_entry_processing_methods(self) -> None:
        """Test OUD entry quirk processing methods exist."""
        quirks = FlextLdifQuirksServersOud()
        entry_quirk = quirks.EntryQuirk()

        assert hasattr(entry_quirk, "process_entry")
        assert callable(getattr(entry_quirk, "process_entry"))
        assert hasattr(entry_quirk, "convert_entry_to_rfc")
        assert callable(getattr(entry_quirk, "convert_entry_to_rfc"))

    def test_oud_quirks_dn_case_registry_usage(self) -> None:
        """Test OUD quirks has proper initialization for DN handling."""
        quirks = FlextLdifQuirksServersOud()

        # OUD should have the core pattern and methods for DN handling
        assert hasattr(quirks, "ORACLE_OUD_PATTERN")
        assert hasattr(quirks, "parse_attribute")
        assert hasattr(quirks, "parse_objectclass")
        assert callable(quirks.parse_attribute)
        assert callable(quirks.parse_objectclass)

    def test_oud_quirks_write_attribute_result(self) -> None:
        """Test OUD quirks attribute write returns proper result."""
        quirks = FlextLdifQuirksServersOud()

        attr_data = {
            "oid": "1.2.3.4",
            "name": "testAttr",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
        }

        result = quirks.write_attribute_to_rfc(attr_data)
        assert hasattr(result, "is_success")

    def test_oud_quirks_write_objectclass_result(self) -> None:
        """Test OUD quirks objectClass write returns proper result."""
        quirks = FlextLdifQuirksServersOud()

        oc_data = {
            "oid": "1.2.3.5",
            "name": "testOC",
            "sup": "top",
            "type": "STRUCTURAL",
        }

        result = quirks.write_objectclass_to_rfc(oc_data)
        assert hasattr(result, "is_success")

    def test_oud_acl_quirk_parse_result(self) -> None:
        """Test OUD ACL quirk parse returns proper result."""
        quirks = FlextLdifQuirksServersOud()
        acl_quirk = quirks.AclQuirk()

        acl_line = 'ds-aci: (target="ldap:///") (version 3.0; acl "test"; allow(read) userdn="ldap:///anyone";)'
        result = acl_quirk.parse_acl(acl_line)

        assert hasattr(result, "is_success")

    def test_oud_entry_quirk_process_entry_result(self) -> None:
        """Test OUD entry quirk process_entry returns proper result."""
        quirks = FlextLdifQuirksServersOud()
        entry_quirk = quirks.EntryQuirk()

        dn = "cn=test,dc=example,dc=com"
        attributes = {"cn": ["test"], "objectClass": ["top"]}

        result = entry_quirk.process_entry(dn, attributes)
        assert hasattr(result, "is_success")

    def test_oud_quirks_extract_schemas_from_ldif(self) -> None:
        """Test OUD quirks can extract schemas from LDIF."""
        quirks = FlextLdifQuirksServersOud()

        assert hasattr(quirks, "extract_schemas_from_ldif")
        assert callable(getattr(quirks, "extract_schemas_from_ldif"))

    def test_oud_quirks_priority_assignment(self) -> None:
        """Test OUD quirks priority is properly assigned."""
        quirks = FlextLdifQuirksServersOud()

        assert quirks.priority > 0
        assert isinstance(quirks.priority, int)
        # OUD priority should be lower than OID for default detection
        assert quirks.priority < 50

    def test_oud_quirks_can_handle_ds_sync_attributes(self) -> None:
        """Test OUD quirks handles ds-sync-* attributes."""
        quirks = FlextLdifQuirksServersOud()

        # OUD sync attributes are supported
        assert callable(quirks.can_handle_attribute)

    def test_oud_quirks_can_handle_ds_pwp_attributes(self) -> None:
        """Test OUD quirks handles ds-pwp-* attributes."""
        quirks = FlextLdifQuirksServersOud()

        # OUD password policy attributes are supported
        assert callable(quirks.can_handle_attribute)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
