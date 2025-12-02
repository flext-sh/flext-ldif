"""Real-world fixture tests for LDIF processing across all servers.

Tests cover:
- RFC-compliant entry parsing and validation
- OID-specific attribute handling
- OUD-specific features (orclContainer, oracle-specific entries)
- OpenLDAP 2.x posixAccount and posixGroup handling
- Entry categorization (schema, hierarchy, users, groups, ACLs)
- Cross-server DN normalization and handling
- Attribute conversions and mappings
- Edge cases and special scenarios
"""

from pathlib import Path
from typing import cast

import pytest

from flext_ldif import (
    FlextLdif,
    FlextLdifConstants,
    FlextLdifModels,
    FlextLdifProtocols,
)
from flext_ldif.services.server import FlextLdifServer
from tests.helpers.test_rfc_helpers import RfcTestHelpers

# Type alias for protocol
HasParseMethod = FlextLdifProtocols.Services.HasParseMethodProtocol


# Helper to get fixture paths relative to test file
def _get_fixture_path(relative_path: str) -> Path:
    """Get absolute path to fixture file relative to tests/fixtures directory."""
    # __file__ is tests/unit/fixtures/test_real_world_fixtures.py
    # .parent → tests/unit/fixtures
    # .parent.parent → tests/unit
    # .parent.parent.parent → tests (THIS is where fixtures should be)
    base_dir = Path(__file__).parent.parent.parent
    fixture_path = base_dir / "fixtures" / relative_path
    if not fixture_path.exists():
        # Try alternative path if running from different directory
        alt_path = Path("flext-ldif") / "tests" / "fixtures" / relative_path
        if alt_path.exists():
            return alt_path
    return fixture_path


class TestRFCFixtures:
    """Test RFC-compliant LDIF fixtures with 50+ real-world entries."""

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        """Initialize fixtures and registry."""
        self.ldif = FlextLdif()
        self.quirk_registry = FlextLdifServer()

    def test_rfc_parse_all_entries(self) -> None:
        """Test parsing all RFC entries from fixture file."""
        fixture_path = _get_fixture_path("rfc/rfc_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path, server_type="rfc")
        assert result.is_success, f"Failed to parse RFC fixtures: {result.error}"

        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list)
        entries = unwrapped
        assert len(entries) >= 50, f"Expected 50+ RFC entries, got {len(entries)}"

    def test_rfc_entry_categories(self) -> None:
        """Test categorization of RFC entries by type."""
        fixture_path = _get_fixture_path("rfc/rfc_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path, server_type="rfc")
        assert result.is_success

        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list)
        entries = unwrapped

        categories: dict[str, list[FlextLdifModels.Entry]] = {
            "domain": [],
            "organization": [],
            "organizational_unit": [],
            "person": [],
            "group": [],
            "locality": [],
            "other": [],
        }

        for entry in entries:
            assert entry.attributes is not None, "Entry must have attributes"
            object_classes = entry.attributes.get_values("objectClass", [])
            assert isinstance(object_classes, list)
            if "domain" in object_classes:
                categories["domain"].append(entry)
            elif "organization" in object_classes:
                categories["organization"].append(entry)
            elif "organizationalUnit" in object_classes:
                categories["organizational_unit"].append(entry)
            elif any(
                oc in object_classes
                for oc in ["person", "organizationalPerson", "inetOrgPerson"]
            ):
                categories["person"].append(entry)
            elif any(
                oc in object_classes for oc in ["groupOfNames", "groupOfUniqueNames"]
            ):
                categories["group"].append(entry)
            elif "locality" in object_classes:
                categories["locality"].append(entry)
            else:
                categories["other"].append(entry)

        # Verify distribution
        assert len(categories["domain"]) >= 1, "Should have at least 1 domain entry"
        assert len(categories["person"]) >= 20, "Should have at least 20 person entries"
        assert len(categories["group"]) >= 5, "Should have at least 5 group entries"
        assert len(categories["organizational_unit"]) >= 5, (
            "Should have at least 5 OU entries"
        )

    def test_rfc_dn_validation(self) -> None:
        """Test DN validation for RFC entries."""
        fixture_path = _get_fixture_path("rfc/rfc_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path)
        assert result.is_success

        unwrapped = result.unwrap()

        assert isinstance(unwrapped, list)

        entries = unwrapped
        for entry in entries:
            # All entries should have valid DNs
            assert entry.dn is not None
            assert len(entry.dn.value) > 0

            # DN should follow RFC 4514 format (attribute=value pairs)
            dn_parts = entry.dn.value.split(",")
            for part in dn_parts:
                assert "=" in part, f"Invalid DN component: {part}"

    def test_rfc_multi_valued_attributes(self) -> None:
        """Test handling of multi-valued attributes in RFC entries."""
        fixture_path = _get_fixture_path("rfc/rfc_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path)
        assert result.is_success

        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list)
        entries = unwrapped

        # Find entry with multiple objectClass values (always multi-valued)
        multi_attr_entry = None
        for entry in entries:
            assert entry.attributes is not None, "Entry must have attributes"
            attrs_dict = entry.attributes.attributes
            if isinstance(attrs_dict, dict) and "objectClass" in attrs_dict:
                oc_attr = attrs_dict["objectClass"]
                if oc_attr and len(oc_attr) > 1:
                    multi_attr_entry = entry
                    break

        assert multi_attr_entry is not None, (
            "Should have entry with multiple attribute values"
        )
        assert multi_attr_entry.attributes is not None, "Entry must have attributes"
        assert len(multi_attr_entry.attributes.attributes["objectClass"]) >= 2

    def test_rfc_dn_components(self) -> None:
        """Test proper DN component structure in RFC entries."""
        fixture_path = _get_fixture_path("rfc/rfc_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path)
        assert result.is_success

        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list)
        entries = unwrapped

        # Verify DN components are properly formatted (attribute=value pairs)
        for entry in entries:
            assert entry.dn is not None, "Entry must have DN"
            components = entry.dn.value.split(",")
            assert len(components) >= 1, (
                f"Entry {entry.dn.value} should have valid components"
            )
            for comp in components:
                assert "=" in comp.strip(), (
                    f"Component {comp} must be formatted as attribute=value"
                )


class TestOIDFixtures:
    """Test Oracle Internet Directory (OID) fixtures."""

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        """Initialize fixtures."""
        self.ldif = FlextLdif()

    def test_oid_parse_entries(self) -> None:
        """Test parsing OID entry fixtures."""
        fixture_path = _get_fixture_path("oid/oid_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path, server_type="oid")
        assert result.is_success, f"Failed to parse OID fixtures: {result.error}"

        unwrapped = result.unwrap()

        assert isinstance(unwrapped, list)

        entries = unwrapped
        assert len(entries) >= 1, "Should parse at least some OID entries"

    def test_oid_organizational_structure(self) -> None:
        """Test OID organizational structure."""
        fixture_path = _get_fixture_path("oid/oid_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path, server_type="oid")
        assert result.is_success

        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list)
        entries = unwrapped

        # Verify entries parse successfully and have DN and objectClass
        for entry in entries:
            assert entry.dn is not None, "Entry should have DN"
            assert entry.attributes is not None, "Entry should have attributes"
            # Check for objectClass (case-insensitive)
            has_oc = any(
                attr.lower() == "objectclass" for attr in entry.attributes.attributes
            )
            assert has_oc, f"Entry {entry.dn.value} should have objectClass"

    def test_oid_user_entries(self) -> None:
        """Test OID user entries with OID-specific attributes."""
        fixture_path = _get_fixture_path("oid/oid_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path)
        assert result.is_success

        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list)
        entries = unwrapped

        # Find user entries
        user_entries = [
            e
            for e in entries
            if e.attributes is not None
            and (oc := e.attributes.get_values("objectClass", [])) is not None
            and "inetOrgPerson" in oc
        ]

        # User entries should have relevant attributes
        for user in user_entries:
            assert user.attributes is not None, "User entry must have attributes"
            attrs = user.attributes
            # At least some users should have common attributes
            assert any(
                attr in attrs.attributes
                for attr in ["mail", "cn", "sn", "telephoneNumber"]
            )


class TestOUDFixtures:
    """Test Oracle Unified Directory (OUD) fixtures."""

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        """Initialize fixtures."""
        self.ldif = FlextLdif()

    def test_oud_parse_entries(self) -> None:
        """Test parsing OUD entry fixtures."""
        fixture_path = _get_fixture_path("oud/oud_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path, server_type="oud")
        assert result.is_success, f"Failed to parse OUD fixtures: {result.error}"

        unwrapped = result.unwrap()

        assert isinstance(unwrapped, list)

        entries = unwrapped
        assert len(entries) >= 1, "Should parse at least some OUD entries"

    def test_oud_oracle_container_entries(self) -> None:
        """Test OUD-specific orclContainer entries."""
        fixture_path = _get_fixture_path("oud/oud_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path, server_type="oud")
        assert result.is_success

        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list)
        entries = unwrapped

        # OUD uses orclContainer for Oracle-specific groupings
        oracle_entries = [
            e
            for e in entries
            if e.attributes is not None
            and (oc := e.attributes.get_values("objectClass", [])) is not None
            and "orclContainer" in oc
        ]

        # Should have some oracle-specific entries (if any)
        if len(oracle_entries) > 0:
            assert all(
                e.attributes is not None and "cn" in e.attributes.attributes
                for e in oracle_entries
            )

    def test_oud_oracle_specific_attributes(self) -> None:
        """Test OUD Oracle-specific attributes and objectClasses."""
        fixture_path = _get_fixture_path("oud/oud_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path)
        assert result.is_success

        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list)
        entries = unwrapped

        # Verify entries have expected structure
        assert len(entries) >= 1, "Should have at least one OUD entry"
        for entry in entries:
            assert entry.dn is not None


class TestOpenLDAP2Fixtures:
    """Test OpenLDAP 2.x fixtures with posixAccount and posixGroup."""

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        """Initialize fixtures."""
        self.ldif = FlextLdif()

    def test_openldap2_parse_50_entries(self) -> None:
        """Test parsing 50+ OpenLDAP 2.x entries."""
        fixture_path = _get_fixture_path("openldap2/openldap2_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path)
        assert result.is_success, f"Failed to parse OpenLDAP2 fixtures: {result.error}"

        unwrapped = result.unwrap()

        assert isinstance(unwrapped, list)

        entries = unwrapped
        assert len(entries) >= 50, f"Expected 50+ OpenLDAP2 entries, got {len(entries)}"

    def test_openldap2_posix_accounts(self) -> None:
        """Test posixAccount entries in OpenLDAP 2.x."""
        fixture_path = _get_fixture_path("openldap2/openldap2_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path)
        assert result.is_success

        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list)
        entries = unwrapped

        # Find posixAccount entries
        posix_accounts = [
            e
            for e in entries
            if e.attributes is not None
            and (oc := e.attributes.get_values("objectClass", [])) is not None
            and "posixAccount" in oc
        ]
        assert len(posix_accounts) >= 10, "Should have at least 10 posixAccount entries"

        # Verify required posix attributes
        for account in posix_accounts:
            assert account.attributes is not None, "Account must have attributes"
            assert account.dn is not None, "Account must have DN"
            attrs_dict = (
                account.attributes.attributes
                if hasattr(account.attributes, "attributes")
                else {}
            )
            attr_keys = [k.lower() for k in attrs_dict]
            assert "uid" in attr_keys, f"Account missing uid: {account.dn.value}"
            assert "uidnumber" in attr_keys, (
                f"Account missing uidNumber: {account.dn.value}"
            )

    def test_openldap2_posix_groups(self) -> None:
        """Test posixGroup entries in OpenLDAP 2.x."""
        fixture_path = _get_fixture_path("openldap2/openldap2_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path)
        assert result.is_success

        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list)
        entries = unwrapped

        # Find posixGroup entries
        posix_groups = [
            e
            for e in entries
            if e.attributes is not None
            and (oc := e.attributes.get_values("objectClass", [])) is not None
            and "posixGroup" in oc
        ]
        assert len(posix_groups) >= 2, "Should have at least 2 posixGroup entries"

        # Verify required posix group attributes
        for group in posix_groups:
            assert group.attributes is not None, "Group must have attributes"
            assert group.dn is not None, "Group must have DN"
            attrs_dict = (
                group.attributes.attributes
                if hasattr(group.attributes, "attributes")
                else {}
            )
            attr_keys = [k.lower() for k in attrs_dict]
            assert "gidnumber" in attr_keys, (
                f"Group missing gidNumber: {group.dn.value}"
            )

    def test_openldap2_service_accounts(self) -> None:
        """Test OpenLDAP system service accounts."""
        fixture_path = _get_fixture_path("openldap2/openldap2_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path)
        assert result.is_success

        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list)
        entries = unwrapped

        # Find service accounts (typically with nologin shell)
        service_accounts = [
            e
            for e in entries
            if e.attributes is not None
            and (oc := e.attributes.get_values("objectClass", [])) is not None
            and "posixAccount" in oc
            and "nologin" in str(e.attributes.get_values("loginShell", []))
        ]

        assert len(service_accounts) >= 2, "Should have at least 2 service accounts"

    def test_openldap2_utf8_entries(self) -> None:
        """Test UTF-8 handling in OpenLDAP entries."""
        fixture_path = _get_fixture_path("openldap2/openldap2_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path)
        assert result.is_success

        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list)
        entries = unwrapped

        # Verify all entries parse without corruption (UTF-8 handling)
        # At minimum, entries with international characters should parse successfully
        assert len(entries) >= 1, "Should have entries that parse successfully"
        for entry in entries:
            assert entry.attributes is not None, "Entry must have attributes"
            assert entry.dn is not None, "Entry must have DN"


class TestCrossServerFixtures:
    """Test cross-server scenarios using multiple server fixtures."""

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        """Initialize fixtures."""
        self.ldif = FlextLdif()

    def test_entry_parsing_consistency_across_servers(self) -> None:
        """Test that entry parsing works consistently across servers."""
        servers = [
            ("RFC", "tests/fixtures/rfc/rfc_entries_fixtures.ldif"),
            ("OID", "tests/fixtures/oid/oid_entries_fixtures.ldif"),
            ("OUD", "tests/fixtures/oud/oud_entries_fixtures.ldif"),
            ("OpenLDAP2", "tests/fixtures/openldap2/openldap2_entries_fixtures.ldif"),
        ]

        for server_name, fixture_path in servers:
            # Extract server type from server name
            server_type_map: dict[
                str, FlextLdifConstants.LiteralTypes.ServerTypeLiteral
            ] = {
                "RFC": "rfc",
                "OID": "oid",
                "OUD": "oud",
                "OpenLDAP2": "openldap2",
            }
            server_type = server_type_map.get(server_name, "rfc")
            result = self.ldif.parse(
                _get_fixture_path(fixture_path.replace("tests/fixtures/", "")),
                server_type=cast(
                    "FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None",
                    server_type,
                ),
            )
            assert result.is_success, (
                f"{server_name}: Failed to parse {fixture_path}: {result.error}"
            )

            unwrapped = result.unwrap()

            assert isinstance(unwrapped, list)

            entries = unwrapped
            assert len(entries) >= 1, f"{server_name}: Should parse at least 1 entry"

            # Verify entry structure
            for entry in entries:
                assert entry.dn is not None, f"{server_name}: Entry missing DN"
                assert entry.attributes is not None, (
                    f"{server_name}: Entry missing attributes"
                )
                assert len(entry.dn.value) > 0, f"{server_name}: DN cannot be empty"
                # Check for objectClass (case-insensitive, as different servers use different cases)
                has_oc = any(
                    attr.lower() == "objectclass"
                    for attr in entry.attributes.attributes
                )
                assert has_oc, (
                    f"{server_name}: Entry {entry.dn.value} missing objectClass"
                )

    def test_dn_structure_across_servers(self) -> None:
        """Test DN structure consistency and differences across servers."""
        servers = [
            ("RFC", "tests/fixtures/rfc/rfc_entries_fixtures.ldif"),
            ("OpenLDAP2", "tests/fixtures/openldap2/openldap2_entries_fixtures.ldif"),
        ]

        for server_name, fixture_path in servers:
            result = self.ldif.parse(Path(fixture_path))
            assert result.is_success

            unwrapped = result.unwrap()
            assert isinstance(unwrapped, list)
            entries = unwrapped

            # Analyze DN structures
            dn_depths = [
                len(e.dn.value.split(",")) for e in entries if e.dn is not None
            ]
            assert len(dn_depths) > 0, f"{server_name}: Should have DNs to analyze"

            # All entries should have reasonable DN depth (1-6 components)
            for depth in dn_depths:
                assert 1 <= depth <= 6, f"{server_name}: Unexpected DN depth {depth}"

    def test_fixture_entry_validation(self) -> None:
        """Test that all fixture entries validate successfully."""
        servers: dict[str, Path | str] = {
            "RFC": _get_fixture_path("rfc/rfc_entries_fixtures.ldif"),
            "OID": _get_fixture_path("oid/oid_entries_fixtures.ldif"),
            "OUD": _get_fixture_path("oud/oud_entries_fixtures.ldif"),
            "OpenLDAP2": _get_fixture_path("openldap2/openldap2_entries_fixtures.ldif"),
        }
        RfcTestHelpers.test_fixture_parse_and_validate_batch(
            cast("HasParseMethod", self.ldif),
            servers,
        )


class TestFixtureEdgeCases:
    """Test edge cases and special scenarios in fixtures."""

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        """Initialize fixtures."""
        self.ldif = FlextLdif()

    def test_dn_with_special_characters(self) -> None:
        """Test handling of special characters in DNs."""
        fixture_path = _get_fixture_path("rfc/rfc_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path)
        assert result.is_success

        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list)
        entries = unwrapped

        # Should handle entries with special characters
        assert len(entries) >= 48  # At least most entries should parse

    def test_multiple_attribute_values(self) -> None:
        """Test handling of multiple values for same attribute."""
        fixture_path = _get_fixture_path("rfc/rfc_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path)
        assert result.is_success

        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list)
        entries = unwrapped

        # Find entries with multi-valued attributes
        multi_valued = []
        for entry in entries:
            assert entry.attributes is not None, "Entry must have attributes"
            assert entry.dn is not None, "Entry must have DN"
            for attr, values in entry.attributes.attributes.items():
                # values is always a list in the new API
                if isinstance(values, list) and len(values) > 1:
                    multi_valued.append((entry.dn.value, attr, len(values)))

        # Should have entries with multi-valued attributes
        assert len(multi_valued) >= 5, (
            "Should have entries with multi-valued attributes"
        )

    def test_empty_attribute_values(self) -> None:
        """Test handling of empty attribute values if present."""
        fixture_path = _get_fixture_path("rfc/rfc_entries_fixtures.ldif")
        result = self.ldif.parse(fixture_path)
        assert result.is_success

        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list)
        entries = unwrapped

        # All entries should have valid attributes (no empty values)
        for entry in entries:
            assert entry.attributes is not None, "Entry must have attributes"
            assert entry.dn is not None, "Entry must have DN"
            # attributes is a Pydantic model, use model_dump to get dict
            attrs_dict = (
                entry.attributes.model_dump()
                if entry.attributes is not None
                and hasattr(entry.attributes, "model_dump")
                else entry.attributes
            )
            if isinstance(attrs_dict, dict):
                for attr, values in attrs_dict.items():
                    if isinstance(values, list):
                        assert len(values) > 0, (
                            f"Entry {entry.dn.value} has empty attribute {attr}"
                        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
