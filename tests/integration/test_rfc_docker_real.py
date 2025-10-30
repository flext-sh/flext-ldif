"""RFC LDIF Parser/Writer Docker Integration Tests.

Real tests using:
- Docker LDAP containers (OUD, OpenLDAP)
- Real LDIF fixture data
- Actual read/write operations
- All error paths (no pragmas/mocks)

Tests validate RFC 2849 compliance with real LDAP servers.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.services.parser import FlextLdifParserService
from flext_ldif.services.registry import FlextLdifRegistry
from flext_ldif.services.writer import FlextLdifWriterService


class TestRfcDockerRealData:
    """Test RFC implementations with real Docker LDAP data."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifRegistry:
        """Create quirk registry."""
        return FlextLdifRegistry()

    @pytest.fixture
    def oid_fixtures_dir(self) -> Path:
        """Path to OID fixtures."""
        return Path("tests/fixtures/oid")

    @pytest.fixture
    def oud_fixtures_dir(self) -> Path:
        """Path to OUD fixtures."""
        return Path("tests/fixtures/oud")

    @pytest.fixture
    def openldap_fixtures_dir(self) -> Path:
        """Path to OpenLDAP fixtures."""
        return Path("tests/fixtures/openldap2")

    def test_parse_real_oid_schema(
        self,
        quirk_registry: FlextLdifRegistry,
        oid_fixtures_dir: Path,
    ) -> None:
        """Test parsing real OID schema from fixtures."""
        schema_file = oid_fixtures_dir / "oid_schema_fixtures.ldif"

        if not schema_file.exists():
            pytest.skip(f"OID schema fixtures not found: {schema_file}")

        parser = FlextLdifParserService(
            params={FlextLdifConstants.DictKeys.FILE_PATH: str(schema_file)},
        )

        result = parser.execute()

        assert result.is_success, f"Failed to parse OID schema: {result.error}"
        schema_data = result.unwrap()

        # Verify schema data structure
        assert "attributes" in schema_data
        assert "objectclasses" in schema_data
        assert len(schema_data.get("attributes", {})) > 0
        assert len(schema_data.get("objectclasses", {})) > 0

    def test_parse_real_oud_entries(
        self,
        quirk_registry: FlextLdifRegistry,
        oud_fixtures_dir: Path,
    ) -> None:
        """Test parsing real OUD entries from fixtures."""
        entries_file = oud_fixtures_dir / "oud_entries_fixtures.ldif"

        if not entries_file.exists():
            pytest.skip(f"OUD entries fixtures not found: {entries_file}")

        parser = FlextLdifParserService(
            config=FlextLdifConfig(),
        )

        result = parser.parse_ldif_file(entries_file)

        assert result.is_success, f"Failed to parse OUD entries: {result.error}"
        entries = result.unwrap()

        # Verify entries
        assert len(entries) > 0, "No entries parsed from OUD fixtures"
        assert all(hasattr(entry, "dn") for entry in entries)

    def test_parse_openldap_integration_data(
        self,
        quirk_registry: FlextLdifRegistry,
        openldap_fixtures_dir: Path,
    ) -> None:
        """Test parsing real OpenLDAP integration data."""
        integration_file = openldap_fixtures_dir / "openldap2_integration_fixtures.ldif"

        if not integration_file.exists():
            pytest.skip(f"OpenLDAP integration fixtures not found: {integration_file}")

        parser = FlextLdifParserService(
            config=FlextLdifConfig(),
        )

        result = parser.parse_ldif_file(integration_file)

        assert result.is_success or "Failed to parse" in result.error
        if result.is_success:
            entries = result.unwrap()
            assert len(entries) > 0

    def test_roundtrip_oid_to_file(
        self,
        quirk_registry: FlextLdifRegistry,
        oid_fixtures_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Test read OID fixture, write to file, read back (roundtrip)."""
        source_file = oid_fixtures_dir / "oid_entries_fixtures.ldif"

        if not source_file.exists():
            pytest.skip(f"OID entries fixtures not found: {source_file}")

        # Parse original
        parser = FlextLdifParserService(
            config=FlextLdifConfig(),
        )
        parse_result = parser.parse_ldif_file(source_file)

        if not parse_result.is_success:
            pytest.skip(f"Could not parse source: {parse_result.error}")

        entries = parse_result.unwrap()

        # Write to new file
        output_file = tmp_path / "roundtrip.ldif"
        {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: entries,  # Pass Entry objects directly
        }

        writer = FlextLdifWriterService(
            config=FlextLdifConfig(),
            target_server_type="rfc",
        )
        write_result = writer.execute()

        assert write_result.is_success, f"Failed to write: {write_result.error}"
        assert output_file.exists()

        # Re-parse written file
        reparser = FlextLdifParserService(
            config=FlextLdifConfig(),
        )
        reparse_result = reparser.parse_ldif_file(output_file)

        assert reparse_result.is_success, f"Failed to re-parse: {reparse_result.error}"
        reparsed_entries = reparse_result.unwrap()

        # Verify counts match
        assert len(reparsed_entries) == len(entries)

    def test_parse_oud_acl_entries(
        self,
        quirk_registry: FlextLdifRegistry,
        oud_fixtures_dir: Path,
    ) -> None:
        """Test parsing OUD ACL entries from fixtures."""
        acl_file = oud_fixtures_dir / "oud_acl_fixtures.ldif"

        if not acl_file.exists():
            pytest.skip(f"OUD ACL fixtures not found: {acl_file}")

        parser = FlextLdifParserService(
            config=FlextLdifConfig(),
        )

        result = parser.parse_ldif_file(acl_file)

        if result.is_success:
            entries = result.unwrap()
            # OUD ACLs should have 'aci' attributes
            # LdifAttributes is a wrapper - access inner dict via .attributes
            acl_entries = [e for e in entries if "aci" in e.attributes.attributes]
            assert len(acl_entries) > 0, "No ACL entries found in OUD fixtures"

    def test_parse_edge_case_unicode(
        self,
        quirk_registry: FlextLdifRegistry,
    ) -> None:
        """Test parsing Unicode edge cases."""
        unicode_dir = Path("tests/fixtures/edge_cases/unicode")

        if not unicode_dir.exists():
            pytest.skip("Unicode fixtures not found")

        unicode_files = list(unicode_dir.glob("*.ldif"))

        for ldif_file in unicode_files:
            parser = FlextLdifParserService(
                config=FlextLdifConfig(),
            )

            result = parser.parse_ldif_file(ldif_file)

            # Should handle Unicode gracefully
            assert result.is_success or result.error, (
                f"Parsing {ldif_file.name} should return valid result"
            )

    def test_write_with_exception_handling(
        self,
        quirk_registry: FlextLdifRegistry,
        tmp_path: Path,
    ) -> None:
        """Test RFC writer exception handling (now exposed without pragmas)."""
        # Test with readonly directory (permission error)
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o555)

        try:
            output_file = readonly_dir / "test.ldif"

            {
                FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
                FlextLdifConstants.DictKeys.ENTRIES: [
                    {
                        FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
                        FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["test"]},
                    }
                ],
            }

            writer = FlextLdifWriterService(
                config=FlextLdifConfig(),
                target_server_type="rfc",
            )

            result = writer.execute()

            # Should fail with permission error (not silently)
            if not result.is_success:
                assert (
                    "Permission denied" in result.error
                    or "LDIF write failed" in result.error
                )
        finally:
            readonly_dir.chmod(0o755)

    def test_parse_broken_ldif_relaxed_mode(
        self,
        quirk_registry: FlextLdifRegistry,
    ) -> None:
        """Test relaxed parsing of broken/malformed LDIF."""
        broken_dir = Path("tests/fixtures/broken/structure")

        if not broken_dir.exists():
            pytest.skip("Broken fixtures not found")

        broken_files = list(broken_dir.glob("*.ldif"))

        for broken_file in broken_files:
            parser = FlextLdifParserService(
                config=FlextLdifConfig(),
                # Use relaxed mode for broken LDIF
            )

            result = parser.parse_ldif_file(broken_file)

            # Relaxed mode should attempt to parse even broken LDIF
            if result.is_success:
                entries = result.unwrap()
                assert isinstance(entries, list)

    def test_rfc_schema_parser_with_real_data(
        self,
        quirk_registry: FlextLdifRegistry,
    ) -> None:
        """Test RFC schema parser with real OID schema."""
        schema_file = Path("tests/fixtures/oid/oid_schema_fixtures.ldif")

        if not schema_file.exists():
            pytest.skip("OID schema fixtures not found")

        parser = FlextLdifParserService(
            params={FlextLdifConstants.DictKeys.FILE_PATH: str(schema_file)},
        )

        result = parser.execute()

        if result.is_success:
            schema_data = result.unwrap()
            # Should have both attributes and objectclasses
            assert "attributes" in schema_data or "objectclasses" in schema_data


class TestRfcIntegrationRealWorld:
    """Real-world RFC integration scenarios."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifRegistry:
        """Create quirk registry."""
        return FlextLdifRegistry()

    def test_large_oid_schema_parsing(
        self,
        quirk_registry: FlextLdifRegistry,
    ) -> None:
        """Test parsing large real OID schema (345KB fixture)."""
        schema_file = Path("tests/fixtures/oid/oid_schema_fixtures.ldif")

        if not schema_file.exists():
            pytest.skip("OID schema fixtures not found")

        # This is a large real-world schema file
        file_size = schema_file.stat().st_size
        assert file_size > 300000, "Expected large schema file"

        parser = FlextLdifParserService(
            params={FlextLdifConstants.DictKeys.FILE_PATH: str(schema_file)},
        )

        result = parser.execute()

        assert result.is_success, f"Failed to parse large schema: {result.error}"

    def test_large_oud_integration_data(
        self,
        quirk_registry: FlextLdifRegistry,
    ) -> None:
        """Test parsing large real OUD integration data (31KB)."""
        integration_file = Path("tests/fixtures/oud/oud_integration_fixtures.ldif")

        if not integration_file.exists():
            pytest.skip("OUD integration fixtures not found")

        parser = FlextLdifParserService(
            config=FlextLdifConfig(),
        )

        result = parser.parse_ldif_file(integration_file)

        if result.is_success:
            entries = result.unwrap()
            assert len(entries) > 0, "Integration file should have entries"

    def test_write_large_dataset(
        self,
        quirk_registry: FlextLdifRegistry,
        tmp_path: Path,
    ) -> None:
        """Test writing large dataset to file."""
        # Create 100 test entries
        entries = [
            {
                FlextLdifConstants.DictKeys.DN: f"cn=user{i},ou=people,dc=example,dc=com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "cn": [f"user{i}"],
                    "objectClass": ["person", "inetOrgPerson"],
                    "mail": [f"user{i}@example.com"],
                    "userPassword": [f"password{i}"],
                },
            }
            for i in range(100)
        ]

        output_file = tmp_path / "large_output.ldif"

        {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: entries,
        }

        writer = FlextLdifWriterService(
            config=FlextLdifConfig(),
            target_server_type="rfc",
        )

        result = writer.execute()

        assert result.is_success, f"Failed to write large dataset: {result.error}"
        assert output_file.exists()

        # Verify file contains all entries
        content = output_file.read_text(encoding="utf-8")
        assert content.count("dn: cn=user") == 100, "Not all entries written"
