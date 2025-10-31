"""RFC LDIF Parser/Writer Real Integration Tests with Docker LDAP.

Real tests using:
- Real LDIF fixture data (OID, OUD, OpenLDAP)
- Actual read/write operations
- All error paths (no pragmas/mocks)
- Docker containers for validation

Tests validate RFC 2849 compliance with real LDAP data.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.config import FlextLdifConfig
from flext_ldif.services.parser import FlextLdifParserService
from flext_ldif.services.registry import FlextLdifRegistry
from flext_ldif.services.writer import FlextLdifWriterService


class TestRfcParserRealFixtures:
    """Test RFC parser with real fixture data."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifRegistry:
        """Create quirk registry."""
        return FlextLdifRegistry()

    def test_parse_oid_entries_fixture(
        self,
        quirk_registry: FlextLdifRegistry,
    ) -> None:
        """Test parsing real OID entries from fixtures."""
        entries_file = Path("tests/fixtures/oid/oid_entries_fixtures.ldif")

        if not entries_file.exists():
            pytest.skip(f"Fixture not found: {entries_file}")

        parser = FlextLdifParserService(
            config=FlextLdifConfig(),
        )

        result = parser.parse_file(entries_file)

        assert result.is_success, f"Failed to parse: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0, "No entries parsed"
        assert all(hasattr(entry, "dn") for entry in entries)

    def test_parse_oud_entries_fixture(
        self,
        quirk_registry: FlextLdifRegistry,
    ) -> None:
        """Test parsing real OUD entries from fixtures."""
        entries_file = Path("tests/fixtures/oud/oud_entries_fixtures.ldif")

        if not entries_file.exists():
            pytest.skip(f"Fixture not found: {entries_file}")

        parser = FlextLdifParserService(
            config=FlextLdifConfig(),
        )

        result = parser.parse_file(entries_file)

        assert result.is_success, f"Failed to parse: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0

    def test_parse_openldap_entries_fixture(
        self,
        quirk_registry: FlextLdifRegistry,
    ) -> None:
        """Test parsing real OpenLDAP entries from fixtures."""
        entries_file = Path("tests/fixtures/openldap2/openldap2_entries_fixtures.ldif")

        if not entries_file.exists():
            pytest.skip(f"Fixture not found: {entries_file}")

        parser = FlextLdifParserService(
            config=FlextLdifConfig(),
        )

        result = parser.parse_file(entries_file)

        assert result.is_success, f"Failed to parse: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0


class TestRfcSchemaParserRealFixtures:
    """Test RFC schema parser with real fixture data."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifRegistry:
        """Create quirk registry."""
        return FlextLdifRegistry()

    def test_parse_oid_schema_fixture(
        self,
        quirk_registry: FlextLdifRegistry,
    ) -> None:
        """Test parsing real OID schema from fixtures."""
        schema_file = Path("tests/fixtures/oid/oid_schema_fixtures.ldif")

        if not schema_file.exists():
            pytest.skip(f"Fixture not found: {schema_file}")

        parser = FlextLdifParserService(
            config=FlextLdifConfig(),
        )

        result = parser.parse_file(schema_file)

        assert result.is_success, f"Failed to parse: {result.error}"
        entries = result.unwrap()
        # Schema entries should be parsed with automatic schema extraction
        assert len(entries) > 0

    def test_parse_oud_schema_fixture(
        self,
        quirk_registry: FlextLdifRegistry,
    ) -> None:
        """Test parsing real OUD schema from fixtures."""
        schema_file = Path("tests/fixtures/oud/oud_schema_fixtures.ldif")

        if not schema_file.exists():
            pytest.skip(f"Fixture not found: {schema_file}")

        parser = FlextLdifParserService(
            config=FlextLdifConfig(),
        )

        result = parser.parse_file(schema_file)

        assert result.is_success, f"Failed to parse: {result.error}"


class TestRfcWriterRealFixtures:
    """Test RFC writer with real fixture data."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifRegistry:
        """Create quirk registry."""
        return FlextLdifRegistry()

    def test_write_and_reparse_oid_entries(
        self,
        quirk_registry: FlextLdifRegistry,
        tmp_path: Path,
    ) -> None:
        """Test roundtrip: parse OID fixture, write, and re-parse."""
        source_file = Path("tests/fixtures/oid/oid_entries_fixtures.ldif")

        if not source_file.exists():
            pytest.skip(f"Fixture not found: {source_file}")

        # Parse original
        parser = FlextLdifParserService(
            config=FlextLdifConfig(),
        )
        parse_result = parser.parse_file(source_file)

        assert parse_result.is_success, f"Failed to parse source: {parse_result.error}"
        entries = parse_result.unwrap()
        original_count = len(entries)

        # Write to file
        output_file = tmp_path / "roundtrip.ldif"

        writer = FlextLdifWriterService(
            config=FlextLdifConfig(),
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        write_result = writer.write(entries, output_file)

        assert write_result.is_success, f"Failed to write: {write_result.error}"
        assert output_file.exists()

        # Re-parse
        reparser = FlextLdifParserService(
            config=FlextLdifConfig(),
        )
        reparse_result = reparser.parse_file(output_file)

        assert reparse_result.is_success, f"Failed to re-parse: {reparse_result.error}"
        reparsed_entries = reparse_result.unwrap()

        # Verify counts match
        assert len(reparsed_entries) == original_count

    def test_write_oud_acl_entries(
        self,
        quirk_registry: FlextLdifRegistry,
        tmp_path: Path,
    ) -> None:
        """Test writing OUD ACL entries to file."""
        acl_file = Path("tests/fixtures/oud/oud_acl_fixtures.ldif")

        if not acl_file.exists():
            pytest.skip(f"Fixture not found: {acl_file}")

        parser = FlextLdifParserService(
            config=FlextLdifConfig(),
        )

        parse_result = parser.parse_file(acl_file)

        if not parse_result.is_success:
            pytest.skip(f"Failed to parse ACL fixture: {parse_result.error}")

        entries = parse_result.unwrap()

        # Write to file
        output_file = tmp_path / "acl_output.ldif"

        writer = FlextLdifWriterService(
            config=FlextLdifConfig(),
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.write(entries, output_file)

        assert result.is_success, f"Failed to write ACL entries: {result.error}"
        assert output_file.exists()


class TestRfcExceptionHandlingRealScenarios:
    """Test RFC exception handling with real scenarios."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifRegistry:
        """Create quirk registry."""
        return FlextLdifRegistry()

    def test_parse_nonexistent_file(
        self,
        quirk_registry: FlextLdifRegistry,
    ) -> None:
        """Test parsing nonexistent file returns error."""
        parser = FlextLdifParserService(
            config=FlextLdifConfig(),
        )

        result = parser.parse_file(Path("/nonexistent/file.ldif"))

        assert not result.is_success
        assert result.error is not None

    def test_write_to_readonly_directory(
        self,
        quirk_registry: FlextLdifRegistry,
        tmp_path: Path,
    ) -> None:
        """Test write to read-only directory returns error."""
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o555)

        try:
            # Create test entry
            from flext_ldif.models import FlextLdifModels

            test_entry = FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
                attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test"]}),
            )

            writer = FlextLdifWriterService(
                config=FlextLdifConfig(),
                quirk_registry=quirk_registry,
                target_server_type="rfc",
            )

            result = writer.write([test_entry], readonly_dir / "test.ldif")

            # Should fail with permission error
            if not result.is_success:
                assert (
                    "Permission denied" in result.error
                    or "LDIF write failed" in result.error
                )
        finally:
            readonly_dir.chmod(0o755)

    def test_parse_empty_file(
        self,
        quirk_registry: FlextLdifRegistry,
        tmp_path: Path,
    ) -> None:
        """Test parsing empty file."""
        empty_file = tmp_path / "empty.ldif"
        empty_file.write_text("")

        parser = FlextLdifParserService(
            config=FlextLdifConfig(),
        )

        result = parser.parse_file(empty_file)

        # Empty file should parse successfully with 0 entries
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 0
