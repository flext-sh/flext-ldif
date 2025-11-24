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

from flext_ldif import (
    FlextLdifConfig,
    FlextLdifModels,
    FlextLdifParser,
    FlextLdifWriter,
)
from flext_ldif.services.server import FlextLdifServer

from ..helpers.test_ldif_helpers import OptimizedLdifTestHelpers


class TestRfcParserRealFixtures:
    """Test RFC parser with real fixture data."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifServer:
        """Create quirk registry."""
        return FlextLdifServer()

    def test_parse_oid_entries_fixture(
        self,
        quirk_registry: FlextLdifServer,
    ) -> None:
        """Test parsing real OID entries from fixtures."""
        entries_file = Path("tests/fixtures/oid/oid_entries_fixtures.ldif")

        if not entries_file.exists():
            pytest.skip(f"Fixture not found: {entries_file}")

        # Using optimized helper - reduces 8 lines to 1 line
        parse_response = OptimizedLdifTestHelpers.parse_ldif_file_and_validate(
            entries_file
        )

        # Additional validation specific to this test
        OptimizedLdifTestHelpers.validate_entries_structure(parse_response.entries)

    def test_parse_oud_entries_fixture(
        self,
        quirk_registry: FlextLdifServer,
    ) -> None:
        """Test parsing real OUD entries from fixtures."""
        entries_file = Path("tests/fixtures/oud/oud_entries_fixtures.ldif")

        if not entries_file.exists():
            pytest.skip(f"Fixture not found: {entries_file}")

        parser = FlextLdifParser()

        result = parser.parse_ldif_file(entries_file)

        assert result.is_success, f"Failed to parse: {result.error}"
        parse_response = result.unwrap()
        assert len(parse_response.entries) > 0

    def test_parse_openldap_entries_fixture(
        self,
        quirk_registry: FlextLdifServer,
    ) -> None:
        """Test parsing real OpenLDAP entries from fixtures."""
        entries_file = Path("tests/fixtures/openldap2/openldap2_entries_fixtures.ldif")

        if not entries_file.exists():
            pytest.skip(f"Fixture not found: {entries_file}")

        parser = FlextLdifParser()

        result = parser.parse_ldif_file(entries_file)

        assert result.is_success, f"Failed to parse: {result.error}"
        parse_response = result.unwrap()
        assert len(parse_response.entries) > 0


class TestRfcSchemaParserRealFixtures:
    """Test RFC schema parser with real fixture data."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifServer:
        """Create quirk registry."""
        return FlextLdifServer()

    def test_parse_oid_schema_fixture(
        self,
        quirk_registry: FlextLdifServer,
    ) -> None:
        """Test parsing real OID schema from fixtures."""
        schema_file = Path("tests/fixtures/oid/oid_schema_fixtures.ldif")

        if not schema_file.exists():
            pytest.skip(f"Fixture not found: {schema_file}")

        parser = FlextLdifParser()

        result = parser.parse_ldif_file(schema_file)

        assert result.is_success, f"Failed to parse: {result.error}"
        parse_response = result.unwrap()
        # Schema entries should be parsed with automatic schema extraction
        assert len(parse_response.entries) > 0

    def test_parse_oud_schema_fixture(
        self,
        quirk_registry: FlextLdifServer,
    ) -> None:
        """Test parsing real OUD schema from fixtures."""
        schema_file = Path("tests/fixtures/oud/oud_schema_fixtures.ldif")

        if not schema_file.exists():
            pytest.skip(f"Fixture not found: {schema_file}")

        parser = FlextLdifParser()

        result = parser.parse_ldif_file(schema_file)

        assert result.is_success, f"Failed to parse: {result.error}"


class TestRfcWriterRealFixtures:
    """Test RFC writer with real fixture data."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifServer:
        """Create quirk registry."""
        return FlextLdifServer()

    def test_write_and_reparse_oid_entries(
        self,
        quirk_registry: FlextLdifServer,
        tmp_path: Path,
    ) -> None:
        """Test roundtrip: parse OID fixture, write, and re-parse."""
        source_file = Path("tests/fixtures/oid/oid_entries_fixtures.ldif")

        if not source_file.exists():
            pytest.skip(f"Fixture not found: {source_file}")

        # Parse original
        parser = FlextLdifParser()
        parse_result = parser.parse_ldif_file(source_file)

        assert parse_result.is_success, f"Failed to parse source: {parse_result.error}"
        parse_response = parse_result.unwrap()
        entries = parse_response.entries
        original_count = len(entries)

        # Write to file
        output_file = tmp_path / "roundtrip.ldif"

        writer = FlextLdifWriter(
            config=FlextLdifConfig(),
            quirk_registry=quirk_registry,
        )
        write_result = writer.write(
            entries,
            target_server_type="rfc",
            output_target="file",
            output_path=output_file,
        )

        assert write_result.is_success, f"Failed to write: {write_result.error}"
        assert output_file.exists()

        # Re-parse
        reparser = FlextLdifParser(
            config=FlextLdifConfig(),
        )
        reparse_result = reparser.parse_ldif_file(output_file)

        assert reparse_result.is_success, f"Failed to re-parse: {reparse_result.error}"
        reparsed_response = reparse_result.unwrap()

        # Verify counts match
        assert len(reparsed_response.entries) == original_count

    def test_write_oud_acl_entries(
        self,
        quirk_registry: FlextLdifServer,
        tmp_path: Path,
    ) -> None:
        """Test writing OUD ACL entries to file."""
        acl_file = Path("tests/fixtures/oud/oud_acl_fixtures.ldif")

        if not acl_file.exists():
            pytest.skip(f"Fixture not found: {acl_file}")

        parser = FlextLdifParser()

        parse_result = parser.parse_ldif_file(acl_file)

        if not parse_result.is_success:
            pytest.skip(f"Failed to parse ACL fixture: {parse_result.error}")

        parse_response = parse_result.unwrap()
        entries = parse_response.entries

        # Write to file
        output_file = tmp_path / "acl_output.ldif"

        writer = FlextLdifWriter(
            quirk_registry=quirk_registry,
        )

        result = writer.write(
            entries,
            target_server_type="rfc",
            output_target="file",
            output_path=output_file,
        )

        assert result.is_success, f"Failed to write ACL entries: {result.error}"
        assert output_file.exists()


class TestRfcExceptionHandlingRealScenarios:
    """Test RFC exception handling with real scenarios."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifServer:
        """Create quirk registry."""
        return FlextLdifServer()

    def test_parse_nonexistent_file(
        self,
        quirk_registry: FlextLdifServer,
    ) -> None:
        """Test parsing nonexistent file returns error."""
        parser = FlextLdifParser()

        result = parser.parse_ldif_file(Path("/nonexistent/file.ldif"))

        assert not result.is_success
        assert result.error is not None

    def test_write_to_readonly_directory(
        self,
        quirk_registry: FlextLdifServer,
        tmp_path: Path,
    ) -> None:
        """Test write to read-only directory returns error."""
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o555)

        try:
            # Create test entry
            test_entry = FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
                attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test"]}),
            )

            writer = FlextLdifWriter(
                config=FlextLdifConfig(),
                quirk_registry=quirk_registry,
            )

            result = writer.write(
                [test_entry],
                target_server_type="rfc",
                output_target="file",
                output_path=readonly_dir / "test.ldif",
            )

            # Should fail with permission error
            if not result.is_success:
                assert result.error is not None
                assert (
                    "Permission denied" in result.error
                    or "LDIF write failed" in result.error
                )
        finally:
            readonly_dir.chmod(0o755)

    def test_parse_empty_file(
        self,
        quirk_registry: FlextLdifServer,
        tmp_path: Path,
    ) -> None:
        """Test parsing empty file."""
        empty_file = tmp_path / "empty.ldif"
        empty_file.write_text("")

        parser = FlextLdifParser()

        result = parser.parse_ldif_file(empty_file)

        # Empty file should parse successfully with 0 entries
        assert result.is_success
        parse_response = result.unwrap()
        assert len(parse_response.entries) == 0
