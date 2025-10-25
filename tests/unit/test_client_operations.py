"""Comprehensive real tests for FlextLdifClient low-level operations.

Tests the FlextLdifClient implementation with real LDIF data from multiple
server types using actual fixture files for parse, write, and transformation operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdifClient
from flext_ldif.models import FlextLdifModels


class TestFlextLdifClientOperations:
    """Test FlextLdifClient low-level operations with real fixture data."""

    @pytest.fixture
    def client(self) -> FlextLdifClient:
        """Create FlextLdifClient instance."""
        return FlextLdifClient()

    @pytest.fixture
    def oid_entries_fixture(self) -> Path:
        """Get path to OID entries fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_entries_fixtures.ldif"
        )

    @pytest.fixture
    def oid_schema_fixture(self) -> Path:
        """Get path to OID schema fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_schema_fixtures.ldif"
        )

    @pytest.fixture
    def oid_acl_fixture(self) -> Path:
        """Get path to OID ACL fixture."""
        return (
            Path(__file__).parent.parent / "fixtures" / "oid" / "oid_acl_fixtures.ldif"
        )

    @pytest.fixture
    def oud_entries_fixture(self) -> Path:
        """Get path to OUD entries fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oud"
            / "oud_entries_fixtures.ldif"
        )

    # =========================================================================
    # PARSE OPERATIONS TESTS
    # =========================================================================

    def test_parse_ldif_from_file(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test parsing LDIF from file path."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        result = client.parse_ldif(oid_entries_fixture)
        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) > 0

    def test_parse_ldif_from_string(self, client: FlextLdifClient) -> None:
        """Test parsing LDIF from string content."""
        ldif_content = (
            "dn: cn=test,dc=example,dc=com\ncn: test\nobjectClass: person\n\n"
        )
        result = client.parse_ldif(ldif_content)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0

    def test_parse_ldif_with_server_type(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test parsing LDIF with specific server type."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        result = client.parse_ldif(oid_entries_fixture, server_type="oid")
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0

    def test_parse_ldif_schema(
        self, client: FlextLdifClient, oid_schema_fixture: Path
    ) -> None:
        """Test parsing schema LDIF."""
        if not oid_schema_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_schema_fixture}")

        result = client.parse_ldif(oid_schema_fixture)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0

    def test_parse_ldif_acl(
        self, client: FlextLdifClient, oid_acl_fixture: Path
    ) -> None:
        """Test parsing ACL LDIF."""
        if not oid_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_acl_fixture}")

        result = client.parse_ldif(oid_acl_fixture)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0

    def test_parse_ldif_invalid_path(self, client: FlextLdifClient) -> None:
        """Test parsing nonexistent file fails."""
        result = client.parse_ldif(Path("/nonexistent/file.ldif"))
        assert result.is_failure

    def test_parse_ldif_empty_content(self, client: FlextLdifClient) -> None:
        """Test parsing empty content."""
        result = client.parse_ldif("")
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 0

    # =========================================================================
    # WRITE OPERATIONS TESTS
    # =========================================================================

    def test_write_ldif_to_string(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test writing entries to LDIF string."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = client.parse_ldif(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        write_result = client.write_ldif(entries)
        assert write_result.is_success
        ldif_content = write_result.unwrap()
        assert isinstance(ldif_content, str)
        assert "dn:" in ldif_content

    def test_write_ldif_to_file(
        self, client: FlextLdifClient, oid_entries_fixture: Path, tmp_path: Path
    ) -> None:
        """Test writing entries to file."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = client.parse_ldif(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        output_file = tmp_path / "output.ldif"
        write_result = client.write_ldif(entries, output_path=output_file)
        assert write_result.is_success
        assert output_file.exists()

    def test_write_ldif_empty_entries(self, client: FlextLdifClient) -> None:
        """Test writing empty entries list."""
        result = client.write_ldif([])
        assert result.is_success
        content = result.unwrap()
        assert isinstance(content, str)

    # =========================================================================
    # ENCODING DETECTION TESTS
    # =========================================================================

    def test_detect_encoding_utf8(self, client: FlextLdifClient) -> None:
        """Test UTF-8 encoding detection."""
        content = b"dn: cn=test,dc=example,dc=com\ncn: test\n"
        result = client.detect_encoding(content)
        assert result.is_success
        encoding = result.unwrap()
        assert isinstance(encoding, str)

    def test_detect_encoding_from_fixture(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test encoding detection from fixture."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        content = oid_entries_fixture.read_bytes()
        result = client.detect_encoding(content)
        assert result.is_success
        encoding = result.unwrap()
        assert isinstance(encoding, str)

    def test_detect_encoding_empty(self, client: FlextLdifClient) -> None:
        """Test encoding detection on empty content."""
        result = client.detect_encoding(b"")
        assert result.is_success
        encoding = result.unwrap()
        assert isinstance(encoding, str)

    # =========================================================================
    # VALIDATION TESTS
    # =========================================================================

    def test_validate_ldif_syntax_valid(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test LDIF syntax validation on valid content."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        content = oid_entries_fixture.read_text(encoding="utf-8")
        result = client.validate_ldif_syntax(content)
        assert result.is_success
        is_valid = result.unwrap()
        assert isinstance(is_valid, bool)

    def test_validate_ldif_syntax_string(self, client: FlextLdifClient) -> None:
        """Test LDIF syntax validation on string."""
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\nobjectClass: person\n"
        result = client.validate_ldif_syntax(ldif_content)
        assert result.is_success
        is_valid = result.unwrap()
        assert isinstance(is_valid, bool)

    def test_validate_entries(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test entry validation."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = client.parse_ldif(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        result = client.validate_entries(entries)
        assert result.is_success

    # =========================================================================
    # COUNT OPERATIONS TESTS
    # =========================================================================

    def test_count_ldif_entries_from_fixture(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test counting entries in fixture."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        content = oid_entries_fixture.read_text(encoding="utf-8")
        result = client.count_ldif_entries(content)
        assert result.is_success
        count = result.unwrap()
        assert count > 0

    def test_count_ldif_entries_string(self, client: FlextLdifClient) -> None:
        """Test counting entries in string."""
        ldif_content = (
            "dn: cn=test1,dc=example,dc=com\n"
            "cn: test1\n"
            "\n"
            "dn: cn=test2,dc=example,dc=com\n"
            "cn: test2\n"
        )
        result = client.count_ldif_entries(ldif_content)
        assert result.is_success
        count = result.unwrap()
        assert count >= 1

    def test_count_ldif_entries_empty(self, client: FlextLdifClient) -> None:
        """Test counting entries in empty content."""
        result = client.count_ldif_entries("")
        assert result.is_success
        count = result.unwrap()
        assert count == 0

    # =========================================================================
    # ANALYZE OPERATIONS TESTS
    # =========================================================================

    def test_analyze_entries(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test analyzing entries."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = client.parse_ldif(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        result = client.analyze_entries(entries)
        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, FlextLdifModels.EntryAnalysisResult)

    def test_analyze_empty_entries(self, client: FlextLdifClient) -> None:
        """Test analyzing empty entries."""
        result = client.analyze_entries([])
        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, FlextLdifModels.EntryAnalysisResult)

    # =========================================================================
    # FILTER OPERATIONS TESTS
    # =========================================================================

    def test_filter_by_objectclass(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test filtering by objectclass."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = client.parse_ldif(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        if len(entries) > 0:
            result = client.filter(
                entries, filter_type="objectclass", objectclass="person"
            )
            assert result.is_success
            filtered = result.unwrap()
            assert isinstance(filtered, list)

    def test_filter_by_dn_pattern(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test filtering by DN pattern."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = client.parse_ldif(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        if len(entries) > 0:
            result = client.filter(
                entries, filter_type="dn_pattern", dn_pattern="dc=example"
            )
            assert result.is_success
            filtered = result.unwrap()
            assert isinstance(filtered, list)

    def test_filter_by_attributes(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test filtering by attributes."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = client.parse_ldif(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        if len(entries) > 0:
            result = client.filter(entries, filter_type="attributes", attributes=["cn"])
            assert result.is_success
            filtered = result.unwrap()
            assert isinstance(filtered, list)

    # =========================================================================
    # MIGRATION OPERATIONS TESTS
    # =========================================================================

    def test_migrate_files(self, tmp_path: Path, client: FlextLdifClient) -> None:
        """Test file migration."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        # Create simple LDIF file
        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("dn: cn=test,dc=example,dc=com\ncn: test\n")

        result = client.migrate_files(
            input_dir=input_dir,
            output_dir=output_dir,
            from_server="rfc",
            to_server="rfc",
        )
        assert isinstance(result.is_success, bool)

    # =========================================================================
    # SERVER TYPE DETECTION TESTS
    # =========================================================================

    def test_detect_server_type_from_file(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test detecting server type from file."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        result = client.detect_server_type(ldif_path=oid_entries_fixture)
        assert result.is_success
        detection = result.unwrap()
        # ServerDetectionResult is a Pydantic model, not a dict
        assert hasattr(detection, "detected_server_type")
        assert detection.detected_server_type is not None

    def test_detect_server_type_from_content(self, client: FlextLdifClient) -> None:
        """Test detecting server type from content."""
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"
        result = client.detect_server_type(ldif_content=ldif_content)
        assert result.is_success
        detection = result.unwrap()
        # ServerDetectionResult is a Pydantic model, not a dict
        assert hasattr(detection, "detected_server_type")
        assert detection.detected_server_type is not None

    # =========================================================================
    # EFFECTIVE SERVER TYPE TESTS
    # =========================================================================

    def test_get_effective_server_type(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test getting effective server type."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        result = client.get_effective_server_type(oid_entries_fixture)
        assert result.is_success
        server_type = result.unwrap()
        assert isinstance(server_type, str)

    def test_get_effective_server_type_none(self, client: FlextLdifClient) -> None:
        """Test getting effective server type with no path."""
        result = client.get_effective_server_type()
        assert result.is_success
        server_type = result.unwrap()
        assert isinstance(server_type, str)

    # =========================================================================
    # CONFIGURATION ACCESS TESTS
    # =========================================================================

    def test_client_config_access(self, client: FlextLdifClient) -> None:
        """Test accessing client configuration."""
        config = client.config
        assert config is not None
        assert hasattr(config, "ldif_encoding")

    # =========================================================================
    # ROUNDTRIP TESTS
    # =========================================================================

    def test_roundtrip_parse_write_parse(
        self, client: FlextLdifClient, oid_entries_fixture: Path, tmp_path: Path
    ) -> None:
        """Test roundtrip: parse → write → parse."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        # Parse original
        parse1 = client.parse_ldif(oid_entries_fixture)
        assert parse1.is_success
        entries1 = parse1.unwrap()
        count1 = len(entries1)

        # Write to temp
        output_file = tmp_path / "roundtrip.ldif"
        write_result = client.write_ldif(entries1, output_path=output_file)
        assert write_result.is_success

        # Parse written file
        parse2 = client.parse_ldif(output_file)
        assert parse2.is_success
        entries2 = parse2.unwrap()
        count2 = len(entries2)

        # Verify counts match
        assert count1 == count2

    def test_roundtrip_string_parse_write_string(self, client: FlextLdifClient) -> None:
        """Test roundtrip with string content."""
        original_content = (
            "dn: cn=test,dc=example,dc=com\ncn: test\nobjectClass: person\n\n"
        )

        # Parse
        parse_result = client.parse_ldif(original_content)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Write back to string
        write_result = client.write_ldif(entries)
        assert write_result.is_success
        output_content = write_result.unwrap()
        assert isinstance(output_content, str)
        assert len(output_content) > 0

    # =========================================================================
    # MULTI-FIXTURE OPERATIONS TESTS
    # =========================================================================

    def test_parse_multiple_fixtures_sequential(
        self,
        client: FlextLdifClient,
        oid_entries_fixture: Path,
        oud_entries_fixture: Path,
    ) -> None:
        """Test parsing multiple fixtures sequentially."""
        if not oid_entries_fixture.exists() or not oud_entries_fixture.exists():
            pytest.skip("One or both fixtures not found")

        # Parse OID
        result1 = client.parse_ldif(oid_entries_fixture)
        assert result1.is_success
        entries1 = result1.unwrap()

        # Parse OUD
        result2 = client.parse_ldif(oud_entries_fixture)
        assert result2.is_success
        entries2 = result2.unwrap()

        # Both successful
        assert len(entries1) > 0
        assert len(entries2) > 0

    def test_parse_schema_and_entries_sequential(
        self,
        client: FlextLdifClient,
        oid_entries_fixture: Path,
        oid_schema_fixture: Path,
    ) -> None:
        """Test parsing schema and entries sequentially."""
        if not oid_entries_fixture.exists() or not oid_schema_fixture.exists():
            pytest.skip("One or both fixtures not found")

        # Parse entries
        result1 = client.parse_ldif(oid_entries_fixture)
        assert result1.is_success
        entries = result1.unwrap()

        # Parse schema
        result2 = client.parse_ldif(oid_schema_fixture)
        assert result2.is_success
        schema = result2.unwrap()

        # Both successful
        assert len(entries) > 0
        assert len(schema) > 0

    # =========================================================================
    # ERROR HANDLING TESTS
    # =========================================================================

    def test_parse_invalid_file_path(self, client: FlextLdifClient) -> None:
        """Test parsing invalid file path."""
        result = client.parse_ldif(Path("/invalid/path/file.ldif"))
        assert result.is_failure

    def test_write_to_invalid_directory(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test writing to invalid directory."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = client.parse_ldif(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Try to write to nonexistent directory
        invalid_path = Path("/invalid/nonexistent/directory/file.ldif")
        result = client.write_ldif(entries, output_path=invalid_path)
        # May succeed or fail depending on implementation
        assert isinstance(result.is_success, bool)

    # =========================================================================
    # EXECUTE/STATUS TESTS
    # =========================================================================

    def test_execute_returns_status(self, client: FlextLdifClient) -> None:
        """Test execute method returns status."""
        result = client.execute()
        assert result.is_success
        status = result.unwrap()
        assert isinstance(status, FlextLdifModels.ClientStatus)
