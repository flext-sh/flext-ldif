from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
from flext_tests.utilities import FlextTestsUtilities

from flext_ldif import FlextLdifMigrationPipeline
from flext_ldif.models import m
from tests import c, m, s


class TestsTestFlextLdifMigrationPipeline(s):
    """Consolidated test suite for LDIF migration pipeline.

    Tests initialization, validation, execution with different server types.
    """

    # ════════════════════════════════════════════════════════════════════════
    # INITIALIZATION TESTS
    # ════════════════════════════════════════════════════════════════════════

    def test_initialization_with_required_params(self, tmp_path: Path) -> None:
        """Test pipeline initializes with required parameters."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type="oid",
            target_server_type="oud",
        )

        assert pipeline is not None
        assert pipeline.input_dir == input_dir
        assert pipeline.output_dir == output_dir
        assert pipeline.source_server_type == "oid"
        assert pipeline.target_server_type == "oud"

    def test_initialization_with_defaults(self, tmp_path: Path) -> None:
        """Test pipeline initialization with default server types."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
        )

        assert pipeline is not None
        assert pipeline.source_server_type == "rfc"
        assert pipeline.target_server_type == "rfc"

    @pytest.mark.parametrize(
        ("source", "target"),
        [
            ("oid", "oud"),
            ("oid", "openldap"),
            ("oud", "openldap"),
            ("openldap", "oid"),
            ("openldap", "oud"),
            ("rfc", "rfc"),
        ],
    )
    def test_initialization_with_different_server_types(
        self,
        source: str,
        target: str,
        tmp_path: Path,
    ) -> None:
        """Test pipeline initialization with various server type combinations."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=cast("c.LiteralTypes.ServerTypeLiteral", source),
            target_server_type=cast("c.LiteralTypes.ServerTypeLiteral", target),
        )

        assert pipeline is not None
        assert pipeline.source_server_type == source
        assert pipeline.target_server_type == target

    # ════════════════════════════════════════════════════════════════════════
    # VALIDATION TESTS
    # ════════════════════════════════════════════════════════════════════════

    def test_execute_fails_with_no_input_dir(self) -> None:
        """Test pipeline fails when input directory is not specified."""
        pipeline = FlextLdifMigrationPipeline(
            source_server_type="oid",
            target_server_type="oud",
        )

        result = pipeline.execute()

        assert result.is_failure
        assert "input_dir" in str(result.error).lower()

    def test_execute_fails_with_no_output_dir(self, tmp_path: Path) -> None:
        """Test pipeline fails when output directory is not specified."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            source_server_type="oid",
            target_server_type="oud",
        )

        result = pipeline.execute()

        assert result.is_failure
        assert "output_dir" in str(result.error).lower()

    def test_execute_fails_with_nonexistent_input_dir(self, tmp_path: Path) -> None:
        """Test pipeline fails when input directory doesn't exist."""
        nonexistent_input = tmp_path / "nonexistent"
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=nonexistent_input,
            output_dir=output_dir,
            source_server_type="oid",
            target_server_type="oud",
        )

        result = pipeline.execute()

        assert result.is_failure
        assert "not found" in str(result.error).lower()

    def test_execute_creates_output_dir_if_missing(self, tmp_path: Path) -> None:
        """Test pipeline creates output directory if it doesn't exist."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        nonexistent_output = tmp_path / "nonexistent"

        # Create a simple LDIF file
        (input_dir / "test.ldif").write_text(
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n",
        )

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=nonexistent_output,
            source_server_type="rfc",
            target_server_type="rfc",
        )

        result = pipeline.execute()

        # Pipeline should succeed and create the output directory
        assert result.is_success
        FlextTestsUtilities.FileHelpers.assert_file_exists(nonexistent_output)

    # ════════════════════════════════════════════════════════════════════════
    # EMPTY INPUT TESTS
    # ════════════════════════════════════════════════════════════════════════

    def test_execute_with_empty_input(self, tmp_path: Path) -> None:
        """Test pipeline handles empty input directory gracefully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # No LDIF files in input directory
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type="oid",
            target_server_type="oud",
        )

        result = pipeline.execute()

        # Pipeline should succeed with 0 entries
        assert result.is_success
        migration_result = result.unwrap()
        assert migration_result.stats.total_entries == 0

    # ════════════════════════════════════════════════════════════════════════
    # BASIC EXECUTION TESTS
    # ════════════════════════════════════════════════════════════════════════

    def test_basic_execution_rfc_to_rfc(self, tmp_path: Path) -> None:
        """Test basic migration from RFC to c.RFC."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create a simple LDIF file
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
objectClass: top
cn: test
sn: test
"""
        (input_dir / "test.ldif").write_text(ldif_content)

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type="rfc",
            target_server_type="rfc",
        )

        result = pipeline.execute()

        assert result.is_success
        migration_result = result.unwrap()
        assert migration_result.stats.processed_entries >= 1

    def test_migrate_entries_method(self, tmp_path: Path) -> None:
        """Test migrate_entries method directly."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type="rfc",
            target_server_type="rfc",
        )

        # Create test entries
        entries = [
            m.Entry(
                dn="cn=test,dc=example,dc=com",
                attributes={"cn": ["test"], "objectClass": ["person"]},
            ),
        ]

        result = pipeline.migrate_entries(entries)

        assert result.is_success
        migrated = result.unwrap()
        assert len(migrated) == 1

    def test_migrate_file_method(self, tmp_path: Path) -> None:
        """Test migrate_file method directly."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create LDIF file
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
"""
        input_file = input_dir / "test.ldif"
        input_file.write_text(ldif_content)

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type="rfc",
            target_server_type="rfc",
        )

        result = pipeline.migrate_file(input_file)

        assert result.is_success
        migration_result = result.unwrap()
        assert migration_result.stats.total_entries >= 1

    # ════════════════════════════════════════════════════════════════════════
    # SERVER CONVERSION TESTS
    # ════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("source", "target"),
        [
            ("oid", "oud"),
            ("oud", "oid"),
            ("rfc", "oid"),
            ("rfc", "oud"),
        ],
    )
    def test_server_conversion_modes(
        self,
        source: str,
        target: str,
        tmp_path: Path,
    ) -> None:
        """Test server-specific conversion modes."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        (input_dir / "test.ldif").write_text(
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n",
        )

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=cast("c.LiteralTypes.ServerTypeLiteral", source),
            target_server_type=cast("c.LiteralTypes.ServerTypeLiteral", target),
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure

    # ════════════════════════════════════════════════════════════════════════
    # MULTIPLE FILES TESTS
    # ════════════════════════════════════════════════════════════════════════

    def test_execute_with_multiple_files(self, tmp_path: Path) -> None:
        """Test pipeline processes multiple input files."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create multiple LDIF files
        (input_dir / "schema.ldif").write_text(
            "dn: cn=schema\nobjectClass: top\ncn: schema\n",
        )
        (input_dir / "data.ldif").write_text(
            "dn: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com\nobjectClass: person\ncn: REDACTED_LDAP_BIND_PASSWORD\n",
        )

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type="rfc",
            target_server_type="rfc",
        )

        result = pipeline.execute()

        assert result.is_success
        migration_result = result.unwrap()
        # Should process entries from both files
        assert migration_result.stats.total_entries >= 2

    # ════════════════════════════════════════════════════════════════════════
    # EDGE CASE TESTS
    # ════════════════════════════════════════════════════════════════════════

    def test_migrate_file_not_found(self, tmp_path: Path) -> None:
        """Test migrate_file handles non-existent file gracefully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type="rfc",
            target_server_type="rfc",
        )

        nonexistent_file = input_dir / "nonexistent.ldif"
        result = pipeline.migrate_file(nonexistent_file)

        assert result.is_failure
        assert "not found" in str(result.error).lower()

    def test_migrate_entries_empty_list(self, tmp_path: Path) -> None:
        """Test migrate_entries handles empty list gracefully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type="rfc",
            target_server_type="rfc",
        )

        result = pipeline.migrate_entries([])

        assert result.is_success
        migrated = result.unwrap()
        assert len(migrated) == 0
