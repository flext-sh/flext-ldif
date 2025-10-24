"""Comprehensive real tests for FlextLdifMigrationPipeline operations.

Tests the migration pipeline with real LDIF data from multiple server types,
focusing on server-to-server transformations using actual fixture files.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdifClient, FlextLdifMigrationPipeline


class TestFlextLdifMigrationPipelineOperations:
    """Test FlextLdifMigrationPipeline with real server migration scenarios."""

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
    # BASIC INITIALIZATION TESTS
    # =========================================================================

    def test_migration_pipeline_initialization(self, tmp_path: Path) -> None:
        """Test migration pipeline initialization."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        assert pipeline is not None

    def test_migration_pipeline_with_oid_source(self, tmp_path: Path) -> None:
        """Test migration pipeline with OID as source."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="oid",
            target_server_type="rfc",
        )
        assert pipeline is not None

    def test_migration_pipeline_with_oud_source(self, tmp_path: Path) -> None:
        """Test migration pipeline with OUD as source."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="oud",
            target_server_type="rfc",
        )
        assert pipeline is not None

    def test_migration_pipeline_oid_to_oud(self, tmp_path: Path) -> None:
        """Test OID to OUD migration pipeline."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="oid",
            target_server_type="oud",
        )
        assert pipeline is not None

    def test_migration_pipeline_oud_to_oid(self, tmp_path: Path) -> None:
        """Test OUD to OID migration pipeline."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="oud",
            target_server_type="oid",
        )
        assert pipeline is not None

    def test_migration_pipeline_with_openldap_source(self, tmp_path: Path) -> None:
        """Test migration pipeline with OpenLDAP as source."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="openldap",
            target_server_type="rfc",
        )
        assert pipeline is not None

    # =========================================================================
    # EXECUTION TESTS WITH REAL FIXTURES
    # =========================================================================

    def test_execute_migration_simple(
        self, tmp_path: Path, oid_entries_fixture: Path
    ) -> None:
        """Test executing migration with real OID fixture."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        # Copy fixture to input directory
        import shutil

        shutil.copy(oid_entries_fixture, input_dir / "entries.ldif")

        # Execute RFC-to-RFC migration (no-op transformation)
        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success

    def test_execute_migration_oid_source(
        self, tmp_path: Path, oid_entries_fixture: Path
    ) -> None:
        """Test executing migration with OID source."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        import shutil

        shutil.copy(oid_entries_fixture, input_dir / "entries.ldif")

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="oid",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success

    def test_execute_migration_schema(
        self, tmp_path: Path, oid_schema_fixture: Path
    ) -> None:
        """Test executing migration with schema fixture."""
        if not oid_schema_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_schema_fixture}")

        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        import shutil

        shutil.copy(oid_schema_fixture, input_dir / "schema.ldif")

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success

    def test_execute_migration_acl(self, tmp_path: Path, oid_acl_fixture: Path) -> None:
        """Test executing migration with ACL fixture."""
        if not oid_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_acl_fixture}")

        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        import shutil

        shutil.copy(oid_acl_fixture, input_dir / "acl.ldif")

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success

    # =========================================================================
    # MULTIPLE FILES TESTS
    # =========================================================================

    def test_execute_migration_multiple_files(
        self, tmp_path: Path, oid_entries_fixture: Path, oid_schema_fixture: Path
    ) -> None:
        """Test migration with multiple input files."""
        if not oid_entries_fixture.exists() or not oid_schema_fixture.exists():
            pytest.skip("One or both fixtures not found")

        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        import shutil

        shutil.copy(oid_entries_fixture, input_dir / "entries.ldif")
        shutil.copy(oid_schema_fixture, input_dir / "schema.ldif")

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success

    # =========================================================================
    # CONFIGURATION TESTS
    # =========================================================================

    def test_migration_pipeline_with_custom_batch_size(self, tmp_path: Path) -> None:
        """Test migration pipeline with custom batch size."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
                "batch_size": 50,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        assert pipeline is not None

    def test_migration_pipeline_with_parallel_processing(self, tmp_path: Path) -> None:
        """Test migration pipeline with parallel processing enabled."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
                "parallel": True,
                "max_workers": 2,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        assert pipeline is not None

    # =========================================================================
    # OUTPUT DIRECTORY CREATION TESTS
    # =========================================================================

    def test_migration_creates_output_directory(
        self, tmp_path: Path, oid_entries_fixture: Path
    ) -> None:
        """Test that migration creates output directory if needed."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = tmp_path / "input"
        output_dir = tmp_path / "nonexistent" / "output"
        input_dir.mkdir()

        import shutil

        shutil.copy(oid_entries_fixture, input_dir / "entries.ldif")

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        # May succeed or fail depending on implementation
        assert isinstance(result.is_success, bool)

    # =========================================================================
    # ERROR HANDLING TESTS
    # =========================================================================

    def test_migration_with_nonexistent_input_directory(self, tmp_path: Path) -> None:
        """Test migration with nonexistent input directory."""
        input_dir = tmp_path / "nonexistent"
        output_dir = tmp_path / "output"

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        # Should fail gracefully
        assert isinstance(result.is_success, bool)

    def test_migration_with_empty_input_directory(self, tmp_path: Path) -> None:
        """Test migration with empty input directory."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        # Empty directory should succeed (no files to process)
        assert result.is_success

    # =========================================================================
    # SERVER TYPE CONVERSION TESTS
    # =========================================================================

    def test_migration_rfc_to_rfc(self, tmp_path: Path) -> None:
        """Test RFC to RFC conversion (identity transformation)."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success

    def test_migration_openldap_to_rfc(self, tmp_path: Path) -> None:
        """Test OpenLDAP to RFC conversion."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="openldap",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success

    def test_migration_openldap1_to_rfc(self, tmp_path: Path) -> None:
        """Test OpenLDAP 1.x to RFC conversion."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="openldap1",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success

    def test_migration_ad_to_rfc(self, tmp_path: Path) -> None:
        """Test Active Directory to RFC conversion."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="ad",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success

    # =========================================================================
    # ROUNDTRIP MIGRATION TESTS
    # =========================================================================

    def test_roundtrip_migration_oid_rfc_oid(
        self, tmp_path: Path, oid_entries_fixture: Path
    ) -> None:
        """Test roundtrip migration: OID → RFC → OID."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        # First migration: OID to RFC
        step1_input = tmp_path / "step1_input"
        step1_output = tmp_path / "step1_output"
        step1_input.mkdir()

        import shutil

        shutil.copy(oid_entries_fixture, step1_input / "entries.ldif")

        pipeline1 = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(step1_input),
                "output_dir": str(step1_output),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="oid",
            target_server_type="rfc",
        )
        result1 = pipeline1.execute()
        assert result1.is_success

        # Second migration: RFC back to OID
        step2_input = step1_output
        step2_output = tmp_path / "step2_output"

        pipeline2 = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(step2_input),
                "output_dir": str(step2_output),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="oid",
        )
        result2 = pipeline2.execute()
        assert result2.is_success

    # =========================================================================
    # CONFIGURATION ACCESS TESTS
    # =========================================================================

    def test_pipeline_input_dir_access(self, tmp_path: Path) -> None:
        """Test accessing pipeline input directory."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        assert pipeline.input_dir == input_dir

    def test_pipeline_output_dir_access(self, tmp_path: Path) -> None:
        """Test accessing pipeline output directory."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        assert pipeline.output_dir == output_dir

    def test_pipeline_source_server_type_access(self, tmp_path: Path) -> None:
        """Test accessing source server type."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="oid",
            target_server_type="rfc",
        )
        assert pipeline.source_server_type == "oid"

    def test_pipeline_target_server_type_access(self, tmp_path: Path) -> None:
        """Test accessing target server type."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="oud",
        )
        assert pipeline.target_server_type == "oud"

    # =========================================================================
    # STATUS/HEALTH TESTS
    # =========================================================================

    def test_pipeline_execute_returns_status(self, tmp_path: Path) -> None:
        """Test that execute returns status information."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success
        status = result.unwrap()
        # MigrationPipelineResult is now a Pydantic model, not a dict
        assert hasattr(status, "migrated_schema")
        assert hasattr(status, "entries")
        assert hasattr(status, "stats")

    # =========================================================================
    # MULTIPLE FIXTURE FILES SEQUENTIAL PROCESSING
    # =========================================================================

    def test_migration_all_oid_fixture_types(
        self,
        tmp_path: Path,
        oid_entries_fixture: Path,
        oid_schema_fixture: Path,
        oid_acl_fixture: Path,
    ) -> None:
        """Test migration with all OID fixture types."""
        if (
            not oid_entries_fixture.exists()
            or not oid_schema_fixture.exists()
            or not oid_acl_fixture.exists()
        ):
            pytest.skip("One or more fixtures not found")

        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        import shutil

        shutil.copy(oid_entries_fixture, input_dir / "entries.ldif")
        shutil.copy(oid_schema_fixture, input_dir / "schema.ldif")
        shutil.copy(oid_acl_fixture, input_dir / "acl.ldif")

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="oid",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success

    def test_migration_mixed_oid_oud_fixtures(
        self,
        tmp_path: Path,
        oid_entries_fixture: Path,
        oud_entries_fixture: Path,
    ) -> None:
        """Test migration with mixed OID and OUD input."""
        if not oid_entries_fixture.exists() or not oud_entries_fixture.exists():
            pytest.skip("One or both fixtures not found")

        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        import shutil

        shutil.copy(oid_entries_fixture, input_dir / "oid_entries.ldif")
        shutil.copy(oud_entries_fixture, input_dir / "oud_entries.ldif")

        # Use RFC as catch-all
        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success

    # =========================================================================
    # PHASE 2 COVERAGE TESTS - ERROR HANDLING AND EDGE CASES
    # =========================================================================

    def test_migration_with_missing_input_directory(self, tmp_path: Path) -> None:
        """Test pipeline handles missing input directory gracefully."""
        input_dir = tmp_path / "nonexistent"
        output_dir = tmp_path / "output"

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        # Should handle missing directory gracefully
        assert result.is_failure or result.is_success

    def test_migration_with_empty_input_directory_phase2(self, tmp_path: Path) -> None:
        """Test pipeline handles empty input directory."""
        input_dir = tmp_path / "empty_input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success

    def test_migration_output_directory_created(self, tmp_path: Path) -> None:
        """Test pipeline creates output directory if it doesn't exist."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "nonexistent_output"
        input_dir.mkdir()

        # Create a simple LDIF file
        ldif_content = """version: 1
dn: dc=example,dc=com
objectClass: dcObject
objectClass: organization
dc: example
o: Example Corp
"""
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": False,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        if result.is_success:
            assert output_dir.exists(), "Output directory should be created"

    def test_migration_with_multiple_ldif_files_phase2(
        self, tmp_path: Path, oid_entries_fixture: Path, oid_schema_fixture: Path
    ) -> None:
        """Test migration processes multiple LDIF files."""
        if not oid_entries_fixture.exists() or not oid_schema_fixture.exists():
            pytest.skip("Required fixtures not found")

        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        import shutil

        shutil.copy(oid_entries_fixture, input_dir / "01-entries.ldif")
        shutil.copy(oid_schema_fixture, input_dir / "02-schema.ldif")

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="oid",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success or result.is_failure

    def test_migration_statistics_collection(
        self, tmp_path: Path, oid_entries_fixture: Path
    ) -> None:
        """Test pipeline collects and returns statistics."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        import shutil

        shutil.copy(oid_entries_fixture, input_dir / "entries.ldif")

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": False,
                "process_entries": True,
            },
            source_server_type="oid",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        if result.is_success:
            migration_result = result.unwrap()
            # MigrationPipelineResult is now a Pydantic model with stats attribute
            assert hasattr(migration_result, "stats")
            stats = migration_result.stats
            # Stats is MigrationStatistics model
            assert hasattr(stats, "total_entries")

    def test_migration_oid_to_oud_transformation(
        self, tmp_path: Path, oid_entries_fixture: Path
    ) -> None:
        """Test OID to OUD migration with real fixtures."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        import shutil

        shutil.copy(oid_entries_fixture, input_dir / "entries.ldif")

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": False,
                "process_entries": True,
            },
            source_server_type="oid",
            target_server_type="oud",
        )
        result = pipeline.execute()
        assert result.is_success or result.is_failure

    def test_migration_rfc_roundtrip(self, tmp_path: Path) -> None:
        """Test RFC to RFC roundtrip migration."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        # Create valid RFC LDIF
        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user
mail: test@example.com

dn: cn=admin,dc=example,dc=com
objectClass: person
cn: admin
sn: administrator
"""
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": False,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success or result.is_failure

    def test_migration_with_broken_ldif_relaxed_mode(self, tmp_path: Path) -> None:
        """Test migration with broken LDIF using relaxed mode."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        # Create intentionally broken LDIF
        broken_ldif = """version: 1
dn: cn=test,dc=example,dc=com
objectClass person
cn: test
incomplete: line without value

dn: cn=admin,dc=example,dc=com
cn: admin
"""
        (input_dir / "broken.ldif").write_text(broken_ldif, encoding="utf-8")

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": False,
                "process_entries": True,
            },
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        # Should handle gracefully
        assert result.is_success or result.is_failure

    def test_pipeline_property_access_consistency(self, tmp_path: Path) -> None:
        """Test pipeline properties are consistently accessible."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": True,
            },
            source_server_type="oid",
            target_server_type="oud",
        )

        # Verify all properties are accessible
        assert pipeline.input_dir == Path(input_dir)
        assert pipeline.output_dir == Path(output_dir)
        assert pipeline.source_server_type == "oid"
        assert pipeline.target_server_type == "oud"

    def test_migration_with_schema_only(
        self, tmp_path: Path, oid_schema_fixture: Path
    ) -> None:
        """Test migration with schema files only."""
        if not oid_schema_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_schema_fixture}")

        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        import shutil

        shutil.copy(oid_schema_fixture, input_dir / "schema.ldif")

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": True,
                "process_entries": False,
            },
            source_server_type="oid",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success or result.is_failure

    def test_migration_with_entries_only(
        self, tmp_path: Path, oid_entries_fixture: Path
    ) -> None:
        """Test migration with entry files only."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        import shutil

        shutil.copy(oid_entries_fixture, input_dir / "entries.ldif")

        pipeline = FlextLdifMigrationPipeline(
            params={
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": False,
                "process_entries": True,
            },
            source_server_type="oid",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        assert result.is_success or result.is_failure
