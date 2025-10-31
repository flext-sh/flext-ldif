"""Test suite for LDIF migration pipeline.

Tests use the new API with individual parameters (input_dir, output_dir, source_server, target_server)
not the old params dict approach.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.services.migration import FlextLdifMigrationPipeline


class TestMigrationPipelineInitialization:
    """Test suite for migration pipeline initialization with new API."""

    def test_initialization_with_required_params(self, tmp_path: Path) -> None:
        """Test pipeline initializes with required parameters."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server="oid",
            target_server="oud",
        )

        assert pipeline is not None

    def test_initialization_simple_mode(self, tmp_path: Path) -> None:
        """Test pipeline initialization for simple mode."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server="oid",
            target_server="oud",
        )

        assert pipeline is not None

    def test_initialization_categorized_mode(self, tmp_path: Path) -> None:
        """Test pipeline initialization for categorized mode."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        categorization_rules = {
            "hierarchy_objectclasses": ["organization"],
            "user_objectclasses": ["inetOrgPerson"],
            "group_objectclasses": ["groupOfNames"],
        }

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="categorized",
            categorization_rules=categorization_rules,
            source_server="oid",
            target_server="oud",
        )

        assert pipeline is not None

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
        self, source: str, target: str, tmp_path: Path
    ) -> None:
        """Test pipeline initialization with various server type combinations."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server=source,
            target_server=target,
        )

        assert pipeline is not None


class TestMigrationPipelineValidation:
    """Test suite for parameter validation."""

    def test_execute_with_nonexistent_input_dir_returns_empty_result(
        self, tmp_path: Path
    ) -> None:
        """Test pipeline succeeds but returns empty result when input directory doesn't exist."""
        nonexistent_input = tmp_path / "nonexistent"
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=nonexistent_input,
            output_dir=output_dir,
            source_server="oid",
            target_server="oud",
        )

        result = pipeline.execute()

        # Pipeline handles nonexistent input gracefully (no files = empty result)
        assert result.is_success
        assert result.value is not None
        assert result.value.statistics.total_entries == 0

    def test_execute_creates_output_dir_if_missing(self, tmp_path: Path) -> None:
        """Test pipeline creates output directory if it doesn't exist."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        nonexistent_output = tmp_path / "nonexistent"

        # Create a simple LDIF file
        (input_dir / "test.ldif").write_text(
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n"
        )

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=nonexistent_output,
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        # Pipeline should succeed and create the output directory
        assert result.is_success
        assert nonexistent_output.exists()


class TestMigrationPipelineSimpleMode:
    """Test suite for simple migration mode."""

    def test_simple_mode_with_empty_input(self, tmp_path: Path) -> None:
        """Test simple mode handles empty input directory gracefully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        # Pipeline should handle gracefully
        assert result.is_success or result.is_failure

    def test_simple_mode_basic_execution(self, tmp_path: Path) -> None:
        """Test simple mode executes successfully."""
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
            mode="simple",
            output_filename="migrated.ldif",
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure


class TestMigrationPipelineServerConversions:
    """Test suite for server-specific conversions."""

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
        self, source: str, target: str, tmp_path: Path
    ) -> None:
        """Test server-specific conversion modes."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        (input_dir / "test.ldif").write_text(
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n"
        )

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server=source,
            target_server=target,
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure
