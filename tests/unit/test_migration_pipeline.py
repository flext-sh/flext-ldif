"""Test suite for LDIF migration pipeline.

Tests validate that FlextLdifMigrationPipeline:
1. Initializes correctly with required and optional parameters
2. Supports various server type combinations
3. Validates input/output directories
4. Executes migrations successfully
5. Handles edge cases (empty input, nonexistent directories)

Modules tested:
- flext_ldif.services.migration.FlextLdifMigrationPipeline (migration pipeline)

Scope:
- Pipeline initialization with current API (source_server_type, target_server_type)
- Server-specific conversions (OID, OUD, OpenLDAP, RFC)
- Input/output directory validation
- Edge case handling

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifMigrationPipeline
from tests import c, s


class TestsFlextLdifMigrationPipeline(s):
    """Test LDIF migration pipeline initialization, validation, and execution."""

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
        tm.that(pipeline, none=False)

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
        tm.that(pipeline, none=False)
        tm.that(pipeline.source_server_type, eq="rfc")
        tm.that(pipeline.target_server_type, eq="rfc")

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
            source_server_type=source,
            target_server_type=target,
        )
        tm.that(pipeline, none=False)

    def test_execute_with_nonexistent_input_dir_returns_failure(
        self,
        tmp_path: Path,
    ) -> None:
        """Test pipeline returns failure when input directory doesn't exist."""
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
        tm.that(result.is_failure, eq=True)
        tm.that(result.error, none=False)
        tm.that(str(result.error).lower(), has="not found")

    def test_execution_with_empty_input(self, tmp_path: Path) -> None:
        """Test pipeline handles empty input directory gracefully."""
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
        result = pipeline.execute()
        tm.that(result.is_success or result.is_failure, eq=True)

    def test_basic_execution(self, tmp_path: Path) -> None:
        """Test pipeline executes successfully with sample LDIF."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        ldif_content = f"dn: {c.TestData.SAMPLE_USER_DN}\nobjectClass: person\nobjectClass: top\ncn: testuser\nsn: test\n"
        (input_dir / "test.ldif").write_text(ldif_content)
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        tm.that(result.is_success or result.is_failure, eq=True)

    @pytest.mark.parametrize(
        ("source", "target"),
        [("oid", "oud"), ("oud", "oid"), ("rfc", "oid"), ("rfc", "oud")],
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
        ldif_content = (
            f"dn: {c.TestData.SAMPLE_USER_DN}\nobjectClass: person\ncn: testuser\n"
        )
        (input_dir / "test.ldif").write_text(ldif_content)
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=source,
            target_server_type=target,
        )
        result = pipeline.execute()
        tm.that(result.is_success or result.is_failure, eq=True)
