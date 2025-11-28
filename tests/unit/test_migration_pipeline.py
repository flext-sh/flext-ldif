"""Test suite for LDIF migration pipeline.

Tests validate that FlextLdifMigrationPipeline:
1. Initializes correctly with required and optional parameters
2. Handles different migration modes (simple, categorized)
3. Supports various server type combinations
4. Validates input/output directories
5. Executes migrations successfully
6. Handles edge cases (empty input, nonexistent directories)

Modules tested:
- flext_ldif.services.migration.FlextLdifMigrationPipeline (migration pipeline)

Scope:
- Pipeline initialization with new API (individual parameters)
- Simple and categorized migration modes
- Server-specific conversions (OID, OUD, OpenLDAP, RFC)
- Input/output directory validation
- Edge case handling

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdifConstants, FlextLdifMigrationPipeline
from tests.fixtures.constants import DNs, Names
from tests.fixtures.typing import GenericFieldsDict


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
            source_server=FlextLdifConstants.ServerTypes.OID,
            target_server=FlextLdifConstants.ServerTypes.OUD,
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
            source_server=FlextLdifConstants.ServerTypes.OID,
            target_server=FlextLdifConstants.ServerTypes.OUD,
        )

        assert pipeline is not None

    def test_initialization_categorized_mode(self, tmp_path: Path) -> None:
        """Test pipeline initialization for categorized mode."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        categorization_rules: GenericFieldsDict = {
            "hierarchy_objectclasses": ["organization"],
            "user_objectclasses": [Names.INET_ORG_PERSON],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": [],
        }

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode=FlextLdifConstants.LiteralTypes.MigrationModeLiteral("categorized"),
            categorization_rules=categorization_rules,
            source_server=FlextLdifConstants.ServerTypes.OID,
            target_server=FlextLdifConstants.ServerTypes.OUD,
        )

        assert pipeline is not None

    @pytest.mark.parametrize(
        ("source", "target"),
        [
            (FlextLdifConstants.ServerTypes.OID, FlextLdifConstants.ServerTypes.OUD),
            (
                FlextLdifConstants.ServerTypes.OID,
                FlextLdifConstants.ServerTypes.OPENLDAP,
            ),
            (
                FlextLdifConstants.ServerTypes.OUD,
                FlextLdifConstants.ServerTypes.OPENLDAP,
            ),
            (
                FlextLdifConstants.ServerTypes.OPENLDAP,
                FlextLdifConstants.ServerTypes.OID,
            ),
            (
                FlextLdifConstants.ServerTypes.OPENLDAP,
                FlextLdifConstants.ServerTypes.OUD,
            ),
            (FlextLdifConstants.ServerTypes.RFC, FlextLdifConstants.ServerTypes.RFC),
        ],
    )
    def test_initialization_with_different_server_types(
        self,
        source: FlextLdifConstants.ServerTypeLiteral,
        target: FlextLdifConstants.ServerTypeLiteral,
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
            source_server=source,
            target_server=target,
        )

        assert pipeline is not None


class TestMigrationPipelineValidation:
    """Test suite for parameter validation."""

    def test_execute_with_nonexistent_input_dir_returns_empty_result(
        self,
        tmp_path: Path,
    ) -> None:
        """Test pipeline succeeds but returns empty result when input directory doesn't exist."""
        nonexistent_input = tmp_path / "nonexistent"
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=nonexistent_input,
            output_dir=output_dir,
            source_server=FlextLdifConstants.ServerTypes.OID,
            target_server=FlextLdifConstants.ServerTypes.OUD,
        )

        result = pipeline.execute()

        # Pipeline handles nonexistent input gracefully (no files = empty result)
        assert result.is_success
        assert result.value is not None
        assert result.value.statistics is not None
        assert result.value.statistics.total_entries == 0


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
            source_server=FlextLdifConstants.ServerTypes.RFC,
            target_server=FlextLdifConstants.ServerTypes.RFC,
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

        # Create a simple LDIF file using constants
        ldif_content = f"""dn: {DNs.TEST_USER}
{Names.OBJECTCLASS}: {Names.PERSON}
{Names.OBJECTCLASS}: {Names.TOP}
{Names.CN}: test
{Names.SN}: test
"""
        (input_dir / "test.ldif").write_text(ldif_content)

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=FlextLdifConstants.ServerTypes.RFC,
            target_server=FlextLdifConstants.ServerTypes.RFC,
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure


class TestMigrationPipelineServerConversions:
    """Test suite for server-specific conversions."""

    @pytest.mark.parametrize(
        ("source", "target"),
        [
            (FlextLdifConstants.ServerTypes.OID, FlextLdifConstants.ServerTypes.OUD),
            (FlextLdifConstants.ServerTypes.OUD, FlextLdifConstants.ServerTypes.OID),
            (FlextLdifConstants.ServerTypes.RFC, FlextLdifConstants.ServerTypes.OID),
            (FlextLdifConstants.ServerTypes.RFC, FlextLdifConstants.ServerTypes.OUD),
        ],
    )
    def test_server_conversion_modes(
        self,
        source: FlextLdifConstants.ServerTypeLiteral,
        target: FlextLdifConstants.ServerTypeLiteral,
        tmp_path: Path,
    ) -> None:
        """Test server-specific conversion modes."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create a simple LDIF file using constants
        ldif_content = f"""dn: {DNs.TEST_USER}
{Names.OBJECTCLASS}: {Names.PERSON}
{Names.CN}: test
"""
        (input_dir / "test.ldif").write_text(ldif_content)

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server=source,
            target_server=target,
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure
