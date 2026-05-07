"""Comprehensive API integration tests for flext-ldif.

Tests the complete ldif facade with all major operations:
- Parsing LDIF files with different servers
- Building entries with unified API
- Configuration and servers integration

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import (
    FlextLdifCategorization,
    FlextLdifMigrationPipeline,
    FlextLdifStatistics,
    ldif,
)
from tests import c, m


class TestsFlextLdifApiIntegration:
    """Comprehensive API integration tests for ldif facade.

    Uses advanced Python 3.13 patterns:
    - StrEnum for test scenarios
    - Mapping for immutable test data
    - Parametrized dynamic tests
    - Factory pattern for test data creation
    - Builder pattern for complex test setup
    """

    @pytest.mark.parametrize(
        ("scenario", "ldif_content", "expected_entries"),
        [
            (
                c.Tests.API_SCENARIO_SIMPLE_LDIF,
                c.Tests.RFC_SAMPLE_LDIF_BASIC,
                1,
            ),
            (
                c.Tests.API_SCENARIO_MULTIPLE_INSTANCES,
                c.Tests.RFC_SAMPLE_LDIF_MULTIPLE,
                2,
            ),
        ],
    )
    def test_parse_ldif_scenarios(
        self,
        scenario: str,
        ldif_content: str,
        expected_entries: int,
    ) -> None:
        """Test parsing LDIF content across different scenarios."""
        _ = scenario
        api = ldif
        result = api.parse_ldif(ldif_content)
        assert result.success
        entries = result.value.entries
        assert len(entries) == expected_entries
        for entry in entries:
            assert entry.dn is not None
            assert entry.attributes is not None
            assert entry.dn.value
            assert entry.attributes.attributes

    def test_build_entry_programmatic(self) -> None:
        """Test building entries programmatically using models."""
        test_dn = c.Tests.RFC_TEST_DN
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=test_dn),
            attributes=m.Ldif.Attributes(
                attributes={
                    c.Tests.NAME_CN: [c.Tests.ATTR_VALUE_TEST],
                    c.Tests.NAME_SN: [c.Tests.ATTR_VALUE_USER],
                    c.Tests.NAME_OBJECTCLASS: [c.Tests.NAME_PERSON],
                },
                attribute_metadata={},
            ),
        )
        assert entry.dn is not None
        assert entry.attributes is not None
        assert entry.dn.value == test_dn
        assert c.Tests.NAME_CN in entry.attributes.attributes
        assert entry.attributes.attributes[c.Tests.NAME_CN] == [c.Tests.ATTR_VALUE_TEST]

    def test_validate_entries_workflow(self) -> None:
        """Test complete validation workflow."""
        api = ldif
        parse_result = api.parse_ldif(c.Tests.RFC_SAMPLE_LDIF_BASIC)
        assert parse_result.success
        entries = parse_result.value.entries
        validate_result = api.validate_entries(entries)
        assert validate_result.success

    def test_multiple_instances_independence(self) -> None:
        """Test that multiple ldif instances work independently."""
        ldif1 = ldif()
        ldif2 = ldif()
        assert ldif1 is not ldif2
        result1 = ldif1.parse_ldif(c.Tests.RFC_SAMPLE_LDIF_BASIC)
        result2 = ldif2.parse_ldif(c.Tests.RFC_SAMPLE_LDIF_BASIC)
        assert result1.success
        assert result2.success
        entries1 = result1.value.entries
        entries2 = result2.value.entries
        assert len(entries1) == len(entries2) == 1
        assert entries1[0].dn is not None
        assert entries2[0].dn is not None
        assert entries1[0].dn.value == entries2[0].dn.value

    def test_api_facade_property_access(self) -> None:
        """Test facade operations with the canonical LDIF model namespace."""
        api = ldif
        create_result = m.Ldif.Entry.create(
            dn="cn=namespace-check,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["namespace-check"],
                "sn": ["check"],
            },
        )
        assert create_result.success
        created = create_result.value
        assert created is not None
        assert isinstance(created, m.Ldif.Entry)
        assert api.validate_entries([created]).success

    def test_end_to_end_workflow_complete(self) -> None:
        """Test complete end-to-end workflow from parse to filter."""
        api = ldif
        parse_result = api.parse_ldif(c.Tests.RFC_SAMPLE_LDIF_BASIC)
        assert parse_result.success
        entries = parse_result.value.entries
        analyze_result = FlextLdifStatistics().calculate_for_entries(entries)
        assert analyze_result.success
        stats = analyze_result.value
        assert stats.total_entries == 1
        validate_result = api.validate_entries(entries)
        assert validate_result.success

    def test_runtime_alias_exposes_direct_dsl(self) -> None:
        """Test the runtime alias as the primary no-ceremony facade."""
        result = ldif.parse_ldif(c.Tests.RFC_SAMPLE_LDIF_BASIC)
        assert result.success
        assert len(result.value.entries) == 1

    def test_categorization_reads_migrate_options(self) -> None:
        """Categorization should reuse migrate options while honoring explicit base DN."""
        api = ldif
        options = m.Ldif.MigrateOptions(
            base_dn="dc=options,dc=example",
            forbidden_attributes=["userPassword"],
            forbidden_objectclasses=["groupOfNames"],
        )

        categorization = api.categorization(
            options=options,
            base_dn="dc=override,dc=example",
            server_type=c.Tests.OUD,
        )

        assert isinstance(categorization, FlextLdifCategorization)
        assert categorization.base_dn == "dc=override,dc=example"
        assert categorization.forbidden_attributes == ["userPassword"]
        assert categorization.forbidden_objectclasses == ["groupOfNames"]

    def test_categorization_uses_migrate_options_base_dn_without_override(self) -> None:
        """Categorization should preserve the model-provided base DN when no override is passed."""
        api = ldif
        options = m.Ldif.MigrateOptions(
            base_dn="dc=options,dc=example",
            forbidden_attributes=["userPassword"],
        )

        categorization = api.categorization(
            options=options,
            server_type=c.Tests.OUD,
        )

        assert isinstance(categorization, FlextLdifCategorization)
        assert categorization.base_dn == "dc=options,dc=example"
        assert categorization.forbidden_attributes == ["userPassword"]

    def test_migration_pipeline_reads_transform_and_migrate_options(
        self,
        tmp_path: Path,
    ) -> None:
        """Migration pipeline should use canonical transform and migrate option models."""
        api = ldif
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = api.migration_pipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            settings=m.Ldif.TransformConfig.servers(
                source_server=c.Tests.OID,
                target_server=c.Tests.OUD,
            ),
            options=m.Ldif.MigrateOptions(output_filename="custom.ldif"),
        )

        assert isinstance(pipeline, FlextLdifMigrationPipeline)
        assert pipeline.input_dir == input_dir
        assert pipeline.output_dir == output_dir
        assert pipeline.source_server_type == c.Tests.OID
        assert pipeline.target_server_type == c.Tests.OUD
        assert pipeline.output_filename == "custom.ldif"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
