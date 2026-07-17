"""Behavioral API integration tests for the flext-ldif facade.

These tests assert the observable public contract of the ``ldif`` facade and
its service factories: return values, ``FlextResult`` outcomes, public model
state, edge cases, invariants, and round-trip idempotence. No private members,
internal collaborators, or implementation details are exercised.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from flext_ldif import ldif
from flext_ldif.services.categorization import FlextLdifCategorization
from flext_ldif.services.migration import FlextLdifMigrationPipeline
from flext_ldif.services.statistics import FlextLdifStatistics
from tests import c, m

if TYPE_CHECKING:
    from pathlib import Path


class TestsFlextLdifApiIntegration:
    """Behavioral contract tests for the ``ldif`` facade and its factories."""

    # ------------------------------------------------------------------
    # Parsing — observable results
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        ("ldif_content", "expected_entries"),
        [
            (c.Tests.RFC_SAMPLE_LDIF_BASIC, 1),
            (c.Tests.RFC_SAMPLE_LDIF_MULTIPLE, 2),
        ],
    )
    def test_parse_ldif_returns_expected_entry_count(
        self,
        ldif_content: str,
        expected_entries: int,
    ) -> None:
        """parse_ldif succeeds and yields entries with populated public state."""
        # Act
        result = ldif.parse_ldif(ldif_content)

        # Assert
        tm.ok(result)
        entries = result.value.entries
        tm.that(len(entries), eq=expected_entries)
        for entry in entries:
            assert entry.dn is not None
            assert entry.attributes is not None
            assert entry.dn.value
            assert entry.attributes.attributes

    @pytest.mark.parametrize(
        "lenient_content",
        [
            "",
            "this is not ldif at all",
            "objectClass: person\ncn: no-dn\n",
        ],
    )
    def test_parse_ldif_is_lenient_and_never_raises_on_non_entries(
        self,
        lenient_content: str,
    ) -> None:
        """Content without complete entries parses to a successful empty result."""
        # Act
        result = ldif.parse_ldif(lenient_content)

        # Assert — invariant: lenient parse, success with zero entries, no crash
        tm.ok(result)
        tm.that(result.value.entries, eq=[])

    def test_parse_ldif_merges_repeated_attribute_into_multivalue(self) -> None:
        """A repeated attribute name is preserved as an ordered multi-value list."""
        # Arrange
        content = "dn: cn=a,dc=example,dc=com\ncn: a\ncn: b\nobjectClass: person\n"

        # Act
        result = ldif.parse_ldif(content)

        # Assert
        tm.ok(result)
        (entry,) = result.value.entries
        assert entry.attributes is not None
        tm.that(entry.attributes.attributes[c.Tests.NAME_CN], eq=["a", "b"])

    def test_parse_write_parse_round_trip_is_idempotent(self) -> None:
        """Parsing serialized output reproduces the same DN and attributes."""
        # Arrange
        original = ldif.parse_ldif(c.Tests.RFC_SAMPLE_LDIF_BASIC)
        tm.ok(original)
        entries = original.value.entries

        # Act
        written = ldif.write_to_string(entries)
        tm.ok(written)
        reparsed = ldif.parse_ldif(written.value)

        # Assert
        tm.ok(reparsed)
        tm.that(len(reparsed.value.entries), eq=len(entries))
        reparsed_dn = reparsed.value.entries[0].dn
        original_dn = entries[0].dn
        assert reparsed_dn is not None
        assert original_dn is not None
        tm.that(reparsed_dn.value, eq=original_dn.value)

    # ------------------------------------------------------------------
    # Entry model construction — public state
    # ------------------------------------------------------------------

    def test_build_entry_exposes_public_model_state(self) -> None:
        """A programmatically built entry exposes its DN and attributes."""
        # Arrange / Act
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Tests.RFC_TEST_DN),
            attributes=m.Ldif.Attributes(
                attributes={
                    c.Tests.NAME_CN: [c.Tests.ATTR_VALUE_TEST],
                    c.Tests.NAME_SN: [c.Tests.ATTR_VALUE_USER],
                    c.Tests.NAME_OBJECTCLASS: [c.Tests.NAME_PERSON],
                },
                attribute_metadata={},
            ),
        )

        # Assert
        assert entry.dn is not None
        assert entry.attributes is not None
        tm.that(entry.dn.value, eq=c.Tests.RFC_TEST_DN)
        tm.that(
            entry.attributes.attributes[c.Tests.NAME_CN], eq=[c.Tests.ATTR_VALUE_TEST]
        )

    def test_entry_create_returns_success_result_and_validates(self) -> None:
        """Entry.create yields a success FlextResult whose value validates."""
        # Act
        create_result = m.Ldif.Entry.create(
            dn="cn=namespace-check,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["namespace-check"],
                "sn": ["check"],
            },
        )

        # Assert
        tm.ok(create_result)
        created = create_result.value
        assert isinstance(created, m.Ldif.Entry)
        tm.ok(ldif.validate_entries([created]))

    # ------------------------------------------------------------------
    # Validation and statistics — end-to-end observable behavior
    # ------------------------------------------------------------------

    def test_validate_parsed_entries_succeeds(self) -> None:
        """Entries parsed from valid LDIF validate successfully."""
        # Arrange
        parsed = ldif.parse_ldif(c.Tests.RFC_SAMPLE_LDIF_BASIC)
        tm.ok(parsed)

        # Act
        validated = ldif.validate_entries(parsed.value.entries)

        # Assert
        tm.ok(validated)

    def test_statistics_report_total_entries_from_public_result(self) -> None:
        """Statistics expose the parsed entry count via the public result model."""
        # Arrange
        parsed = ldif.parse_ldif(c.Tests.RFC_SAMPLE_LDIF_BASIC)
        tm.ok(parsed)

        # Act
        analyzed = FlextLdifStatistics().calculate_for_entries(parsed.value.entries)

        # Assert
        tm.ok(analyzed)
        tm.that(analyzed.value.total_entries, eq=1)

    def test_statistics_over_empty_input_reports_zero_total(self) -> None:
        """Statistics over an empty entry list report zero total entries."""
        # Act
        analyzed = FlextLdifStatistics().calculate_for_entries([])

        # Assert
        tm.ok(analyzed)
        tm.that(analyzed.value.total_entries, eq=0)

    # ------------------------------------------------------------------
    # Facade instance semantics
    # ------------------------------------------------------------------

    def test_configured_facade_instances_are_independent(self) -> None:
        """Calling the facade yields distinct instances with consistent output."""
        # Arrange
        ldif1 = ldif()
        ldif2 = ldif()

        # Act
        result1 = ldif1.parse_ldif(c.Tests.RFC_SAMPLE_LDIF_BASIC)
        result2 = ldif2.parse_ldif(c.Tests.RFC_SAMPLE_LDIF_BASIC)

        # Assert
        assert ldif1 is not ldif2
        tm.ok(result1)
        tm.ok(result2)
        dn1 = result1.value.entries[0].dn
        dn2 = result2.value.entries[0].dn
        assert dn1 is not None
        assert dn2 is not None
        tm.that(dn1.value, eq=dn2.value)

    # ------------------------------------------------------------------
    # Categorization factory — options binding contract
    # ------------------------------------------------------------------

    def test_categorization_explicit_base_dn_overrides_options(self) -> None:
        """An explicit base_dn overrides the value carried by migrate options."""
        # Arrange
        options = m.Ldif.MigrateOptions(
            base_dn="dc=options,dc=example",
            forbidden_attributes=["userPassword"],
            forbidden_objectclasses=["groupOfNames"],
        )

        # Act
        categorization = ldif.categorization(
            options=options,
            base_dn="dc=override,dc=example",
            server_type=c.Tests.OUD,
        )

        # Assert
        assert isinstance(categorization, FlextLdifCategorization)
        tm.that(categorization.base_dn, eq="dc=override,dc=example")
        tm.that(categorization.forbidden_attributes, eq=["userPassword"])
        tm.that(categorization.forbidden_objectclasses, eq=["groupOfNames"])

    def test_categorization_defaults_base_dn_from_options(self) -> None:
        """Without an override, categorization keeps the options base DN."""
        # Arrange
        options = m.Ldif.MigrateOptions(
            base_dn="dc=options,dc=example",
            forbidden_attributes=["userPassword"],
        )

        # Act
        categorization = ldif.categorization(
            options=options,
            server_type=c.Tests.OUD,
        )

        # Assert
        assert isinstance(categorization, FlextLdifCategorization)
        tm.that(categorization.base_dn, eq="dc=options,dc=example")
        tm.that(categorization.forbidden_attributes, eq=["userPassword"])

    def test_categorization_normalizes_schema_whitelist_rules(self) -> None:
        """Raw whitelist mappings are normalized into a WhitelistRules model."""
        # Act
        categorization = ldif.categorization(
            options=m.Ldif.MigrateOptions(
                schema_whitelist_rules=m.Ldif.WhitelistRules.model_validate(
                    {
                        "allowed_attribute_oids": {"1.2.3.4"},
                        "allowed_objectclass_oids": {"2.3.4.5"},
                    },
                ),
            ),
            server_type=c.Tests.OUD,
        )

        # Assert
        assert isinstance(categorization, FlextLdifCategorization)
        assert isinstance(categorization.schema_whitelist_rules, m.Ldif.WhitelistRules)
        assert categorization.schema_whitelist_rules.has_oid_filters

    # ------------------------------------------------------------------
    # Migration pipeline factory — configuration contract
    # ------------------------------------------------------------------

    def test_migration_pipeline_binds_dirs_servers_and_output_name(
        self,
        tmp_path: Path,
    ) -> None:
        """The pipeline reflects the transform config and migrate options given."""
        # Arrange
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Act
        pipeline = ldif.migration_pipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            settings=m.Ldif.TransformConfig.servers(
                source_server=c.Tests.OID,
                target_server=c.Tests.OUD,
            ),
            options=m.Ldif.MigrateOptions(output_filename="custom.ldif"),
        )

        # Assert
        assert isinstance(pipeline, FlextLdifMigrationPipeline)
        tm.that(pipeline.input_dir, eq=input_dir)
        tm.that(pipeline.output_dir, eq=output_dir)
        tm.that(pipeline.source_server_type, eq=c.Tests.OID)
        tm.that(pipeline.target_server_type, eq=c.Tests.OUD)
        tm.that(pipeline.output_filename, eq="custom.ldif")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
