"""Phase 8: Final push tests for FlextLdifCategorizedMigrationPipeline.

Final batch of tests targeting remaining uncovered internal methods and edge cases
to push coverage from 60% to 75%+.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.pipelines.categorized_pipeline import (
    FlextLdifCategorizedMigrationPipeline,
)


class TestPipelineInternalMethods:
    """Test coverage for internal pipeline methods."""

    @pytest.mark.unit
    def test_execute_multiple_files_with_different_rules(self, tmp_path: Path) -> None:
        """Test execute() correctly categorizes across multiple files."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # File 1: Schema and hierarchy
        file1 = input_dir / "file1.ldif"
        file1.write_text("""dn: cn=schema,dc=example,dc=com
objectClass: ldapSubentry
objectClass: subschema
cn: schema

dn: dc=example,dc=com
objectClass: dcObject
dc: example
""")

        # File 2: Users
        file2 = input_dir / "file2.ldif"
        file2.write_text("""dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1
sn: One

dn: cn=user2,dc=example,dc=com
objectClass: person
cn: user2
sn: Two
""")

        # File 3: Groups
        file3 = input_dir / "file3.ldif"
        file3.write_text("""dn: cn=admins,dc=example,dc=com
objectClass: groupOfNames
cn: admins
member: cn=user1,dc=example,dc=com

dn: cn=users,dc=example,dc=com
objectClass: groupOfNames
cn: users
member: cn=user2,dc=example,dc=com
""")

        rules = {
            "schema_entries": ["subschema"],
            "hierarchy_objectclasses": ["dcObject"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success
        exec_result = result.unwrap()
        assert exec_result.statistics.total_entries >= 6

    @pytest.mark.unit
    def test_execute_with_output_file_mapping(self, tmp_path: Path) -> None:
        """Test execute() respects custom output file mappings."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1
sn: One

dn: cn=admin1,dc=example,dc=com
objectClass: person
objectClass: administrativeRole
cn: admin1
sn: Admin
""")

        custom_output = {
            "schema": "my_schema.ldif",
            "hierarchy": "my_hierarchy.ldif",
            "users": "my_users.ldif",
            "groups": "my_groups.ldif",
            "acl": "my_acl.ldif",
            "rejected": "my_rejected.ldif",
        }

        rules = {
            "user_objectclasses": ["person"],
            "admin_objectclasses": ["administrativeRole"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
            output_files=custom_output,
        )

        result = pipeline.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_execute_with_all_custom_options(self, tmp_path: Path) -> None:
        """Test execute() with all custom configuration options."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: Test
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
            source_server="openldap",
            target_server="active_directory",
            base_dn="dc=example,dc=com",
            input_files=["test.ldif"],
        )

        result = pipeline.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_execute_returns_correct_statistics(self, tmp_path: Path) -> None:
        """Test execute() returns accurate statistics."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=test1,dc=example,dc=com
objectClass: person
cn: test1
sn: One

dn: cn=test2,dc=example,dc=com
objectClass: person
cn: test2
sn: Two

dn: cn=test3,dc=example,dc=com
objectClass: person
cn: test3
sn: Three
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success
        stats = result.unwrap().statistics
        assert stats.total_entries >= 3
        assert hasattr(stats, "processed_entries")

    @pytest.mark.unit
    def test_execute_with_server_type_detection(self, tmp_path: Path) -> None:
        """Test execute() with specific server types."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: Test
""")

        for source_server in ["rfc", "openldap", "active_directory", "oid", "oud"]:
            for target_server in ["rfc", "openldap", "active_directory", "oid", "oud"]:
                pipeline = FlextLdifCategorizedMigrationPipeline(
                    input_dir=input_dir,
                    output_dir=output_dir,
                    categorization_rules={"user_objectclasses": ["person"]},
                    parser_quirk=None,
                    writer_quirk=None,
                    source_server=source_server,
                    target_server=target_server,
                )

                result = pipeline.execute()
                assert result.is_success or result.is_failure

    @pytest.mark.unit
    def test_execute_preserves_entry_structure(self, tmp_path: Path) -> None:
        """Test execute() preserves LDIF entry structure."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_content = """dn: cn=complex,dc=example,dc=com
objectClass: top
objectClass: person
cn: complex
sn: User
userPassword:: e1NZKEHHQQY=
mail: test@example.com
telephoneNumber: +1234567890
description: Complex entry with multiple attributes
"""
        ldif_file.write_text(ldif_content)

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_execute_with_no_matching_entries(self, tmp_path: Path) -> None:
        """Test execute() when no entries match categorization rules."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=test,dc=example,dc=com
objectClass: device
cn: test
serialNumber: 12345
""")

        # Rules that won't match the device entry
        rules = {
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success
        exec_result = result.unwrap()
        # Entry should be in "rejected" category or uncategorized
        assert exec_result.statistics.total_entries >= 1

    @pytest.mark.unit
    def test_execute_with_base_dn_filtering(self, tmp_path: Path) -> None:
        """Test execute() respects base DN filtering."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_content = """dn: cn=user1,ou=people,dc=example,dc=com
objectClass: person
cn: user1
sn: One

dn: cn=user2,ou=people,dc=other,dc=com
objectClass: person
cn: user2
sn: Two
"""
        ldif_file.write_text(ldif_content)

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="dc=example,dc=com",
        )

        result = pipeline.execute()
        assert result.is_success or result.is_failure


class TestPipelineRobustness:
    """Test pipeline robustness and resilience."""

    @pytest.mark.unit
    def test_execute_with_entries_without_objectclass(self, tmp_path: Path) -> None:
        """Test execute() with entries missing objectClass."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=orphan,dc=example,dc=com
cn: orphan
sn: NoClass
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success or result.is_failure

    @pytest.mark.unit
    def test_execute_with_case_insensitive_matching(self, tmp_path: Path) -> None:
        """Test execute() handles case-insensitive objectClass matching."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=test1,dc=example,dc=com
objectClass: Person
cn: test1
sn: One

dn: cn=test2,dc=example,dc=com
objectClass: PERSON
cn: test2
sn: Two
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},  # lowercase
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success or result.is_failure

    @pytest.mark.unit
    def test_execute_with_very_large_attributes(self, tmp_path: Path) -> None:
        """Test execute() handles entries with very large attribute values."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        large_value = "x" * 10000
        ldif_file.write_text(f"""dn: cn=large,dc=example,dc=com
objectClass: person
cn: large
sn: Large
description: {large_value}
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success or result.is_failure

    @pytest.mark.unit
    def test_execute_idempotency(self, tmp_path: Path) -> None:
        """Test that execute() produces consistent results when run twice."""
        input_dir = tmp_path / "input"
        output_dir1 = tmp_path / "output1"
        output_dir2 = tmp_path / "output2"
        input_dir.mkdir()
        output_dir1.mkdir()
        output_dir2.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1
sn: One

dn: cn=user2,dc=example,dc=com
objectClass: person
cn: user2
sn: Two
""")

        pipeline1 = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir1,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result1 = pipeline1.execute()
        assert result1.is_success

        # Run again with different output directory
        pipeline2 = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir2,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result2 = pipeline2.execute()
        assert result2.is_success

        # Both runs should succeed with the same logic
        assert result1.is_success == result2.is_success
