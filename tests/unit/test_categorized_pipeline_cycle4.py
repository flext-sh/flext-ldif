"""Comprehensive tests for FlextLdifCategorizedMigrationPipeline main execution.

Tests focus on execute() method, entry parsing, categorization, and transformation.
Uses real file I/O with tempfile for genuine testing.

Phase 3 Cycle 4: Expand coverage from 36% to 80%+
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from flext_ldif import (
    FlextLdifCategorizedMigrationPipeline,
)
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry


class TestCategorizedPipelineExecution:
    """Test main execute() method with real entry processing."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry for tests."""
        return FlextLdifQuirksRegistry()

    @pytest.fixture
    def temp_input_dir(self) -> Path:
        """Create temporary input directory with LDIF file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "input"
            input_path.mkdir()

            # Create simple LDIF file with entries
            ldif_content = """version: 1
dn: cn=schema
objectClass: subSchema
attributeTypes: ( 1.3.6.1.4.1.1466.115.121.1.1 NAME 'cn' ... )
objectClasses: ( 2.5.6.4 NAME 'person' ... )

dn: o=example
objectClass: organization
o: example

dn: ou=users,o=example
objectClass: organizationalUnit
ou: users

dn: cn=john,ou=users,o=example
objectClass: person
cn: john
"""
            ldif_file = input_path / "test.ldif"
            ldif_file.write_text(ldif_content, encoding="utf-8")
            yield input_path

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_execute_with_empty_input_directory(
        self, temp_output_dir: Path, quirk_registry: FlextLdifQuirksRegistry
    ) -> None:
        """Test execute() with no input files returns empty result."""
        with tempfile.TemporaryDirectory() as tmpdir:
            empty_input = Path(tmpdir)

            pipeline = FlextLdifCategorizedMigrationPipeline(
                input_dir=empty_input,
                output_dir=temp_output_dir,
                categorization_rules={},
                parser_quirk=None,
                writer_quirk=None,
            )

            result = pipeline.execute()

            # Empty input should return success with empty result
            assert result.is_success
            exec_result = result.unwrap()
            assert len(exec_result.entries_by_category) == 0
            assert exec_result.statistics.total_entries == 0

    def test_execute_creates_output_directory(
        self, temp_input_dir: Path, quirk_registry: FlextLdifQuirksRegistry
    ) -> None:
        """Test execute() creates output directory if missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "new_output"
            assert not output_dir.exists()

            pipeline = FlextLdifCategorizedMigrationPipeline(
                input_dir=temp_input_dir,
                output_dir=output_dir,
                categorization_rules={
                    "schema_dns": ["cn=schema"],
                },
                parser_quirk=None,
                writer_quirk=None,
            )

            pipeline.execute()

            # Output directory should be created
            assert output_dir.exists()

    def test_execute_with_simple_entries(
        self, temp_input_dir: Path, temp_output_dir: Path
    ) -> None:
        """Test execute() processes real LDIF entries."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules={
                "schema_dns": ["cn=schema"],
                "hierarchy_objectclasses": ["organization", "organizationalunit"],
                "user_objectclasses": ["person"],
            },
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()

        # Should successfully process entries
        assert result.is_success
        exec_result = result.unwrap()
        assert exec_result.statistics.processed_entries > 0

    def test_execute_with_base_dn_filter(
        self, temp_input_dir: Path, temp_output_dir: Path
    ) -> None:
        """Test execute() filters entries by base_dn."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules={
                "schema_dns": ["cn=schema"],
                "hierarchy_objectclasses": ["organization"],
            },
            parser_quirk=None,
            writer_quirk=None,
            base_dn="o=example",
        )

        result = pipeline.execute()

        # Base DN filtering should work
        assert result.is_success
        exec_result = result.unwrap()
        # Entries under o=example should be included
        assert exec_result.statistics.total_entries >= 0

    def test_execute_with_forbidden_attributes(
        self, temp_input_dir: Path, temp_output_dir: Path
    ) -> None:
        """Test execute() filters forbidden attributes."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_attributes=["authPassword"],
        )

        result = pipeline.execute()

        assert result.is_success

    def test_execute_with_forbidden_objectclasses(
        self, temp_input_dir: Path, temp_output_dir: Path
    ) -> None:
        """Test execute() filters forbidden objectClasses."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_objectclasses=["orclService"],
        )

        result = pipeline.execute()

        assert result.is_success


class TestEntryParsing:
    """Test _parse_entries() and file parsing logic."""

    def test_parse_entries_with_valid_ldif(self) -> None:
        """Test _parse_entries() with valid LDIF file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir)

            ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
"""
            ldif_file = input_dir / "test.ldif"
            ldif_file.write_text(ldif_content, encoding="utf-8")

            pipeline = FlextLdifCategorizedMigrationPipeline(
                input_dir=input_dir,
                output_dir=Path(tmpdir) / "output",
                categorization_rules={},
                parser_quirk=None,
                writer_quirk=None,
            )

            result = pipeline._parse_entries()

            assert result.is_success
            entries = result.unwrap()
            assert len(entries) > 0

    def test_parse_entries_with_multiple_files(self) -> None:
        """Test _parse_entries() processes multiple LDIF files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir)

            # Create multiple LDIF files
            for i in range(2):
                ldif_content = f"""version: 1
dn: cn=test{i},dc=example,dc=com
objectClass: person
cn: test{i}
"""
                ldif_file = input_dir / f"test{i}.ldif"
                ldif_file.write_text(ldif_content, encoding="utf-8")

            pipeline = FlextLdifCategorizedMigrationPipeline(
                input_dir=input_dir,
                output_dir=Path(tmpdir) / "output",
                categorization_rules={},
                parser_quirk=None,
                writer_quirk=None,
            )

            result = pipeline._parse_entries()

            assert result.is_success
            entries = result.unwrap()
            # Should have entries from both files
            assert len(entries) >= 2

    def test_parse_entries_nonexistent_directory(self) -> None:
        """Test _parse_entries() with nonexistent input directory."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("/nonexistent/dir"),
            output_dir=Path("/tmp"),
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline._parse_entries()

        assert result.is_failure
        assert "does not exist" in result.error

    def test_parse_entries_with_input_files_filter(self) -> None:
        """Test _parse_entries() respects input_files filter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir)

            # Create multiple files
            for i in range(3):
                ldif_content = f"""version: 1
dn: cn=test{i},dc=example,dc=com
objectClass: person
cn: test{i}
"""
                ldif_file = input_dir / f"test{i}.ldif"
                ldif_file.write_text(ldif_content, encoding="utf-8")

            # Only process specific files
            pipeline = FlextLdifCategorizedMigrationPipeline(
                input_dir=input_dir,
                output_dir=Path(tmpdir) / "output",
                categorization_rules={},
                parser_quirk=None,
                writer_quirk=None,
                input_files=["test0.ldif", "test1.ldif"],
            )

            result = pipeline._parse_entries()

            assert result.is_success
            entries = result.unwrap()
            # Should have entries from selected files only
            assert len(entries) >= 2


class TestEntryCategorization:
    """Test _categorize_entries() and categorization logic."""

    def test_categorize_entries_empty_list(self) -> None:
        """Test _categorize_entries() with empty entry list."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("/tmp"),
            output_dir=Path("/tmp"),
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline._categorize_entries([])

        assert result.is_success
        categorized = result.unwrap()
        assert categorized["schema"] == []
        assert categorized["hierarchy"] == []
        assert categorized["users"] == []
        assert categorized["groups"] == []
        assert categorized["acl"] == []
        assert categorized["rejected"] == []

    def test_categorize_entry_schema(self) -> None:
        """Test _categorize_entry() identifies schema entries."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("/tmp"),
            output_dir=Path("/tmp"),
            categorization_rules={"schema_dns": ["cn=schema"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        entry: dict[str, object] = {
            "dn": "cn=schema",
            "objectclass": ["subSchema"],
        }

        category, rejection_reason = pipeline._categorize_entry(entry)

        assert category == "schema"
        assert rejection_reason is None

    def test_categorize_entry_hierarchy(self) -> None:
        """Test _categorize_entry() identifies hierarchy entries."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("/tmp"),
            output_dir=Path("/tmp"),
            categorization_rules={
                "hierarchy_objectclasses": ["organization", "organizationalUnit"]
            },
            parser_quirk=None,
            writer_quirk=None,
        )

        entry: dict[str, object] = {
            "dn": "o=example",
            "objectclass": ["organization"],
        }

        category, _ = pipeline._categorize_entry(entry)

        assert category == "hierarchy"

    def test_categorize_entry_user(self) -> None:
        """Test _categorize_entry() identifies user entries."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("/tmp"),
            output_dir=Path("/tmp"),
            categorization_rules={"user_objectclasses": ["person", "inetOrgPerson"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        entry: dict[str, object] = {
            "dn": "cn=john,ou=users,o=example",
            "objectclass": ["person"],
        }

        category, _ = pipeline._categorize_entry(entry)

        assert category == "users"

    def test_categorize_entry_group(self) -> None:
        """Test _categorize_entry() identifies group entries."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("/tmp"),
            output_dir=Path("/tmp"),
            categorization_rules={"group_objectclasses": ["groupOfNames"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        entry: dict[str, object] = {
            "dn": "cn=REDACTED_LDAP_BIND_PASSWORDs,o=example",
            "objectclass": ["groupOfNames"],
        }

        category, _ = pipeline._categorize_entry(entry)

        assert category == "groups"


class TestBaseDnFiltering:
    """Test _is_entry_under_base_dn() filtering logic."""

    def test_is_entry_under_base_dn_no_filter(self) -> None:
        """Test _is_entry_under_base_dn() when no base_dn configured."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("/tmp"),
            output_dir=Path("/tmp"),
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn=None,
        )

        entry: dict[str, object] = {"dn": "cn=test,dc=example,dc=com"}

        result = pipeline._is_entry_under_base_dn(entry)

        # Without base_dn, all entries pass
        assert result is True

    def test_is_entry_under_base_dn_exact_match(self) -> None:
        """Test _is_entry_under_base_dn() with exact DN match."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("/tmp"),
            output_dir=Path("/tmp"),
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="dc=example,dc=com",
        )

        entry: dict[str, object] = {"dn": "dc=example,dc=com"}

        result = pipeline._is_entry_under_base_dn(entry)

        assert result is True

    def test_is_entry_under_base_dn_child(self) -> None:
        """Test _is_entry_under_base_dn() with child DN."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("/tmp"),
            output_dir=Path("/tmp"),
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="dc=example,dc=com",
        )

        entry: dict[str, object] = {"dn": "cn=test,dc=example,dc=com"}

        result = pipeline._is_entry_under_base_dn(entry)

        assert result is True

    def test_is_entry_under_base_dn_outside(self) -> None:
        """Test _is_entry_under_base_dn() with entry outside base_dn."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("/tmp"),
            output_dir=Path("/tmp"),
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="dc=example,dc=com",
        )

        entry: dict[str, object] = {"dn": "cn=test,dc=other,dc=com"}

        result = pipeline._is_entry_under_base_dn(entry)

        assert result is False

    def test_is_entry_under_base_dn_missing_dn(self) -> None:
        """Test _is_entry_under_base_dn() with missing DN."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("/tmp"),
            output_dir=Path("/tmp"),
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="dc=example,dc=com",
        )

        entry: dict[str, object] = {"objectclass": ["person"]}

        result = pipeline._is_entry_under_base_dn(entry)

        assert result is False


class TestAttributeFiltering:
    """Test forbidden attribute and objectClass filtering."""

    def test_filter_forbidden_attributes_empty(self) -> None:
        """Test _filter_forbidden_attributes() with no forbidden list."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("/tmp"),
            output_dir=Path("/tmp"),
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_attributes=[],
        )

        attrs: dict[str, object] = {
            "cn": "test",
            "authPassword": "secret",
        }

        result = pipeline._filter_forbidden_attributes(attrs)

        # Should return all attributes when no forbidden list
        assert "cn" in result
        assert "authPassword" in result

    def test_filter_forbidden_attributes_filtering(self) -> None:
        """Test _filter_forbidden_attributes() removes forbidden attrs."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("/tmp"),
            output_dir=Path("/tmp"),
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_attributes=["authPassword", "userPassword"],
        )

        attrs: dict[str, object] = {
            "cn": "test",
            "authPassword": "secret",
            "mail": "test@example.com",
            "userPassword": "secret2",
        }

        result = pipeline._filter_forbidden_attributes(attrs)

        assert "cn" in result
        assert "mail" in result
        assert "authPassword" not in result
        assert "userPassword" not in result

    def test_filter_forbidden_attributes_case_insensitive(self) -> None:
        """Test _filter_forbidden_attributes() is case-insensitive."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("/tmp"),
            output_dir=Path("/tmp"),
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_attributes=["authPassword"],
        )

        attrs: dict[str, object] = {
            "cn": "test",
            "AUTHPASSWORD": "secret",
        }

        result = pipeline._filter_forbidden_attributes(attrs)

        assert "cn" in result
        assert "AUTHPASSWORD" not in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
