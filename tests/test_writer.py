"""Tests for FLEXT LDIF Writer."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from flext_ldif import (
    FlextLdifHierarchicalSorter,
    FlextLdifWriter,
    LDIFWriter,
    flext_ldif_sort_entries_hierarchically,
)


class TestFlextLdifWriter:
    """Test FlextLdifWriter functionality."""

    def test_write_entries_to_file_basic(self) -> None:
        """Test basic entry writing functionality."""
        entries = [
            {
                "dn": "cn=test,dc=example,dc=com",
                "cn": "test",
                "objectClass": ["person"],
            }
        ]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w+",
            delete=False,
            suffix=".ldif",
        ) as f:
            file_path = Path(f.name)

        try:
            result = FlextLdifWriter.write_entries_to_file(file_path, entries)

            assert result.success
            assert result.data == 1
            assert file_path.exists()

            content = file_path.read_text(encoding="utf-8")
            assert "dn: cn=test,dc=example,dc=com" in content
            assert "cn: test" in content
            assert "objectClass: person" in content
        finally:
            file_path.unlink(missing_ok=True)

    def test_write_entries_with_comments(self) -> None:
        """Test writing entries with comments."""
        entries = [
            {
                "dn": "cn=test,dc=example,dc=com",
                "cn": "test",
                "_comments": ["# This is a test entry"],
            }
        ]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w+",
            delete=False,
            suffix=".ldif",
        ) as f:
            file_path = Path(f.name)

        try:
            result = FlextLdifWriter.write_entries_to_file(
                file_path,
                entries,
                include_comments=True,
            )

            assert result.success
            content = file_path.read_text(encoding="utf-8")
            assert "# This is a test entry" in content
        finally:
            file_path.unlink(missing_ok=True)

    def test_write_entries_without_comments(self) -> None:
        """Test writing entries without comments."""
        entries = [
            {
                "dn": "cn=test,dc=example,dc=com",
                "cn": "test",
                "_comments": ["# This should not appear"],
            }
        ]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w+",
            delete=False,
            suffix=".ldif",
        ) as f:
            file_path = Path(f.name)

        try:
            result = FlextLdifWriter.write_entries_to_file(
                file_path,
                entries,
                include_comments=False,
            )

            assert result.success
            content = file_path.read_text(encoding="utf-8")
            assert "# This should not appear" not in content
        finally:
            file_path.unlink(missing_ok=True)

    def test_write_schema_to_file(self) -> None:
        """Test schema writing functionality."""
        schema_content = (
            "add: attributeTypes\nattributeTypes: ( 1.2.3.4 NAME 'testAttr' )"
        )

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w+",
            delete=False,
            suffix=".ldif",
        ) as f:
            file_path = Path(f.name)

        try:
            result = FlextLdifWriter.write_schema_to_file(
                file_path,
                schema_content,
                "Test Schema",
            )

            assert result.success
            assert result.data is True

            content = file_path.read_text(encoding="utf-8")
            assert "# Test Schema" in content
            assert "dn: cn=schema" in content
            assert "changetype: modify" in content
            assert schema_content in content
        finally:
            file_path.unlink(missing_ok=True)

    def test_write_text_lines_to_file(self) -> None:
        """Test text lines writing functionality."""
        lines = ["line1", "line2", "line3"]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w+",
            delete=False,
            suffix=".txt",
        ) as f:
            file_path = Path(f.name)

        try:
            result = FlextLdifWriter.write_text_lines_to_file(
                file_path,
                lines,
                "Test Header",
            )

            assert result.success
            assert result.data == 3

            content = file_path.read_text(encoding="utf-8")
            assert "# Test Header" in content
            assert "line1" in content
            assert "line2" in content
            assert "line3" in content
        finally:
            file_path.unlink(missing_ok=True)


class TestFlextLdifHierarchicalSorter:
    """Test FlextLdifHierarchicalSorter functionality."""

    def test_sort_entries_hierarchically(self) -> None:
        """Test hierarchical sorting of entries."""
        from flext_ldif import (
            FlextLdifAttributes,
            FlextLdifDistinguishedName,
            FlextLdifEntry,
        )

        # Create real FlextLdifEntry objects
        entries = [
            FlextLdifEntry(
                dn=FlextLdifDistinguishedName.model_validate({"value": "cn=child,ou=people,dc=example,dc=com"}),
                attributes=FlextLdifAttributes.model_validate({"attributes": {"objectClass": ["person"]}})
            ),
            FlextLdifEntry(
                dn=FlextLdifDistinguishedName.model_validate({"value": "dc=example,dc=com"}),
                attributes=FlextLdifAttributes.model_validate({"attributes": {"objectClass": ["domain"]}})
            ),
            FlextLdifEntry(
                dn=FlextLdifDistinguishedName.model_validate({"value": "ou=people,dc=example,dc=com"}),
                attributes=FlextLdifAttributes.model_validate({"attributes": {"objectClass": ["organizationalUnit"]}})
            ),
        ]

        result = flext_ldif_sort_entries_hierarchically(entries)

        # Should be sorted by depth (shallow first)
        assert result.success
        sorted_entries = result.data
        assert sorted_entries is not None
        assert str(sorted_entries[0].dn) == "dc=example,dc=com"  # depth 2
        assert str(sorted_entries[1].dn) == "ou=people,dc=example,dc=com"  # depth 3
        assert str(sorted_entries[2].dn) == "cn=child,ou=people,dc=example,dc=com"  # depth 4

    def test_sort_entries_with_list_dn(self) -> None:
        """Test sorting with DN as list."""
        from flext_ldif import (
            FlextLdifAttributes,
            FlextLdifDistinguishedName,
            FlextLdifEntry,
        )

        entries = [
            FlextLdifEntry(
                dn=FlextLdifDistinguishedName.model_validate({"value": "cn=child,ou=people,dc=example,dc=com"}),
                attributes=FlextLdifAttributes.model_validate({"attributes": {"objectClass": ["person"]}})
            ),
            FlextLdifEntry(
                dn=FlextLdifDistinguishedName.model_validate({"value": "dc=example,dc=com"}),
                attributes=FlextLdifAttributes.model_validate({"attributes": {"objectClass": ["domain"]}})
            ),
        ]

        result = flext_ldif_sort_entries_hierarchically(entries)

        assert result.success
        sorted_entries = result.data
        assert sorted_entries is not None
        assert str(sorted_entries[0].dn) == "dc=example,dc=com"
        assert str(sorted_entries[1].dn) == "cn=child,ou=people,dc=example,dc=com"

    def test_sort_entries_simple_dn(self) -> None:
        """Test sorting with simple DN."""
        from flext_ldif import (
            FlextLdifAttributes,
            FlextLdifDistinguishedName,
            FlextLdifEntry,
        )

        entries = [
            FlextLdifEntry(
                dn=FlextLdifDistinguishedName.model_validate({"value": "cn=simple"}),
                attributes=FlextLdifAttributes.model_validate({"attributes": {"objectClass": ["person"]}})
            ),
            FlextLdifEntry(
                dn=FlextLdifDistinguishedName.model_validate({"value": "dc=example,dc=com"}),
                attributes=FlextLdifAttributes.model_validate({"attributes": {"objectClass": ["domain"]}})
            ),
        ]

        result = flext_ldif_sort_entries_hierarchically(entries)

        # Simple DN should come first (depth 0 - no commas)
        assert result.success
        sorted_entries = result.data
        assert sorted_entries is not None
        assert str(sorted_entries[0].dn) == "cn=simple"
        assert str(sorted_entries[1].dn) == "dc=example,dc=com"


class TestLDIFWriterAlias:
    """Test LDIFWriter alias."""

    def test_ldif_writer_is_alias(self) -> None:
        """Test that LDIFWriter is an alias for FlextLdifWriter."""
        assert LDIFWriter is FlextLdifWriter

    def test_ldif_writer_functionality(self) -> None:
        """Test that LDIFWriter works the same as FlextLdifWriter."""
        entries = [{"dn": "cn=test,dc=example,dc=com", "cn": "test"}]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w+",
            delete=False,
            suffix=".ldif",
        ) as f:
            file_path = Path(f.name)

        try:
            result = LDIFWriter.write_entries_to_file(file_path, entries)
            assert result.success
            assert result.data == 1
        finally:
            file_path.unlink(missing_ok=True)


class TestWriterErrorHandling:
    """Test error handling in writer functions."""

    def test_write_to_invalid_path(self) -> None:
        """Test writing to invalid path."""
        entries = [{"dn": "cn=test", "cn": "test"}]

        # Try to write to a path that can't be created
        invalid_path = Path("/root/invalid/path/file.ldif")

        result = FlextLdifWriter.write_entries_to_file(invalid_path, entries)
        assert result.is_failure
        assert result.error is not None
        assert "Failed to write LDIF" in result.error

    def test_write_schema_to_invalid_path(self) -> None:
        """Test writing schema to invalid path."""
        invalid_path = Path("/root/invalid/path/schema.ldif")

        result = FlextLdifWriter.write_schema_to_file(invalid_path, "test content")
        assert result.is_failure
        assert result.error is not None
        assert "Failed to write schema" in result.error

    def test_write_text_to_invalid_path(self) -> None:
        """Test writing text to invalid path."""
        invalid_path = Path("/root/invalid/path/text.txt")

        result = FlextLdifWriter.write_text_lines_to_file(invalid_path, ["test"])
        assert result.is_failure
        assert result.error is not None
        assert "Failed to write text" in result.error


@pytest.mark.integration
class TestWriterIntegration:
    """Integration tests for writer functionality."""

    def test_hierarchical_sorting_integration(self) -> None:
        """Test integration of hierarchical sorting with file writing."""
        entries = [
            {
                "dn": "cn=john,ou=people,dc=example,dc=com",
                "cn": "john",
                "objectClass": ["person"],
            },
            {
                "dn": "dc=example,dc=com",
                "dc": "example",
                "objectClass": ["domain"],
            },
            {
                "dn": "ou=people,dc=example,dc=com",
                "ou": "people",
                "objectClass": ["organizationalUnit"],
            },
        ]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w+",
            delete=False,
            suffix=".ldif",
        ) as f:
            file_path = Path(f.name)

        try:
            result = FlextLdifWriter.write_entries_to_file(
                file_path,
                entries,
                sort_hierarchically=True,
            )

            assert result.success
            assert result.data == 3

            content = file_path.read_text(encoding="utf-8")
            lines = content.strip().split("\n")

            # Find DN positions in the file
            dn_positions = {
                line: i for i, line in enumerate(lines) if line.startswith("dn: ")
            }

            # Verify correct order (shallow to deep)
            dc_pos = dn_positions["dn: dc=example,dc=com"]
            ou_pos = dn_positions["dn: ou=people,dc=example,dc=com"]
            cn_pos = dn_positions["dn: cn=john,ou=people,dc=example,dc=com"]

            assert dc_pos < ou_pos < cn_pos

        finally:
            file_path.unlink(missing_ok=True)
