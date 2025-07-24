"""Tests for LDIF parser."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Never

from flext_ldif import LDIFContent, LDIFParser


class TestLDIFParser:
    """Test LDIF parser functionality."""

    def test_parse_single_entry(self) -> None:
        """Test parsing single LDIF entry."""
        content = LDIFContent(
            """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
mail: test@example.com"""
        )

        parser = LDIFParser()
        result = parser.parse_ldif_content(content)

        assert result.success
        entries = result.data
        assert entries is not None
        assert len(entries) == 1

        entry = entries[0]
        assert str(entry.dn) == "cn=test,dc=example,dc=com"
        assert entry.get_attribute("cn") == ["test"]
        assert entry.get_attribute("objectClass") == ["person"]
        assert entry.get_attribute("mail") == ["test@example.com"]

    def test_parse_multiple_entries(self) -> None:
        """Test parsing multiple LDIF entries."""
        content = LDIFContent(
            """dn: cn=user1,dc=example,dc=com
cn: user1
objectClass: person

dn: cn=user2,dc=example,dc=com
cn: user2
objectClass: person
mail: user2@example.com"""
        )

        parser = LDIFParser()
        result = parser.parse_ldif_content(content)

        assert result.success
        entries = result.data
        assert entries is not None
        assert len(entries) == 2

        # Check first entry
        entry1 = entries[0]
        assert str(entry1.dn) == "cn=user1,dc=example,dc=com"
        assert entry1.get_attribute("cn") == ["user1"]
        assert entry1.get_attribute("objectClass") == ["person"]

        # Check second entry
        entry2 = entries[1]
        assert str(entry2.dn) == "cn=user2,dc=example,dc=com"
        assert entry2.get_attribute("cn") == ["user2"]
        assert entry2.get_attribute("objectClass") == ["person"]
        assert entry2.get_attribute("mail") == ["user2@example.com"]

    def test_parse_empty_content(self) -> None:
        """Test parsing empty LDIF content."""
        content = LDIFContent("")

        parser = LDIFParser()
        result = parser.parse_ldif_content(content)

        assert result.success
        entries = result.data
        assert entries is not None
        assert len(entries) == 0

    def test_parse_whitespace_only(self) -> None:
        """Test parsing whitespace-only content."""
        content = LDIFContent("   \n   \n   ")

        parser = LDIFParser()
        result = parser.parse_ldif_content(content)

        assert result.success
        entries = result.data
        assert entries is not None
        assert len(entries) == 0

    def test_parse_invalid_entry_no_dn(self) -> None:
        """Test parsing invalid entry without DN."""
        content = LDIFContent(
            """cn: test
objectClass: person"""
        )

        parser = LDIFParser()
        result = parser.parse_ldif_content(content)

        assert not result.success
        assert result.error is not None
        assert "First line must be DN" in result.error

    def test_parse_invalid_entry_empty_block(self) -> None:
        """Test parsing with empty block between entries."""
        content = LDIFContent(
            """dn: cn=user1,dc=example,dc=com
cn: user1

dn: cn=user2,dc=example,dc=com
cn: user2"""
        )

        parser = LDIFParser()
        result = parser.parse_ldif_content(content)

        assert result.success
        entries = result.data
        assert entries is not None
        assert len(entries) == 2

    def test_parse_entries_with_extra_whitespace(self) -> None:
        """Test parsing entries with extra whitespace."""
        content = LDIFContent(
            """

dn: cn=test,dc=example,dc=com
cn: test
objectClass: person

        """
        )

        parser = LDIFParser()
        result = parser.parse_ldif_content(content)

        assert result.success
        entries = result.data
        assert entries is not None
        assert len(entries) == 1

        entry = entries[0]
        assert str(entry.dn) == "cn=test,dc=example,dc=com"
        assert entry.get_attribute("cn") == ["test"]

    def test_parse_multiple_values_same_attribute(self) -> None:
        """Test parsing entry with multiple values for same attribute."""
        content = LDIFContent(
            """dn: cn=test,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
mail: test@example.com
mail: test2@example.com"""
        )

        parser = LDIFParser()
        result = parser.parse_ldif_content(content)

        assert result.success
        entries = result.data
        assert entries is not None
        assert len(entries) == 1

        entry = entries[0]
        assert entry.get_attribute("objectClass") == ["person", "inetOrgPerson"]
        assert entry.get_attribute("mail") == ["test@example.com", "test2@example.com"]

    def test_parse_ldif_file_success(self) -> None:
        """Test parsing LDIF from file successfully."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
mail: test@example.com"""

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(ldif_content)
            temp_file = f.name

        try:
            parser = LDIFParser()
            result = parser.parse_ldif_file(temp_file)

            assert result.success
            entries = result.data
            assert entries is not None
            assert len(entries) == 1

            entry = entries[0]
            assert str(entry.dn) == "cn=test,dc=example,dc=com"
            assert entry.get_attribute("cn") == ["test"]
        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_parse_ldif_file_not_found(self) -> None:
        """Test parsing LDIF from non-existent file."""
        parser = LDIFParser()
        result = parser.parse_ldif_file("/non/existent/file.ldif")

        assert not result.success
        assert result.error is not None
        assert "Failed to read LDIF file" in result.error

    def test_parse_ldif_file_permission_error(self) -> None:
        """Test parsing LDIF from file with permission issues."""
        # Create temporary file and remove read permissions
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("dn: cn=test,dc=example,dc=com\ncn: test")
            temp_file = f.name

        try:
            # Remove read permissions
            Path(temp_file).chmod(0o000)

            parser = LDIFParser()
            result = parser.parse_ldif_file(temp_file)

            assert not result.success
            assert result.error is not None
            assert "Failed to read LDIF file" in result.error
        finally:
            # Restore permissions and cleanup
            try:
                Path(temp_file).chmod(0o644)
                Path(temp_file).unlink(missing_ok=True)
            except OSError:
                pass  # Might fail if permissions are really messed up

    def test_parse_content_with_type_error(self) -> None:
        """Test parsing content that causes type error."""
        # This will test the exception handling in parse_ldif_content
        parser = LDIFParser()

        # Mock the LDIFContent to cause an issue during __str__ conversion
        class BadContent:
            def __str__(self) -> str:
                msg = "Simulated type error"
                raise TypeError(msg)

        from typing import Any, cast

        result = parser.parse_ldif_content(cast("Any", BadContent()))

        assert not result.success
        assert result.error is not None
        assert "Failed to parse LDIF" in result.error

    def test_parse_content_with_attribute_error(self) -> None:
        """Test parsing content that causes attribute error in LDIFEntry creation."""
        from unittest.mock import patch

        # Create content that will cause LDIFEntry.from_ldif_block to fail
        content = LDIFContent("dn: cn=test,dc=example,dc=com")

        parser = LDIFParser()

        # Mock the from_ldif_block method to raise AttributeError
        with patch("flext_ldif.LDIFEntry.from_ldif_block") as mock_from_ldif:
            mock_from_ldif.side_effect = AttributeError("Simulated attribute error")

            result = parser.parse_ldif_content(content)
            assert not result.success
            assert result.error is not None
            assert "Failed to parse LDIF" in result.error
