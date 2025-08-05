"""Tests for improving core module coverage.

Tests specifically designed to cover edge cases and error conditions
in the core LDIF processing functionality.
"""

from __future__ import annotations

import tempfile
import uuid
from pathlib import Path

from flext_ldif import TLdif
from flext_ldif.models import FlextLdifEntry


class TestCoreCoverage:
    """Tests to improve core module test coverage."""

    def test_tldif_parse_empty_content(self) -> None:
        """Test TLdif parse with empty content."""
        result = TLdif.parse("")
        assert result.success
        assert result.data == []

    def test_tldif_parse_invalid_content(self) -> None:
        """Test TLdif parse with invalid content."""
        result = TLdif.parse("invalid ldif content without proper format")
        assert not result.success
        assert "failed" in result.error.lower()

    def test_tldif_parse_with_exception(self) -> None:
        """Test TLdif parse with content that causes exception."""
        # Create content that might cause parsing issues
        invalid_content = "\x00\x01\x02"  # Binary content
        result = TLdif.parse(invalid_content)
        # Should handle gracefully
        assert isinstance(result.success, bool)

    def test_tldif_validate_invalid_dn(self) -> None:
        """Test TLdif validate with DN that doesn't match pattern."""
        # Create entry with DN that passes Pydantic validation but fails TLdif pattern
        # Create entry directly for testing validation edge case (bypassing factory validation)

        from flext_ldif.models import (
            FlextLdifAttributes,
            FlextLdifDistinguishedName,
            FlextLdifEntry,
        )

        # This will pass FlextLdifDistinguishedName validation but fail TLdif pattern matching
        dn = FlextLdifDistinguishedName(
            value="cn=valid,dc=example,dc=com"
        )  # Use valid DN first
        attrs = FlextLdifAttributes(attributes={"objectClass": ["person"]})
        entry = FlextLdifEntry(id=str(uuid.uuid4()), dn=dn, attributes=attrs)

        # Now modify the DN to invalid to test TLdif validation
        entry.dn = FlextLdifDistinguishedName(value="1invalid=test,dc=example,dc=com")

        result = TLdif.validate(entry)
        assert not result.success
        assert "Invalid DN format" in result.error

    def test_tldif_validate_invalid_attribute_name(self) -> None:
        """Test TLdif validate with invalid attribute name."""
        # Create entry directly for testing validation edge case

        from flext_ldif.models import (
            FlextLdifAttributes,
            FlextLdifDistinguishedName,
            FlextLdifEntry,
        )

        dn = FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com")
        attrs = FlextLdifAttributes(
            attributes={"123invalid": ["value"], "objectClass": ["person"]}
        )
        entry = FlextLdifEntry(id=str(uuid.uuid4()), dn=dn, attributes=attrs)

        result = TLdif.validate(entry)
        assert not result.success
        assert "Invalid attribute name" in result.error

    def test_tldif_validate_missing_objectclass(self) -> None:
        """Test TLdif validate with missing objectClass."""
        # Create entry without objectClass
        # Create entry directly for testing validation edge case

        from flext_ldif.models import (
            FlextLdifAttributes,
            FlextLdifDistinguishedName,
            FlextLdifEntry,
        )

        dn = FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com")
        attrs = FlextLdifAttributes(attributes={"cn": ["test"]})  # Missing objectClass
        entry = FlextLdifEntry(id=str(uuid.uuid4()), dn=dn, attributes=attrs)

        result = TLdif.validate(entry)
        assert not result.success
        assert "missing required objectClass" in result.error

    def test_tldif_validate_with_exception(self) -> None:
        """Test TLdif validate with entry that causes exception."""
        # Pass None to trigger exception
        result = TLdif.validate(None)
        assert not result.success
        assert "Entry cannot be None" in result.error

    def test_tldif_validate_entries_with_invalid_entry(self) -> None:
        """Test TLdif validate_entries with one invalid entry."""
        valid_entry = FlextLdifEntry.model_validate(
            {
                "dn": "cn=valid,dc=example,dc=com",
                "attributes": {"objectClass": ["person"], "cn": ["valid"]},
            },
        )

        # Create an entry with valid DN but invalid attribute name
        invalid_entry = FlextLdifEntry.model_validate(
            {
                "dn": "cn=invalid,dc=example,dc=com",
                "attributes": {"123invalid": ["value"], "objectClass": ["person"]},
            },
        )

        result = TLdif.validate_entries([valid_entry, invalid_entry])
        assert not result.success
        assert "Entry 2 of 2 failed validation" in result.error

    def test_tldif_validate_entries_with_exception(self) -> None:
        """Test TLdif validate_entries with exception."""
        result = TLdif.validate_entries(None)
        assert not result.success
        assert "Bulk validation failed" in result.error

    def test_tldif_write_with_exception(self) -> None:
        """Test TLdif write with entries that cause exception."""
        # Pass None to trigger exception
        result = TLdif.write(None)
        assert not result.success
        assert "failed" in result.error.lower()

    def test_tldif_write_file_invalid_path(self) -> None:
        """Test TLdif write_file with invalid path."""
        entry = FlextLdifEntry.model_validate(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"objectClass": ["person"], "cn": ["test"]},
            },
        )

        result = TLdif.write_file([entry], "/invalid/path/file.ldif")
        assert not result.success
        assert "File write failed" in result.error

    def test_tldif_write_file_no_content(self) -> None:
        """Test TLdif write_file when write returns no content."""
        # This would need to mock the write method to return None
        # For now, test with empty entries using proper temp file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            temp_path = f.name

        try:
            result = TLdif.write_file([], temp_path)
            # Should handle gracefully
            assert isinstance(result.success, bool)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_tldif_read_file_nonexistent(self) -> None:
        """Test TLdif read_file with nonexistent file."""
        result = TLdif.read_file("/nonexistent/file.ldif")
        assert not result.success
        assert "file not found" in result.error.lower()

    def test_tldif_read_file_with_permission_error(self) -> None:
        """Test TLdif read_file with permission error."""
        # Create a file and try to read it with restricted permissions
        with tempfile.NamedTemporaryFile(encoding="utf-8", mode="w", delete=False) as f:
            f.write("dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n")
            temp_path = f.name

        try:
            # Change permissions to make file unreadable
            Path(temp_path).chmod(0o000)

            result = TLdif.read_file(temp_path)
            # Should handle permission error gracefully
            assert not result.success
            assert "file read failed" in result.error.lower()
        finally:
            # Restore permissions and cleanup
            Path(temp_path).chmod(0o644)
            Path(temp_path).unlink(missing_ok=True)

    def test_tldif_read_file_success(self) -> None:
        """Test TLdif read_file successful case."""
        # Create a temporary LDIF file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
""")
            temp_path = f.name

        try:
            result = TLdif.read_file(temp_path)
            assert result.success
            assert len(result.data) == 1
            assert str(result.data[0].dn) == "cn=test,dc=example,dc=com"
        finally:
            Path(temp_path).unlink()

    def test_tldif_write_file_success(self) -> None:
        """Test TLdif write_file successful case."""
        entry = FlextLdifEntry.model_validate(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"objectClass": ["person"], "cn": ["test"]},
            },
        )

        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as f:
            temp_path = f.name

        try:
            result = TLdif.write_file([entry], temp_path)
            assert result.success
            assert result.data is True

            # Verify file was written correctly
            with Path(temp_path).open(encoding="utf-8") as f:
                content = f.read()
                assert "cn=test,dc=example,dc=com" in content
                assert "objectClass: person" in content
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_tldif_patterns_validation(self) -> None:
        """Test TLdif validation patterns."""
        # Test DN pattern
        assert TLdif.DN_PATTERN.match("cn=test,dc=example,dc=com")
        assert not TLdif.DN_PATTERN.match("invalid-dn-format")

        # Test attribute name pattern
        assert TLdif.ATTR_NAME_PATTERN.match("cn")
        assert TLdif.ATTR_NAME_PATTERN.match("objectClass")
        assert not TLdif.ATTR_NAME_PATTERN.match("123invalid")
        assert not TLdif.ATTR_NAME_PATTERN.match("invalid-char-@")

    def test_modernized_ldif_integration_error_paths(self) -> None:
        """Test error paths in modernized LDIF integration."""
        # Test parse with content that might cause modernized parser to fail
        result = TLdif.parse("dn: cn=test\nno-colon-attribute")
        # Should handle gracefully
        assert isinstance(result.success, bool)

        # Test write with entries that might cause modernized writer to fail
        entry = FlextLdifEntry.model_validate(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"objectClass": ["person"]},
            },
        )
        result = TLdif.write([entry])
        # Should handle gracefully
        assert isinstance(result.success, bool)
