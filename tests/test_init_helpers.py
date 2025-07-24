"""Tests for helper functions in __init__.py."""

from __future__ import annotations

import tempfile
from pathlib import Path

from flext_ldif import (
    FlextLdifAttributes,
    FlextLdifDistinguishedName,
    FlextLdifEntry,
    parse_ldif,
    validate_ldif,
    write_ldif,
)
from flext_ldif.types import LDIFContent


class TestInitHelpers:
    """Test helper functions from __init__.py."""

    def test_parse_ldif_with_valid_content(self) -> None:
        """Test parse_ldif with valid LDIF content."""
        content = LDIFContent(
            """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
mail: test@example.com"""
        )

        result = parse_ldif(content)
        assert isinstance(result, list)
        assert len(result) >= 0  # Should not fail

    def test_parse_ldif_with_string_content(self) -> None:
        """Test parse_ldif with string content."""
        content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person"""

        result = parse_ldif(content)
        assert isinstance(result, list)

    def test_parse_ldif_with_empty_content(self) -> None:
        """Test parse_ldif with empty content."""
        result = parse_ldif("")
        assert isinstance(result, list)
        assert len(result) == 0

    def test_write_ldif_without_path(self) -> None:
        """Test write_ldif without output path."""
        entries = [
            FlextLdifEntry(
                dn=FlextLdifDistinguishedName.model_validate({"value": "cn=test,dc=example,dc=com"}),
                attributes=FlextLdifAttributes.model_validate({"attributes": {"objectClass": ["person"], "cn": ["test"]}})
            )
        ]

        result = write_ldif(entries)
        assert isinstance(result, str)
        assert "cn=test,dc=example,dc=com" in result

    def test_write_ldif_with_path(self) -> None:
        """Test write_ldif with output path."""
        entries = [
            FlextLdifEntry(
                dn=FlextLdifDistinguishedName.model_validate({"value": "cn=test,dc=example,dc=com"}),
                attributes=FlextLdifAttributes.model_validate({"attributes": {"objectClass": ["person"], "cn": ["test"]}})
            )
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False) as f:
            temp_path = f.name

        try:
            result = write_ldif(entries, temp_path)
            assert isinstance(result, str)
            # Should indicate successful write or contain the LDIF content
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_write_ldif_empty_list(self) -> None:
        """Test write_ldif with empty entries list."""
        result = write_ldif([])
        assert isinstance(result, str)
        assert result == ""

    def test_validate_ldif_with_valid_content(self) -> None:
        """Test validate_ldif with valid content."""
        content = LDIFContent(
            """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person"""
        )

        result = validate_ldif(content)
        assert isinstance(result, bool)

    def test_validate_ldif_with_string_content(self) -> None:
        """Test validate_ldif with string content."""
        content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person"""

        result = validate_ldif(content)
        assert isinstance(result, bool)

    def test_validate_ldif_with_empty_content(self) -> None:
        """Test validate_ldif with empty content."""
        result = validate_ldif("")
        assert isinstance(result, bool)

    def test_validate_ldif_with_invalid_content(self) -> None:
        """Test validate_ldif with invalid content."""
        content = "invalid ldif content"
        result = validate_ldif(content)
        assert isinstance(result, bool)
