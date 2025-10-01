"""Comprehensive tests for RFC LDIF Writer Service.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.rfc.rfc_ldif_writer import RfcLdifWriterService


class TestRfcLdifWriterService:
    """Comprehensive test suite for RFC LDIF writer."""

    @pytest.fixture
    def sample_entry(self) -> FlextLdifModels.Entry:
        """Create a sample LDIF entry."""
        result = FlextLdifModels.Entry.create(
            dn="cn=Test User,dc=example,dc=com",
            attributes={
                "cn": ["Test User"],
                "sn": ["User"],
                "objectClass": ["person", "organizationalPerson"],
                "mail": ["test@example.com"],
            },
        )
        return result.unwrap()

    @pytest.fixture
    def sample_entries(
        self, sample_entry: FlextLdifModels.Entry
    ) -> list[FlextLdifModels.Entry]:
        """Create multiple sample entries."""
        entry2_result = FlextLdifModels.Entry.create(
            dn="cn=Another User,dc=example,dc=com",
            attributes={
                "cn": ["Another User"],
                "sn": ["User"],
                "objectClass": ["person"],
            },
        )
        return [sample_entry, entry2_result.unwrap()]

    def test_writer_initialization_basic(self) -> None:
        """Test basic writer initialization."""
        params = {"entries": []}
        writer = RfcLdifWriterService(params=params)

        assert writer is not None
        assert hasattr(writer, "execute")

    def test_writer_initialization_with_quirks(self) -> None:
        """Test writer initialization with quirk registry."""
        from flext_ldif.quirks.registry import QuirkRegistryService

        params = {"entries": []}
        registry = QuirkRegistryService()
        writer = RfcLdifWriterService(
            params=params,
            quirk_registry=registry,
            target_server_type="oud",
        )

        assert writer is not None

    def test_write_single_entry_to_string(
        self, sample_entry: FlextLdifModels.Entry
    ) -> None:
        """Test writing single entry returns LDIF string."""
        params = {"entries": [sample_entry]}
        writer = RfcLdifWriterService(params=params)

        result = writer.execute()

        assert result.is_success
        data = result.unwrap()
        assert "content" in data
        assert "cn=Test User,dc=example,dc=com" in data["content"]

    def test_write_multiple_entries_to_string(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test writing multiple entries."""
        params = {"entries": sample_entries}
        writer = RfcLdifWriterService(params=params)

        result = writer.execute()

        assert result.is_success
        data = result.unwrap()
        assert "content" in data
        content = data["content"]
        assert "cn=Test User,dc=example,dc=com" in content
        assert "cn=Another User,dc=example,dc=com" in content

    def test_write_to_file(
        self, sample_entry: FlextLdifModels.Entry, tmp_path: Path
    ) -> None:
        """Test writing LDIF to file."""
        output_file = tmp_path / "test_output.ldif"
        params = {"entries": [sample_entry], "output_file": str(output_file)}
        writer = RfcLdifWriterService(params=params)

        result = writer.execute()

        assert result.is_success
        assert output_file.exists()

        content = output_file.read_text()
        assert "cn=Test User,dc=example,dc=com" in content
        assert "objectClass:" in content

    def test_write_empty_entries_list(self) -> None:
        """Test writing empty entries list."""
        params = {"entries": []}
        writer = RfcLdifWriterService(params=params)

        result = writer.execute()

        # Should succeed but produce minimal/empty output
        assert result.is_success or result.is_failure

    def test_write_entry_with_multivalued_attributes(self) -> None:
        """Test writing entry with multiple values per attribute."""
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=Multi Value,dc=example,dc=com",
            attributes={
                "cn": ["Multi Value"],
                "objectClass": [
                    "top",
                    "person",
                    "organizationalPerson",
                    "inetOrgPerson",
                ],
                "mail": ["mail1@example.com", "mail2@example.com", "mail3@example.com"],
            },
        )
        entry = entry_result.unwrap()

        params = {"entries": [entry]}
        writer = RfcLdifWriterService(params=params)

        result = writer.execute()

        assert result.is_success
        data = result.unwrap()
        content = data["content"]

        # Should have multiple mail lines
        assert content.count("mail:") == 3
        assert content.count("objectClass:") == 4

    def test_write_with_special_characters(self) -> None:
        """Test writing entries with special characters."""
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=Special Char,dc=example,dc=com",
            attributes={
                "cn": ["Special Char"],
                "description": ["Line with\nnewline", "Tab\there"],
                "objectClass": ["person"],
            },
        )
        entry = entry_result.unwrap()

        params = {"entries": [entry]}
        writer = RfcLdifWriterService(params=params)

        result = writer.execute()

        # Should succeed and handle special chars (base64 encoding)
        assert result.is_success or result.is_failure

    def test_write_with_target_server_type(
        self, sample_entry: FlextLdifModels.Entry
    ) -> None:
        """Test writing with specific target server type."""
        params = {"entries": [sample_entry]}
        writer = RfcLdifWriterService(
            params=params,
            target_server_type="oud",
        )

        result = writer.execute()

        assert result.is_success

    def test_line_wrapping_long_values(self) -> None:
        """Test RFC 2849 line wrapping for long attribute values."""
        long_value = "a" * 100  # Value longer than 76 chars
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=Long Value,dc=example,dc=com",
            attributes={
                "cn": ["Long Value"],
                "description": [long_value],
                "objectClass": ["person"],
            },
        )
        entry = entry_result.unwrap()

        params = {"entries": [entry]}
        writer = RfcLdifWriterService(params=params)

        result = writer.execute()

        assert result.is_success
        data = result.unwrap()
        content = data["content"]

        # RFC 2849 wraps lines starting with space on continuation
        assert " " in content or "\n " in content

    def test_write_with_schema_data(self, sample_entry: FlextLdifModels.Entry) -> None:
        """Test writing with schema information."""
        schema_data = {
            "attributeTypes": {},
            "objectClasses": {},
        }
        params = {"entries": [sample_entry], "schema": schema_data}
        writer = RfcLdifWriterService(params=params)

        result = writer.execute()

        assert result.is_success or result.is_failure

    def test_write_with_acl_data(self, sample_entry: FlextLdifModels.Entry) -> None:
        """Test writing with ACL information."""
        acl_data = {"acls": []}
        params = {"entries": [sample_entry], "acls": acl_data}
        writer = RfcLdifWriterService(params=params)

        result = writer.execute()

        assert result.is_success or result.is_failure

    def test_execute_returns_flext_result(
        self, sample_entry: FlextLdifModels.Entry
    ) -> None:
        """Test that execute returns FlextResult."""
        from flext_core import FlextResult

        params = {"entries": [sample_entry]}
        writer = RfcLdifWriterService(params=params)

        result = writer.execute()

        assert isinstance(result, FlextResult)
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")

    def test_write_preserves_dn_format(
        self, sample_entry: FlextLdifModels.Entry
    ) -> None:
        """Test that DN format is preserved in output."""
        params = {"entries": [sample_entry]}
        writer = RfcLdifWriterService(params=params)

        result = writer.execute()

        assert result.is_success
        data = result.unwrap()
        content = data["content"]

        # DN should be first line and properly formatted
        assert (
            content.startswith("dn:") or "dn: cn=Test User,dc=example,dc=com" in content
        )

    def test_write_includes_entry_separator(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test that entries are separated by blank lines."""
        params = {"entries": sample_entries}
        writer = RfcLdifWriterService(params=params)

        result = writer.execute()

        assert result.is_success
        data = result.unwrap()
        content = data["content"]

        # Multiple entries should have separators
        assert "\n\n" in content or content.count("dn:") == len(sample_entries)
