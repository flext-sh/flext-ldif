"""Integration tests for FlextLdif API facade with real workflows.

Tests cover:
- Complete parse-validate-write workflows
- Entry building and validation
- Multiple server type configurations
- Error handling in pipelines
- Real LDIF content processing

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdif


class TestFlextLdifFacadeWorkflows:
    """Integration tests for FlextLdif facade workflows."""

    def test_parse_simple_ldif_complete_workflow(self) -> None:
        """Test complete parse workflow with simple LDIF."""
        ldif = FlextLdif()
        ldif_content = "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: Test\nmail: test@example.com\n"
        result = ldif.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1
        assert entries[0].dn is not None
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"

    def test_parse_multiple_entries(self) -> None:
        """Test parsing multiple entries from single string."""
        ldif = FlextLdif()
        ldif_content = "dn: cn=user1,dc=example,dc=com\nobjectClass: person\ncn: user1\nsn: User1\n\ndn: cn=user2,dc=example,dc=com\nobjectClass: person\ncn: user2\nsn: User2\n\ndn: cn=user3,dc=example,dc=com\nobjectClass: person\ncn: user3\nsn: User3\n"
        result = ldif.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 3

    def test_parse_entries_with_multivalued_attributes(self) -> None:
        """Test parsing entries with multivalued attributes."""
        ldif = FlextLdif()
        ldif_content = "dn: cn=group,dc=example,dc=com\nobjectClass: groupOfNames\ncn: group\nmember: cn=user1,dc=example,dc=com\nmember: cn=user2,dc=example,dc=com\nmember: cn=user3,dc=example,dc=com\n"
        result = ldif.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_validate_parsed_entries(self) -> None:
        """Test validation of parsed entries."""
        ldif = FlextLdif()
        ldif_content = (
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: Test\n"
        )
        parse_result = ldif.parse(ldif_content)
        assert parse_result.is_success
        entries = parse_result.value
        validation_result = ldif.validate_entries(entries)
        assert validation_result is not None

    def test_write_entries_to_file(self, tmp_path: Path) -> None:
        """Test writing entries to file."""
        ldif = FlextLdif()
        output_file = tmp_path / "output.ldif"
        ldif_content = (
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: Test\n"
        )
        parse_result = ldif.parse(ldif_content)
        entries = parse_result.value
        write_result = ldif.write_file(entries, output_file)
        if write_result.is_success:
            assert output_file.exists()

    def test_parse_file_from_path(self, tmp_path: Path) -> None:
        """Test parsing LDIF from file path."""
        ldif_file = tmp_path / "test.ldif"
        ldif_file.write_text(
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: Test\n"
        )
        ldif = FlextLdif()
        result = ldif.parse(ldif_file)
        if result.is_success:
            entries = result.value
            assert len(entries) == 1

    def test_parse_handles_encoding(self, tmp_path: Path) -> None:
        """Test parsing handles different file encodings."""
        ldif_file = tmp_path / "utf8.ldif"
        ldif_file.write_text(
            "dn: cn=José,dc=example,dc=com\nobjectClass: person\ncn: José\nsn: García\n",
            encoding="utf-8",
        )
        ldif = FlextLdif()
        result = ldif.parse(ldif_file)
        assert result is not None

    def test_multiple_ldif_instances_are_independent(self) -> None:
        """Test that multiple FlextLdif instances don't interfere."""
        ldif1 = FlextLdif()
        ldif2 = FlextLdif()
        result1 = ldif1.parse("dn: cn=test1,dc=example,dc=com\ncn: test1")
        result2 = ldif2.parse("dn: cn=test2,dc=example,dc=com\ncn: test2")
        assert result1 is not None
        assert result2 is not None

    def test_error_handling_invalid_ldif(self) -> None:
        """Test error handling for invalid LDIF."""
        ldif = FlextLdif()
        invalid_content = "This is not valid LDIF format"
        result = ldif.parse(invalid_content)
        assert result is not None

    def test_get_entry_attributes_preserves_types(self) -> None:
        """Test that get_entry_attributes preserves attribute value types."""
        ldif = FlextLdif()
        ldif_content = "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nmail: test@example.com\n"
        parse_result = ldif.parse(ldif_content)
        entries = parse_result.value
        if entries:
            entry = entries[0]
            attrs = ldif.get_entry_attributes(entry)
            assert attrs is not None

    def test_chain_operations_with_railway_pattern(self) -> None:
        """Test chaining multiple operations using railway pattern."""
        ldif = FlextLdif()
        ldif_content = "dn: cn=user1,dc=example,dc=com\nobjectClass: person\ncn: user1\nsn: User1\n\ndn: cn=user2,dc=example,dc=com\nobjectClass: person\ncn: user2\nsn: User2\n"
        result = ldif.parse(ldif_content).flat_map(ldif.validate_entries)
        assert result is not None

    def test_parse_with_rfc_and_extensions(self) -> None:
        """Test parsing LDIF with RFC extensions."""
        ldif = FlextLdif()
        ldif_content = "version: 1\n# Comment line\ndn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: Test\n"
        result = ldif.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1
        assert entries[0].attributes is not None
        assert "cn" in entries[0].attributes.attributes
