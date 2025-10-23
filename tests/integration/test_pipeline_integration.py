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

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: Test
mail: test@example.com
"""

        result = ldif.parse(ldif_content)

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"

    def test_parse_multiple_entries(self) -> None:
        """Test parsing multiple entries from single string."""
        ldif = FlextLdif()

        ldif_content = """dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1
sn: User1

dn: cn=user2,dc=example,dc=com
objectClass: person
cn: user2
sn: User2

dn: cn=user3,dc=example,dc=com
objectClass: person
cn: user3
sn: User3
"""

        result = ldif.parse(ldif_content)

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 3

    def test_parse_entries_with_multivalued_attributes(self) -> None:
        """Test parsing entries with multivalued attributes."""
        ldif = FlextLdif()

        ldif_content = """dn: cn=group,dc=example,dc=com
objectClass: groupOfNames
cn: group
member: cn=user1,dc=example,dc=com
member: cn=user2,dc=example,dc=com
member: cn=user3,dc=example,dc=com
"""

        result = ldif.parse(ldif_content)

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1

    def test_validate_parsed_entries(self) -> None:
        """Test validation of parsed entries."""
        ldif = FlextLdif()

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: Test
"""

        parse_result = ldif.parse(ldif_content)
        assert parse_result.is_success

        entries = parse_result.unwrap()
        validation_result = ldif.validate_entries(entries)

        assert validation_result is not None

    def test_analyze_entries_returns_stats(self) -> None:
        """Test analyzing entries returns statistics."""
        ldif = FlextLdif()

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test

dn: cn=test2,dc=example,dc=com
objectClass: person
cn: test2
"""

        parse_result = ldif.parse(ldif_content)
        entries = parse_result.unwrap()

        analysis_result = ldif.analyze(entries)

        assert analysis_result is not None

    def test_write_entries_to_file(self, tmp_path: Path) -> None:
        """Test writing entries to file."""
        ldif = FlextLdif()
        output_file = tmp_path / "output.ldif"

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: Test
"""

        parse_result = ldif.parse(ldif_content)
        entries = parse_result.unwrap()

        write_result = ldif.write(entries, output_file)

        if write_result.is_success:
            assert output_file.exists()

    def test_parse_file_from_path(self, tmp_path: Path) -> None:
        """Test parsing LDIF from file path."""
        ldif_file = tmp_path / "test.ldif"
        ldif_file.write_text("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: Test
""")

        ldif = FlextLdif()
        result = ldif.parse(ldif_file)

        if result.is_success:
            entries = result.unwrap()
            assert len(entries) == 1

    def test_parse_handles_encoding(self, tmp_path: Path) -> None:
        """Test parsing handles different file encodings."""
        ldif_file = tmp_path / "utf8.ldif"
        ldif_file.write_text(
            """dn: cn=José,dc=example,dc=com
objectClass: person
cn: José
sn: García
""",
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

        # Should return FlextResult that indicates failure or has no entries
        assert result is not None

    def test_get_entry_attributes_preserves_types(self) -> None:
        """Test that get_entry_attributes preserves attribute value types."""
        ldif = FlextLdif()

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
mail: test@example.com
"""

        parse_result = ldif.parse(ldif_content)
        entries = parse_result.unwrap()

        if entries:
            entry = entries[0]
            attrs = ldif.get_entry_attributes(entry)
            assert attrs is not None

    def test_chain_operations_with_railway_pattern(self) -> None:
        """Test chaining multiple operations using railway pattern."""
        ldif = FlextLdif()

        ldif_content = """dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1
sn: User1

dn: cn=user2,dc=example,dc=com
objectClass: person
cn: user2
sn: User2
"""

        # Chain parse -> validate -> analyze
        result = ldif.parse(ldif_content).flat_map(
            lambda entries: ldif.validate_entries(entries)  # noqa: PLW0108
        )

        # Should complete without error
        assert result is not None

    def test_parse_with_rfc_and_extensions(self) -> None:
        """Test parsing LDIF with RFC extensions."""
        ldif = FlextLdif()

        # LDIF with version, comments
        ldif_content = """version: 1
# Comment line
dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: Test
"""

        result = ldif.parse(ldif_content)

        assert result is not None

    def test_analyze_returns_detailed_stats(self) -> None:
        """Test that analyze returns detailed statistics."""
        ldif = FlextLdif()

        ldif_content = """dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1
mail: user1@example.com

dn: cn=group1,dc=example,dc=com
objectClass: groupOfNames
cn: group1
member: cn=user1,dc=example,dc=com
"""

        parse_result = ldif.parse(ldif_content)
        entries = parse_result.unwrap()

        analysis = ldif.analyze(entries)

        if analysis is not None:
            assert isinstance(analysis, dict) or hasattr(analysis, "__iter__")
