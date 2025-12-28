"""Tests for parser-writer roundtrip integration.

This module tests parser-writer roundtrip functionality including basic
transformations, complex LDIF structures, file I/O, error handling, performance
benchmarks, and edge cases with different LDAP server implementations.
"""
# type: ignore

from __future__ import annotations

import time
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Final

import pytest
from flext_tests import tm, tt, u

from flext_ldif import FlextLdifParser, FlextLdifWriter
from flext_ldif.models import m
from flext_ldif.protocols import p
from tests import OIDs, Syntax, c


class ParserWriterScenarios(StrEnum):
    """Test scenarios for parser-writer integration testing."""

    ROUNDTRIP_BASIC = "roundtrip_basic"
    ROUNDTRIP_COMPLEX = "roundtrip_complex"
    ROUNDTRIP_FILE_IO = "roundtrip_file_io"
    ROUNDTRIP_ERROR_HANDLING = "roundtrip_error_handling"
    ROUNDTRIP_PERFORMANCE = "roundtrip_performance"
    ROUNDTRIP_EDGE_CASES = "roundtrip_edge_cases"


class IntegrationTestData:
    """Test data constants for parser-writer integration tests."""

    # Basic test content
    BASIC_LDIF: Final[str] = f"""version: 1

dn: cn=test,{c.DNs.EXAMPLE}
objectClass: {c.Names.PERSON}
cn: Test User
sn: User
mail: test@example.com
"""

    # Complex test content with schema and ACL
    COMPLEX_LDIF: Final[str] = f"""version: 1

dn: {c.DNs.SCHEMA}
objectClass: ldapSubentry
objectClass: subschema
cn: schema
attributeTypes: ( {OIDs.CN} NAME '{c.Names.CN}' EQUALITY caseIgnoreMatch SYNTAX {Syntax.DIRECTORY_STRING} )

dn: ou=people,{c.DNs.EXAMPLE}
objectClass: organizationalUnit
ou: people
aci: (targetattr="*")(version 3.0; acl "Admin Access"; allow (all) userdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,{c.DNs.EXAMPLE}";)

dn: cn=John Doe,ou=people,{c.DNs.EXAMPLE}
objectClass: {c.Names.PERSON}
cn: John Doe
sn: Doe
mail: john.doe@example.com
"""

    # Invalid content for error testing
    INVALID_LDIF: Final[str] = """version: 1

dn: invalid dn format
cn: test
"""

    # Performance test configurations
    PERFORMANCE_CONFIGS: Final[Mapping[str, Mapping[str, int]]] = {
        "small": {"entry_count": 5, "max_time_ms": 50},
        "medium": {"entry_count": 20, "max_time_ms": 200},
    }


class FlextLdifParserWriterIntegrationTests(tt):
    """Comprehensive parser-writer integration tests using advanced Python 3.13 patterns.

    Tests roundtrip operations with format options compatibility, error handling,
    performance, and edge cases using dynamic parametrization and factory patterns.
    """

    # Test data constants
    _BASIC_LDIF: Final[str] = IntegrationTestData.BASIC_LDIF
    _COMPLEX_LDIF: Final[str] = IntegrationTestData.COMPLEX_LDIF
    _INVALID_LDIF: Final[str] = IntegrationTestData.INVALID_LDIF
    _PERFORMANCE_CONFIGS: Final[Mapping[str, Mapping[str, int]]] = (
        IntegrationTestData.PERFORMANCE_CONFIGS
    )

    @pytest.mark.parametrize(
        ("scenario", "content"),
        [
            (ParserWriterScenarios.ROUNDTRIP_BASIC, IntegrationTestData.BASIC_LDIF),
            (ParserWriterScenarios.ROUNDTRIP_COMPLEX, IntegrationTestData.COMPLEX_LDIF),
        ],
    )
    def test_roundtrip_scenarios_dynamic(
        self,
        scenario: str,
        content: str,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
    ) -> None:
        """Dynamically test roundtrip operations for different content types."""
        # Parse the content
        parse_result = parser_service.parse(
            content=content,
            input_source="string",
            server_type="rfc",
        )

        assert parse_result.is_success, f"Failed to parse content for {scenario}"
        parse_response = parse_result.value
        entries_list = parse_response.entries
        # Convert to list[p.Entry] for write method
        entries: list[p.Entry] = [
            entry for entry in entries_list if isinstance(entry, m.Ldif.Entry)
        ]

        # Verify we got entries
        tm.assert_length_greater_than(
            entries,
            0,
            f"No entries parsed for {scenario}",
        )

        # Write the entries back
        write_result = writer_service.write(
            entries=entries,
            target_server_type="rfc",
            output_target="string",
        )

        tm.assert_result_success(write_result)
        output_content_raw = write_result.value
        # Extract string from WriteResponse if needed
        if isinstance(output_content_raw, str):
            output_content = output_content_raw
        elif hasattr(output_content_raw, "content"):
            output_content = output_content_raw.content or ""
        else:
            output_content = str(output_content_raw)

        # Verify output contains expected elements
        assert "version: 1" in output_content, (
            f"Version missing in output for {scenario}"
        )
        assert "dn:" in output_content, f"DN missing in output for {scenario}"

        # Re-parse the output to verify roundtrip integrity
        reparse_result = parser_service.parse(
            content=output_content,
            input_source="string",
            server_type="rfc",
        )

        assert reparse_result.is_success, f"Failed to re-parse output for {scenario}"
        reparsed_response = reparse_result.value
        reparsed_entries = reparsed_response.entries

        # Should have same number of entries
        assert len(reparsed_entries) == len(entries), (
            f"Entry count mismatch in roundtrip for {scenario}"
        )

    def test_file_operations_roundtrip(
        self,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
        tmp_path: Path,
    ) -> None:
        """Test roundtrip operations with file I/O."""
        # Write content to temporary file
        input_file = tmp_path / "input.ldif"
        input_file.write_text(self._BASIC_LDIF)

        # Parse from file
        parse_result = parser_service.parse(
            content=str(input_file),
            input_source="file",
            server_type="rfc",
        )

        assert parse_result.is_success, "Failed to parse from file"
        parse_response = parse_result.value
        entries_list = parse_response.entries
        # Convert to list[p.Entry] for write method
        entries: list[p.Entry] = [
            entry for entry in entries_list if isinstance(entry, m.Ldif.Entry)
        ]
        tm.assert_length_equals(
            entries,
            1,
            "Should parse one entry from file",
        )

        # Write to another file
        output_file = tmp_path / "output.ldif"
        write_result = writer_service.write(
            entries=entries,
            target_server_type="rfc",
            output_target="file",
            output_path=output_file,
        )

        assert write_result.is_success, "Failed to write to file"

        # Verify file was created and has content
        u.Tests.FileHelpers.assert_file_exists(output_file)
        output_content = output_file.read_text()
        tm.assert_length_greater_than(
            output_content,
            0,
            "Output file should not be empty",
        )

        # Re-parse from file to verify integrity
        reparse_result = parser_service.parse(
            content=str(output_file),
            input_source="file",
            server_type="rfc",
        )

        assert reparse_result.is_success, "Failed to re-parse from file"
        reparsed_response = reparse_result.value
        reparsed_entries = reparsed_response.entries
        assert len(reparsed_entries) == len(entries), (
            "File roundtrip entry count mismatch"
        )

    def test_error_handling_invalid_content(
        self,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
    ) -> None:
        """Test error handling with invalid LDIF content."""
        # Try to parse invalid content
        parse_result = parser_service.parse(
            content=self._INVALID_LDIF,
            input_source="string",
            server_type="rfc",
        )

        # Should either fail or succeed with errors
        if parse_result.is_failure:
            assert parse_result.error is not None
            assert (
                "invalid" in parse_result.error.lower()
                or "error" in parse_result.error.lower()
            )
        else:
            # If parsing succeeded, entries might have validation issues
            parse_response = parse_result.value
            entries = parse_response.entries
            # At minimum, we should have attempted to parse something
            u.Tests.Assertions.assert_result_matches_expected(
                entries,
                list,
                description="parse response entries",
            )

    @pytest.mark.parametrize(
        ("perf_case", "entry_count", "max_time_ms"),
        [
            (name, config["entry_count"], config["max_time_ms"])
            for name, config in _PERFORMANCE_CONFIGS.items()
        ],
    )
    def test_performance_basic_roundtrip(
        self,
        perf_case: str,
        entry_count: int,
        max_time_ms: int,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
    ) -> None:
        """Test basic performance of roundtrip operations."""
        # Generate content with specified number of entries
        content = self._generate_multi_entry_content(entry_count)

        # Measure parse time
        start_time = time.time()
        parse_result = parser_service.parse(
            content=content,
            input_source="string",
            server_type="rfc",
        )
        parse_time = (time.time() - start_time) * 1000

        assert parse_result.is_success, f"Failed to parse {entry_count} entries"
        parse_response = parse_result.value
        entries_list = parse_response.entries
        # Convert to list[p.Entry] for write method
        entries: list[p.Entry] = [
            entry for entry in entries_list if isinstance(entry, m.Ldif.Entry)
        ]
        assert len(entries) == entry_count, (
            f"Expected {entry_count} entries, got {len(entries)}"
        )

        # Measure write time
        start_time = time.time()
        write_result = writer_service.write(
            entries=entries,
            target_server_type="rfc",
            output_target="string",
        )
        write_time = (time.time() - start_time) * 1000

        assert write_result.is_success, f"Failed to write {entry_count} entries"

        total_time = parse_time + write_time
        assert total_time < max_time_ms, (
            f"Performance test failed: {total_time:.2f}ms > {max_time_ms}ms for {perf_case}"
        )

    def test_edge_cases_empty_and_special(
        self,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
    ) -> None:
        """Test edge cases with empty content and special scenarios."""
        # Test empty content
        parse_result = parser_service.parse(
            content="",
            input_source="string",
            server_type="rfc",
        )
        assert parse_result.is_success, "Empty content should parse successfully"
        parse_response = parse_result.value
        entries = parse_response.entries
        tm.assert_length_equals(
            entries,
            0,
            "Empty content should produce no entries",
        )

        # Test content with only version
        version_only = "version: 1\n"
        parse_result = parser_service.parse(
            content=version_only,
            input_source="string",
            server_type="rfc",
        )
        assert parse_result.is_success, "Version-only content should parse successfully"
        parse_response = parse_result.value
        entries = parse_response.entries
        tm.assert_length_equals(
            entries,
            0,
            "Version-only content should produce no entries",
        )

    def _generate_multi_entry_content(self, count: int) -> str:
        """Generate LDIF content with specified number of entries."""
        lines = ["version: 1", ""]

        for i in range(count):
            lines.extend([
                f"dn: cn=user{i},{c.DNs.EXAMPLE}",
                f"objectClass: {c.Names.PERSON}",
                f"cn: User {i}",
                f"sn: User{i}",
                f"mail: user{i}@example.com",
                "",
            ])

        return "\n".join(lines)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
