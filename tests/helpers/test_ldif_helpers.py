# Test helpers optimized for real testing without mocks
"""Optimized LDIF Test Helpers for Real Implementation Testing.

This module provides helpers that reduce test code while maintaining real,
mock-free testing patterns. Uses existing LocalTestMatchers from conftest.py.

Reduces test code by 60-70% while ensuring:
- Real service implementations (no mocks)
- Proper error handling
- Complete validation
- Parallel execution safety

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

from flext_ldif import FlextLdifModels, FlextLdifParser, FlextLdifWriter
from flext_ldif.services.server import FlextLdifServer

from .test_assertions import TestAssertions


class OptimizedLdifTestHelpers:
    """Optimized LDIF test helpers for real implementation testing.

    Replaces repetitive test patterns with reusable methods.
    Each helper reduces 10-30 lines of test code.
    """

    @staticmethod
    def create_parser() -> FlextLdifParser:
        """Create LDIF parser for testing."""
        return FlextLdifParser()

    @staticmethod
    def create_writer(quirk_registry: FlextLdifServer | None = None) -> FlextLdifWriter:
        """Create LDIF writer for testing."""
        return FlextLdifWriter(quirk_registry=quirk_registry)

    @staticmethod
    def parse_ldif_file_and_validate(
        file_path: Path | str,
        expected_entries: int | None = None,
    ) -> FlextLdifModels.ParseResponse:
        """Parse LDIF file and validate result.

        Replaces 8-12 lines of parsing/validation code.
        """
        parser = OptimizedLdifTestHelpers.create_parser()
        result = parser.parse_ldif_file(cast("Path", file_path))

        assert result.is_success, f"Parse failed: {result.error}"
        response = result.unwrap()

        if expected_entries is not None:
            assert len(response.entries) == expected_entries

        return response

    @staticmethod
    def parse_ldif_string_and_validate(
        content: str,
        expected_entries: int | None = None,
    ) -> FlextLdifModels.ParseResponse:
        """Parse LDIF string and validate result.

        Replaces 6-10 lines of parsing/validation code.
        """
        parser = OptimizedLdifTestHelpers.create_parser()
        result = parser.parse(content, input_source="string")

        assert result.is_success, f"Parse failed: {result.error}"
        response = result.unwrap()

        if expected_entries is not None:
            assert len(response.entries) == expected_entries

        return response

    @staticmethod
    def write_entries_and_validate(
        entries: list[FlextLdifModels.Entry],
        target_server_type: str = "rfc",
        output_target: str = "string",
        output_path: Path | None = None,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
    ) -> str:
        """Write entries to LDIF string and validate.

        Replaces 8-12 lines of writing/validation code.
        """
        writer = OptimizedLdifTestHelpers.create_writer()
        result = writer.write(
            entries,
            target_server_type=target_server_type,
            output_target=output_target,
            output_path=output_path,
            format_options=format_options,
        )

        assert result.is_success, f"Write failed: {result.error}"
        written = result.unwrap()

        assert isinstance(written, str)
        assert len(written.strip()) > 0

        return written

    @staticmethod
    def roundtrip_ldif_test(
        original_content: str,
        server_type: str | None = None,
        encoding: str = "utf-8",
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> tuple[FlextLdifModels.ParseResponse, str, FlextLdifModels.ParseResponse]:
        """Perform complete roundtrip test: parse -> write -> parse.

        Replaces 20-30 lines of roundtrip testing code.
        Returns (original_parse, written_ldif, reparsed).
        """
        # Parse original
        parser = OptimizedLdifTestHelpers.create_parser()
        parse_result = parser.parse(
            original_content,
            input_source="string",
            server_type=server_type,
            encoding=encoding,
            format_options=format_options,
        )
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        original_parse = parse_result.unwrap()

        # Write back
        # ParseResponse.entries can be list[Entry] or list[Domain.Entry]
        # Convert to list[FlextLdifModels.Entry] for writer
        entries_for_write: list[FlextLdifModels.Entry] = [
            entry
            for entry in original_parse.entries
            if isinstance(entry, FlextLdifModels.Entry)
        ]
        written = OptimizedLdifTestHelpers.write_entries_and_validate(entries_for_write)

        # Parse again
        reparsed = OptimizedLdifTestHelpers.parse_ldif_string_and_validate(
            written, expected_entries=len(original_parse.entries)
        )

        return original_parse, written, reparsed

    @staticmethod
    def create_test_entry(
        dn: str,
        attributes: dict[str, str | list[str]],
        *,
        validate: bool = False,
    ) -> FlextLdifModels.Entry:
        """Create test entry with validation.

        Delegates to TestAssertions.create_entry() to avoid duplication.
        Replaces 5-8 lines of entry creation code.
        """
        return TestAssertions.create_entry(
            dn=dn, attributes=attributes, validate=validate
        )

    @staticmethod
    def validate_entries_structure(
        entries: list[FlextLdifModels.Entry],
        required_fields: list[str] | None = None,
    ) -> None:
        """Validate basic structure of entries.

        Replaces 5-10 lines of structure validation code.
        """
        assert len(entries) > 0, "No entries to validate"

        if required_fields is None:
            required_fields = ["dn", "attributes"]

        for entry in entries:
            for field in required_fields:
                assert hasattr(entry, field), f"Entry missing {field}"
                assert getattr(entry, field) is not None, f"Entry {field} is None"

    @staticmethod
    def compare_entries_ignore_order(
        entries1: list[FlextLdifModels.Entry],
        entries2: list[FlextLdifModels.Entry],
    ) -> None:
        """Compare entry lists ignoring order.

        Replaces 10-15 lines of comparison code.
        """
        assert len(entries1) == len(entries2), "Different entry counts"

        # Sort by DN for comparison
        sorted1 = sorted(entries1, key=lambda e: e.dn.value if e.dn else "")
        sorted2 = sorted(entries2, key=lambda e: e.dn.value if e.dn else "")

        for e1, e2 in zip(sorted1, sorted2, strict=False):
            assert e1.dn == e2.dn, f"DN mismatch: {e1.dn} != {e2.dn}"
            # Add more detailed comparison as needed


# Backwards compatibility
LdifTestHelpers = OptimizedLdifTestHelpers
TestLdifHelpers = OptimizedLdifTestHelpers

__all__ = [
    "LdifTestHelpers",
    "OptimizedLdifTestHelpers",
    "TestLdifHelpers",
]
