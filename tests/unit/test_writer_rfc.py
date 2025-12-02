"""Test suite for FlextLdifWriter RFC compliance.

Tests validate that FlextLdifWriter:
1. Writes single and multiple entries correctly (RFC 2849)
2. Supports string and file output targets
3. Handles multi-value attributes correctly
4. Provides entry statistics
5. Validates server types
6. Handles edge cases (empty lists, invalid servers)

Modules tested:
- flext_ldif.writer.FlextLdifWriter (RFC 2849 writing)
- flext_ldif.models.FlextLdifModels.WriteFormatOptions (format options)
- flext_ldif.models.FlextLdifModels.Entry (entry writing)

Scope:
- Single/multiple entry writing
- String/file output targets
- Statistics collection
- Multi-value attributes
- Empty entries handling
- Server validation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from pathlib import Path
from typing import Final

import pytest
from flext_tests import FlextTestsMatchers  # Mocked in conftest

from flext_ldif import FlextLdifModels, FlextLdifWriter
from tests.fixtures.constants import DNs, Names, Values
from tests.helpers.test_factories import FlextLdifTestFactories


class WriteTarget(StrEnum):
    """Write output target types."""

    STRING = "string"
    FILE = "file"


class WriterTestType(StrEnum):
    """Types of writer tests."""

    SINGLE_ENTRY = "single_entry"
    MULTIPLE_ENTRIES = "multiple_entries"
    STATISTICS = "statistics"
    MULTIVALUE = "multivalue"
    EMPTY_LIST = "empty_list"
    INVALID_SERVER = "invalid_server"
    INITIALIZATION = "initialization"


@dataclasses.dataclass(frozen=True)
class WriterTestCase:
    """Writer test case definition."""

    test_type: WriterTestType
    target_type: str = WriteTarget.STRING
    expect_success: bool = True
    expected_entry_count: int | None = None
    expected_member_count: int | None = None
    server_type: str = "rfc"
    description: str = ""


# Writer test cases
WRITER_TESTS: Final[list[WriterTestCase]] = [
    WriterTestCase(
        WriterTestType.SINGLE_ENTRY,
        WriteTarget.STRING,
        description="Write single entry to string",
    ),
    WriterTestCase(
        WriterTestType.SINGLE_ENTRY,
        WriteTarget.FILE,
        description="Write single entry to file",
    ),
    WriterTestCase(
        WriterTestType.MULTIPLE_ENTRIES,
        WriteTarget.STRING,
        expected_entry_count=2,
        description="Write multiple entries to string",
    ),
    WriterTestCase(
        WriterTestType.STATISTICS,
        WriteTarget.STRING,
        expected_entry_count=1,
        description="Verify entry statistics on write",
    ),
    WriterTestCase(
        WriterTestType.MULTIVALUE,
        WriteTarget.STRING,
        expected_member_count=3,
        description="Write entry with multiple attribute values",
    ),
    WriterTestCase(
        WriterTestType.EMPTY_LIST,
        WriteTarget.STRING,
        description="Write empty entries list",
    ),
    WriterTestCase(
        WriterTestType.INVALID_SERVER,
        WriteTarget.STRING,
        expect_success=False,
        server_type="nonexistent-server",
        description="Fail on non-existent server type",
    ),
    WriterTestCase(
        WriterTestType.INITIALIZATION,
        WriteTarget.STRING,
        description="Test writer initialization",
    ),
]


class WriterTestFactory:
    """Factory for creating writer test instances and data."""

    @staticmethod
    def create_writer() -> FlextLdifWriter:
        """Create FlextLdifWriter instance."""
        return FlextLdifWriter()

    @staticmethod
    def create_format_options(
        *,
        base64_encode: bool = False,
    ) -> FlextLdifModels.WriteFormatOptions:
        """Create write format options."""
        return FlextLdifModels.WriteFormatOptions(base64_encode_binary=base64_encode)

    @classmethod
    def create_simple_entry(cls) -> FlextLdifModels.Entry:
        """Create a simple RFC-compliant entry."""
        return FlextLdifTestFactories.create_entry(
            dn=DNs.TEST_USER,
            attributes={
                Names.CN: [Values.TEST],
                Names.OBJECTCLASS: [Names.PERSON, Names.INET_ORG_PERSON],
                Names.SN: [f"{Values.TEST}-user"],
                Names.MAIL: [Values.TEST_EMAIL],
            },
        )

    @classmethod
    def create_multivalue_entry(cls) -> FlextLdifModels.Entry:
        """Create entry with multiple values for same attribute."""
        return FlextLdifTestFactories.create_entry(
            dn=DNs.TEST_GROUP,
            attributes={
                Names.CN: [Values.TEST],
                Names.OBJECTCLASS: ["groupOfNames", Names.TOP],
                "member": [
                    f"cn={Values.USER1},{DNs.EXAMPLE}",
                    f"cn={Values.USER2},{DNs.EXAMPLE}",
                    f"cn=user3,{DNs.EXAMPLE}",
                ],
            },
        )

    @classmethod
    def create_second_entry(cls) -> FlextLdifModels.Entry:
        """Create a second RFC-compliant entry."""
        return FlextLdifTestFactories.create_entry(
            dn=f"cn=test2,{DNs.EXAMPLE}",
            attributes={
                Names.CN: ["test2"],
                Names.OBJECTCLASS: [Names.PERSON],
            },
        )


def get_writer_tests() -> list[WriterTestCase]:
    """Parametrization helper for writer tests."""
    return WRITER_TESTS


class TestWriterRfc:
    """Comprehensive RFC writer tests.

    Tests all writer functionality using factories, parametrization, and helpers
    for minimal code with complete coverage.
    """

    @pytest.mark.parametrize("test_case", get_writer_tests())
    def test_writer_operations(
        self,
        test_case: WriterTestCase,
        tmp_path: Path,
    ) -> None:
        """Comprehensive writer test for all scenarios."""
        writer = WriterTestFactory.create_writer()
        format_options = WriterTestFactory.create_format_options()

        match test_case.test_type:
            case WriterTestType.SINGLE_ENTRY:
                # Test single entry writing
                entry = WriterTestFactory.create_simple_entry()

                if test_case.target_type == WriteTarget.FILE:
                    output_path = tmp_path / "output.ldif"
                    result = writer.write(
                        entries=[entry],
                        target_server_type=test_case.server_type,
                        output_path=output_path,
                        format_options=format_options,
                    )
                    unwrapped = FlextTestsMatchers.assert_success(result)
                    assert output_path.exists()
                    content = output_path.read_text()
                else:
                    result = writer.write(
                        entries=[entry],
                        target_server_type=test_case.server_type,
                        format_options=format_options,
                    )
                    unwrapped = FlextTestsMatchers.assert_success(result)
                    assert isinstance(unwrapped, str)
                    content = unwrapped

                # Verify LDIF structure
                assert content.startswith("version: 1\n")
                assert f"dn: {DNs.TEST_USER}" in content
                assert f"{Names.CN}: {Values.TEST}" in content
                assert f"{Names.OBJECTCLASS}: {Names.PERSON}" in content
                assert f"{Names.OBJECTCLASS}: {Names.INET_ORG_PERSON}" in content

            case WriterTestType.MULTIPLE_ENTRIES:
                # Test multiple entry writing
                entry1 = WriterTestFactory.create_simple_entry()
                entry2 = WriterTestFactory.create_second_entry()

                result = writer.write(
                    [entry1, entry2],
                    target_server_type=test_case.server_type,
                    format_options=format_options,
                )

                unwrapped = FlextTestsMatchers.assert_success(result)
                assert isinstance(unwrapped, str)
                content = unwrapped

                # Verify both entries are present
                lines = content.split("\n")
                dn_line_indices = [
                    i for i, line in enumerate(lines) if line.startswith("dn:")
                ]
                # Should have at least expected count
                expected_count = test_case.expected_entry_count or 2
                assert len(dn_line_indices) >= expected_count, (
                    f"Expected at least {expected_count} "
                    f"DN lines, found {len(dn_line_indices)}"
                )
                assert f"dn: {DNs.TEST_USER}" in content
                assert "dn: cn=test2,dc=example,dc=com" in content

            case WriterTestType.STATISTICS:
                # Test entry statistics
                entry = WriterTestFactory.create_simple_entry()

                result = writer.write(
                    [entry],
                    target_server_type=test_case.server_type,
                    format_options=format_options,
                )

                unwrapped = FlextTestsMatchers.assert_success(result)
                assert isinstance(unwrapped, str)
                # Verify we have the entry in output
                assert f"dn: {DNs.TEST_USER}" in unwrapped

            case WriterTestType.MULTIVALUE:
                # Test multi-value attributes
                entry = WriterTestFactory.create_multivalue_entry()

                result = writer.write(
                    [entry],
                    target_server_type=test_case.server_type,
                    format_options=format_options,
                )

                unwrapped = FlextTestsMatchers.assert_success(result)
                assert isinstance(unwrapped, str)
                content = unwrapped

                # Check all member values are present
                assert content.count("member: ") == test_case.expected_member_count
                assert f"member: cn={Values.USER1},dc=example,dc=com" in content
                assert f"member: cn={Values.USER2},dc=example,dc=com" in content
                assert "member: cn=user3,dc=example,dc=com" in content

            case WriterTestType.EMPTY_LIST:
                # Test empty entries list
                result = writer.write(
                    [],
                    target_server_type=test_case.server_type,
                    format_options=format_options,
                )

                unwrapped = FlextTestsMatchers.assert_success(result)
                assert isinstance(unwrapped, str)
                # Empty list produces LDIF version header but no entries
                assert unwrapped == "version: 1\n"
                assert unwrapped.count("dn:") == 0

            case WriterTestType.INVALID_SERVER:
                # Test invalid server type
                entry = WriterTestFactory.create_simple_entry()

                result = writer.write(
                    [entry],
                    target_server_type=test_case.server_type,
                    format_options=format_options,
                )

                # Should fail with clear error message
                assert result.is_failure
                assert result.error is not None
                assert "no entry quirk found" in result.error.lower()

            case WriterTestType.INITIALIZATION:
                # Test writer initialization
                assert writer is not None
                assert isinstance(writer, FlextLdifWriter)


__all__ = [
    "TestWriterRfc",
    "WriteTarget",
    "WriterTestFactory",
]
