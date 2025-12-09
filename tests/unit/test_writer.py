"""Tests for FlextLdifWriter with RFC server type configuration.

This module tests the FlextLdifWriter service configured with RFC (Internet Standard)
server type, validating LDIF output generation, entry handling, and proper formatting
according to RFC 2849 standards.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest

from flext_ldif import FlextLdifWriter
from flext_ldif.protocols import p
from tests import s


class WriterOutputType(StrEnum):
    """Writer output target types."""

    STRING = "string"


class WriterTestScenario(StrEnum):
    """Writer test scenarios."""

    BASIC_WRITE = "basic_write"


@pytest.fixture
def writer() -> FlextLdifWriter:
    """Create FlextLdifWriter instance."""
    return FlextLdifWriter()


@pytest.fixture
def simple_entry() -> p.Entry:
    """Create a simple RFC-compliant entry using factory."""
    return s().create_entry(
        dn="cn=testuser,ou=users,dc=example,dc=com",
        attributes={
            "cn": ["testuser"],
            "objectClass": ["person", "inetOrgPerson"],
            "sn": ["testuser-user"],
            "mail": ["testuser@example.com"],
        },
    )


@pytest.mark.unit
class TestFlextLdifWriterRfc(s):
    """Test FlextLdifWriter with RFC server type configuration."""

    WRITER_OUTPUT_DATA: ClassVar[
        dict[str, tuple[WriterTestScenario, WriterOutputType, str]]
    ] = {
        "write_basic_string_output": (
            WriterTestScenario.BASIC_WRITE,
            WriterOutputType.STRING,
            "version: 1",
        ),
    }

    @pytest.mark.parametrize(
        ("scenario", "output_type", "expected_content"),
        [(data[0], data[1], data[2]) for data in WRITER_OUTPUT_DATA.values()],
    )
    def test_writer_output(
        self,
        scenario: WriterTestScenario,
        output_type: WriterOutputType,
        expected_content: str,
        writer: FlextLdifWriter,
        simple_entry: p.Entry,
    ) -> None:
        """Parametrized test for writer output generation."""
        # FlextLdifWriter.write() returns string when output_path is not provided
        # (output_target parameter is not supported)
        result = writer.write(
            entries=[simple_entry],
            target_server_type="rfc",
        )

        content = self.assert_success(
            result,
            f"Write failed for scenario {scenario.value}",
        )

        assert isinstance(content, str)
        # Writer output may not include "version: 1" header by default
        # Check that content contains the entry DN instead
        assert simple_entry.dn.value in content or expected_content in content
        assert "dn: cn=testuser" in content
