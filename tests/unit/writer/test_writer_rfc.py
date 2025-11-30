"""Test FlextLdifWriter with RFC quirks.

Tests validate that FlextLdifWriter:
1. Writes entries correctly with RFC server type
2. Generates correct LDIF format output
3. Handles string output targets
4. Produces valid RFC 2849 compliant LDIF

Modules tested:
- flext_ldif.writer.FlextLdifWriter (LDIF writing service)
- flext_ldif.models.FlextLdifModels.Entry (entry models)

Scope:
- RFC server type configuration
- String output target
- Basic entry writing
- LDIF format validation

Uses FlextTestsMatchers and FlextLdifTestFactories for reduced code duplication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest

# from flext_tests import FlextTestsMatchers  # Mocked in conftest
from tests.fixtures.constants import DNs, Names, Values
from tests.helpers.test_factories import FlextLdifTestFactories

from flext_ldif import FlextLdifModels, FlextLdifWriter


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
def simple_entry() -> FlextLdifModels.Entry:
    """Create a simple RFC-compliant entry using factory."""
    return FlextLdifTestFactories.create_entry(
        dn=DNs.TEST_USER,
        attributes={
            Names.CN: [Values.TEST],
            Names.OBJECTCLASS: [Names.PERSON, Names.INET_ORG_PERSON],
            Names.SN: [f"{Values.TEST}-{Values.USER}"],
            Names.MAIL: [Values.TEST_EMAIL],
        },
    )


@pytest.mark.unit
class TestFlextLdifWriterRfc:
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
        simple_entry: FlextLdifModels.Entry,
    ) -> None:
        """Parametrized test for writer output generation."""
        result = writer.write(
            entries=[simple_entry],
            target_server_type="rfc",
            output_target=output_type.value,
        )

        content = FlextTestsMatchers.assert_success(
            result,
            f"Write failed for scenario {scenario.value}",
        )

        assert isinstance(content, str)
        assert expected_content in content
        assert f"dn: {DNs.TEST_USER}" in content
