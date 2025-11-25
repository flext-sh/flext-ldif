"""Test FlextLdifWriter with RFC quirks."""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest

from flext_ldif import FlextLdifConfig, FlextLdifModels, FlextLdifWriter
from flext_ldif.services.server import FlextLdifServer

# =============================================================================
# TEST SCENARIO ENUMS
# =============================================================================


class WriterOutputType(StrEnum):
    """Writer output target types."""

    STRING = "string"


class WriterTestScenario(StrEnum):
    """Writer test scenarios."""

    BASIC_WRITE = "basic_write"


# =============================================================================
# TEST FIXTURES
# =============================================================================


@pytest.fixture
def rfc_config() -> FlextLdifConfig:
    """Create RFC configuration."""
    return FlextLdifConfig(
        quirks_detection_mode="manual",
        quirks_server_type="rfc",
        enable_relaxed_parsing=False,
    )


@pytest.fixture
def registry() -> FlextLdifServer:
    """Get global FlextLdifServer with all registered quirks."""
    return FlextLdifServer.get_global_instance()


@pytest.fixture
def writer(rfc_config: FlextLdifConfig, registry: FlextLdifServer) -> FlextLdifWriter:
    """Create FlextLdifWriter with RFC server type."""
    # WriterService is stateless and uses global singleton registry
    # Config is not passed to constructor but used via write() method parameters
    return FlextLdifWriter()


@pytest.fixture
def simple_entry() -> FlextLdifModels.Entry:
    """Create a simple RFC-compliant entry."""
    return FlextLdifModels.Entry(
        dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
        attributes=FlextLdifModels.LdifAttributes(
            attributes={
                "cn": ["test"],
                "objectClass": ["person", "inetOrgPerson"],
                "sn": ["test-user"],
                "mail": ["test@example.com"],
            },
        ),
    )


# =============================================================================
# PARAMETRIZED TEST DATA
# =============================================================================


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
        [
            (data[0], data[1], data[2])
            for data in WRITER_OUTPUT_DATA.values()
        ],
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

        assert result.is_success, f"Write failed: {result.error}"
        content = result.unwrap()

        # Verify it's a string with LDIF structure
        assert isinstance(content, str)
        assert expected_content in content
        assert "dn: cn=test,dc=example,dc=com" in content
