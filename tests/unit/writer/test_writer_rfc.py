"""Test FlextLdifWriterService with RFC quirks."""

from __future__ import annotations

import pytest

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels

# Import RFC quirks to ensure they are auto-registered
from flext_ldif.services.registry import FlextLdifRegistry
from flext_ldif.services.writer import FlextLdifWriterService


@pytest.fixture
def rfc_config() -> FlextLdifConfig:
    """Create RFC configuration."""
    return FlextLdifConfig(
        quirks_detection_mode="manual",
        quirks_server_type="rfc",
        enable_relaxed_parsing=False,
    )


@pytest.fixture
def registry() -> FlextLdifRegistry:
    """Get global FlextLdifRegistry with all registered quirks."""
    return FlextLdifRegistry.get_global_instance()


@pytest.fixture
def writer(
    rfc_config: FlextLdifConfig, registry: FlextLdifRegistry
) -> FlextLdifWriterService:
    """Create FlextLdifWriterService with RFC server type."""
    # WriterService is stateless and uses global singleton registry
    # Config is not passed to constructor but used via write() method parameters
    return FlextLdifWriterService()


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
            }
        ),
    )


def test_write_basic_string_output(
    writer: FlextLdifWriterService, simple_entry: FlextLdifModels.Entry
) -> None:
    """Test writing entries to string returns LDIF content."""
    result = writer.write(
        entries=[simple_entry], target_server_type="rfc", output_target="string"
    )

    assert result.is_success, f"Write failed: {result.error}"
    content = result.unwrap()

    # Verify it's a string with LDIF structure
    assert isinstance(content, str)
    assert "version: 1" in content
    assert "dn: cn=test,dc=example,dc=com" in content
